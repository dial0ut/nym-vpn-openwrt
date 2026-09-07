#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw4 (nftables)
#
# This script is called by fw4 on start and restart.
# It re-applies the Nym VPN integration that lives inside fw4's own table and
# keeps the boot-time kill-switch block in step with the daemon's state.
#
# Installation:
#   1. Copy to /usr/share/nym-vpn/fw4-include.sh
#   2. Add to /etc/config/firewall:
#      config include 'nym_vpn'
#          option type 'script'
#          option path '/usr/share/nym-vpn/fw4-include.sh'
#          option enabled '1'
#
# Why this exists:
#   A `fw4 reload` rebuilds the `inet fw4` table from scratch. The kill-switch
#   blocking rules live in a SEPARATE `inet nym` table (priority filter -10) and
#   survive a reload untouched — the daemon owns that table's lifecycle, so this
#   script must never delete it. What does NOT survive are the daemon's tunnel
#   integration chains, which live INSIDE `inet fw4`:
#     - nym_postrouting  (masquerade for tunnel interfaces; jumped from srcnat)
#     - nym_forward_lan   (LAN<->tunnel forward accepts; jumped from forward_lan)
#   Those are wiped on every reload, breaking LAN-client connectivity until the
#   daemon happens to re-apply. This script restores them on each reload so a
#   reload (ours via split-tunnel regen, the user's, mwan3's, ...) is transparent.
#
#   The boot window is the other gap. The firewall starts at S19 and network
#   at S20, but nym-vpnd only at S90: until its first policy lands, nothing
#   fences WAN egress even with the kill-switch on. When the kill-switch is
#   armed (fw-boot-guard.sh: on in the daemon's saved settings, daemon enabled
#   at boot, not stopped by the administrator) and no `inet nym` table exists
#   yet, this script installs a boot-time emergency block in its own
#   `inet nym_boot` table. The daemon deletes that table once its first policy
#   (kill-switch on or off) is live; this script removes it whenever the
#   conditions no longer hold, and the init script and package prerm remove it
#   on explicit stop and removal.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Optional daemon-written hints (kept for forward-compatibility; the script does
# not depend on them and falls back to live detection when absent). They live
# in the root-owned runtime directory shared with the daemon, the boot guard
# and the init script, and are read only once nym_runtime_dir_trusted (from
# fw-boot-guard.sh) has vouched for it: a saved ruleset is fed to `nft -f`,
# so it must not be something any local user could have planted in /tmp.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
RULES_NFT="$NYM_RUNTIME_DIR/policy.nft"
IFACES_FILE="$NYM_RUNTIME_DIR/ifaces"

# Chain names — kept identical to the daemon's fw4 backend (integrate_with_fw4)
# so restore and the daemon converge on a single structure instead of two
# competing sets of rules.
NAT_CHAIN="nym_postrouting"
FORWARD_CHAIN="nym_forward_lan"

# Kill-switch tables. `inet nym` is the daemon's: with the kill-switch on it
# exists in every tunnel state, so its presence means the daemon has applied a
# policy since boot. `inet nym_boot` is ours, the boot-time emergency block.
# Both names are a contract with the fw4 backend (common.rs) and the package
# scripts.
NYM_TABLE="nym"

# Boot-time kill-switch guard: the shared decision logic. A missing helper
# must fail towards not blocking, never towards a block nothing can lift.
NYM_SHARE_DIR="${NYM_SHARE_DIR:-/usr/share/nym-vpn}"
if [ -r "$NYM_SHARE_DIR/fw-boot-guard.sh" ]; then
    # shellcheck source-path=SCRIPTDIR
    # shellcheck source=fw-boot-guard.sh
    . "$NYM_SHARE_DIR/fw-boot-guard.sh"
else
    nym_boot_block_wanted() {
        NYM_BOOT_REASON="$NYM_SHARE_DIR/fw-boot-guard.sh is missing; not blocking"
        return 1
    }
    # Without the shared checks nothing in the runtime directory is trusted.
    nym_runtime_dir_trusted() { return 1; }
fi

# The emergency and boot-time rule sets. Generated from the daemon's own
# definition (nym-firewall/src/openwrt/boot_rules.rs → fw-rules.sh) so this
# script, the fw4 include and the daemon install one and the same block.
# Without it no emergency block can be built: the generator stubs fail, the
# callers log CRITICAL, and the persisted policy is still restored.
if [ -r "$NYM_SHARE_DIR/fw-rules.sh" ]; then
    # shellcheck source-path=SCRIPTDIR
    # shellcheck source=fw-rules.sh
    . "$NYM_SHARE_DIR/fw-rules.sh"
else
    logger -t nym-vpn "CRITICAL: $NYM_SHARE_DIR/fw-rules.sh is missing; no emergency block can be installed"
    NYM_EMERGENCY_OUT="NYM_EMERGENCY_OUT"
    NYM_EMERGENCY_FWD="NYM_EMERGENCY_FWD"
    NYM_BOOT_TABLE="nym_boot"
    nym_emergency_rules_v4() { return 1; }
    nym_emergency_rules_v6() { return 1; }
    nym_boot_block_nft() { return 1; }
fi

# The boot-time block's table, as the daemon and the generated rule set name
# it (the daemon deletes it once its own policy is live).
BOOT_TABLE="$NYM_BOOT_TABLE"

# A hint file exists AND its directory passed the ownership/mode checks.
STATE_TRUSTED=0
have_state() {
    [ "$STATE_TRUSTED" = 1 ] && [ -f "$1" ]
}

# Resolve the active tunnel interfaces to masquerade/forward. Order of trust:
#   1. daemon-written iface list (authoritative, if present)
#   2. tunnel ifaces named in a saved blocking ruleset (if present)
#   3. live detection of nym* tunnel devices (the common case — the daemon
#      pipes its ruleset to `nft -f -` and writes no file)
get_tunnel_interfaces() {
    if have_state "$IFACES_FILE"; then
        grep -v '^lo$' "$IFACES_FILE" 2>/dev/null | sort -u
        return
    fi
    if have_state "$RULES_NFT"; then
        grep -o 'oifname "[^"]*" accept' "$RULES_NFT" 2>/dev/null | \
            sed 's/oifname "//;s/" accept//' | \
            grep -v '^lo$' | \
            sort -u
        return
    fi
    # Live-detect: nym tunnel devices created by the daemon (nym0, nym1, ...).
    ip -o link show 2>/dev/null | \
        sed -n 's/^[0-9]*: \(nym[0-9][0-9]*\)[@:].*/\1/p' | \
        sort -u
}

# Recreate the daemon's masquerade + forward integration inside inet fw4 for the
# active tunnel interfaces. Mirrors integrate_with_fw4 in the fw4 backend:
# owned chains, flushed and repopulated, with jumps added only when missing.
# Idempotent and safe to run on every reload.
restore_fw4_tunnel_rules() {
    local ifaces
    ifaces="$(get_tunnel_interfaces)"
    [ -n "$ifaces" ] || return 0

    # Own chains (ignore "File exists" — these are recreated each reload).
    nft add chain inet fw4 "$NAT_CHAIN" 2>/dev/null || true
    nft add chain inet fw4 "$FORWARD_CHAIN" 2>/dev/null || true
    nft flush chain inet fw4 "$NAT_CHAIN" 2>/dev/null || true
    nft flush chain inet fw4 "$FORWARD_CHAIN" 2>/dev/null || true

    local iface
    for iface in $ifaces; do
        nft add rule inet fw4 "$NAT_CHAIN" \
            oifname "$iface" counter masquerade \
            comment "\"nym-vpn: masquerade tunnel traffic\"" 2>/dev/null || true
        nft add rule inet fw4 "$FORWARD_CHAIN" \
            oifname "$iface" tcp flags syn tcp option maxseg size set rt mtu \
            comment "\"nym-vpn: clamp MSS to tunnel PMTU\"" 2>/dev/null || true
        nft add rule inet fw4 "$FORWARD_CHAIN" \
            iifname "$iface" tcp flags syn tcp option maxseg size set rt mtu \
            comment "\"nym-vpn: clamp MSS to tunnel PMTU\"" 2>/dev/null || true
        nft add rule inet fw4 "$FORWARD_CHAIN" \
            oifname "$iface" accept \
            comment "\"nym-vpn: forward LAN to tunnel\"" 2>/dev/null || true
        nft add rule inet fw4 "$FORWARD_CHAIN" \
            iifname "$iface" ct state established,related accept \
            comment "\"nym-vpn: forward tunnel to LAN\"" 2>/dev/null || true
        logger -t nym-vpn "Restored fw4 integration rules for interface $iface"
    done

    # Jumps from fw4's own chains — add only if absent (match structurally on
    # `jump <chain>` so a comment mentioning the name can't collide).
    nft list chain inet fw4 srcnat 2>/dev/null | grep -q "jump $NAT_CHAIN" || \
        nft add rule inet fw4 srcnat jump "$NAT_CHAIN" 2>/dev/null || true
    nft list chain inet fw4 forward_lan 2>/dev/null | grep -q "jump $FORWARD_CHAIN" || \
        nft add rule inet fw4 forward_lan jump "$FORWARD_CHAIN" 2>/dev/null || true
}

nym_table_present() {
    nft list table inet "$NYM_TABLE" >/dev/null 2>&1
}

boot_block_present() {
    nft list table inet "$BOOT_TABLE" >/dev/null 2>&1
}

# Boot-time emergency block for WAN egress: drop new router-originated and
# forwarded traffic except what the router needs to come up and stay
# manageable from the LAN. The rule set is the generated one (fw-rules.sh,
# from boot_rules.rs): reply-direction and loopback first, DHCP/DHCPv6 and
# IPv6 ND, DNS rejected BEFORE the LAN/link-local/ULA/multicast accepts, a
# terminal drop, INPUT left to fw4. Its chains run ahead of both `inet nym`
# (filter -10) and fw4 (filter); accept here only means "let the next table
# decide". The create/delete/create dance in the generated text makes the
# load an atomic replace, exactly like the daemon's own table.
install_boot_block() {
    nym_boot_block_nft | nft -f -
}

# Remove the boot-time block if present. $1 is the reason, for the log.
remove_boot_block() {
    boot_block_present || return 0
    if nft delete table inet "$BOOT_TABLE" 2>/dev/null; then
        logger -t nym-vpn "Removed boot-time kill-switch block: $1"
        return 0
    fi
    logger -t nym-vpn "CRITICAL: failed to remove boot-time kill-switch block (inet $BOOT_TABLE)"
    return 1
}

# Converge the boot-time block on the current state. Order matters: the
# daemon applies `inet nym` first and deletes `inet nym_boot` last, and it
# persists a kill-switch toggle before opening the firewall, so re-checking
# after the install catches a decision that raced either — the alternative
# is a block that only the next daemon state change would lift.
reconcile_boot_block() {
    if nym_table_present; then
        # The daemon's policy is live and it lifts the block itself; one left
        # over here would only keep the daemon's bootstrap traffic blocked.
        remove_boot_block "daemon policy is live" || return 1
        return 0
    fi
    if ! nym_boot_block_wanted; then
        remove_boot_block "$NYM_BOOT_REASON" || return 1
        return 0
    fi

    logger -t nym-vpn "Installing boot-time kill-switch block: $NYM_BOOT_REASON"
    if ! install_boot_block; then
        logger -t nym-vpn "CRITICAL: failed to install boot-time kill-switch block (inet $BOOT_TABLE)"
        return 1
    fi

    if nym_table_present; then
        remove_boot_block "daemon policy went live meanwhile" || return 1
    elif ! nym_boot_block_wanted; then
        remove_boot_block "$NYM_BOOT_REASON" || return 1
    fi
    return 0
}

# Main logic
main() {
    local failed=0

    # If the daemon ever persists its blocking ruleset, re-apply it (the inet nym
    # table is otherwise daemon-managed and survives the reload on its own — we
    # must NOT delete it here, or a firewall reload would silently drop the
    # kill-switch while the daemon thinks it is still up).
    if have_state "$RULES_NFT"; then
        logger -t nym-vpn "Re-applying saved nftables rules after fw4 restart"
        nft -f "$RULES_NFT" 2>/dev/null || logger -t nym-vpn "Failed to apply saved rules"
    fi

    # Boot-time block before the tunnel plane: fail closed first.
    reconcile_boot_block || failed=1

    # Always restore the in-fw4 tunnel integration that the reload wiped.
    restore_fw4_tunnel_rules
    return "$failed"
}

# Trust the runtime directory only if the daemon (or the init script) created
# it and it still is a private root-owned directory. Missing is normal before
# the daemon's first run and simply means no hints.
if nym_runtime_dir_trusted; then
    STATE_TRUSTED=1
elif [ -e "$NYM_RUNTIME_DIR" ] || [ -L "$NYM_RUNTIME_DIR" ]; then
    logger -t nym-vpn "$NYM_RUNTIME_DIR is not a private root-owned directory; ignoring persisted state"
fi

main "$@"
