#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw4 (nftables). Run by fw4 on
# start, restart and reload via a `config include` in /etc/config/firewall.
#
# `fw4 reload` rebuilds `inet fw4` from scratch, wiping the daemon's
# integration chains inside it (nym_postrouting from srcnat, nym_forward_lan
# from forward_lan); this script restores them. The kill-switch itself is the
# daemon's separate `inet nym` table, which survives a reload and must never
# be deleted here. The other gap is boot: firewall S19 and network S20 come
# up long before nym-vpnd S90, so when fw-boot-guard.sh says the kill-switch
# is armed and no `inet nym` exists yet, an `inet nym_boot` block goes in.
# The daemon deletes it once its first policy is live; this script, the init
# script and prerm remove it when the conditions no longer hold.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Optional hints, read only once nym_runtime_dir_trusted has vouched for the
# directory (RULES_NFT is fed to `nft -f`). Nothing writes policy.nft today;
# the fw4 backend pipes its ruleset to `nft -f -`.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
RULES_NFT="$NYM_RUNTIME_DIR/policy.nft"
IFACES_FILE="$NYM_RUNTIME_DIR/ifaces"

# Same chain names as the daemon's fw4 backend (integrate_with_fw4).
NAT_CHAIN="nym_postrouting"
FORWARD_CHAIN="nym_forward_lan"

# The daemon's table; present in every tunnel state once a policy is applied.
NYM_TABLE="nym"

# A missing guard must fail towards not blocking, never towards a block
# nothing can lift.
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
    nym_runtime_dir_trusted() { return 1; }
fi

# Boot-time rule set, generated from boot_rules.rs. Without the file the
# generator prints nothing and no block can be built.
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

BOOT_TABLE="$NYM_BOOT_TABLE"

STATE_TRUSTED=0
have_state() {
    [ "$STATE_TRUSTED" = 1 ] && [ -f "$1" ]
}

# Iface list, then a saved ruleset, then live detection of nym* devices
# (the common case).
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
    ip -o link show 2>/dev/null | \
        sed -n 's/^[0-9]*: \(nym[0-9][0-9]*\)[@:].*/\1/p' | \
        sort -u
}

# Mirrors integrate_with_fw4 in the fw4 backend.
restore_fw4_tunnel_rules() {
    local ifaces
    ifaces="$(get_tunnel_interfaces)"
    [ -n "$ifaces" ] || return 0

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

# Atomic replace of the generated table; rules and order: boot_rules.rs.
install_boot_block() {
    nym_boot_block_nft | nft -f -
}

# $1 is the reason, for the log.
remove_boot_block() {
    boot_block_present || return 0
    if nft delete table inet "$BOOT_TABLE" 2>/dev/null; then
        logger -t nym-vpn "Removed boot-time kill-switch block: $1"
        return 0
    fi
    logger -t nym-vpn "CRITICAL: failed to remove boot-time kill-switch block (inet $BOOT_TABLE)"
    return 1
}

# The daemon applies `inet nym` first and deletes `inet nym_boot` last, and
# persists a kill-switch toggle before opening the firewall, so the re-check
# after the install catches a decision that raced either.
reconcile_boot_block() {
    if nym_table_present; then
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

main() {
    local failed=0

    # Dead today (nothing writes RULES_NFT); `inet nym` survives reloads on its own.
    if have_state "$RULES_NFT"; then
        logger -t nym-vpn "Re-applying saved nftables rules after fw4 restart"
        nft -f "$RULES_NFT" 2>/dev/null || logger -t nym-vpn "Failed to apply saved rules"
    fi

    # Fail closed before the tunnel plane.
    reconcile_boot_block || failed=1

    restore_fw4_tunnel_rules
    return "$failed"
}

# Missing is normal before the daemon's first run: no hints.
if nym_runtime_dir_trusted; then
    STATE_TRUSTED=1
elif [ -e "$NYM_RUNTIME_DIR" ] || [ -L "$NYM_RUNTIME_DIR" ]; then
    logger -t nym-vpn "$NYM_RUNTIME_DIR is not a private root-owned directory; ignoring persisted state"
fi

main "$@"
