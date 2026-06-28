#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw4 (nftables)
#
# This script is called by fw4 on start and restart.
# It re-applies the Nym VPN integration that lives inside fw4's own table.
#
# Installation:
#   1. Copy to /usr/share/nym-vpn/fw4-include.sh
#   2. Add to /etc/config/firewall:
#      config include 'nym_vpn'
#          option type 'script'
#          option path '/usr/share/nym-vpn/fw4-include.sh'
#          option fw4_compatible '1'
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
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Optional daemon-written hints (kept for forward-compatibility; the script does
# not depend on them and falls back to live detection when absent).
RULES_NFT="/tmp/nym-firewall.nft"
IFACES_FILE="/tmp/nym-firewall.ifaces"

# Chain names — kept identical to the daemon's fw4 backend (integrate_with_fw4)
# so restore and the daemon converge on a single structure instead of two
# competing sets of rules.
NAT_CHAIN="nym_postrouting"
FORWARD_CHAIN="nym_forward_lan"

# Resolve the active tunnel interfaces to masquerade/forward. Order of trust:
#   1. daemon-written iface list (authoritative, if present)
#   2. tunnel ifaces named in a saved blocking ruleset (if present)
#   3. live detection of nym* tunnel devices (the common case — the daemon
#      pipes its ruleset to `nft -f -` and writes no file)
get_tunnel_interfaces() {
    if [ -f "$IFACES_FILE" ]; then
        grep -v '^lo$' "$IFACES_FILE" 2>/dev/null | sort -u
        return
    fi
    if [ -f "$RULES_NFT" ]; then
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

# Main logic
main() {
    # If the daemon ever persists its blocking ruleset, re-apply it (the inet nym
    # table is otherwise daemon-managed and survives the reload on its own — we
    # must NOT delete it here, or a firewall reload would silently drop the
    # kill-switch while the daemon thinks it is still up).
    if [ -f "$RULES_NFT" ]; then
        logger -t nym-vpn "Re-applying saved nftables rules after fw4 restart"
        nft -f "$RULES_NFT" 2>/dev/null || logger -t nym-vpn "Failed to apply saved rules"
    fi

    # Always restore the in-fw4 tunnel integration that the reload wiped.
    restore_fw4_tunnel_rules
}

main "$@"
