#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw3 (iptables)
#
# This script is called by fw3 on start, restart, and reload (reload=1).
#
# Why this exists (mirror of fw4-include.sh, adapted to fw3's world):
#   On fw4 the kill-switch lives in a separate `inet nym` table that a
#   firewall reload cannot touch — only the small in-fw4 integration has to
#   be restored. fw3 has no such isolation: a reload wipes the shared
#   filter/mangle/nat tables wholesale, custom chains included, so the whole
#   kill-switch would silently vanish until the daemon's next state change.
#   To close that gap the daemon persists exactly what it applied:
#     /tmp/nym-firewall-v4.rules  iptables-restore script (filter [+ mangle])
#     /tmp/nym-firewall-v6.rules  ip6tables-restore script, if IPv6 is up
#     /tmp/nym-firewall.ifaces    tunnel interfaces needing masquerade
#   and this script re-applies them after every reload. No rules files means
#   no blocking policy is in force (kill-switch off, or daemon stopped) and
#   any leftover Nym chains are torn down instead. The init script runs this
#   script for that cleanup branch on explicit daemon stop, too.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Persisted daemon state (paths are a contract with the fw3 backend).
RULES_V4="/tmp/nym-firewall-v4.rules"
RULES_V6="/tmp/nym-firewall-v6.rules"
IFACES_FILE="/tmp/nym-firewall.ifaces"

# fw3 hook chains (user chains fw3 recreates on every reload).
HOOK_INPUT="input_rule"
HOOK_OUTPUT="output_rule"
HOOK_FORWARD="forwarding_rule"

# Our chains — kept identical to the daemon's fw3 backend so this script and
# the daemon converge on a single structure instead of two competing sets.
NYM_INPUT="NYM_INPUT"
NYM_OUTPUT="NYM_OUTPUT"
NYM_FORWARD="NYM_FORWARD"
NYM_MANGLE_PRE="NYM_MANGLE_PREROUTING"
NYM_MANGLE_OUT="NYM_MANGLE_OUTPUT"
NAT_CHAIN="NYM_POSTROUTING"

# Set up jump rules from fw3's hook chains to our filter chains.
setup_jumps() {
    local ipt="$1"

    # Remove any existing jumps first (handles duplicates from previous runs)
    $ipt -w -D "$HOOK_INPUT" -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null || true

    # Insert jumps at position 1 (first rule, highest priority)
    $ipt -w -I "$HOOK_INPUT" 1 -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -w -I "$HOOK_OUTPUT" 1 -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -w -I "$HOOK_FORWARD" 1 -j "$NYM_FORWARD" 2>/dev/null || true
}

# Mangle has no fw3 *_rule hook chains — jump straight from the built-ins,
# exactly like the daemon's fw3 backend does.
setup_mangle_jumps() {
    local ipt="$1"

    $ipt -w -t mangle -D PREROUTING -j "$NYM_MANGLE_PRE" 2>/dev/null || true
    $ipt -w -t mangle -D OUTPUT -j "$NYM_MANGLE_OUT" 2>/dev/null || true
    $ipt -w -t mangle -I PREROUTING 1 -j "$NYM_MANGLE_PRE" 2>/dev/null || true
    $ipt -w -t mangle -I OUTPUT 1 -j "$NYM_MANGLE_OUT" 2>/dev/null || true
}

cleanup_filter() {
    local ipt="$1"

    $ipt -w -D "$HOOK_INPUT" -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null || true

    local chain
    for chain in "$NYM_INPUT" "$NYM_OUTPUT" "$NYM_FORWARD"; do
        $ipt -w -F "$chain" 2>/dev/null || true
        $ipt -w -X "$chain" 2>/dev/null || true
    done
}

cleanup_mangle() {
    local ipt="$1"

    $ipt -w -t mangle -D PREROUTING -j "$NYM_MANGLE_PRE" 2>/dev/null || true
    $ipt -w -t mangle -D OUTPUT -j "$NYM_MANGLE_OUT" 2>/dev/null || true

    local chain
    for chain in "$NYM_MANGLE_PRE" "$NYM_MANGLE_OUT"; do
        $ipt -w -t mangle -F "$chain" 2>/dev/null || true
        $ipt -w -t mangle -X "$chain" 2>/dev/null || true
    done
}

# Re-apply one family's persisted ruleset and its jumps. The daemon renders
# the restore script with chain declarations and -F lines, so re-applying
# with --noflush is idempotent. Mangle jumps are set up only when the script
# actually carries a *mangle block (inbound exemptions configured).
apply_rules() {
    local restore="$1" file="$2" ipt="$3"

    if $restore --noflush -w < "$file" 2>/dev/null || $restore --noflush < "$file"; then
        setup_jumps "$ipt"
        if grep -q '^\*mangle' "$file"; then
            setup_mangle_jumps "$ipt"
        else
            cleanup_mangle "$ipt"
        fi
        logger -t nym-vpn "Restored $ipt kill-switch rules after firewall reload"
    else
        logger -t nym-vpn "Failed to apply saved $ipt rules"
    fi
}

# Rebuild the masquerade chain from the daemon's interface list. Mirrors
# add_masquerade_rules in the fw3 backend: owned chain, flush + repopulate,
# jump added only when missing.
restore_masquerade() {
    if [ ! -f "$IFACES_FILE" ]; then
        cleanup_masquerade
        return 0
    fi

    iptables -w -t nat -N "$NAT_CHAIN" 2>/dev/null || true
    iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true

    local iface
    while read -r iface; do
        [ -n "$iface" ] || continue
        iptables -w -t nat -A "$NAT_CHAIN" -o "$iface" -j MASQUERADE 2>/dev/null || true
        logger -t nym-vpn "Restored masquerade for interface $iface"
    done < "$IFACES_FILE"

    iptables -w -t nat -C POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || \
        iptables -w -t nat -A POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || true
}

cleanup_masquerade() {
    while iptables -w -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null; do :; done
    iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -w -t nat -X "$NAT_CHAIN" 2>/dev/null || true
}

# Main logic
main() {
    if [ -f "$RULES_V4" ]; then
        apply_rules "iptables-restore" "$RULES_V4" "iptables"
        if [ -f "$RULES_V6" ]; then
            apply_rules "ip6tables-restore" "$RULES_V6" "ip6tables"
        else
            # Daemon decided IPv6 needs no rules (kernel v6 off) — make sure
            # nothing stale lingers from an earlier v6-enabled apply.
            cleanup_filter "ip6tables"
            cleanup_mangle "ip6tables"
        fi
    else
        # No blocking policy in force: kill-switch off or daemon stopped.
        logger -t nym-vpn "No active rules, cleaning up"
        cleanup_filter "iptables"
        cleanup_mangle "iptables"
        cleanup_filter "ip6tables"
        cleanup_mangle "ip6tables"
    fi

    # Always reconcile masquerade with the persisted interface list — it is
    # needed with the kill-switch both on and off (forwarding-only mode).
    restore_masquerade
}

main "$@"
