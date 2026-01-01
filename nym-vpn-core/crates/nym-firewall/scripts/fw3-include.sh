#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw3 (iptables)
#
# This script is called by fw3 on start, restart, and reload (if reload=1).
# It manages the integration between Nym VPN's kill-switch and OpenWrt's firewall.
#
# Installation:
#   1. Copy to /usr/share/nym-vpn/fw3-include.sh
#   2. Add to /etc/config/firewall:
#      config include 'nym_vpn'
#          option type 'script'
#          option path '/usr/share/nym-vpn/fw3-include.sh'
#          option reload '1'
#          option enabled '1'
#
# How it works:
#   - The Nym VPN daemon writes iptables-restore format rules to /tmp/nym-firewall-*.rules
#   - This script applies those rules and sets up jump rules from fw3's *_rule chains
#   - When the daemon stops, it removes the rules files, and this script cleans up
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Paths to rules files written by the daemon
RULES_V4="/tmp/nym-firewall-v4.rules"
RULES_V6="/tmp/nym-firewall-v6.rules"

# fw3 hook chains (user chains that survive reload)
HOOK_INPUT="input_rule"
HOOK_OUTPUT="output_rule"
HOOK_FORWARD="forwarding_rule"

# Our custom chains
NYM_INPUT="NYM_INPUT"
NYM_OUTPUT="NYM_OUTPUT"
NYM_FORWARD="NYM_FORWARD"

# Set up jump rules from fw3's hook chains to our chains
setup_jumps() {
    local ipt="$1"

    # Remove any existing jumps first (handles duplicates from previous runs)
    $ipt -D "$HOOK_INPUT" -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -D "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -D "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null || true

    # Insert jumps at position 1 (first rule, highest priority)
    $ipt -I "$HOOK_INPUT" 1 -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -I "$HOOK_OUTPUT" 1 -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -I "$HOOK_FORWARD" 1 -j "$NYM_FORWARD" 2>/dev/null || true
}

# Clean up all Nym VPN firewall rules
cleanup() {
    local ipt="$1"

    # Remove jump rules
    $ipt -D "$HOOK_INPUT" -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -D "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -D "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null || true

    # Flush our chains
    $ipt -F "$NYM_INPUT" 2>/dev/null || true
    $ipt -F "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -F "$NYM_FORWARD" 2>/dev/null || true

    # Delete our chains
    $ipt -X "$NYM_INPUT" 2>/dev/null || true
    $ipt -X "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -X "$NYM_FORWARD" 2>/dev/null || true
}

# Main logic
main() {
    # Check if VPN daemon has written rules
    if [ -f "$RULES_V4" ]; then
        logger -t nym-vpn "Applying IPv4 firewall rules"

        # Apply IPv4 rules atomically
        if iptables-restore --noflush < "$RULES_V4"; then
            setup_jumps "iptables"
        else
            logger -t nym-vpn "Failed to apply IPv4 rules"
        fi

        # Apply IPv6 rules if available
        if [ -f "$RULES_V6" ]; then
            logger -t nym-vpn "Applying IPv6 firewall rules"
            if ip6tables-restore --noflush < "$RULES_V6"; then
                setup_jumps "ip6tables"
            else
                logger -t nym-vpn "Failed to apply IPv6 rules"
            fi
        fi
    else
        # No rules file means daemon is not running - clean up any stale rules
        logger -t nym-vpn "No active rules, cleaning up"
        cleanup "iptables"
        cleanup "ip6tables"
    fi
}

main "$@"
