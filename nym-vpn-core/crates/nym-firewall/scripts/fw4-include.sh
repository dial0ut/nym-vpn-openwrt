#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw4 (nftables)
#
# This script is called by fw4 on start and restart.
# It re-applies Nym VPN's kill-switch rules if the daemon is running.
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
# How it works:
#   - The Nym VPN daemon writes nftables rules to /tmp/nym-firewall.nft
#   - This script re-applies those rules after fw4 restarts
#   - The rules create a separate 'inet nym' table at priority -10
#   - This runs before fw4's 'inet fw4' table at priority 0
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Path to rules file written by the daemon
RULES_NFT="/tmp/nym-firewall.nft"

# Main logic
main() {
    # Check if VPN daemon has written rules
    if [ -f "$RULES_NFT" ]; then
        logger -t nym-vpn "Re-applying nftables firewall rules after fw4 restart"

        # Apply rules atomically
        if nft -f "$RULES_NFT"; then
            logger -t nym-vpn "Firewall rules applied successfully"
        else
            logger -t nym-vpn "Failed to apply firewall rules"
        fi
    else
        # No rules file - ensure our table is removed if it exists
        logger -t nym-vpn "No active rules, ensuring cleanup"
        nft delete table inet nym 2>/dev/null || true
    fi
}

main "$@"
