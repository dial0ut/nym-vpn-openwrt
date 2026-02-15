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
#   - It also restores masquerade and forward rules in fw4's own chains
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Path to rules file written by the daemon
RULES_NFT="/tmp/nym-firewall.nft"

# Extract tunnel interface names from the saved nft rules file.
# Looks for oifname "xyz" accept patterns in the forward chain,
# which indicate tunnel interfaces (e.g., wg0, tun0).
get_tunnel_interfaces() {
    if [ ! -f "$RULES_NFT" ]; then
        return
    fi
    # Match lines like: oifname "wg0" accept
    # Exclude loopback. Deduplicate results.
    grep -o 'oifname "[^"]*" accept' "$RULES_NFT" 2>/dev/null | \
        sed 's/oifname "//;s/" accept//' | \
        grep -v '^lo$' | \
        sort -u
}

# Re-add masquerade and forward rules to fw4's chains for tunnel interfaces.
# These rules are lost when fw4 restarts because fw4 recreates its table.
restore_fw4_tunnel_rules() {
    for iface in $(get_tunnel_interfaces); do
        # Masquerade for tunnel interface (NAT for LAN clients)
        nft add rule inet fw4 srcnat \
            oifname "$iface" counter masquerade \
            comment "\"nym-vpn: masquerade tunnel traffic\"" 2>/dev/null || true

        # Forward LAN to tunnel
        nft add rule inet fw4 forward_lan \
            oifname "$iface" accept \
            comment "\"nym-vpn: forward LAN to tunnel\"" 2>/dev/null || true

        # Forward tunnel to LAN
        nft add rule inet fw4 forward_lan \
            iifname "$iface" accept \
            comment "\"nym-vpn: forward tunnel to LAN\"" 2>/dev/null || true

        logger -t nym-vpn "Restored fw4 integration rules for interface $iface"
    done
}

# Main logic
main() {
    # Check if VPN daemon has written rules
    if [ -f "$RULES_NFT" ]; then
        logger -t nym-vpn "Re-applying nftables firewall rules after fw4 restart"

        # Apply the inet nym table rules atomically
        if nft -f "$RULES_NFT"; then
            logger -t nym-vpn "Firewall rules applied successfully"
        else
            logger -t nym-vpn "Failed to apply firewall rules"
        fi

        # Restore masquerade and forward rules in fw4's own chains
        restore_fw4_tunnel_rules
    else
        # No rules file - ensure our table is removed if it exists
        logger -t nym-vpn "No active rules, ensuring cleanup"
        nft delete table inet nym 2>/dev/null || true
    fi
}

main "$@"
