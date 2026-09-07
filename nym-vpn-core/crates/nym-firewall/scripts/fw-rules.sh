#!/bin/sh
# GENERATED FILE — do not edit. Rendered by nym-firewall/build.rs from
# src/openwrt/boot_rules.rs, the single definition of the emergency and
# boot-time kill-switch rule sets shared by the daemon and the includes.
# Regenerate after changing that file:
#   NYM_FW_RULES_REGEN=1 cargo build -p nym-firewall
# and commit the result; the build fails while this file is stale.
#
# Sourced (not executed) by fw3-include.sh and fw4-include.sh.
#
# SPDX-License-Identifier: GPL-3.0-only

NYM_EMERGENCY_OUT="NYM_EMERGENCY_OUT"
NYM_EMERGENCY_FWD="NYM_EMERGENCY_FWD"
NYM_BOOT_TABLE="nym_boot"
NYM_LAN_NETS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"
NYM_LAN_NETS_V6="fe80::/10 fc00::/7"
NYM_MCAST_V4="224.0.0.0/4"
NYM_MCAST_V6="ff00::/8"

# v4: iptables-restore script for the emergency OUTPUT/FORWARD block.
# $1 is "boot" (router may come up and stay manageable) or anything
# else for the transition set. Apply with `--noflush`.
nym_emergency_rules_v4() {
    case "$1" in
        boot) cat <<'EOF'
*filter
:NYM_EMERGENCY_OUT - [0:0]
:NYM_EMERGENCY_FWD - [0:0]
-F NYM_EMERGENCY_OUT
-F NYM_EMERGENCY_FWD
-A NYM_EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
-A NYM_EMERGENCY_OUT -o lo -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --sport 68 --dport 67 -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --sport 67 --dport 68 -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
-A NYM_EMERGENCY_OUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset
-A NYM_EMERGENCY_FWD -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
-A NYM_EMERGENCY_FWD -p tcp --dport 53 -j REJECT --reject-with tcp-reset
-A NYM_EMERGENCY_OUT -d 224.0.0.0/4 -j ACCEPT
-A NYM_EMERGENCY_OUT -d 10.0.0.0/8 -j ACCEPT
-A NYM_EMERGENCY_FWD -d 10.0.0.0/8 -j ACCEPT
-A NYM_EMERGENCY_OUT -d 172.16.0.0/12 -j ACCEPT
-A NYM_EMERGENCY_FWD -d 172.16.0.0/12 -j ACCEPT
-A NYM_EMERGENCY_OUT -d 192.168.0.0/16 -j ACCEPT
-A NYM_EMERGENCY_FWD -d 192.168.0.0/16 -j ACCEPT
-A NYM_EMERGENCY_OUT -d 169.254.0.0/16 -j ACCEPT
-A NYM_EMERGENCY_FWD -d 169.254.0.0/16 -j ACCEPT
-A NYM_EMERGENCY_OUT -j DROP
-A NYM_EMERGENCY_FWD -j DROP
-I output_rule 1 -j NYM_EMERGENCY_OUT
-I forwarding_rule 1 -j NYM_EMERGENCY_FWD
COMMIT
EOF
        ;;
        *) cat <<'EOF'
*filter
:NYM_EMERGENCY_OUT - [0:0]
:NYM_EMERGENCY_FWD - [0:0]
-F NYM_EMERGENCY_OUT
-F NYM_EMERGENCY_FWD
-A NYM_EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
-A NYM_EMERGENCY_OUT -j DROP
-A NYM_EMERGENCY_FWD -j DROP
-I output_rule 1 -j NYM_EMERGENCY_OUT
-I forwarding_rule 1 -j NYM_EMERGENCY_FWD
COMMIT
EOF
        ;;
    esac
}

# v6: iptables-restore script for the emergency OUTPUT/FORWARD block.
# $1 is "boot" (router may come up and stay manageable) or anything
# else for the transition set. Apply with `--noflush`.
nym_emergency_rules_v6() {
    case "$1" in
        boot) cat <<'EOF'
*filter
:NYM_EMERGENCY_OUT - [0:0]
:NYM_EMERGENCY_FWD - [0:0]
-F NYM_EMERGENCY_OUT
-F NYM_EMERGENCY_FWD
-A NYM_EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
-A NYM_EMERGENCY_OUT -o lo -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --sport 546 --dport 547 -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --sport 547 --dport 546 -j ACCEPT
-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT
-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT
-A NYM_EMERGENCY_OUT -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
-A NYM_EMERGENCY_OUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset
-A NYM_EMERGENCY_FWD -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
-A NYM_EMERGENCY_FWD -p tcp --dport 53 -j REJECT --reject-with tcp-reset
-A NYM_EMERGENCY_OUT -d ff00::/8 -j ACCEPT
-A NYM_EMERGENCY_OUT -d fe80::/10 -j ACCEPT
-A NYM_EMERGENCY_FWD -d fe80::/10 -j ACCEPT
-A NYM_EMERGENCY_OUT -d fc00::/7 -j ACCEPT
-A NYM_EMERGENCY_FWD -d fc00::/7 -j ACCEPT
-A NYM_EMERGENCY_OUT -j DROP
-A NYM_EMERGENCY_FWD -j DROP
-I output_rule 1 -j NYM_EMERGENCY_OUT
-I forwarding_rule 1 -j NYM_EMERGENCY_FWD
COMMIT
EOF
        ;;
        *) cat <<'EOF'
*filter
:NYM_EMERGENCY_OUT - [0:0]
:NYM_EMERGENCY_FWD - [0:0]
-F NYM_EMERGENCY_OUT
-F NYM_EMERGENCY_FWD
-A NYM_EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT
-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT
-A NYM_EMERGENCY_OUT -j DROP
-A NYM_EMERGENCY_FWD -j DROP
-I output_rule 1 -j NYM_EMERGENCY_OUT
-I forwarding_rule 1 -j NYM_EMERGENCY_FWD
COMMIT
EOF
        ;;
    esac
}

# nft -f input installing the fw4 boot-time block as an atomic replace of
# the inet nym_boot table.
nym_boot_block_nft() {
    cat <<'EOF'
table inet nym_boot
delete table inet nym_boot
table inet nym_boot {
    chain output {
        type filter hook output priority filter - 20; policy accept;
        oifname "lo" accept
        ct state established,related ct direction reply accept
        udp sport 68 udp dport 67 accept
        udp sport 67 udp dport 68 accept
        udp sport 546 udp dport 547 accept
        udp sport 547 udp dport 546 accept
        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        udp dport 53 reject
        tcp dport 53 reject
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } accept
        ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept
        drop
    }
    chain forward {
        type filter hook forward priority filter - 20; policy accept;
        udp dport 53 reject
        tcp dport 53 reject
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept
        ip6 daddr { fe80::/10, fc00::/7 } accept
        drop
    }
}
EOF
}
