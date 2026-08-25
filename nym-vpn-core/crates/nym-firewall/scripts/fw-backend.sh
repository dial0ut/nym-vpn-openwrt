#!/bin/sh
# Print the OpenWrt firewall backend this router uses: "fw4" or "fw3".
#
# Shared by the uci-defaults include registration, the package prerm and the
# init script so they cannot disagree. Live state wins (a vendor image may
# ship both stacks' binaries); when neither framework is up yet — the boot
# defaults runner executes before the firewall service — the firewall init
# script itself says which one will start; binary presence is the last
# resort.
if command -v nft >/dev/null 2>&1 && nft list table inet fw4 >/dev/null 2>&1; then
    echo fw4
elif command -v iptables >/dev/null 2>&1 && iptables -L input_rule -n >/dev/null 2>&1; then
    echo fw3
elif grep -q -w fw4 /etc/init.d/firewall 2>/dev/null; then
    echo fw4
elif grep -q -w fw3 /etc/init.d/firewall 2>/dev/null; then
    echo fw3
elif [ -x /sbin/fw4 ] || [ -x /usr/sbin/fw4 ]; then
    echo fw4
else
    echo fw3
fi
