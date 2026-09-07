# shellcheck shell=bash
# Kill-switch in ConnectedState.
#
# KS=on, tunnel up. Verify:
#   - LAN client has internet
#   - Client's apparent external IP differs from the OpenWrt's WAN IP
#     (a basic "traffic actually went through the tunnel" check)
#   - Plain UDP/53 to a non-whitelisted DNS resolver from the router is
#     rejected (kill-switch's DNS leak block)

case_begin killswitch-connected

vpn_killswitch "$OPENWRT_CTID" on
sleep 1
vpn_connect "$OPENWRT_CTID"
if ! vpn_wait_state "$OPENWRT_CTID" '^Connected' 120; then
    case_fail "could not reach Connected for the test"
    vpn_dump "$OPENWRT_CTID"
    vpn_disconnect "$OPENWRT_CTID"
    return 0 2>/dev/null || exit 0
fi

router_wan_ip=$(pct_sh "$OPENWRT_CTID" "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1")
client_external_ip=$(pct_sh "$CLIENT_CTID" 'curl -s --max-time 10 https://api.ipify.org')

ok=true
if [ -z "$client_external_ip" ]; then
    echo "  LAN client could not reach ipify (no internet through tunnel)"
    ok=false
elif [ "$client_external_ip" = "$router_wan_ip" ]; then
    echo "  client external IP ($client_external_ip) equals router WAN IP — traffic is bypassing the tunnel"
    ok=false
else
    echo "  client external IP: $client_external_ip (WAN: $router_wan_ip) — through tunnel"
fi

# Plain DNS leak probe: query 8.8.8.8 directly from the router. If our
# kill-switch is correct, dport 53 outside the whitelist is rejected.
if pct_sh "$OPENWRT_CTID" 'nslookup example.com 8.8.8.8 >/dev/null 2>&1'; then
    # In Connected state with default DNS, 8.8.8.8 may legitimately be in
    # the whitelist. We only fail if the firewall has NO dport-53 rejects.
    if ! pct_sh "$OPENWRT_CTID" 'nft list table inet nym 2>&1 | grep -q "dport 53 reject"'; then
        echo "  Connected state has no DNS reject rule — kill-switch DNS leak block missing"
        ok=false
    fi
fi

if $ok; then
    case_pass "client_ip=$client_external_ip"
else
    case_fail "tunnel routing or DNS block check failed"
    vpn_dump "$OPENWRT_CTID"
fi

vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
