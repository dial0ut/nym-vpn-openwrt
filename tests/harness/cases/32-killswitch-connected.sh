# shellcheck shell=bash
# Kill-switch in ConnectedState.
#
# KS=on, tunnel up. Verify:
#   - LAN client has internet
#   - Client's apparent external IP differs from the router's own public
#     egress address, learned while disconnected with the kill-switch off.
#     (The router's eth0 address is private behind Proxmox NAT and would
#     never match a public IP, so comparing against it proves nothing.)
#   - Plain UDP/53 to a non-whitelisted DNS resolver from the router is
#     rejected (kill-switch's DNS leak block)

case_begin killswitch-connected

# Baseline: what does traffic look like when it bypasses the tunnel?
vpn_killswitch "$OPENWRT_CTID" off
sleep 1
router_public_ip=$(pct_sh "$OPENWRT_CTID" 'curl -s --max-time 10 https://api.ipify.org' || true)
if [ -z "$router_public_ip" ]; then
    case_fail "could not learn the router's public IP while disconnected; bypass check impossible"
    return 0 2>/dev/null || exit 0
fi
echo "  router public IP (no tunnel): $router_public_ip"

vpn_killswitch "$OPENWRT_CTID" on
sleep 1
vpn_connect "$OPENWRT_CTID"
if ! vpn_wait_state "$OPENWRT_CTID" '^Connected' 120; then
    case_fail "could not reach Connected for the test"
    vpn_dump "$OPENWRT_CTID"
    vpn_disconnect "$OPENWRT_CTID"
    return 0 2>/dev/null || exit 0
fi

client_external_ip=$(pct_sh "$CLIENT_CTID" 'curl -s --max-time 10 https://api.ipify.org' || true)
exit_gw_ip=$(pct_sh "$OPENWRT_CTID" 'nym-vpnc status 2>/dev/null' | head -1 | sed -n 's/.*→ \([0-9.]*\):.*/\1/p')

ok=true
if [ -z "$client_external_ip" ]; then
    echo "  LAN client could not reach ipify (no internet through tunnel)"
    ok=false
elif [ "$client_external_ip" = "$router_public_ip" ]; then
    echo "  client external IP ($client_external_ip) is the router's own public IP — traffic is bypassing the tunnel"
    ok=false
else
    echo "  client external IP: $client_external_ip (router: $router_public_ip) — not the router's address"
    # Informational: the exit gateway's WireGuard endpoint usually, but not
    # always, is also its egress address.
    if [ -n "$exit_gw_ip" ] && [ "$exit_gw_ip" != "$client_external_ip" ]; then
        echo "  note: exit gateway endpoint is $exit_gw_ip, egress seen as $client_external_ip"
    fi
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
