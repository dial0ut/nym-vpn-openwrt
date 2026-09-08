# shellcheck shell=bash
# Kill-switch in ConnectedState.
#
# KS=on, tunnel up. Verify:
#   - LAN client has internet
#   - Client's apparent external IP differs from the router's own public
#     egress address, learned while disconnected with the kill-switch off.
#     (The router's eth0 address is private behind Proxmox NAT and would
#     never match a public IP, so comparing against it proves nothing.)
#   - A plain UDP/53 query from the router to a resolver outside the tunnel
#     never leaves on the WAN wire (kill-switch's DNS leak block), watched
#     with tcpdump on the host side of the router's WAN veth

case_begin killswitch-connected

vpn_require_ready || return 0 2>/dev/null || exit 0

# Baseline: what does traffic look like when it bypasses the tunnel?
vpn_killswitch "$OPENWRT_CTID" off
sleep 1
router_public_ip=$(pct_sh "$OPENWRT_CTID" 'wget -qO- -T 10 https://api.ipify.org 2>/dev/null' || true)
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

# Plain DNS leak probe: query 8.8.8.8 directly from the router while the
# host captures UDP/53 on the router's WAN veth. The verdict is what leaves
# the wire: any plain DNS packet from the router's WAN address is a leak,
# whatever the rule set says and whether or not the lookup was answered (an
# answer that came back through the tunnel is not a leak; one that came
# back over the WAN is). A capture that cannot be taken fails the check
# rather than passing it by default.
wan_if="veth${OPENWRT_CTID}i0"
dns_pcap="/tmp/harness-dns-${OPENWRT_CTID}.pcap"
router_wan_ip=$(pct_sh "$OPENWRT_CTID" 'ip -4 -o addr show eth0 | awk "{print \$4}" | cut -d/ -f1' | head -1)
if [ -z "$router_wan_ip" ]; then
    echo "  could not learn the router's WAN address; the DNS leak probe cannot be attributed"
    ok=false
elif ! pmx "rm -f $dns_pcap; (nohup tcpdump -ni $wan_if -w $dns_pcap 'udp port 53' </dev/null >/dev/null 2>&1 &); sleep 1; pgrep -f 'tcpdump -ni $wan_if ' >/dev/null"; then
    echo "  could not start the WAN-side DNS capture on $wan_if; the DNS leak block is unverified"
    ok=false
else
    lookup=blocked
    pct_sh "$OPENWRT_CTID" 'nslookup example.com 8.8.8.8 >/dev/null 2>&1' && lookup=answered
    sleep 2
    wire=$(pmx "for p in \$(pgrep -f 'tcpdump -ni $wan_if '); do kill \$p; done; sleep 1; tcpdump -nr $dns_pcap 'src host $router_wan_ip and udp dst port 53' 2>/dev/null | wc -l; rm -f $dns_pcap" | tr -d ' ')
    if [ -z "$wire" ]; then
        echo "  the WAN-side DNS capture produced no result; the DNS leak block is unverified"
        ok=false
    elif [ "$wire" -gt 0 ]; then
        echo "  $wire plain DNS packet(s) from the router left the WAN (lookup $lookup) — kill-switch DNS leak block is open"
        ok=false
    else
        echo "  no plain DNS from the router on the WAN wire (lookup $lookup)"
    fi
fi

if $ok; then
    case_pass "client_ip=$client_external_ip"
else
    case_fail "tunnel routing or DNS leak check failed (see log)"
    vpn_dump "$OPENWRT_CTID"
fi

vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
