# shellcheck shell=bash
# Regression test for the ErrorState empty-exemption deadlock (fixed in v1.27.1).
#
# Trigger ErrorState by moving /usr/sbin/nft aside so apply_policy fails.
# After the daemon enters Error, restore nft and prod the firewall to re-apply
# (toggle lan policy). With the fix, the re-applied Blocked policy preserves
# the API + DNS exemptions, so the daemon's own API call still works. With
# the buggy v1.27.0, exemptions would be empty and the daemon would be locked
# out of its own API.

case_begin killswitch-error

# Precondition: KS on, Disconnected with a populated endpoint cache (set up
# by an earlier successful connect).
vpn_killswitch "$OPENWRT_CTID" on
vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true

# The precondition is that the idle Blocked policy lets the daemon reach its
# API. Counting "sport 443 accept" rules is not enough: the DNS-over-HTTPS
# hatch (9.9.9.9, 1.1.1.1 ...) matches too, and it says nothing about API
# reachability. Probe the API itself; without a populated endpoint cache
# (fresh install, see issue #15) it is unreachable and the deadlock cannot be
# triggered fairly.
if ! vpn_api_reachable "$OPENWRT_CTID"; then
    case_skip "daemon cannot reach the API while idle with the kill-switch on (#15 regression); cannot trigger fairly"
    return 0 2>/dev/null || exit 0
fi
endpoints_before=$(pct_sh "$OPENWRT_CTID" 'nft list table inet nym 2>/dev/null | awk "/ip saddr .* tcp sport 443 accept/ {n++} END {print n+0}"')

# Force SetFirewallPolicy by hiding nft, then issuing connect.
pct_sh "$OPENWRT_CTID" 'mv /usr/sbin/nft /tmp/nft.bak'
vpn_connect "$OPENWRT_CTID"
sleep 6
pct_sh "$OPENWRT_CTID" 'mv /tmp/nft.bak /usr/sbin/nft'

if ! vpn_wait_state "$OPENWRT_CTID" '^Error' 20; then
    case_fail "daemon did not enter Error state after nft sabotage"
    # Best-effort cleanup
    pct_sh "$OPENWRT_CTID" 'test -f /tmp/nft.bak && mv /tmp/nft.bak /usr/sbin/nft' || true
    vpn_disconnect "$OPENWRT_CTID"
    return 0 2>/dev/null || exit 0
fi

# Force ErrorState to re-apply firewall (allow_lan toggle in v1.27.0 was the
# only nudge; on the fix this just calls apply_killswitch_policy).
current_lan=$(pct_sh "$OPENWRT_CTID" 'nym-vpnc lan get 2>&1' | awk -F': ' '{print $2}')
flip=$([ "$current_lan" = "allow" ] && echo block || echo allow)
pct_sh "$OPENWRT_CTID" "nym-vpnc lan set $flip >/dev/null 2>&1" || true
sleep 1
pct_sh "$OPENWRT_CTID" "nym-vpnc lan set ${current_lan:-allow} >/dev/null 2>&1" || true
sleep 1

endpoints_after=$(pct_sh "$OPENWRT_CTID" 'nft list table inet nym 2>/dev/null | awk "/ip saddr .* tcp sport 443 accept/ {n++} END {print n+0}"')

ok=true
if [ "${endpoints_after:-0}" -eq 0 ]; then
    echo "  ErrorState wiped API exemptions ($endpoints_before -> 0) — deadlock present"
    ok=false
fi
if ! vpn_api_reachable "$OPENWRT_CTID"; then
    echo "  daemon cannot reach its own API from Error state — self-recovery blocked"
    ok=false
fi

if $ok; then
    case_pass "exemptions $endpoints_before -> $endpoints_after, API reachable"
else
    case_fail "ErrorState deadlock regression"
    vpn_dump "$OPENWRT_CTID"
fi

# Reset to a clean Disconnected for downstream cases.
vpn_disconnect "$OPENWRT_CTID" || true
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
