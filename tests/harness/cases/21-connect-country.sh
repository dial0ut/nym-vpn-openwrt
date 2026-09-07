# shellcheck shell=bash
# Connect with a specific country pair. Gateway selection narrows the pool,
# so transient retries are expected; we give it longer than 20-connect-random.
# Pass = lands in Connected within 3 minutes.

case_begin connect-country

pct_sh "$OPENWRT_CTID" 'nym-vpnc gateway set --entry-country US --exit-country DE >/dev/null 2>&1' || true

vpn_connect "$OPENWRT_CTID"
if vpn_wait_state "$OPENWRT_CTID" '^Connected' 180; then
    case_pass "$(vpn_state "$OPENWRT_CTID")"
else
    case_fail "no Connected in 180s with US->DE; last: $(vpn_state "$OPENWRT_CTID")"
    vpn_dump "$OPENWRT_CTID"
fi

vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
# Reset to random for downstream cases.
pct_sh "$OPENWRT_CTID" 'nym-vpnc gateway set --entry-random --exit-random >/dev/null 2>&1' || true
