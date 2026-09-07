# shellcheck shell=bash
# Custom DNS plumbing.
#
# Set the slot's dedicated dnsmasq logger as the configured DNS server,
# trigger a uniquely-marked lookup from the router, and assert the query
# arrived at the logger's /tmp/queries.log. This exercises:
#   - nym-vpnc dns set actually plumbs into the resolved DnsConfig
#   - the kill-switch (when active) whitelists configured DNS servers
#   - no silent fallthrough to a baked-in resolver

case_begin custom-dns

marker="harness-${SLOT}-$(date +%s).example.test"

# Configure custom DNS to our logger.
if ! pct_sh "$OPENWRT_CTID" "nym-vpnc dns custom on >/dev/null 2>&1"; then
    echo "  nym-vpnc dns custom on failed; CLI may differ on this version"
fi
if ! pct_sh "$OPENWRT_CTID" "nym-vpnc dns set ${DNS_IP} >/dev/null 2>&1"; then
    case_fail "could not set custom DNS to $DNS_IP"
    return 0 2>/dev/null || exit 0
fi

# Connect so the daemon picks up the new DNS config in Connecting/Connected.
vpn_killswitch "$OPENWRT_CTID" on
vpn_connect "$OPENWRT_CTID"
if ! vpn_wait_state "$OPENWRT_CTID" '^Connected' 120; then
    case_fail "could not Connect to validate custom DNS"
    vpn_dump "$OPENWRT_CTID"
    vpn_disconnect "$OPENWRT_CTID"
    return 0 2>/dev/null || exit 0
fi

# Trigger a uniquely-marked lookup. nslookup uses the system resolver;
# from the router, that should be plumbed to our DNS_IP.
pct_sh "$OPENWRT_CTID" "nslookup $marker >/dev/null 2>&1" || true
sleep 2

# Did the query reach our logger?
if pct_sh "$DNS_CTID" "grep -q '$marker' /tmp/queries.log"; then
    case_pass "logger saw marker $marker"
else
    case_fail "marker $marker never reached DNS logger at $DNS_IP"
    pct_sh "$DNS_CTID" "tail -20 /tmp/queries.log" >&2 || true
fi

# Restore default DNS for downstream cases.
pct_sh "$OPENWRT_CTID" "nym-vpnc dns custom off >/dev/null 2>&1" || true
vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
