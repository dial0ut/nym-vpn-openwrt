# shellcheck shell=bash
# Connect with random gateways. Pass = lands in Connected within 90s.
# Inputs (env, exported by run-slot.sh):
#   OPENWRT_CTID, SLOT, VERSION

case_begin connect-random

vpn_require_ready || return 0 2>/dev/null || exit 0

# Clear any pinned gateway selection from a prior case.
pct_sh "$OPENWRT_CTID" 'nym-vpnc gateway set --entry-random --exit-random >/dev/null 2>&1' || true

vpn_connect "$OPENWRT_CTID"
if vpn_wait_state "$OPENWRT_CTID" '^Connected' 90; then
    case_pass "$(vpn_state "$OPENWRT_CTID")"
else
    case_fail "did not reach Connected in 90s; last state: $(vpn_state "$OPENWRT_CTID")"
    vpn_dump "$OPENWRT_CTID"
fi

# Leave Disconnected for the next case.
vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true
