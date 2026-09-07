# shellcheck shell=bash
# Kill-switch in DisconnectedState.
#
# When KS=on and the API endpoint cache is populated (it will be, since a
# prior case has Connected at least once), the firewall should be in Blocked
# mode with API + DNS exemptions. Concretely:
#   - LAN client cannot reach the open internet
#   - The daemon CAN reach the Nym API (resolved endpoints, root-scoped;
#     the router shell cannot resolve names — only the daemon DNS hatch is open)
#
# When KS=off, the firewall should be reset (no table inet nym), and the LAN
# client should have unrestricted forwarding through WAN.

case_begin killswitch-disconnected

# Make sure we're in Disconnected to start.
vpn_disconnect "$OPENWRT_CTID"
vpn_wait_state "$OPENWRT_CTID" '^Disconnected' 30 || true

# --- killswitch on ---
vpn_killswitch "$OPENWRT_CTID" on
sleep 2

ks_on_pass=true
why=""
# The daemon must still reach its API while idle (issue #15: the Blocked
# policy admits the resolved API endpoints for the daemon). Probed through
# the daemon; the router shell's own lookups are blocked by design.
if ! vpn_api_reachable "$OPENWRT_CTID"; then
    echo "  daemon could not reach the Nym API while idle with KS=on (#15)"
    why="$why daemon-api-blocked-with-ks-on;"
    ks_on_pass=false
fi
# LAN client traffic should be blocked (forward chain rejects).
if ct_reachable "$CLIENT_CTID" 'https://example.com' 6; then
    echo "  LAN client reached internet with KS=on; expected block"
    why="$why lan-client-leaked-with-ks-on;"
    ks_on_pass=false
fi

# --- killswitch off ---
vpn_killswitch "$OPENWRT_CTID" off
sleep 2

ks_off_pass=true
# Now LAN client must have unrestricted forwarding.
if ! ct_reachable "$CLIENT_CTID" 'https://example.com' 8; then
    echo "  LAN client still blocked with KS=off"
    why="$why lan-client-blocked-with-ks-off;"
    ks_off_pass=false
fi
# And the inet nym table should be gone or empty.
if pct_sh "$OPENWRT_CTID" 'nft list table inet nym 2>&1 | grep -qE "udp dport 53 reject|tcp dport 53 reject"'; then
    echo "  inet nym table still rejecting DNS with KS=off"
    why="$why dns-still-rejected-with-ks-off;"
    ks_off_pass=false
fi

# Restore KS=on for downstream cases.
vpn_killswitch "$OPENWRT_CTID" on
sleep 2

if $ks_on_pass && $ks_off_pass; then
    case_pass
else
    case_fail "failed checks:$why"
    vpn_dump "$OPENWRT_CTID"
fi
