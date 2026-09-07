# shellcheck shell=bash
# Kill-switch in DisconnectedState.
#
# When KS=on and the API endpoint cache is populated (it will be, since a
# prior case has Connected at least once), the firewall should be in Blocked
# mode with API + DNS exemptions. Concretely:
#   - LAN client cannot reach the open internet
#   - The router itself CAN reach validator.nymtech.net (API whitelist)
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
# Daemon should still reach its API. On a fresh install with no endpoint
# cache this is exactly issue #15 (idle Blocked policy allows no API hosts).
if ! pct_sh "$OPENWRT_CTID" 'wget --timeout=8 -qO- https://validator.nymtech.net/api/v1/epoch/key-rotation-info >/dev/null 2>&1'; then
    echo "  router could not reach Nym API with KS=on (no endpoint cache / exemptions, #15)"
    why="$why router-api-blocked-with-ks-on;"
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
