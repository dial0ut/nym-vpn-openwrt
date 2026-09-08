# shellcheck shell=bash
# The rpcd bridge's restart paths with the kill-switch on.
#
# LuCI's Restart button is `daemon_restart` and the Account card's hard reset
# is `account_reset`; the bridge runs them as `/etc/init.d/nym-vpnd restart`
# and `reset_account`, both keep paths for the kill-switch. This case calls
# the bridge exactly as rpcd does and asserts:
#   - the kill-switch table (fw4: inet nym) is present at every 1 s sample
#     taken inside the router from before the first call until the daemon
#     is back after the second — neither path may open the firewall
#   - both calls report success and the daemon runs under procd afterwards
#   - the init script logged the keep path for each action
#   - account_reset wiped the account store
# The account is registered again at the end for the cases that follow.

case_begin restart-paths

vpn_killswitch "$OPENWRT_CTID" on
sleep 2
before_id=$(vpn_account_identity "$OPENWRT_CTID")
keep_restart_before=$(pct_sh "$OPENWRT_CTID" 'logread 2>/dev/null | grep -c "nym-vpnd restart: leaving the kill-switch armed"; true' | tr -d ' ')
keep_reset_before=$(pct_sh "$OPENWRT_CTID" 'logread 2>/dev/null | grep -c "nym-vpnd reset_account: leaving the kill-switch armed"; true' | tr -d ' ')

# Sampler inside the router: one line per second, table present or GONE.
# Its pid is recorded so it can be stopped once the daemon is back; the
# 300 s bound only guards against a runner that never comes back.
pct_sh "$OPENWRT_CTID" 'cat > /tmp/ks-poll.sh <<"S"
#!/bin/sh
for i in $(seq 1 300); do
  if nft list table inet nym >/dev/null 2>&1; then echo "$(date +%T) present"; else echo "$(date +%T) GONE"; fi
  sleep 1
done
S
chmod +x /tmp/ks-poll.sh; rm -f /tmp/ks-poll.log
( /tmp/ks-poll.sh </dev/null >/tmp/ks-poll.log 2>&1 & echo $! > /tmp/ks-poll.pid )'
sleep 2

paths_ok=true

# The bridge blocks for the init script's real restart and answers with the
# daemon's state afterwards.
restart_reply=$(pct_sh "$OPENWRT_CTID" 'nym-vpnc rpcd call daemon_restart 2>&1')
echo "  daemon_restart: $restart_reply"
if ! echo "$restart_reply" | grep -q '"success":true'; then
    echo "  daemon_restart did not report success"
    paths_ok=false
fi
vpn_daemon_wait "$OPENWRT_CTID" 40 || { echo "  daemon did not answer after daemon_restart"; paths_ok=false; }

reset_reply=$(pct_sh "$OPENWRT_CTID" 'nym-vpnc rpcd call account_reset 2>&1')
echo "  account_reset: $reset_reply"
if ! echo "$reset_reply" | grep -q '"success":true'; then
    echo "  account_reset did not report success"
    paths_ok=false
fi
vpn_daemon_wait "$OPENWRT_CTID" 40 || { echo "  daemon did not answer after account_reset"; paths_ok=false; }
sleep 3
pct_sh "$OPENWRT_CTID" 'kill "$(cat /tmp/ks-poll.pid 2>/dev/null)" >/dev/null 2>&1 || true'

samples=$(pct_sh "$OPENWRT_CTID" 'wc -l < /tmp/ks-poll.log' | tr -d ' ')
gone=$(pct_sh "$OPENWRT_CTID" 'grep -c GONE /tmp/ks-poll.log' | tr -d ' ')
echo "  kill-switch samples: $samples, table gone in: ${gone:-?}"
if [ "${samples:-0}" -lt 5 ]; then
    echo "  too few samples; the sampler did not run"
    paths_ok=false
fi
if [ "${gone:-1}" -ne 0 ]; then
    echo "  the kill-switch table disappeared during a restart path"
    pct_sh "$OPENWRT_CTID" 'grep -n GONE /tmp/ks-poll.log | head -5' >&2 || true
    paths_ok=false
fi

if ! vpn_daemon_under_procd "$OPENWRT_CTID"; then
    echo "  procd does not list the daemon as running"
    paths_ok=false
fi
keep_restart_after=$(pct_sh "$OPENWRT_CTID" 'logread 2>/dev/null | grep -c "nym-vpnd restart: leaving the kill-switch armed"; true' | tr -d ' ')
keep_reset_after=$(pct_sh "$OPENWRT_CTID" 'logread 2>/dev/null | grep -c "nym-vpnd reset_account: leaving the kill-switch armed"; true' | tr -d ' ')
if [ "${keep_restart_after:-0}" -le "${keep_restart_before:-0}" ]; then
    echo "  init script did not log the restart keep path"
    paths_ok=false
fi
if [ "${keep_reset_after:-0}" -le "${keep_reset_before:-0}" ]; then
    echo "  init script did not log the reset_account keep path"
    paths_ok=false
fi
after_id=$(vpn_account_identity "$OPENWRT_CTID")
if [ -n "$before_id" ] && [ "$after_id" = "$before_id" ]; then
    echo "  account identity survived the reset: '$before_id'"
    paths_ok=false
fi

# The store is empty now; the tunnel cases need the account back.
if ! vpn_account_set "$OPENWRT_CTID" || ! vpn_wait_ready "$OPENWRT_CTID" 120; then
    echo "  account did not reach ReadyToConnect again after the reset; state: $(vpn_account_state "$OPENWRT_CTID")"
    paths_ok=false
fi

if $paths_ok; then
    case_pass "daemon_restart and account_reset kept the table in all $samples samples"
else
    case_fail "restart paths (see log)"
    vpn_dump "$OPENWRT_CTID"
fi
