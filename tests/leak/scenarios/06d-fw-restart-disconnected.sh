# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# firewall restart with the tunnel down (Blocked policy): the sharpest case
# for the fw3 window, since nothing is routed into a tunnel and any traffic
# during fw3's rebuild would go straight out of the WAN. Expect: no leak.
scenario_wait=12
scenario_pre() {
    rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 4; nym-vpnc status | head -1'
}
scenario_inject() {
    rt 'echo "restart at $(date +%T)"; /etc/init.d/firewall restart >/dev/null 2>&1; echo "restart returned at $(date +%T)"'
}
scenario_check() {
    note "fw3 restart window while disconnected: see watcher"
}
