# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# /etc/init.d/firewall restart with the tunnel up. fw3 flushes every table,
# rebuilds, then runs the include, which restores the persisted policy. This
# is the documented fw3 window; the capture measures what actually leaves.
scenario_wait=12
scenario_inject() {
    rt 'echo "restart at $(date +%T)"; /etc/init.d/firewall restart >/dev/null 2>&1; echo "restart returned at $(date +%T)"'
}
scenario_check() {
    rt 'logread | grep -E "nym-vpn:" | tail -3 | cut -c1-140'
    note "fw3 restart window: see watcher for unhooked samples"
}
