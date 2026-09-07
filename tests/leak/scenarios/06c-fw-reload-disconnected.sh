# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# firewall reload with the tunnel down (Blocked policy). Expect: no leak.
scenario_wait=10
scenario_pre() {
    rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 4; nym-vpnc status | head -1'
}
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "reload at $(date +%T)"'
}
