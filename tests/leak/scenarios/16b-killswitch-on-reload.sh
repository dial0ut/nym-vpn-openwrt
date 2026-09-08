# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Disconnected, the kill-switch is turned off and back on before the
# capture, then the firewall reloads. Expect: on re-armed the Blocked policy,
# it stays armed across the reload, no leak.
scenario_connected=0
scenario_mgmt=1
scenario_wait=5
scenario_pre() {
    local st
    rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 3
        nym-vpnc tunnel set --killswitch off >/dev/null 2>&1; sleep 3
        nym-vpnc tunnel set --killswitch on >/dev/null 2>&1; sleep 3'
    st=$(state); echo "ks off then on: $st"
    printf '%s' "$st" | grep -q 'policy=yes' || not_recovered "kill-switch on did not re-arm the Blocked policy: $st"
}
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "reload at $(date +%T)"'
}
scenario_check() {
    local st
    st=$(state); log "ks on + reload: $st"
    log "$(lan_probe)"
    if printf '%s' "$st" | grep -q 'policy=yes'; then
        recovered "re-armed and stayed armed across the reload"
    else
        not_recovered "policy gone after the reload: $st"
    fi
}
