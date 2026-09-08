# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# The documented escape hatch with the binary unusable: an administrator's
# `/etc/init.d/nym-vpnd stop` must open the router even though the daemon
# cannot run. The firewall is expected to be open after the stop, so a leak
# MUST be visible; then restoring the binary + start must re-arm.
scenario_expect=leak
scenario_connected=0
scenario_mgmt=1
scenario_wait=10
scenario_pre() {
    local st
    rt 'chmod 000 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart >/dev/null 2>&1'; sleep 6
    st=$(state); echo "held before the stop: $st"
    printf '%s' "$st" | grep -qE 'policy=yes .*vpnd=none' || inconclusive "block not held with the binary unusable before the stop: $st"
}
scenario_inject() {
    rt '/etc/init.d/nym-vpnd stop >/dev/null 2>&1; echo "stop issued at $(date +%T)"'
}
scenario_check() {
    local st tp
    st=$(state); log "after stop: $st"
    log "$(lan_probe) (expected open: the administrator asked for it)"
    printf '%s' "$st" | grep -qE 'policy=no boot=no' || not_recovered "stop did not open the router: $st"
    log "recover: restore binary, start"
    rt 'chmod 755 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd start'
    if tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); then
        recovered "protection back ${tp}s after start"
    else
        not_recovered "daemon policy not back after restore + start: $(state)"
    fi
}
scenario_post() { reset_state; }
