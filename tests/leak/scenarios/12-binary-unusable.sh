# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Daemon binary unusable (chmod 000), restart, then a firewall reload.
# Expect: the block holds without a daemon (the include keeps the stale
# policy through the reload), no leak, ssh and LuCI stay reachable, and
# restoring the binary + start brings the daemon's policy back.
scenario_mgmt=1
scenario_wait=6
scenario_inject() {
    rt 'chmod 000 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart >/dev/null 2>&1; echo "binary unusable, restart issued at $(date +%T)"'
}
scenario_check() {
    local held tp
    log "after restart with unusable binary: $(state)"
    rt '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    held=$(state); log "after firewall reload: $held"
    rt 'logread | grep -E "nym-vpn:|procd:.*nym-vpnd" | tail -3 | cut -c1-150'
    probes
    printf '%s' "$held" | grep -qE 'policy=yes .*vpnd=none' || not_recovered "block did not hold without a daemon: $held"
    log "recover: restore binary, start"
    rt 'chmod 755 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd start'
    if tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); then
        recovered "stale policy kept through the reload with no daemon; start brought the daemon's policy back in ${tp}s"
    else
        not_recovered "daemon policy not back after restore + start: $(state)"
    fi
}
scenario_post() { reset_state; }
