# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Runtime directory mode 0755 (not a private root-owned directory). Expect:
# `stop` refuses to write the open marker there, a firewall reload installs
# the boot-time block with the reason logged, no leak, ssh and LuCI stay
# reachable, and restoring the mode + start recovers. Caveat this documents:
# while the directory is untrusted, `stop` cannot open the router.
scenario_mgmt=1
scenario_wait=3
scenario_inject() {
    rt 'chmod 0755 /var/run/nym-firewall; /etc/init.d/nym-vpnd stop >/dev/null 2>&1; echo "dir mode 0755, stop issued at $(date +%T)"'
}
scenario_check() {
    local blocked tp
    log "after stop with an untrusted dir: $(state)"
    rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-150'
    rt '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    blocked=$(state); log "after firewall reload: $blocked"
    rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-170'
    probes
    printf '%s' "$blocked" | grep -q 'boot=yes marker=no' || not_recovered "expected the boot block and no marker after the reload: $blocked"
    log "recover: chmod 0700, start"
    rt 'chmod 0700 /var/run/nym-firewall; /etc/init.d/nym-vpnd start'
    if tp=$(wait_state 'policy=yes boot=no .*vpnd=[0-9]' 60); then
        recovered "no marker written into the untrusted dir, reload installed the boot block; chmod 0700 + start brought the daemon's policy back in ${tp}s"
    else
        not_recovered "daemon policy not back after chmod + start: $(state)"
    fi
}
scenario_post() { reset_state; }
