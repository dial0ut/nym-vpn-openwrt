# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# The daemon exits immediately on every start for 60 s (procd respawn
# `3600 5 0`: retry 0, never gives up). Expect: the block holds the whole
# time, no leak, ssh and LuCI stay reachable, and the real binary restarts
# cleanly.
scenario_mgmt=1
scenario_wait=60
scenario_inject() {
    rt 'mv /usr/sbin/nym-vpnd /usr/sbin/nym-vpnd.real; printf "#!/bin/sh\nexit 1\n" > /usr/sbin/nym-vpnd; chmod 755 /usr/sbin/nym-vpnd
        /etc/init.d/nym-vpnd restart >/dev/null 2>&1; echo "crash loop started at $(date +%T)"
        echo "respawn params: $(grep respawn /etc/init.d/nym-vpnd | tr -s " ")"'
}
scenario_check() {
    local held tp
    held=$(state)
    log "t+60s: $held respawns_logged=$(rt 'logread | grep -c "nym-vpnd.*respawn\|Instance nym-vpnd::instance1 .*exited\|crashed"')"
    rt 'ubus call service list "{\"name\":\"nym-vpnd\"}" 2>/dev/null | grep -E "respawn|running|exit" | head -4'
    probes
    printf '%s' "$held" | grep -q 'policy=yes' || not_recovered "block did not hold through the crash loop: $held"
    log "recover: restore binary, restart"
    rt 'mv /usr/sbin/nym-vpnd.real /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart'
    if tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); then
        recovered "block held through 60 s of crash-looping; real binary back with policy in ${tp}s"
    else
        not_recovered "daemon policy not back after the real binary was restored: $(state)"
    fi
}
scenario_post() {
    rt '[ -e /usr/sbin/nym-vpnd.real ] && mv /usr/sbin/nym-vpnd.real /usr/sbin/nym-vpnd; true'
    reset_state
}
