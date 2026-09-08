# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Daemon SIGKILLed while a connect is in flight (Connecting state, firewall
# policy mid-change). Expect: no leak, procd respawns it, any leftover
# transition marker keeps the include fail-closed, and the respawned daemon
# converges (policy hooked, no boot block left).
scenario_connected=0
scenario_wait=45
scenario_pre() {
    rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 4; nym-vpnc status | head -1'
}
scenario_inject() {
    rt 'nym-vpnc connect >/dev/null 2>&1 &
        sleep 2
        echo "state at kill: $(nym-vpnc status | head -1 | cut -c1-40)"
        kill -9 $(pidof nym-vpnd); echo "SIGKILL at $(date +%T)"
        sleep 1; ls /var/run/nym-firewall/'
}
scenario_check() {
    local st
    rt 'echo "pid now: $(pidof nym-vpnd)"; nym-vpnc status 2>&1 | head -1 | cut -c1-60; ls /var/run/nym-firewall/
        logread | grep -E "nym-vpn:|procd.*nym-vpnd" | tail -5 | cut -c1-150'
    st=$(state); echo "$st"
    if printf '%s' "$st" | grep -qE 'policy=yes boot=no .*vpnd=[0-9]'; then
        recovered "daemon respawned, policy hooked"
    else
        not_recovered "after respawn: $st"
    fi
}
