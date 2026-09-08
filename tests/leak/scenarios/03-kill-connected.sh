# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Daemon SIGKILLed in steady state (Connected). Expect: no leak (the tunnel
# routing and the Connected policy stay in the kernel; the kill-switch keeps
# non-tunnel egress closed), procd respawns, daemon comes back Disconnected
# with the Blocked policy hooked.
scenario_wait=40
scenario_inject() {
    rt 'kill -9 $(pidof nym-vpnd); echo "SIGKILL at $(date +%T)"'
}
scenario_check() {
    local st
    rt 'echo "pid now: $(pidof nym-vpnd)"; nym-vpnc status 2>&1 | head -1 | cut -c1-60; ls /var/run/nym-firewall/'
    st=$(state); echo "$st"
    if printf '%s' "$st" | grep -qE 'policy=yes boot=no .*vpnd=[0-9]'; then
        recovered "daemon respawned, policy hooked"
    else
        not_recovered "after respawn: $st"
    fi
}
