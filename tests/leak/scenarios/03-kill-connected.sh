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
    local out
    out=$(rt 'echo "pid now: $(pidof nym-vpnd)"; nym-vpnc status 2>&1 | head -1 | cut -c1-60
        iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && echo "policy hooked" || echo "policy NOT hooked"
        echo "emergency chains: $(iptables -w -S | grep -c NYM_EMERGENCY)"; ls /var/run/nym-firewall/')
    printf '%s\n' "$out"
    if [ "$(printf '%s\n' "$out" | grep -c '^policy hooked')" -gt 0 ]; then
        note "recovered: daemon respawned, policy hooked"
    else
        note "NOT recovered"
    fi
}
