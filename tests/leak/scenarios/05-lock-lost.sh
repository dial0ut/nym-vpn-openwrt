# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Lock lost: flock is hidden and the firewall is reloaded. Expect: the include
# logs CRITICAL, leaves the live policy untouched, no leak; flock restored.
scenario_wait=8
scenario_pre() {
    rt 'mv /usr/bin/flock /tmp/leak/flock.bak && echo "flock hidden"'
}
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "firewall reloaded at $(date +%T)"'
}
scenario_check() {
    local out
    out=$(rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-170
        iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && echo "policy hooked (untouched)" || echo "policy NOT hooked"
        echo "emergency chains: $(iptables -w -S | grep -c NYM_EMERGENCY)"')
    printf '%s\n' "$out"
    if [ "$(printf '%s\n' "$out" | grep -c 'CRITICAL')" -gt 0 ] && [ "$(printf '%s\n' "$out" | grep -c '^policy hooked')" -gt 0 ]; then
        note "CRITICAL logged, live policy untouched"
    else
        note "expected CRITICAL log + untouched policy not both observed"
    fi
}
scenario_post() {
    rt 'mv /tmp/leak/flock.bak /usr/bin/flock; command -v flock'
}
