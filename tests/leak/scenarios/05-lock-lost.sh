# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Lock lost (fw3): flock is hidden and the firewall is reloaded. Expect: the
# include logs CRITICAL, leaves the live policy untouched, no leak; flock
# restored.
scenario_wait=8
scenario_pre() {
    if [ "$LEAK_FW" != fw3 ]; then
        skip "fw3-only: the fw4 include does not take the fw3 state lock"
        return 1
    fi
    rt 'mv /usr/bin/flock /tmp/leak/flock.bak && echo "flock hidden"'
}
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "firewall reloaded at $(date +%T)"'
}
scenario_check() {
    local out st
    out=$(rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-170')
    printf '%s\n' "$out"
    st=$(state); echo "$st"
    if printf '%s\n' "$out" | grep -q CRITICAL && printf '%s' "$st" | grep -q 'policy=yes'; then
        recovered "CRITICAL logged, live policy untouched"
    else
        not_recovered "expected CRITICAL log + untouched policy not both observed: $st"
    fi
}
scenario_post() {
    rt 'mv /tmp/leak/flock.bak /usr/bin/flock; command -v flock'
}
