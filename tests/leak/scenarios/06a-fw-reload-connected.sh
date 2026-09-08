# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# /etc/init.d/firewall reload with the tunnel up. fw3 preserves foreign
# chains on reload and fw4 leaves the separate nym table alone; the include
# only reconciles. Expect: no leak, hooked throughout.
scenario_wait=10
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "reload at $(date +%T)"'
}
scenario_check() {
    local st
    rt 'logread | grep -E "nym-vpn:" | tail -3 | cut -c1-140'
    st=$(state); echo "$st"
    if printf '%s' "$st" | grep -q 'policy=yes'; then recovered "policy hooked after the reload"; else not_recovered "$st"; fi
}
