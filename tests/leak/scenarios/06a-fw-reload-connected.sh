# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# /etc/init.d/firewall reload with the tunnel up. fw3 preserves foreign
# chains on reload; the include only reconciles. Expect: no leak, hooked
# throughout.
scenario_wait=10
scenario_inject() {
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "reload at $(date +%T)"'
}
scenario_check() {
    rt 'logread | grep -E "nym-vpn:" | tail -3 | cut -c1-140'
}
