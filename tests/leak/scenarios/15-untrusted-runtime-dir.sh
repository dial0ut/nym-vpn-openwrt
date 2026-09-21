# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# An untrusted directory prevents writing the stop marker. fw4 removes its
# tables on Stop; fw3 cannot take its state lock and leaves policy in place.
# Both must block after reload and recover after restoring the directory.
scenario_expect=noleak
[ "$LEAK_FW" != fw4 ] || scenario_expect=leak
scenario_mgmt=1
scenario_tunnel_after=0
scenario_wait=3
scenario_inject() {
    rt 'chmod 0755 /var/run/nym-firewall; /etc/init.d/nym-vpnd stop >/dev/null 2>&1; echo "dir mode 0755, stop issued at $(date +%T)"'
}
scenario_check() {
    local blocked tp expected
    log "after stop with an untrusted dir: $(state)"
    rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-150'
    rt '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    blocked=$(state); log "after firewall reload: $blocked"
    rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-170'
    probes
    expected='boot=yes marker=no'
    if [ "$LEAK_FW" = fw3 ]; then
        expected='(policy=yes boot=(yes|no)|policy=no boot=yes) marker=no'
    fi
    printf '%s' "$blocked" | grep -qE "$expected" || not_recovered "expected protection and no marker after the reload: $blocked"
    lan_probe | grep -q 'egress=blocked' || not_recovered "LAN still open after the reload: $(lan_probe)"
    log "recover: chmod 0700, start"
    rt 'chmod 0700 /var/run/nym-firewall; /etc/init.d/nym-vpnd start'
    if tp=$(wait_state 'policy=yes boot=no .*vpnd=[0-9]' 60); then
        recovered "no marker written into the untrusted dir, protection held after reload; chmod 0700 + start brought the daemon's policy back in ${tp}s"
    else
        not_recovered "daemon policy not back after chmod + start: $(state)"
    fi
}
scenario_post() { reset_state; }
