# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Runtime directory mode 0755 (not a private root-owned directory). Expect:
# `stop` opens the router as always (that window is expected open here) but
# refuses to write the open marker there, so the next firewall reload
# installs the boot-time block with the reason logged and the LAN is blocked
# again; ssh and LuCI stay reachable, and restoring the mode + start
# recovers. Caveat this documents: while the directory is untrusted, `stop`
# opens the router only until the next reload.
scenario_expect=leak
scenario_mgmt=1
scenario_tunnel_after=0
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
    lan_probe | grep -q 'egress=blocked' || not_recovered "LAN still open after the reload installed the boot block: $(lan_probe)"
    log "recover: chmod 0700, start"
    rt 'chmod 0700 /var/run/nym-firewall; /etc/init.d/nym-vpnd start'
    if tp=$(wait_state 'policy=yes boot=no .*vpnd=[0-9]' 60); then
        recovered "no marker written into the untrusted dir, reload installed the boot block; chmod 0700 + start brought the daemon's policy back in ${tp}s"
    else
        not_recovered "daemon policy not back after chmod + start: $(state)"
    fi
}
scenario_post() { reset_state; }
