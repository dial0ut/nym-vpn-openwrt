# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Disconnected, the administrator turns the kill-switch off, then the
# firewall reloads. The router is expected to be OPEN (no policy, no boot
# block) and to stay open across the reload, so a leak MUST be visible on
# the LAN probe and in the capture.
scenario_expect=leak
scenario_connected=0
scenario_mgmt=1
scenario_wait=5
scenario_pre() {
    rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 3; nym-vpnc status | head -1'
}
scenario_inject() {
    rt 'nym-vpnc tunnel set --killswitch off >/dev/null 2>&1; echo "kill-switch off at $(date +%T)"'
    sleep 3
    log "ks off: $(state)"
    rt '/etc/init.d/firewall reload >/dev/null 2>&1; echo "reload at $(date +%T)"'
}
scenario_check() {
    local st
    st=$(state); log "ks off + reload: $st"
    rt 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-150'
    log "$(lan_probe) (expected open: the administrator turned the kill-switch off)"
    if printf '%s' "$st" | grep -q 'policy=no boot=no'; then
        recovered "off opened (no policy, no boot block) and stayed open across the reload"
    else
        not_recovered "kill-switch off did not open the router: $st"
    fi
}
scenario_post() {
    rt 'nym-vpnc tunnel set --killswitch on >/dev/null 2>&1; sleep 2'
    log "ks on again: $(state)"
}
