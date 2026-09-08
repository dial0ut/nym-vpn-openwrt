# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# WAN link down for 15 s while connected (the host side of the router's WAN
# interface). Expect: no leak across the flap, the tunnel reconnects after
# the link is back. The held ssh session dropping while the link itself is
# down is expected, so management access is recorded but not gated here.
# On an ssh-controlled bed the router cannot be queried during the outage;
# the LAN probe and the capture cover that window.
scenario_wait=1
scenario_inject() {
    px "ip link set $LEAK_WAN_IF down"; log "WAN down at $(date +%T)"
    sleep 6
    [ -n "${LEAK_ROUTER_CT:-}" ] && log "t+6s: $(state)"
    log "t+6s: $(lan_probe)"
    sleep 9
    px "ip link set $LEAK_WAN_IF up"; log "WAN up at $(date +%T), after 15 s"
}
scenario_check() {
    local i=0 tp st
    until rt true 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 12 ] && break
        sleep 5
    done
    tp=$(wait_state 'state=Connected' 120); st=$(state); log "reconnected ${tp}s after link up: $st"
    rt 'logread | grep -E "Offline|offline|reconnect|nym-vpn:" | tail -4 | cut -c1-140'
    probes
    if printf '%s' "$st" | grep -q 'state=Connected'; then
        recovered "reconnected ${tp}s after link up"
    else
        not_recovered "not Connected 120 s after link up: $st"
    fi
}
