# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Invalid JSON in /etc/nym/nym-vpnd.json, then a restart. Expect: the daemon
# starts on defaults with the kill-switch on and the Blocked policy applied,
# the unreadable file is preserved as .json.bak, no leak, management access
# kept, and a connect on request works (service usable).
scenario_mgmt=1
scenario_wait=2
scenario_inject() {
    rt 'cp /etc/nym/nym-vpnd.json /tmp/leak/nym-vpnd.json.orig; printf "{ this is not json" > /etc/nym/nym-vpnd.json
        /etc/init.d/nym-vpnd restart; echo "config corrupted and daemon restarted at $(date +%T)"'
}
scenario_check() {
    local tp bak st tc
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); log "daemon up with policy after ${tp}s: $(state)"
    bak=$(rt 'ls /etc/nym/nym-vpnd.json.bak 2>/dev/null'); log "preserved copy: ${bak:-none}"
    rt 'logread | grep -E "Preserved unreadable|Failed to read service config" | tail -2 | cut -c1-150'
    probes
    tc=$(epoch); rt 'nym-vpnc connect --wait >/dev/null 2>&1'
    st=$(state); log "service usable (connect returned) after $(( $(epoch) - tc ))s: $st"
    probes
    if printf '%s' "$st" | grep -q 'ks=on' && [ -n "$bak" ] && printf '%s' "$st" | grep -q 'state=Connected'; then
        recovered "defaults with the kill-switch on, bad config kept as .json.bak, policy back in ${tp}s, connected on request"
    else
        not_recovered "bak=${bak:-none} state=[$st]"
    fi
}
scenario_post() {
    rt 'cp /tmp/leak/nym-vpnd.json.orig /etc/nym/nym-vpnd.json; rm -f /etc/nym/nym-vpnd.json.bak /tmp/leak/nym-vpnd.json.orig
        /etc/init.d/nym-vpnd restart; sleep 4'
    reset_state
}
