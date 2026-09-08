# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# fw4 only. A foreign process holds the fw3 state lock for 60 s while policy
# changes are requested (fw4 must not wait for it), then 12 `fw4 reload`s run
# while a connect is in flight. Expect: the policy changes complete in
# seconds, the reload storm leaves policy=yes boot=no, the tunnel reaches
# Connected, no leak.
scenario_mgmt=1
scenario_wait=1
scenario_pre() {
    if [ "$LEAK_FW" != fw4 ]; then
        skip "fw4-only: the fw3 backend does take the state lock, so a held lock is expected to block it"
        return 1
    fi
}
scenario_inject() {
    rt '(setsid sh -c "flock /var/run/nym-firewall/lock sleep 60" </dev/null >/dev/null 2>&1 &); sleep 1; echo "fw3 lock held by a foreign process for 60 s from $(date +%T)"'
}
scenario_check() {
    local applies0 applies t0 took tp st
    applies0=$(rt 'logread | grep -c "Applying firewall policy"')
    t0=$(epoch); rt 'nym-vpnc disconnect >/dev/null 2>&1; sleep 2; nym-vpnc connect --wait >/dev/null 2>&1'
    took=$(( $(epoch) - t0 ))
    applies=$(( $(rt 'logread | grep -c "Applying firewall policy"') - applies0 ))
    log "with the lock held: disconnect+connect produced $applies policy applies in ${took}s"
    log "race: 12 fw4 reloads while disconnect+connect runs"
    rt 'nym-vpnc disconnect >/dev/null 2>&1; (setsid sh -c "nym-vpnc connect --wait" </dev/null >/dev/null 2>&1 &); for i in $(seq 1 12); do fw4 reload >/dev/null 2>&1; sleep 1; done'
    tp=$(wait_state 'state=Connected' 90); st=$(state); log "connected after ${tp}s: $st"
    rt 'logread | grep -E "nym-vpn:" | tail -3 | cut -c1-140'
    probes
    if [ "$applies" -ge 2 ] && [ "$took" -lt 55 ] && printf '%s' "$st" | grep -q 'policy=yes boot=no' && printf '%s' "$st" | grep -q 'state=Connected'; then
        recovered "fw4 policy changes unaffected by the held fw3 lock ($applies applies in ${took}s); reload storm left policy=yes boot=no, connected in ${tp}s"
    else
        not_recovered "applies=$applies took=${took}s state=[$st]"
    fi
}
scenario_post() { reset_state; }
