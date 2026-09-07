#!/bin/bash
# Failure-injection scenarios. Each function: begin, capture, inject, observe
# protection + management access + recovery clock, restore, verdict.
# Sourced by run.sh after lib.sh.

# Did any probe line in this scenario's log report a leak?
leaked() { grep -q 'LEAK:' "$SCENARIO_LOG"; }
# Management access counts as kept when either the held session survived or
# the wired vantage saw the ssh port reachable throughout.
mgmt_ok() { grep -q 'session survived' "$SCENARIO_LOG" || wired_ok; }

s1() {
    scenario_begin s1-corrupt-config "invalid JSON in /etc/nym/nym-vpnd.json, then restart"
    cap_start s1; mgmt_start
    r 'cp /etc/nym/nym-vpnd.json /tmp/nym-vpnd.json.orig; printf "{ this is not json" > /etc/nym/nym-vpnd.json'
    log "inject: config corrupted; restart"
    t0=$(epoch); r '/etc/init.d/nym-vpnd restart'
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60)
    log "daemon up with policy after ${tp}s: $(state)"
    log "preserved copy: $(r 'ls /etc/nym/*.json.bak 2>/dev/null | xargs echo')"
    r 'logread | grep -E "Preserved unreadable|Failed to read service config" | tail -2 | cut -c1-150' | tee -a "$SCENARIO_LOG"
    probes
    t1=$(epoch); r 'nym-vpnc connect --wait >/dev/null 2>&1'
    log "service usable (connected) after $(( $(epoch) - t1 ))s, $(( $(epoch) - t0 ))s from injection: $(state)"
    probes; mgmt_stop; cap_stop; cap_summary s1
    ks=$(r 'nym-vpnc tunnel get | sed -n "s/Kill-switch: //p"')
    bak=$(r 'ls /etc/nym/nym-vpnd.json.bak 2>/dev/null')
    r 'cp /tmp/nym-vpnd.json.orig /etc/nym/nym-vpnd.json; rm -f /etc/nym/nym-vpnd.json.bak /tmp/nym-vpnd.json.orig; /etc/init.d/nym-vpnd restart; sleep 4'
    reset_state
    if [ "$ks" = on ] && [ -n "$bak" ] && ! leaked && mgmt_ok; then
        verdict PASS "daemon started on defaults (kill-switch on), bad config preserved as .json.bak, no leak, ssh survived, connected in $(( t1 - t0 ))s+"
    else
        verdict FAIL "ks=$ks bak=${bak:-none} leaked=$(leaked && echo yes || echo no) mgmt=$(mgmt_ok && echo ok || echo dropped)"
    fi
}

s2() {
    scenario_begin s2-binary-unusable "chmod 000 nym-vpnd, restart, firewall reload; then the documented escape hatch"
    cap_start s2; mgmt_start
    r 'chmod 000 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart >/dev/null 2>&1'; sleep 6
    log "after restart with unusable binary: $(state)"
    r '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    log "after firewall reload: $(state)"
    r 'logread | grep -E "nym-vpn:|procd:.*nym-vpnd" | tail -3 | cut -c1-150' | tee -a "$SCENARIO_LOG"
    probes
    held_state=$(state)
    log "escape hatch: /etc/init.d/nym-vpnd stop"
    r '/etc/init.d/nym-vpnd stop >/dev/null 2>&1'; sleep 3
    log "after stop: $(state)"
    open_probe=$(lan_probe); log "$open_probe (expected: open, the administrator asked for it)"
    log "recover: restore binary, start"
    t0=$(epoch); r 'chmod 755 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd start'
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); log "protection back after ${tp}s: $(state)"
    mgmt_stop; cap_stop; cap_summary s2
    reset_state
    pre_hatch_leaks=$(sed '/escape hatch/,$d' "$SCENARIO_LOG" | grep -c 'LEAK')
    if echo "$held_state" | grep -q 'policy=yes.*vpnd=none' && [ "$pre_hatch_leaks" = 0 ] && mgmt_ok && echo "$open_probe" | grep -q LEAK; then
        verdict PASS "block held with daemon unusable (stale policy kept, reload left it), ssh/LuCI stayed up, stop opened as documented, start recovered in ${tp}s"
    else
        verdict FAIL "held=[$held_state] open_probe=[$open_probe] mgmt=$(mgmt_ok && echo ok || echo dropped)"
    fi
}

s3() {
    scenario_begin s3-crash-loop "daemon exits immediately on every start; observe procd respawn for 60 s"
    cap_start s3; mgmt_start
    r 'mv /usr/sbin/nym-vpnd /usr/sbin/nym-vpnd.real; printf "#!/bin/sh\nexit 1\n" > /usr/sbin/nym-vpnd; chmod 755 /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart >/dev/null 2>&1'
    log "respawn params: $(r 'grep respawn /etc/init.d/nym-vpnd | tr -s " "')"
    for i in 1 2 3; do sleep 20; log "t+$((i*20))s: $(state) respawns_logged=$(r 'logread | grep -c "nym-vpnd.*respawn\|Instance nym-vpnd::instance1 .*exited\|crashed"')"; probes; done
    r 'ubus call service list "{\"name\":\"nym-vpnd\"}" 2>/dev/null | grep -E "respawn|running|exit" | head -4' | tee -a "$SCENARIO_LOG"
    held=$(state)
    log "recover: restore binary, restart"
    t0=$(epoch); r 'mv /usr/sbin/nym-vpnd.real /usr/sbin/nym-vpnd; /etc/init.d/nym-vpnd restart'
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); log "protection back after ${tp}s: $(state)"
    mgmt_stop; cap_stop; cap_summary s3
    reset_state
    if echo "$held" | grep -q 'policy=yes' && ! leaked && mgmt_ok; then
        verdict PASS "block held through 60 s of crash-looping (procd retry=0: never gives up), no leak, ssh survived, recovered in ${tp}s"
    else
        verdict FAIL "held=[$held] leaked=$(leaked && echo yes || echo no) mgmt=$(mgmt_ok && echo ok || echo dropped)"
    fi
}

s4() {
    scenario_begin s4-lock-and-reload-race "hold the fw3 lock during a policy change (fw4 must ignore it); then fw4 reload loop during connect"
    cap_start s4; mgmt_start
    r '(setsid sh -c "flock /var/run/nym-firewall/lock sleep 60" </dev/null >/dev/null 2>&1 &); sleep 1'
    applies0=$(r 'logread | grep -c "Applying firewall policy"')
    t0=$(epoch); r 'nym-vpnc disconnect >/dev/null 2>&1; sleep 2; nym-vpnc connect --wait >/dev/null 2>&1'
    took=$(( $(epoch) - t0 ))
    applies=$(( $(r 'logread | grep -c "Applying firewall policy"') - applies0 ))
    log "with the fw3 lock held by another process for 60s: disconnect+connect produced $applies policy applies in ${took}s (fw4 does not use the lock; a blocked apply would have waited for the holder)"
    log "race: 12 fw4 reloads while disconnect+connect runs"
    r 'nym-vpnc disconnect >/dev/null 2>&1; (setsid sh -c "nym-vpnc connect --wait" </dev/null >/dev/null 2>&1 &); for i in $(seq 1 12); do fw4 reload >/dev/null 2>&1; sleep 1; done'
    tp=$(wait_state 'Connected' 90); log "connected after ${tp}s: $(state)"
    r 'logread | grep -E "nym-vpn:" | tail -3 | cut -c1-140' | tee -a "$SCENARIO_LOG"
    probes; mgmt_stop; cap_stop; cap_summary s4
    st=$(state); reset_state
    if [ "$applies" -ge 2 ] && [ "$took" -lt 55 ] && echo "$st" | grep -q 'policy=yes boot=no' && ! leaked && mgmt_ok; then
        verdict PASS "fw4 policy changes unaffected by a held fw3 lock ($applies applies in ${took}s); 12 reloads during connect left policy=yes boot=no, connected in ${tp}s, no leak"
    else
        verdict FAIL "applies=$applies took=${took}s state=[$st] leaked=$(leaked && echo yes || echo no) mgmt=$(mgmt_ok && echo ok || echo dropped)"
    fi
}

s5() {
    scenario_begin s5-untrusted-runtime-dir "runtime dir mode 0755: stop must not write the marker, reload must block, restoring the mode must recover"
    cap_start s5; mgmt_start
    r 'chmod 0755 /var/run/nym-firewall; /etc/init.d/nym-vpnd stop >/dev/null 2>&1'; sleep 3
    log "after stop with untrusted dir: $(state)"
    r 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-150' | tee -a "$SCENARIO_LOG"
    r '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    blocked_state=$(state); log "after firewall reload: $blocked_state"
    r 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-170' | tee -a "$SCENARIO_LOG"
    probes
    log "recover: chmod 0700, start"
    t0=$(epoch); r 'chmod 0700 /var/run/nym-firewall; /etc/init.d/nym-vpnd start'
    tp=$(wait_state 'policy=yes boot=no .*vpnd=[0-9]' 60); log "protection by the daemon after ${tp}s: $(state)"
    mgmt_stop; cap_stop; cap_summary s5
    reset_state
    if echo "$blocked_state" | grep -q 'boot=yes marker=no' && ! leaked && mgmt_ok; then
        verdict PASS "stop wrote no marker into an untrusted dir, reload installed the boot block with a logged reason, ssh/LuCI stayed up, chmod+start recovered in ${tp}s. Caveat: while the dir is untrusted, 'stop' cannot open the router; the fix is the mode."
    else
        verdict FAIL "blocked_state=[$blocked_state] leaked=$(leaked && echo yes || echo no) mgmt=$(mgmt_ok && echo ok || echo dropped)"
    fi
}

s6() {
    scenario_begin s6-killswitch-toggle "disconnected: kill-switch off + reload must open; on + reload must re-arm"
    cap_start s6; mgmt_start
    r 'nym-vpnc disconnect >/dev/null 2>&1'; sleep 3
    r 'nym-vpnc tunnel set --killswitch off >/dev/null 2>&1'; sleep 3
    off_state=$(state); log "ks off: $off_state"
    r '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    off_reload=$(state); log "ks off + reload: $off_reload"
    r 'logread | grep -E "nym-vpn:" | tail -2 | cut -c1-150' | tee -a "$SCENARIO_LOG"
    off_probe=$(lan_probe); log "$off_probe (expected open: administrator turned the kill-switch off)"
    r 'nym-vpnc tunnel set --killswitch on >/dev/null 2>&1'; sleep 3
    on_state=$(state); log "ks on: $on_state"
    r '/etc/init.d/firewall reload >/dev/null 2>&1'; sleep 3
    on_reload=$(state); log "ks on + reload: $on_reload"
    on_probe=$(lan_probe); log "$on_probe"
    mgmt_stop; cap_stop; cap_summary s6
    reset_state
    if echo "$off_reload" | grep -q 'policy=no boot=no' && echo "$off_probe" | grep -q 'LEAK' && echo "$on_reload" | grep -q 'policy=yes' && echo "$on_probe" | grep -q 'blocked' && mgmt_ok; then
        verdict PASS "off opened (no policy, no boot block, LAN egress on the real address) and stayed open across a reload; on re-armed Blocked and stayed armed across a reload"
    else
        verdict FAIL "off=[$off_reload] off_probe=[$off_probe] on=[$on_reload] on_probe=[$on_probe]"
    fi
}

s7() {
    scenario_begin s7-wan-flap "WAN link down 15 s while connected"
    cap_start s7; mgmt_start
    t0=$(epoch); h "ip link set $WAN_IF down"; log "WAN down"
    sleep 6; log "t+6s: $(state)"; log "$(lan_probe)"
    sleep 9; h "ip link set $WAN_IF up"; log "WAN up after 15s"
    tp=$(wait_state 'Connected' 120); log "reconnected ${tp}s after link up, $(( $(epoch) - t0 ))s after the flap began: $(state)"
    r 'logread | grep -E "Offline|offline|reconnect|nym-vpn:" | tail -4 | cut -c1-140' | tee -a "$SCENARIO_LOG"
    probes; mgmt_stop; cap_stop; cap_summary s7
    st=$(state); reset_state
    if echo "$st" | grep -q 'Connected' && ! leaked; then
        verdict PASS "no leak across the flap, reconnected ${tp}s after link up (the held ssh session dropping while the WAN link itself was down is expected)"
    else
        verdict FAIL "state=[$st] leaked=$(leaked && echo yes || echo no) reconnect=$tp"
    fi
}

s8() {
    # S8_VERSION must be newer than the installed package or apk runs no
    # post-upgrade step at all.
    local v=${S8_VERSION:-1.34.0_p13} apk
    apk="/tmp/nym-vpn_${v}_x86_64.apk"
    scenario_begin s8-upgrade-interrupted "kill -9 apk during the $v upgrade's post-upgrade step"
    if ! r "ls $apk" >/dev/null; then
        log "building $v on $LAN"; l "cd ~/nym-review && ./scripts/apk/build-apk.sh $v x86_64 nym-vpn-core/target/x86_64-unknown-linux-musl/release luci-app-nym-vpn out >/dev/null 2>&1; ls out/*${v}*"
        l "cat ~/nym-review/out/nym-vpn_${v}_x86_64.apk" | r "cat > $apk"
    fi
    cap_start s8; mgmt_start
    t0=$(epoch)
    # Kill apk once its post-upgrade script (our postinst) is running: that is
    # the window where the old daemon is being replaced by the new one.
    r '(setsid sh -c "apk add --allow-untrusted '"$apk"' > /tmp/apk-run.log 2>&1" </dev/null >/dev/null 2>&1 &); i=0; while [ $i -lt 30 ]; do ps w | grep -qE "[.]post-upgrade|nym-vpnd [r]estart" && break; sleep 1; i=$((i+1)); done; echo "at kill (${i}s): $(ps w | grep -E "[a]pk add|post-upgrade|nym-vpnd (restart|start|stop)" | grep -v "grep" | awk "{\$1=\$2=\$3=\$4=\"\"; print}" | cut -c1-80 | tr "\n" ";")"; kill -9 $(pidof apk) 2>/dev/null && echo "apk killed" || echo "apk already gone"' | tee -a "$SCENARIO_LOG"
    sleep 8
    log "after kill: $(state)"
    log "apk view: $(r 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"; echo "audit_nym_lines=$(apk audit 2>/dev/null | grep -c nym)"' | tr '\n' ' ')"
    r 'tail -3 /tmp/apk-run.log 2>/dev/null | cut -c1-120' | tee -a "$SCENARIO_LOG"
    probes
    log "recover: re-run the same apk add (apk fix only re-checks the recorded version)"
    t1=$(epoch); r 'apk add --allow-untrusted '"$apk"' >/tmp/apk-fix.log 2>&1; tail -2 /tmp/apk-fix.log | cut -c1-120; echo "audit_nym_lines_after=$(apk audit 2>/dev/null | grep -c nym)"' | tee -a "$SCENARIO_LOG"
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); log "daemon with policy after recovery in ${tp}s (+$(( $(epoch) - t1 ))s apk): $(state) installed=$(r 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"')"
    mgmt_stop; cap_stop; cap_summary s8
    reset_state
    if ! leaked && mgmt_ok && state | grep -q 'policy=yes'; then
        verdict PASS "no leak while apk was killed mid-upgrade, ssh survived, apk fix/re-add restored a working daemon"
    else
        verdict FAIL "leaked=$(leaked && echo yes || echo no) mgmt=$(mgmt_ok && echo ok || echo dropped) state=[$(state)]"
    fi
}
