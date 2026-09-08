# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Interrupted upgrade on an apk router (OpenWrt 25.x): apk is SIGKILLed the
# moment its post-upgrade step (our postinst) is running, the window in
# which the old daemon is being replaced. Expect: no leak, ssh survives, the
# policy never leaves, and re-running the same `apk add` completes the
# upgrade (apk fix only re-checks the recorded version). Needs a package
# with a version higher than the installed one at $LEAK_UPGRADE_APK on the
# router, or apk runs no post-upgrade step at all. Never downgrade to set
# this up: a downgrade runs prerm's removal branch, which deletes /etc/nym.
# The opkg counterpart is 08-interrupted-upgrade.
scenario_mgmt=1
scenario_wait=8
LEAK_UPGRADE_APK=${LEAK_UPGRADE_APK:-/tmp/nym-vpn_1.34.0_p14_x86_64.apk}
scenario_pre() {
    if ! rt 'command -v apk >/dev/null 2>&1'; then
        skip "router has no apk (opkg router: see 08-interrupted-upgrade)"
        return 1
    fi
    if ! rt "ls $LEAK_UPGRADE_APK >/dev/null 2>&1"; then
        skip "no $LEAK_UPGRADE_APK on the router (build one with scripts/apk/build-apk.sh from the same binaries, version above the installed one)"
        return 1
    fi
    rt 'echo "installed before: $(apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*") pid=$(pidof nym-vpnd)"'
}
scenario_inject() {
    rt "(setsid sh -c 'apk add --allow-untrusted $LEAK_UPGRADE_APK > /tmp/leak/apk-run.log 2>&1' </dev/null >/dev/null 2>&1 &)
        i=0; while [ \$i -lt 30 ]; do ps w | grep -qE '[.]post-upgrade|nym-vpnd [r]estart' && break; sleep 1; i=\$((i+1)); done
        echo \"at kill (\${i}s): \$(ps w | grep -E '[a]pk add|post-upgrade|nym-vpnd (restart|start|stop)' | grep -v grep | awk '{\$1=\$2=\$3=\$4=\"\"; print}' | cut -c1-80 | tr '\n' ';')\"
        kill -9 \$(pidof apk) 2>/dev/null && echo 'apk killed' || echo 'apk already gone'"
}
scenario_check() {
    local tp st
    log "after kill: $(state)"
    log "apk view: $(rt 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"; echo "audit_nym_lines=$(apk audit 2>/dev/null | grep -c nym)"' | tr '\n' ' ')"
    rt 'tail -3 /tmp/leak/apk-run.log 2>/dev/null | cut -c1-120'
    probes
    log "recover: re-run the same apk add"
    rt "apk add --allow-untrusted $LEAK_UPGRADE_APK >/tmp/leak/apk-fix.log 2>&1; tail -2 /tmp/leak/apk-fix.log | cut -c1-120; echo \"audit_nym_lines_after=\$(apk audit 2>/dev/null | grep -c nym)\""
    tp=$(wait_state 'policy=yes .*vpnd=[0-9]' 60); st=$(state)
    log "daemon with policy after recovery in ${tp}s: $st installed=$(rt 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"')"
    if printf '%s' "$st" | grep -qE 'policy=yes .*vpnd=[0-9]'; then
        recovered "policy never left; re-running apk add restored a working daemon in ${tp}s"
    else
        not_recovered "after re-running apk add: $st"
    fi
}
scenario_post() { reset_state; }
