# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Interrupted upgrade: opkg is SIGKILLed together with the post-upgrade
# script the moment that script starts, i.e. after the new files are unpacked
# and before post-upgrade has done its work (opkg writes files in place and
# only marks the status entry at the very end, so the script appearing is the
# usable signal; opkg runs it as `sh -c "... /usr/lib/opkg/info/nym-vpn.postinst configure"`,
# and the [.] in the pattern keeps it from matching this ssh session's own
# command line, which carries the pattern text). prerm leaves the old daemon
# running on upgrade, so expect: no leak, the old daemon still up with its
# policy hooked, and a recovery that completes. Observed on 21.02: opkg has
# not touched its status entry at that point (it still reads the OLD version,
# "installed"), so `opkg configure` is a no-op; the recovery that works is to
# re-run the install, which the running daemon survives with the kill-switch
# armed. The check tries configure first and falls back to the re-install.
# Needs an ipk with a version higher than the installed one at
# $LEAK_UPGRADE_IPK on the router (default /tmp/nym-vpn_1.34.0_p15_x86_64.ipk).
# Never downgrade to set this up: a downgrade runs prerm's removal branch,
# which deletes /etc/nym and with it the account.
scenario_wait=15
LEAK_UPGRADE_IPK=${LEAK_UPGRADE_IPK:-/tmp/nym-vpn_1.34.0_p15_x86_64.ipk}
scenario_pre() {
    if ! rt "ls $LEAK_UPGRADE_IPK >/dev/null 2>&1"; then
        skip "no $LEAK_UPGRADE_IPK on the router (build one with scripts/ipk/build-ipk.sh from the same binaries, version above the installed one)"
        return 1
    fi
    rt 'echo "installed before: $(opkg list-installed | grep ^nym-vpn) pid=$(pidof nym-vpnd)"'
}
scenario_inject() {
    rt "end=\$(( \$(date +%s) + 90 )); hit=none
        opkg install $LEAK_UPGRADE_IPK >/tmp/leak/opkg.log 2>&1 &
        P=\$!
        while [ \"\$(date +%s)\" -lt \"\$end\" ]; do
            pi=\$(pgrep -f 'opkg/info/nym-vpn[.]postinst' | head -1)
            if [ -n \"\$pi\" ]; then hit=postinst-started; kill -9 \$P \$pi 2>/dev/null; break; fi
            kill -0 \$P 2>/dev/null || { hit=opkg-finished-first; break; }
        done
        kill -9 \$P 2>/dev/null; echo \"opkg SIGKILLed at \$(date +%T); trigger=\$hit\"
        sleep 1; echo 'opkg log:'; sed 's/^/  /' /tmp/leak/opkg.log | head -4
        echo 'status entry:'; awk '/^Package: nym-vpn\$/,/^\$/' /usr/lib/opkg/status | grep -E '^(Version|Status)'
        echo \"on-disk control: \$(grep ^Version /usr/lib/opkg/info/nym-vpn.control); pid still: \$(pidof nym-vpnd)\""
}
scenario_check() {
    local out
    out=$(rt "echo '-- after interruption:'; echo \"pid: \$(pidof nym-vpnd)\"; nym-vpnc status 2>&1 | head -1 | cut -c1-60
        iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && echo 'policy hooked' || echo 'policy NOT hooked'
        want=\$(grep ^Version /usr/lib/opkg/info/nym-vpn.control | cut -d' ' -f2)
        echo '-- recovery 1: opkg configure nym-vpn'; opkg configure nym-vpn 2>&1 | tail -2
        have=\$(opkg list-installed | sed -n 's/^nym-vpn - //p')
        if [ \"\$have\" != \"\$want\" ]; then
            echo \"status still says \$have (files are \$want): configure was a no-op\"
            echo '-- recovery 2: re-run the install'; opkg install $LEAK_UPGRADE_IPK 2>&1 | grep -E '^(Upgrading|Configuring)'; sleep 10
        fi
        echo \"installed: \$(opkg list-installed | grep ^nym-vpn)\"; echo \"pid: \$(pidof nym-vpnd)\"
        iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && echo 'recovered: policy hooked' || echo 'NOT recovered'
        logread | grep -E 'leaving the kill-switch armed' | tail -1 | cut -c1-90")
    printf '%s\n' "$out"
    if [ "$(printf '%s\n' "$out" | grep -c '^recovered: policy hooked')" -gt 0 ]; then
        if [ "$(printf '%s\n' "$out" | grep -c 'recovery 2')" -gt 0 ]; then
            note "old daemon kept running through the interruption; opkg configure was a no-op (status still old version); re-running the install completed it with the kill-switch armed"
        else
            note "recovered via opkg configure"
        fi
    else
        note "recovery did NOT complete"
    fi
}
