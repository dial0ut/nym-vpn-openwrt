# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Rule application failure (fw3): iptables-restore is replaced by a script
# that exits 1, then a policy change is requested (IPv6 toggle: it re-applies
# the whole fw3 policy). Expect: fail-closed (the previous rules stay, the
# daemon reports the failure), no leak, and RECOVERY once the real binary is
# back and the setting is toggled back.
scenario_wait=15
scenario_pre() {
    if [ "$LEAK_FW" != fw3 ]; then
        skip "fw3-only: replaces iptables-restore (the fw4 backend applies with nft -f)"
        return 1
    fi
    rt 'cp -a /usr/sbin/iptables-restore /tmp/leak/iptables-restore.bak && rm -f /usr/sbin/iptables-restore
        printf "#!/bin/sh\necho iptables-restore: injected failure >&2\nexit 1\n" > /usr/sbin/iptables-restore && chmod 755 /usr/sbin/iptables-restore
        echo "iptables-restore replaced ($(readlink /tmp/leak/iptables-restore.bak 2>/dev/null || echo regular file) backed up)"'
}
scenario_inject() {
    local out
    out=$(rt 'nym-vpnc tunnel set --ipv6 on 2>&1 && echo "SET_OK at $(date +%T)" || echo "SET_FAILED"')
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -q SET_OK || inconclusive "injection failed: tunnel set did not succeed"
}
scenario_check() {
    local st
    echo "-- while broken:"
    st=$(state); echo "$st"
    printf '%s' "$st" | grep -q 'policy=yes' || not_recovered "previous rules not kept while the apply failed: $st"
    rt 'logread | grep -iE "nym-vpn:|injected failure|SetFirewallPolicy|Failed to (set|apply) firewall|error state" | tail -4 | cut -c1-170'
    echo "-- restore binary, toggle back:"
    rt 'rm -f /usr/sbin/iptables-restore; cp -a /tmp/leak/iptables-restore.bak /usr/sbin/iptables-restore
        nym-vpnc tunnel set --ipv6 off 2>&1 | tail -1; sleep 6
        logread | grep -E "Applying firewall policy" | tail -1 | cut -c1-120'
    st=$(state); echo "$st"
    if printf '%s' "$st" | grep -q 'policy=yes'; then
        recovered "policy re-applied after the binary was restored and the setting toggled back"
    else
        not_recovered "after restore + re-apply: $st"
    fi
}
scenario_post() {
    rt 'if [ -e /usr/sbin/iptables-restore ] && iptables-restore --version >/dev/null 2>&1; then :; else cp -a /tmp/leak/iptables-restore.bak /usr/sbin/iptables-restore; fi
        nym-vpnc tunnel get | grep -q "^IPv6: off" || nym-vpnc tunnel set --ipv6 off >/dev/null 2>&1
        echo "iptables-restore: $(readlink -f /usr/sbin/iptables-restore); $(nym-vpnc tunnel get | grep ^IPv6)"'
}
