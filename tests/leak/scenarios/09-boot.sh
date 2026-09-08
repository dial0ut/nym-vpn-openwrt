# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Reboot under capture. Expect: during shutdown the kill-switch stays armed
# (keep path for action=shutdown), on the way up the boot-time block is
# installed at firewall start and lifted by the daemon's first policy, and
# nothing but DHCP leaves before that. The router-side watcher does not
# survive the reboot; the LAN probe and the WAN capture do. A container
# restart is not a router boot (no firewall-before-network ordering), so the
# scenario is skipped on an LXC bed.
scenario_wait=85
scenario_pre() {
    if [ -n "${LEAK_ROUTER_CT:-}" ]; then
        skip "router is an LXC; a container restart is not a router boot"
        return 1
    fi
}
scenario_inject() {
    rt 'echo "reboot at $(date +%T)"; reboot' 2>/dev/null
    echo "reboot issued"
}
scenario_check() {
    local i=0 st
    until rt true 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 12 ] && break
        sleep 5
    done
    rt 'echo "back, uptime $(cut -d. -f1 /proc/uptime)s"
        logread | grep -E "nym-vpn:" | head -4 | cut -c1-120
        ls -ld /var/run/nym-firewall; ls /var/run/nym-firewall/
        mkdir -p /tmp/leak'
    st=$(state); echo "$st"
    if printf '%s' "$st" | grep -qE 'policy=yes boot=no .*vpnd=[0-9]'; then
        recovered "boot block installed then lifted; policy hooked after boot"
    else
        not_recovered "after boot: $st"
    fi
    push_watcher
}
