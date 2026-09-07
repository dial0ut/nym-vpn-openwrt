# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# Reboot under capture. Expect: during shutdown the kill-switch stays armed
# (keep path for action=shutdown), on the way up the boot-time block is
# installed at firewall start and lifted by the daemon's first policy, and
# nothing but DHCP leaves before that. The router-side watcher does not
# survive the reboot; the LAN probe and the WAN capture do.
scenario_wait=85
scenario_inject() {
    rt 'echo "reboot at $(date +%T)"; reboot' 2>/dev/null
    echo "reboot issued"
}
scenario_check() {
    local i=0 out
    until rt true 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 12 ] && break
        sleep 5
    done
    out=$(rt 'echo "back, uptime $(cut -d. -f1 /proc/uptime)s"
        logread | grep -E "nym-vpn:" | head -4 | cut -c1-120
        iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && echo "policy hooked" || echo "policy NOT hooked"
        echo "emergency chains: $(iptables -w -S | grep -c NYM_EMERGENCY)"; ls -ld /var/run/nym-firewall; ls /var/run/nym-firewall/
        mkdir -p /tmp/leak')
    printf '%s\n' "$out"
    if [ "$(printf '%s\n' "$out" | grep -c '^policy hooked')" -gt 0 ]; then
        note "boot block installed then lifted; policy hooked after boot"
    else
        note "policy NOT hooked after boot"
    fi
    push_watcher
}
