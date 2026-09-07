# shellcheck shell=bash disable=SC2034  # sourced by run.sh; scenario_* vars are read there
# IPv6: only meaningful if the WAN has a global IPv6 address to leak through.
# Reports SKIP with the reason when the bed has none (a PASS here would be
# unearned).
scenario_wait=10
scenario_pre() {
    local v6
    v6=$(rt 'sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1; ip -6 addr show dev eth1 2>/dev/null | grep -E "inet6 (2|3)" | head -1')
    if [ -z "$v6" ]; then
        skip "no global IPv6 on the WAN (bed has no v6 upstream); v6 path not exercised"
        return 1
    fi
    echo "WAN v6: $v6"
}
scenario_inject() {
    rt 'echo "probing v6 from the router itself:"; wget -6 -qO- -T 5 https://api64.ipify.org 2>&1 | head -1 || echo blocked'
    ct 'curl -6 -s -m5 https://api64.ipify.org || echo "v6 blocked from LAN"'
}
