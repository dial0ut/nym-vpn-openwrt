#!/bin/bash
# Shared helpers for the recovery-evidence suite. Runs on a dev machine that
# can ssh to the router (ROUTER), its LAN client (LAN) and the hypervisor
# (HOST) that owns the router's WAN interface (WAN_IF) for packet capture.
#
# Every scenario records: a WAN capture, LAN-client and router probes, an
# SSH session held open across the failure (management access), a LuCI TCP
# connect test, and wall-clock times for "protection re-established" and
# "service usable". Verdicts go to results/verdicts.log.
set -uo pipefail

ROUTER=${ROUTER:-openwrt25}
LAN=${LAN:-ubuntu-vm}
HOST=${HOST:-proxmox}
WAN_IF=${WAN_IF:-veth425i0}
WAN_IP=${WAN_IP:-192.168.1.252}
LAN_GW=${LAN_GW:-10.10.10.1}
# The ISP address behind the upstream router: a LAN or router probe that
# reports it has left the box outside the tunnel.
REAL_PUBLIC_IP=${REAL_PUBLIC_IP:-203.0.113.1}
# ifconfig.me, the LAN probe's target; its address in a capture is a leak.
PROBE_TARGET_IP=${PROBE_TARGET_IP:-34.160.111.145}
CAP_DIR=${CAP_DIR:-/tmp/recovery-caps}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$HERE/results"
mkdir -p "$RESULTS"
SCENARIO_LOG="$RESULTS/setup.log"

ts() { date +%H:%M:%S; }
epoch() { date +%s; }
log() { echo "[$(ts)] $*" | tee -a "$SCENARIO_LOG"; }
# ServerAlive so a command caught by a WAN outage fails instead of hanging the run.
SSH_OPTS=(-o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=5 -o ServerAliveCountMax=4)
# SSH_JUMP=<host>: reach the router (and the LAN client behind it) through a
# jump host on the router's WAN segment when the dev machine's own path to
# that segment is unreliable. The hypervisor is the natural choice.
SSH_JUMP=${SSH_JUMP:-}
r() { ssh "${SSH_OPTS[@]}" ${SSH_JUMP:+-o ProxyJump="$SSH_JUMP"} "$ROUTER" "$@" 2>/dev/null; }
l() { ssh "${SSH_OPTS[@]}" ${SSH_JUMP:+-o ProxyJump="$SSH_JUMP,$ROUTER"} "$LAN" "$@" 2>/dev/null; }
h() { ssh "${SSH_OPTS[@]}" "$HOST" "$@" 2>/dev/null; }

scenario_begin() {
    SCENARIO="$1"
    SCENARIO_LOG="$RESULTS/$SCENARIO.log"
    : > "$SCENARIO_LOG"
    log "===== $SCENARIO: $2"
    ENTRY=$(r 'nym-vpnc status | head -1 | sed -n "s/.*wg to \([0-9.]*\):.*/\1/p"')
    log "state: $(state)"
}

# One line of router state.
state() {
    r 'printf "policy=%s boot=%s marker=%s vpnd=%s ks=%s %s" \
        "$(nft list table inet nym >/dev/null 2>&1 && echo yes || echo no)" \
        "$(nft list table inet nym_boot >/dev/null 2>&1 && echo yes || echo no)" \
        "$([ -f /var/run/nym-firewall/stopped ] && echo yes || echo no)" \
        "$(pidof nym-vpnd || echo none)" \
        "$(nym-vpnc tunnel get 2>/dev/null | sed -n "s/Kill-switch: //p")" \
        "$(nym-vpnc status 2>/dev/null | head -1 | cut -c1-24)"'
}

# ---- WAN capture on the hypervisor ----
cap_start() {
    h "mkdir -p $CAP_DIR; (setsid tcpdump -ni $WAN_IF -w $CAP_DIR/$1.pcap </dev/null >/dev/null 2>&1 &); sleep 1; pgrep -f '^tcpdump -ni $WAN_IF' >/dev/null && echo capture-running || echo CAPTURE-FAILED" | tee -a "$SCENARIO_LOG"
}
cap_stop() {
    h "for p in \$(pgrep -f '^tcpdump -ni $WAN_IF'); do kill \$p; done; sleep 1" >/dev/null
}
# Summary of router-originated egress. The WG entry and the daemon's own
# bootstrap destinations are expected; everything else is listed so a reader
# can judge it. Upstream DNS and packets to the probe target are the two
# signatures the LAN probes would leave if the kill-switch were open.
cap_summary() {
    local name=$1 entry=${ENTRY:-none}
    h "cd $CAP_DIR && echo \"pcap $name: total=\$(tcpdump -nr $name.pcap 2>/dev/null | wc -l) upstream_dns=\$(tcpdump -nr $name.pcap 'src host $WAN_IP and udp dst port 53' 2>/dev/null | wc -l) to_probe_target=\$(tcpdump -nr $name.pcap 'src host $WAN_IP and dst host $PROBE_TARGET_IP' 2>/dev/null | wc -l)\"; echo '  egress by destination (excluding WG entry, DHCP, ssh replies):'; tcpdump -nr $name.pcap 'src host $WAN_IP and (tcp or udp) and not port 67 and not port 68 and not host $entry and not udp port 51822 and not tcp src port 22' 2>/dev/null | sed -nE 's/.* > ([0-9.]+)\.([0-9]+):.*/\1:\2/p' | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'" | tee -a "$SCENARIO_LOG"
}

# ---- management access: an SSH session held open across the scenario ----
# Two vantages: an ssh session held open from this machine, and a wired
# TCP-connect probe to the router's ssh port from the hypervisor, which sits
# on the same L2 segment. The dev machine may reach the segment over Wi-Fi
# through the upstream router, so a drop seen only here is a path problem,
# not the router's.
mgmt_start() {
    MGMT_LOG=$(mktemp)
    ssh -o ConnectTimeout=10 -o ServerAliveInterval=2 -o ServerAliveCountMax=3 ${SSH_JUMP:+-o ProxyJump="$SSH_JUMP"} "$ROUTER" 'while sleep 1; do echo alive; done' > "$MGMT_LOG" 2>/dev/null &
    MGMT_PID=$!
    MGMT_T0=$(epoch)
    h "rm -f /tmp/reach.log; (setsid sh -c 'for i in \$(seq 1 900); do nc -z -w1 $WAN_IP 22 >/dev/null 2>&1 && echo ok || echo down; sleep 1; done > /tmp/reach.log' </dev/null >/dev/null 2>&1 &)"
    sleep 2
}
mgmt_stop() {
    kill "$MGMT_PID" 2>/dev/null; wait "$MGMT_PID" 2>/dev/null
    local n elapsed wired
    n=$(grep -c alive "$MGMT_LOG"); elapsed=$(( $(epoch) - MGMT_T0 ))
    wired=$(h "for p in \$(pgrep -f 'nc -z -w1 $WAN_IP 22|for i in'); do kill \$p 2>/dev/null; done; sort /tmp/reach.log | uniq -c | awk '{printf \"%s=%s \", \$2, \$1}'")
    if [ "$n" -ge $((elapsed - 6)) ]; then
        log "management ssh held open over WAN: $n ticks in ${elapsed}s -> session survived; wired probe from hypervisor: ${wired:-n/a}"
    else
        log "management ssh held open over WAN: $n ticks in ${elapsed}s -> SESSION DROPPED (dev-machine vantage); wired probe from hypervisor: ${wired:-n/a}"
    fi
    rm -f "$MGMT_LOG"
}
# The wired vantage saw the router's ssh port reachable throughout.
wired_ok() { grep -q 'wired probe from hypervisor: ok=[0-9]* *$' "$SCENARIO_LOG" || grep -qE 'wired probe from hypervisor: (down=[0-3] )?ok=[0-9]+' "$SCENARIO_LOG"; }

# ---- probes ----
classify() {  # <ip> -> blocked | LEAK:ip | vpn:ip
    if [ -z "$1" ]; then echo blocked; elif [ "$1" = "$REAL_PUBLIC_IP" ]; then echo "LEAK:$1"; else echo "vpn:$1"; fi
}
lan_probe() {  # egress ip via HTTPS and DNS via the router, from the LAN client
    local ip d
    ip=$(l 'curl -s -m3 https://ifconfig.me' || true)
    d=$(l "dig +time=1 +tries=1 +short @$LAN_GW example.com 2>/dev/null | head -1" || true)
    echo "lan: http=$(classify "$ip") dns=${d:-fail}"
}
# Router-originated HTTPS only. A root DNS lookup from the router is let
# through by the daemon's own bootstrap hatch under Blocked (uid 0 covers
# every process on OpenWrt, a known design limit), so it is not a leak
# signature and would pollute the capture's upstream-DNS count.
router_probe() {
    local ip
    ip=$(r 'curl -s -m3 https://ifconfig.me' || true)
    echo "router: http=$(classify "$ip")"
}
luci_probe() {  # TCP connect to uhttpd/ssh from the LAN client and from here over the WAN
    local lan wan22 wan80
    lan=$(l "nc -z -w2 $LAN_GW 80 >/dev/null 2>&1 && echo ok || echo no" || echo unreachable)
    wan80=$(nc -z -w2 -G2 "$WAN_IP" 80 >/dev/null 2>&1 && echo ok || echo no)
    wan22=$(nc -z -w2 -G2 "$WAN_IP" 22 >/dev/null 2>&1 && echo ok || echo no)
    echo "luci: lan:80=$lan wan:80=$wan80 wan:22=$wan22"
}
probes() { log "$(lan_probe) | $(router_probe) | $(luci_probe)"; }

# Wait (max $2 s) until the state line matches grep pattern $1; prints seconds taken.
wait_state() {
    local pat=$1 max=${2:-90} t0; t0=$(epoch)
    while [ $(( $(epoch) - t0 )) -lt "$max" ]; do
        if state | grep -qE "$pat"; then echo $(( $(epoch) - t0 )); return 0; fi
        sleep 2
    done
    echo "timeout(${max}s)"; return 1
}

verdict() {  # verdict <PASS|FAIL|INCONCLUSIVE> <text>
    log "VERDICT $1: $2"
    printf '%s | %s | %s | %s\n' "$(date -u +%FT%TZ)" "$SCENARIO" "$1" "$2" >> "$RESULTS/verdicts.log"
}

# Return the router to the handover state: package as found, connected,
# kill-switch on, Stealth off, watchdog running, no stray marker.
reset_state() {
    # `connect --wait` on an already-connected daemon does not return, so
    # only connect when the status says otherwise.
    r 'rm -f /var/run/nym-firewall/stopped; chmod 0700 /var/run/nym-firewall 2>/dev/null; chmod 755 /usr/sbin/nym-vpnd 2>/dev/null; pidof nym-vpnd >/dev/null || /etc/init.d/nym-vpnd start; sleep 3; nym-vpnc tunnel set --killswitch on >/dev/null 2>&1; nym-vpnc tunnel set --stealth-api off >/dev/null 2>&1; nym-vpnc status | grep -q "^State: Connected" || nym-vpnc connect --wait >/dev/null 2>&1; pgrep -f "^/bin/sh /usr/sbin/nym-vpn-watchdog" >/dev/null || /etc/init.d/nym-vpn-watchdog start' >/dev/null
    log "reset: $(state)"
}
