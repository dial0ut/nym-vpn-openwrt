#!/bin/bash
# Shared helpers for the packet-level kill-switch failure-injection suite.
# Runs from a dev machine; talks to the Proxmox host (capture point), the fw3
# router VM (injection target) and the LAN client container (probe source).
# The remote sides are busybox ash (router, no setsid/nohup/timeout/stat) and
# Alpine busybox (client).

LEAK_PROXMOX=${LEAK_PROXMOX:-proxmox}
# shellcheck disable=SC2206  # word-split on purpose: a command line
LEAK_ROUTER_SSH=(${LEAK_ROUTER_SSH:-ssh -o ConnectTimeout=40 -o BatchMode=yes -i $HOME/.ssh/id_ed25519 root@192.168.1.180})
LEAK_ROUTER_WAN_IP=${LEAK_ROUTER_WAN_IP:-192.168.1.180}
LEAK_ROUTER_LAN_IP=${LEAK_ROUTER_LAN_IP:-10.30.30.1}
LEAK_UPSTREAM_DNS=${LEAK_UPSTREAM_DNS:-192.168.1.1}
LEAK_TAP=${LEAK_TAP:-tap902i1}
LEAK_CT=${LEAK_CT:-903}
LEAK_VMID=${LEAK_VMID:-902}
LEAK_HOST_DIR=/tmp/leak-suite
# Hosts the daemon itself is allowed to reach while the kill-switch is on
# (its Blocked/Connected policies open uid-0 hatches for them): API and
# cover domains, DNS-over-TLS/HTTPS resolvers. Anything else from the
# router's WAN address is "unattributed" and always reported.
LEAK_DAEMON_HOSTS=${LEAK_DAEMON_HOSTS:-"76.76.21.21 92.39.63.14 9.9.9.9 149.112.112.112 1.1.1.1 1.0.0.1"}
LEAK_DAEMON_NETS=${LEAK_DAEMON_NETS:-"151.101.0.0/16"}

# ssh exits 255 only when the connection itself failed (the command never
# ran), so retrying is safe for every command the suite issues; the Proxmox
# host's uplink has been seen to stall for tens of seconds under load.
_retry_ssh() {
    local n=0 rc
    while :; do
        "$@"
        rc=$?
        [ "$rc" -ne 255 ] && return "$rc"
        n=$((n + 1))
        [ "$n" -ge 4 ] && return 255
        sleep 8
    done
}
rt() { _retry_ssh "${LEAK_ROUTER_SSH[@]}" "$@"; }
px() { _retry_ssh ssh -o ConnectTimeout=40 -o BatchMode=yes "$LEAK_PROXMOX" "$@"; }
ct() { px "pct exec $LEAK_CT -- sh -c $(printf %q "$1")"; }

log() { printf '%s %s\n' "$(date +%T)" "$*" | tee -a "${SCENARIO_LOG:-/dev/null}"; }

# ---- bed control -------------------------------------------------------------
bed_up() {
    px "qm status $LEAK_VMID | grep -q running || qm start $LEAK_VMID; pct status $LEAK_CT | grep -q running || pct start $LEAK_CT; mkdir -p $LEAK_HOST_DIR" >/dev/null
    local i=0
    until rt true 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 24 ] && { echo "router not reachable"; return 1; }
        sleep 5
    done
    rt 'mkdir -p /tmp/leak' >/dev/null
    # Operator address: whatever ssh'd in, so its own packets are not counted.
    LEAK_OPERATOR_IP=$(rt 'echo ${SSH_CLIENT%% *}')
    # Probe target pinned to an address so the LAN client's SYN is attempted
    # even when its DNS is blocked (curl --resolve).
    LEAK_PROBE_HOST=ifconfig.me
    LEAK_PROBE_IP=$(ct "dig +short +time=2 +tries=1 $LEAK_PROBE_HOST @$LEAK_UPSTREAM_DNS 2>/dev/null | grep -E '^[0-9.]+$' | head -1")
    [ -n "$LEAK_PROBE_IP" ] || LEAK_PROBE_IP=$(dig +short "$LEAK_PROBE_HOST" | grep -E '^[0-9.]+$' | head -1)
    export LEAK_OPERATOR_IP LEAK_PROBE_IP LEAK_PROBE_HOST
    push_probe
    push_watcher
}
bed_down() {
    rt 'rm -rf /tmp/leak' 2>/dev/null
    px "qm shutdown $LEAK_VMID --timeout 60 >/dev/null 2>&1 || qm stop $LEAK_VMID; pct stop $LEAK_CT 2>/dev/null; true"
}

# ---- LAN client probe ----------------------------------------------------------
push_probe() {
    px "cat > $LEAK_HOST_DIR/probe.sh" <<'P'
#!/bin/sh
# probe.sh <log> <probe_host> <probe_ip> <router_lan_ip> <upstream_dns>
OUT=$1; H=$2; IP=$3; GW=$4; UP=$5; : > "$OUT"; echo $$ > /tmp/probe.pid
while :; do
  ts=$(date +%T)
  e=$(curl -s -m2 --resolve "$H:443:$IP" "https://$H" 2>/dev/null); [ -n "$e" ] || e=blocked
  r=$(dig +time=1 +tries=1 +short @"$GW" example.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1); [ -n "$r" ] && r=ok || r=fail
  d=$(dig +time=1 +tries=1 @"$UP" example.com 2>&1); case "$d" in *NOERROR*) d=ok;; *refused*|*REFUSED*) d=refused;; *) d=fail;; esac
  echo "$ts egress=$e dns_router=$r dns_upstream=$d" >> "$OUT"
  sleep 1
done
P
    px "pct push $LEAK_CT $LEAK_HOST_DIR/probe.sh /tmp/probe.sh --perms 755" >/dev/null
}
probe_start() { ct "(nohup /tmp/probe.sh /tmp/probe.log $LEAK_PROBE_HOST $LEAK_PROBE_IP $LEAK_ROUTER_LAN_IP $LEAK_UPSTREAM_DNS </dev/null >/dev/null 2>&1 &)"; }
probe_stop() { ct 'kill $(cat /tmp/probe.pid) 2>/dev/null; cat /tmp/probe.log'; }

# ---- router state watcher ------------------------------------------------------
push_watcher() {
    rt 'cat > /tmp/leak/watch.sh' <<'W'
#!/bin/sh
OUT=$1; : > "$OUT"; echo $$ > /tmp/leak/watch.pid
while :; do
  ts=$(date +%T)
  iptables -w -C output_rule -j NYM_OUTPUT 2>/dev/null && p=hooked || p=unhooked
  iptables -w -S NYM_EMERGENCY_OUT >/dev/null 2>&1 && e=emergency || e=-
  [ -f /var/run/nym-firewall/transition ] && t=transition || t=-
  [ -f /var/run/nym-firewall/stopped ] && m=stopped || m=-
  pid=$(pidof nym-vpnd | tr ' ' ','); [ -n "$pid" ] || pid=none
  st=$(nym-vpnc status 2>/dev/null | sed -n 's/^State: \([A-Za-z]*\).*/\1/p' | head -1); [ -n "$st" ] || st=noreply
  echo "$ts $p $e $t $m vpnd=$pid state=$st" >> "$OUT"
  sleep 1
done
W
    rt 'chmod +x /tmp/leak/watch.sh'
}
watch_start() { rt '( trap "" HUP; /tmp/leak/watch.sh /tmp/leak/watch.log </dev/null >/dev/null 2>&1 & )'; }
watch_stop() { rt 'kill $(cat /tmp/leak/watch.pid) 2>/dev/null; cat /tmp/leak/watch.log'; }

# ---- WAN capture on the host ---------------------------------------------------
cap_start() {
    CAP_PID=$(px "nohup tcpdump -ni $LEAK_TAP -w $LEAK_HOST_DIR/$1.pcap </dev/null >/dev/null 2>&1 & echo \$!")
    sleep 1
}
cap_stop() { px "kill $CAP_PID 2>/dev/null; sleep 1"; }
cap_fetch() { px "cat $LEAK_HOST_DIR/$1.pcap" > "$2"; }

# ---- gateway addresses from the daemon -----------------------------------------
learn_gateways() {
    local st
    st=$(rt 'nym-vpnc status 2>/dev/null | head -1')
    LEAK_ENTRY=$(printf '%s' "$st" | sed -n 's/.*wg to \([0-9.]*\):.*/\1/p')
    LEAK_EXIT=$(printf '%s' "$st" | sed -n 's/.*→ \([0-9.]*\):.*/\1/p')
    # Keep the last known pair when the tunnel is down, so post-disconnect
    # WireGuard tail packets are still attributed.
    [ -n "$LEAK_ENTRY" ] && LEAK_LAST_ENTRY=$LEAK_ENTRY
    [ -n "$LEAK_EXIT" ] && LEAK_LAST_EXIT=$LEAK_EXIT
    export LEAK_ENTRY LEAK_EXIT LEAK_LAST_ENTRY LEAK_LAST_EXIT
}

# ---- analysis ------------------------------------------------------------------
# analyze <name>: sets LEAK_SYN LEAK_DNS UNATTRIBUTED UNATTRIBUTED_LIST TOTAL
analyze() {
    local name=$1 allow="" h
    for h in $LEAK_ENTRY $LEAK_EXIT ${LEAK_LAST_ENTRY:-} ${LEAK_LAST_EXIT:-} $LEAK_DAEMON_HOSTS $LEAK_OPERATOR_IP; do
        [ -n "$h" ] && allow="$allow and not host $h"
    done
    for h in $LEAK_DAEMON_NETS; do allow="$allow and not net $h"; done
    local base="src host $LEAK_ROUTER_WAN_IP and (tcp or udp) and not port 67 and not port 68 and not port 123 and not port 853"
    LEAK_SYN=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 'src host $LEAK_ROUTER_WAN_IP and dst host $LEAK_PROBE_IP and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' 2>/dev/null | wc -l" | tr -d ' ')
    LEAK_DNS=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 'src host $LEAK_ROUTER_WAN_IP and udp dst port 53' 2>/dev/null | wc -l" | tr -d ' ')
    UNATTRIBUTED_LIST=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap '$base $allow' 2>/dev/null | sed -nE 's/.* > ([0-9.]+)\.([0-9]+):.*/\1:\2/p' | sort | uniq -c | sort -rn | head -10")
    UNATTRIBUTED=$(printf '%s\n' "$UNATTRIBUTED_LIST" | awk '{s+=$1} END{print s+0}')
    TOTAL=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 2>/dev/null | wc -l" | tr -d ' ')
    export LEAK_SYN LEAK_DNS UNATTRIBUTED UNATTRIBUTED_LIST TOTAL
}
