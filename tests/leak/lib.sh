#!/bin/bash
# Shared helpers for the packet-level kill-switch evidence suite.
# Runs from a dev machine; talks to the Proxmox host (capture point), the
# router under test (injection target) and the LAN client (probe source).
# The remote sides are busybox ash (router, no setsid/nohup/timeout/stat) and
# Alpine busybox (client); the hypervisor is Debian with bash and coreutils.
#
# Bed parameters come from beds/<name>.env, sourced by run.sh before this
# file; they are LEAK_* variables with environment overrides. Nothing
# host-specific is defined here.

: "${LEAK_FW:?no bed loaded (run.sh sources beds/\$BED.env first)}"
LEAK_PROXMOX=${LEAK_PROXMOX:-proxmox}
LEAK_HOST_DIR=${LEAK_HOST_DIR:-/tmp/leak-suite}
LEAK_PROBE_HOST=${LEAK_PROBE_HOST:-ifconfig.me}
# Hosts the daemon itself is allowed to reach while the kill-switch is on
# (its Blocked/Connected policies open uid-0 hatches for them): API and
# cover domains, DNS-over-TLS/HTTPS resolvers. Anything else from the
# router's WAN address is "unattributed" and always reported.
LEAK_DAEMON_HOSTS=${LEAK_DAEMON_HOSTS:-"76.76.21.21 92.39.63.14 9.9.9.9 149.112.112.112 1.1.1.1 1.0.0.1"}
LEAK_DAEMON_NETS=${LEAK_DAEMON_NETS:-"151.101.0.0/16"}

# ---- remote command paths --------------------------------------------------------
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
px() { _retry_ssh ssh -o ConnectTimeout=40 -o BatchMode=yes "$LEAK_PROXMOX" "$@"; }

# _router_ssh_cmd [extra ssh options]: sets ROUTER_SSH, the ssh command line
# to the router without the host (bash 3.2 on macOS has no mapfile, so the
# array is a global rather than a printed list).
_router_ssh_cmd() {
    # shellcheck disable=SC2206  # word-split on purpose: ssh options
    ROUTER_SSH=(ssh -o ConnectTimeout=40 -o BatchMode=yes ${1:-})
    [ -n "${LEAK_SSH_JUMP:-}" ] && ROUTER_SSH+=(-o "ProxyJump=$LEAK_SSH_JUMP")
    # shellcheck disable=SC2206  # word-split on purpose: bed-specific options
    ROUTER_SSH+=(${LEAK_ROUTER_SSH_OPTS:-})
}
# rt <script>: run a shell snippet on the router. pct exec from the
# hypervisor when the bed has LEAK_ROUTER_CT (survives a WAN outage), ssh to
# LEAK_ROUTER_HOST otherwise.
rt() {
    if [ -n "${LEAK_ROUTER_CT:-}" ]; then
        px "pct exec $LEAK_ROUTER_CT -- sh -c $(printf %q "$*")"
    else
        _router_ssh_cmd
        _retry_ssh "${ROUTER_SSH[@]}" "$LEAK_ROUTER_HOST" "$@"
    fi
}
# ct <script>: run a shell snippet on the LAN client.
ct() {
    if [ -n "${LEAK_LAN_CT:-}" ]; then
        px "pct exec $LEAK_LAN_CT -- sh -c $(printf %q "$1")"
    else
        # shellcheck disable=SC2206  # word-split on purpose: a command line
        local -a cmd=(${LEAK_LAN_SSH:?bed has neither LEAK_LAN_CT nor LEAK_LAN_SSH})
        _retry_ssh "${cmd[@]}" "$1"
    fi
}
# ct_push <remote path>: install stdin as an executable file on the LAN client.
ct_push() {
    if [ -n "${LEAK_LAN_CT:-}" ]; then
        px "cat > $LEAK_HOST_DIR/$(basename "$1")" &&
            px "pct push $LEAK_LAN_CT $LEAK_HOST_DIR/$(basename "$1") $1 --perms 755" >/dev/null
    else
        ct "cat > $1 && chmod 755 $1"
    fi
}

log() { printf '%s %s\n' "$(date +%T)" "$*" | tee -a "${SCENARIO_LOG:-/dev/null}"; }
epoch() { date +%s; }

# ---- bed control -------------------------------------------------------------
bed_up() {
    local start="" i=0
    [ -n "${LEAK_VMID:-}" ] && start="qm status $LEAK_VMID | grep -q running || qm start $LEAK_VMID;"
    [ -n "${LEAK_ROUTER_CT:-}" ] && start="$start pct status $LEAK_ROUTER_CT | grep -q running || pct start $LEAK_ROUTER_CT;"
    [ -n "${LEAK_LAN_CT:-}" ] && start="$start pct status $LEAK_LAN_CT | grep -q running || pct start $LEAK_LAN_CT;"
    px "$start mkdir -p $LEAK_HOST_DIR; command -v tcpdump >/dev/null || echo 'tcpdump missing on the hypervisor'" || return 1
    until rt true 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 24 ] && { echo "router not reachable"; return 1; }
        sleep 5
    done
    rt 'mkdir -p /tmp/leak' >/dev/null
    # Operator address as the router sees it, so its own ssh packets are not
    # counted. Only known when the router is reachable over ssh.
    LEAK_OPERATOR_IP=""
    if [ -n "${LEAK_ROUTER_HOST:-}" ]; then
        _router_ssh_cmd
        LEAK_OPERATOR_IP=$("${ROUTER_SSH[@]}" "$LEAK_ROUTER_HOST" 'echo ${SSH_CLIENT%% *}' 2>/dev/null)
    fi
    # Probe target pinned to an address so the LAN client's SYN is attempted
    # even when its DNS is blocked (curl --resolve).
    LEAK_PROBE_IP=$(ct "dig +short +time=2 +tries=1 $LEAK_PROBE_HOST @$LEAK_UPSTREAM_DNS 2>/dev/null | grep -E '^[0-9.]+$' | head -1")
    [ -n "$LEAK_PROBE_IP" ] || LEAK_PROBE_IP=$(dig +short "$LEAK_PROBE_HOST" | grep -E '^[0-9.]+$' | head -1)
    [ -n "$LEAK_PROBE_IP" ] || { echo "cannot resolve $LEAK_PROBE_HOST"; return 1; }
    # The address a leak would show. The hypervisor sits behind the same
    # upstream NAT as the router's WAN, so its egress address is the one.
    if [ -z "${LEAK_REAL_PUBLIC_IP:-}" ]; then
        LEAK_REAL_PUBLIC_IP=$(px "curl -s -m5 https://$LEAK_PROBE_HOST 2>/dev/null || wget -qO- -T5 https://$LEAK_PROBE_HOST 2>/dev/null" | grep -E '^[0-9.]+$' | head -1)
        [ -n "$LEAK_REAL_PUBLIC_IP" ] || echo "could not learn the real egress address; LEAK: classification is off, the capture still gates"
    fi
    export LEAK_OPERATOR_IP LEAK_PROBE_IP LEAK_PROBE_HOST LEAK_REAL_PUBLIC_IP
    push_probe && push_watcher && push_reach
}
bed_down() {
    rt 'rm -rf /tmp/leak' 2>/dev/null
    local stop=""
    [ -n "${LEAK_VMID:-}" ] && stop="qm shutdown $LEAK_VMID --timeout 60 >/dev/null 2>&1 || qm stop $LEAK_VMID;"
    [ -n "${LEAK_ROUTER_CT:-}" ] && stop="$stop pct stop $LEAK_ROUTER_CT 2>/dev/null;"
    [ -n "${LEAK_LAN_CT:-}" ] && stop="$stop pct stop $LEAK_LAN_CT 2>/dev/null;"
    px "$stop true"
}

# ---- LAN client probe ----------------------------------------------------------
# One line per second (or once with `-` as the log): HTTPS egress to the
# pinned probe address, DNS through the router, DNS straight to the upstream
# resolver. The egress field is classified from curl's exit code, never from
# an empty body: 7/28 (refused, timed out) = blocked, 6 = dns-blocked, 0 with
# an address = LEAK:<ip> when it is the real egress address, egress:<ip>
# otherwise; everything else is probe-failed, which makes the scenario
# INCONCLUSIVE rather than passing as "blocked".
push_probe() {
    ct_push /tmp/probe.sh <<'P'
#!/bin/sh
# probe.sh <log|-> <probe_host> <probe_ip> <router_lan_ip> <upstream_dns> <real_public_ip>
OUT=$1; H=$2; IP=$3; GW=$4; UP=$5; REAL=$6
[ "$OUT" = - ] || { : > "$OUT"; echo $$ > /tmp/probe.pid; }
classify() {
  case "$1" in
    0) case "$2" in
         "") echo probe-failed:empty ;;
         "$REAL") echo "LEAK:$2" ;;
         *[!0-9.]*) echo probe-failed:body ;;
         *) echo "egress:$2" ;;
       esac ;;
    7|28) echo blocked ;;
    6) echo dns-blocked ;;
    *) echo "probe-failed:rc=$1" ;;
  esac
}
while :; do
  ts=$(date +%T)
  body=$(curl -s -m2 --resolve "$H:443:$IP" "https://$H" 2>/dev/null); rc=$?
  e=$(classify "$rc" "$body")
  r=$(dig +time=1 +tries=1 +short @"$GW" example.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1); [ -n "$r" ] && r=ok || r=fail
  d=$(dig +time=1 +tries=1 @"$UP" example.com 2>&1); case "$d" in *NOERROR*) d=ok;; *refused*|*REFUSED*) d=refused;; *) d=fail;; esac
  line="$ts egress=$e dns_router=$r dns_upstream=$d"
  if [ "$OUT" = - ]; then echo "$line"; exit 0; fi
  echo "$line" >> "$OUT"
  sleep 1
done
P
}
_probe_args() { printf '%s %s %s %s %q' "$LEAK_PROBE_HOST" "$LEAK_PROBE_IP" "$LEAK_ROUTER_LAN_IP" "$LEAK_UPSTREAM_DNS" "${LEAK_REAL_PUBLIC_IP:-}"; }
probe_start() { ct "(nohup /tmp/probe.sh /tmp/probe.log $(_probe_args) </dev/null >/dev/null 2>&1 &)"; }
probe_stop() { ct 'kill $(cat /tmp/probe.pid) 2>/dev/null; cat /tmp/probe.log'; }
# One-shot probes. Their lines are recorded for the verdict (a LEAK: or
# probe-failed result counts like one from the probe loop).
lan_probe() {
    local line
    line=$(ct "/tmp/probe.sh - $(_probe_args)")
    [ -n "${SCENARIO_PROBE_FILE:-}" ] && printf '%s\n' "$line" >> "$SCENARIO_PROBE_FILE"
    echo "lan: ${line#* }"
}
# Router-originated HTTPS, informational: the router's own lookups go through
# the daemon's uid-0 hatch under Blocked, so this is not a leak signature.
router_probe() {
    local ip
    ip=$(rt "wget -qO- -T3 https://$LEAK_PROBE_HOST 2>/dev/null || curl -s -m3 https://$LEAK_PROBE_HOST 2>/dev/null" | grep -E '^[0-9.]+$' | head -1)
    if [ -z "$ip" ]; then echo "router: http=no-answer"
    elif [ "$ip" = "${LEAK_REAL_PUBLIC_IP:-}" ]; then echo "router: http=LEAK:$ip"
    else echo "router: http=egress:$ip"; fi
}
# TCP connects to LuCI on the LAN address from the client and to the WAN
# address (ssh, http) from the dev machine. The dev-machine vantage may sit
# behind an unreliable path; the wired probe in mgmt_* is the one that gates.
luci_probe() {
    local lan wan22 wan80
    lan=$(ct "curl -s -m2 -o /dev/null -w '%{http_code}' http://$LEAK_ROUTER_LAN_IP/ 2>/dev/null" | grep -qE '^[1-5][0-9][0-9]$' && echo ok || echo no)
    wan22=$(nc -z -w2 "$LEAK_ROUTER_WAN_IP" 22 >/dev/null 2>&1 && echo ok || echo no)
    wan80=$(nc -z -w2 "$LEAK_ROUTER_WAN_IP" 80 >/dev/null 2>&1 && echo ok || echo no)
    echo "luci: lan:80=$lan wan:22=$wan22 wan:80=$wan80"
}
probes() { log "$(lan_probe) | $(router_probe) | $(luci_probe)"; }

# ---- router state ------------------------------------------------------------------
# One line: policy (the daemon's kill-switch rules hooked), boot (the
# boot-time/emergency block present), the stop and transition markers, the
# daemon pid, the kill-switch setting and the tunnel state.
_state_snippet() {
    local p b
    case "$LEAK_FW" in
        fw3) p='iptables -w -C output_rule -j NYM_OUTPUT >/dev/null 2>&1'
             b='iptables -w -S NYM_EMERGENCY_OUT >/dev/null 2>&1' ;;
        fw4) p='nft list table inet nym >/dev/null 2>&1'
             b='nft list table inet nym_boot >/dev/null 2>&1' ;;
        *) echo "unknown LEAK_FW=$LEAK_FW" >&2; return 1 ;;
    esac
    cat <<EOF
printf 'policy=%s boot=%s marker=%s transition=%s vpnd=%s ks=%s state=%s' \
 "\$($p && echo yes || echo no)" "\$($b && echo yes || echo no)" \
 "\$([ -f /var/run/nym-firewall/stopped ] && echo yes || echo no)" \
 "\$([ -f /var/run/nym-firewall/transition ] && echo yes || echo no)" \
 "\$(pidof nym-vpnd | tr ' ' ',' | grep . || echo none)" \
 "\$(nym-vpnc tunnel get 2>/dev/null | sed -n 's/^Kill-switch: //p' | head -1 | grep . || echo unknown)" \
 "\$(nym-vpnc status 2>/dev/null | sed -n 's/^State: \([A-Za-z]*\).*/\1/p' | head -1 | grep . || echo noreply)"
EOF
}
state() { rt "$(_state_snippet)"; }
# policy_hooked: true when the daemon's kill-switch rules are in place.
policy_hooked() { state | grep -q 'policy=yes'; }
# wait_state <grep pattern> [max s]: poll the state line; prints seconds taken.
wait_state() {
    local pat=$1 max=${2:-90} t0
    t0=$(epoch)
    while [ $(( $(epoch) - t0 )) -lt "$max" ]; do
        if state 2>/dev/null | grep -qE "$pat"; then echo $(( $(epoch) - t0 )); return 0; fi
        sleep 2
    done
    echo "timeout(${max}s)"; return 1
}
# Return the router to the handover state after a recovery scenario: marker
# gone, runtime dir and binary modes restored, daemon up, kill-switch on,
# Stealth off, connected, always-on.
reset_state() {
    rt 'rm -f /var/run/nym-firewall/stopped; chmod 0700 /var/run/nym-firewall 2>/dev/null; chmod 755 /usr/sbin/nym-vpnd 2>/dev/null
        pidof nym-vpnd >/dev/null || /etc/init.d/nym-vpnd start; sleep 3
        nym-vpnc tunnel set --killswitch on >/dev/null 2>&1; nym-vpnc tunnel set --stealth-api off >/dev/null 2>&1
        nym-vpnc status | grep -q "^State: Connected" || nym-vpnc connect --wait >/dev/null 2>&1
        nym-vpnc tunnel set --always-on on >/dev/null 2>&1 || true' >/dev/null  # always-on is a daemon setting; needs a daemon that has it
    log "reset: $(state)"
}

# ---- router state watcher ------------------------------------------------------
push_watcher() {
    rt "cat > /tmp/leak/watch.sh <<'W'
#!/bin/sh
OUT=\$1; : > \"\$OUT\"; echo \$\$ > /tmp/leak/watch.pid
while :; do
  echo \"\$(date +%T) \$($(_state_snippet))\" >> \"\$OUT\"
  sleep 1
done
W
chmod +x /tmp/leak/watch.sh"
}
watch_start() { rt '( trap "" HUP; /tmp/leak/watch.sh /tmp/leak/watch.log </dev/null >/dev/null 2>&1 & )'; }
watch_stop() { rt 'kill $(cat /tmp/leak/watch.pid) 2>/dev/null; cat /tmp/leak/watch.log'; }

# ---- WAN capture on the host ---------------------------------------------------
# cap_start <name>: tcpdump on the router's WAN interface. CAP_ALIVE says
# whether it was actually running a second later; a capture that never
# started makes the scenario INCONCLUSIVE, not PASS.
cap_start() {
    CAP_PID=$(px "nohup tcpdump -ni $LEAK_WAN_IF -w $LEAK_HOST_DIR/$1.pcap </dev/null >/dev/null 2>&1 & echo \$!")
    sleep 1
    if px "pgrep -f '^tcpdump -ni $LEAK_WAN_IF -w $LEAK_HOST_DIR/$1.pcap' >/dev/null"; then
        CAP_ALIVE=1
    else
        CAP_ALIVE=0
        log "CAPTURE NOT RUNNING on $LEAK_PROXMOX ($LEAK_WAN_IF)"
    fi
    export CAP_PID CAP_ALIVE
}
cap_stop() { px "kill $CAP_PID 2>/dev/null; sleep 1"; }
cap_fetch() { px "cat $LEAK_HOST_DIR/$1.pcap" > "$2"; }

# ---- management access ---------------------------------------------------------------
# Two vantages: an ssh session held open from the dev machine over the WAN
# address, and a TCP-connect loop to the router's ssh port from the
# hypervisor, wired on the same segment. A drop seen only from the dev
# machine is a path problem, not the router's; the wired vantage gates.
push_reach() {
    px "cat > $LEAK_HOST_DIR/reach.sh" <<'R'
#!/bin/bash
# reach.sh <log> <ip> <port>: one TCP connect per second, ok|down per line
OUT=$1; IP=$2; PORT=$3; : > "$OUT"; echo $$ > "$OUT.pid"
while :; do
  if timeout 1 bash -c "exec 3<>/dev/tcp/$IP/$PORT" 2>/dev/null; then echo ok; else echo down; fi >> "$OUT"
  sleep 1
done
R
}
mgmt_start() {
    MGMT_LOG=$(mktemp); MGMT_PID=""
    if [ -n "${LEAK_ROUTER_HOST:-}" ]; then
        _router_ssh_cmd "-o ServerAliveInterval=2 -o ServerAliveCountMax=3"
        "${ROUTER_SSH[@]}" "$LEAK_ROUTER_HOST" 'while sleep 1; do echo alive; done' > "$MGMT_LOG" 2>/dev/null &
        MGMT_PID=$!
    fi
    MGMT_T0=$(epoch)
    px "(nohup bash $LEAK_HOST_DIR/reach.sh $LEAK_HOST_DIR/reach.log $LEAK_ROUTER_WAN_IP 22 </dev/null >/dev/null 2>&1 &)"
    sleep 2
}
# Sets MGMT_HELD (yes|no|n/a) and MGMT_WIRED_DOWN (down samples from the
# hypervisor, or "n/a"); logs one summary line.
mgmt_stop() {
    local n=0 elapsed wired
    elapsed=$(( $(epoch) - MGMT_T0 ))
    if [ -n "$MGMT_PID" ]; then
        kill "$MGMT_PID" 2>/dev/null; wait "$MGMT_PID" 2>/dev/null
        n=$(grep -c alive "$MGMT_LOG")
        if [ "$n" -ge $((elapsed - 6)) ]; then MGMT_HELD=yes; else MGMT_HELD=no; fi
    else
        MGMT_HELD=n/a
    fi
    wired=$(px "kill \$(cat $LEAK_HOST_DIR/reach.log.pid) 2>/dev/null; sort $LEAK_HOST_DIR/reach.log | uniq -c | awk '{printf \"%s=%s \", \$2, \$1}'")
    if printf '%s' "$wired" | grep -q 'ok='; then
        MGMT_WIRED_DOWN=$(printf '%s' "$wired" | sed -n 's/.*down=\([0-9]*\).*/\1/p'); : "${MGMT_WIRED_DOWN:=0}"
    else
        MGMT_WIRED_DOWN=n/a
    fi
    export MGMT_HELD MGMT_WIRED_DOWN
    log "management: held ssh session $n ticks in ${elapsed}s -> held=$MGMT_HELD; wired :22 from the hypervisor: ${wired:-n/a}"
    rm -f "$MGMT_LOG"
}
# Management access kept: the held session survived, or the wired vantage
# saw the ssh port reachable in every sample.
mgmt_ok() { [ "${MGMT_HELD:-}" = yes ] || [ "${MGMT_WIRED_DOWN:-n/a}" = 0 ]; }

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
# analyze <name>: sets LEAK_SYN LEAK_DNS LEAK_WG UNATTRIBUTED UNATTRIBUTED_LIST
# TOTAL. LEAK_WG counts UDP from the router's WAN address to the entry
# gateway (the tunnel's own packets), the liveness signal of a capture taken
# with the tunnel up.
analyze() {
    local name=$1 allow="" wg="" h
    for h in $LEAK_ENTRY $LEAK_EXIT ${LEAK_LAST_ENTRY:-} ${LEAK_LAST_EXIT:-} $LEAK_DAEMON_HOSTS ${LEAK_OPERATOR_IP:-}; do
        [ -n "$h" ] && allow="$allow and not host $h"
    done
    for h in $LEAK_DAEMON_NETS; do allow="$allow and not net $h"; done
    for h in $LEAK_ENTRY ${LEAK_LAST_ENTRY:-}; do wg="$wg${wg:+ or }dst host $h"; done
    local base="src host $LEAK_ROUTER_WAN_IP and (tcp or udp) and not port 67 and not port 68 and not port 123 and not port 853 and not tcp src port 22"
    LEAK_SYN=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 'src host $LEAK_ROUTER_WAN_IP and dst host $LEAK_PROBE_IP and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' 2>/dev/null | wc -l" | tr -d ' ')
    LEAK_DNS=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 'src host $LEAK_ROUTER_WAN_IP and udp dst port 53' 2>/dev/null | wc -l" | tr -d ' ')
    if [ -n "$wg" ]; then
        LEAK_WG=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 'src host $LEAK_ROUTER_WAN_IP and udp and ($wg)' 2>/dev/null | wc -l" | tr -d ' ')
    else
        LEAK_WG=0
    fi
    UNATTRIBUTED_LIST=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap '$base $allow' 2>/dev/null | sed -nE 's/.* > ([0-9.]+)\.([0-9]+):.*/\1:\2/p' | sort | uniq -c | sort -rn | head -10")
    UNATTRIBUTED=$(printf '%s\n' "$UNATTRIBUTED_LIST" | awk '{s+=$1} END{print s+0}')
    TOTAL=$(px "tcpdump -nr $LEAK_HOST_DIR/$name.pcap 2>/dev/null | wc -l" | tr -d ' ')
    : "${LEAK_SYN:=0}" "${LEAK_DNS:=0}" "${LEAK_WG:=0}" "${TOTAL:=0}"
    export LEAK_SYN LEAK_DNS LEAK_WG UNATTRIBUTED UNATTRIBUTED_LIST TOTAL
}
