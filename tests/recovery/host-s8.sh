#!/bin/bash
# Scenario 8 (upgrade interrupted) driven entirely from the hypervisor: the
# router is an LXC container reached with `pct exec`, so this needs no network
# path to it and keeps running if the dev machine's connection drops. Use it
# when run.sh's dev-machine vantage is unreliable.
#
#   scp host-s8.sh proxmox:/root/ && ssh proxmox 'bash /root/host-s8.sh <version>'
#
# Assumes: router CT $CT with the new package already at /tmp/nym-vpn_<ver>_x86_64.apk,
# a LAN client CT $LANCT (Alpine, curl + dig) behind the router, WAN veth $WAN_IF.
set -uo pipefail
VER=${1:?version, e.g. 1.34.0_p14}
CT=${CT:-425}; LANCT=${LANCT:-903}; WAN_IF=${WAN_IF:-veth425i0}; WAN_IP=${WAN_IP:-192.168.1.252}
LAN_GW=${LAN_GW:-10.10.10.1}; REAL_PUBLIC_IP=${REAL_PUBLIC_IP:-203.0.113.1}
OUT=${OUT:-/root/s8-host.log}; PCAP=/tmp/recovery-caps/s8-host.pcap
APK="/tmp/nym-vpn_${VER}_x86_64.apk"
R() { pct exec "$CT" -- sh -c "$*"; }
L() { pct exec "$LANCT" -- sh -c "$*"; }
ts() { date +%H:%M:%S; }
log() { echo "[$(ts)] $*" | tee -a "$OUT"; }
state() { R 'printf "policy=%s boot=%s marker=%s vpnd=%s ks=%s %s" "$(nft list table inet nym >/dev/null 2>&1 && echo yes || echo no)" "$(nft list table inet nym_boot >/dev/null 2>&1 && echo yes || echo no)" "$([ -f /var/run/nym-firewall/stopped ] && echo yes || echo no)" "$(pidof nym-vpnd || echo none)" "$(nym-vpnc tunnel get 2>/dev/null | sed -n "s/Kill-switch: //p")" "$(nym-vpnc status 2>/dev/null | head -1 | cut -c1-24)"'; }
classify() { if [ -z "$1" ]; then echo blocked; elif [ "$1" = "$REAL_PUBLIC_IP" ]; then echo "LEAK:$1"; else echo "vpn:$1"; fi; }
lan_probe() { local ip d; ip=$(L 'curl -s -m3 https://ifconfig.me' || true); d=$(L "dig +time=1 +tries=1 +short @$LAN_GW example.com 2>/dev/null | head -1" || true); echo "lan: http=$(classify "$ip") dns=${d:-fail}"; }

: > "$OUT"
log "===== s8-host: kill -9 apk during the $VER post-upgrade step (driven from the hypervisor)"
log "state: $(state) installed=$(R 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"')"
R "ls $APK" >/dev/null || { log "package $APK missing on the router"; exit 2; }
mkdir -p "$(dirname "$PCAP")"; rm -f "$PCAP"
tcpdump -ni "$WAN_IF" -w "$PCAP" >/dev/null 2>&1 & TD=$!
( for _ in $(seq 1 300); do nc -z -w1 "$WAN_IP" 22 >/dev/null 2>&1 && echo ok || echo down; sleep 1; done > /tmp/s8-reach.log ) & RC=$!
( for _ in $(seq 1 120); do lan_probe; sleep 1; done > /tmp/s8-lan.log ) & LP=$!
sleep 3
log "$(lan_probe)"
# Start the upgrade detached inside the router and kill apk the moment its
# post-upgrade script (our postinst) is running.
R "(setsid sh -c 'apk add --allow-untrusted $APK > /tmp/apk-run.log 2>&1' </dev/null >/dev/null 2>&1 &)"
hit=""; for i in $(seq 1 300); do
    if R 'ps w | grep -qE "[.]post-upgrade|nym-vpnd [r]estart"'; then hit=$i; break; fi
    sleep 0.2
done
snap=$(R 'ps w | grep -E "[a]pk add|[.]post-upgrade|nym-vpnd [r]estart|nym-vpnd [s]tart|nym-vpnd [s]top" | awk "{\$1=\$2=\$3=\$4=\"\"; print}" | cut -c1-90 | tr "\n" ";"')
if R 'kill -9 $(pidof apk)'; then log "apk killed after ${hit:-timeout} polls (0.2s); running then: $snap"; else log "apk already gone (${hit:-timeout} polls); $snap"; fi
sleep 6
log "after kill: $(state)"
log "apk view: $(R 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"; echo " audit_nym_lines=$(apk audit 2>/dev/null | grep -c nym)"' | tr '\n' ' ')"
log "apk-run.log tail: $(R 'tail -2 /tmp/apk-run.log 2>/dev/null | cut -c1-100' | tr '\n' ' | ')"
log "$(lan_probe)"
log "recover: re-run apk add"
t0=$(date +%s)
log "$(R "apk add --allow-untrusted $APK 2>&1 | grep -E '^\(|OK:|ERROR' | tr '\n' ' '")"
for _ in $(seq 1 30); do state | grep -qE 'policy=yes .*vpnd=[0-9]' && break; sleep 2; done
log "recovered in $(( $(date +%s) - t0 ))s: $(state) installed=$(R 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9._p-]*"')"
R 'nym-vpnc status | grep -q "^State: Connected" || nym-vpnc connect --wait >/dev/null 2>&1'
log "connected: $(state)"; log "$(lan_probe)"
kill $TD $RC $LP 2>/dev/null; wait $TD $RC $LP 2>/dev/null
log "wired ssh reachability during the scenario: $(sort /tmp/s8-reach.log | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
log "LAN client probes during the scenario: $(awk '{print $2}' /tmp/s8-lan.log | sort | uniq -c | awk '{printf "%s x%s; ", $2, $1}')"
log "pcap: total=$(tcpdump -nr "$PCAP" 2>/dev/null | wc -l) upstream_dns=$(tcpdump -nr "$PCAP" "src host $WAN_IP and udp dst port 53" 2>/dev/null | wc -l) to_probe_target=$(tcpdump -nr "$PCAP" "src host $WAN_IP and dst host 34.160.111.145" 2>/dev/null | wc -l)"
if grep -q 'LEAK:' "$OUT" /tmp/s8-lan.log; then log "VERDICT FAIL: leak observed"; elif ! grep -q 'wired ssh reachability during the scenario: ok=' "$OUT" || grep -q 'down=' "$OUT"; then log "VERDICT INCONCLUSIVE: wired reachability gaps, see log"; else log "VERDICT PASS: no leak, ssh reachable throughout, daemon restored"; fi
