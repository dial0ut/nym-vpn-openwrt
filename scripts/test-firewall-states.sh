#!/bin/sh
# Verify the nym-vpn kill-switch firewall policy across tunnel states on a live
# router. Drives a real connect with `nym-vpnc connect-v2`, samples the tunnel
# state and the installed firewall rules once per second, and checks the
# state->rule correlation. Headline checks: the NTP escape hatch in the
# *Connecting* state (the C1 change — a clockless router must be able to reach
# NTP while connecting, or it deadlocks in DeviceTimeDesynced), and the DNS
# invariant that every DNS accept is uid-scoped to root in every state where
# the tunnel is not up (Blocked AND Connecting) — the daemon owns cold-boot
# NTP-pool resolution now, so no unscoped DNS accept may exist anywhere.
#
# Run as root ON THE ROUTER after installing the new nym-vpnd + nym-vpnc.
#   scp scripts/test-firewall-states.sh root@router:/tmp/ && ssh root@router sh /tmp/test-firewall-states.sh
#
# Env overrides: VPNC=/path/to/nym-vpnc  SAMPLE_SECS=90  BACKEND=nft|iptables
set -u

VPNC="${VPNC:-/usr/bin/nym-vpnc}"
SAMPLE_SECS="${SAMPLE_SECS:-90}"
OUT=/tmp/nym-fw-test
mkdir -p "$OUT"

[ "$(id -u)" = 0 ] || { echo "Run as root (reading the firewall needs root)." >&2; exit 1; }
[ -x "$VPNC" ] || command -v "$VPNC" >/dev/null 2>&1 || { echo "nym-vpnc not found at '$VPNC' (set VPNC=...)." >&2; exit 1; }

# ---- backend detection -------------------------------------------------------
if [ "${BACKEND:-}" = "" ]; then
    if command -v nft >/dev/null 2>&1; then BACKEND=nft; else BACKEND=iptables; fi
fi

fw_dump() {
    if [ "$BACKEND" = nft ]; then
        nft list table inet nym 2>/dev/null
    else
        { iptables-save 2>/dev/null; ip6tables-save 2>/dev/null; } | grep -- 'NYM_'
    fi
}
fw_table_present() {            # is the kill-switch table installed at all?
    [ -n "$(fw_dump)" ]
}
has_ntp_hatch() {               # rate-limited udp/123 accept in the OUTPUT chain
    if [ "$BACKEND" = nft ]; then
        fw_dump | grep -qE 'udp dport 123 .*limit rate .*accept'
    else
        fw_dump | grep -- '-A NYM_OUTPUT' | grep -- '--dport 123' | grep -q -- 'limit'
    fi
}
has_final_reject() {            # kill-switch active => OUTPUT terminates in reject
    fw_dump | grep -qiE 'reject'
}
has_tunnel_allow() {            # Connected => egress allowed out the tunnel iface
    if [ "$BACKEND" = nft ]; then
        fw_dump | grep -qE 'oifname "(nym|wg|tun)[0-9a-z._-]*" accept'
    else
        fw_dump | grep -- '-A NYM_OUTPUT' | grep -qE -- '-o (nym|wg|tun)'
    fi
}
has_root_scoped_dns() {         # DNS accepts uid-scoped to the daemon
    # (dnsmasq relays LAN queries as router OUTPUT; without the uid scope
    # they leak to the WAN — the moejoe pcap repro). Must be PRESENT while
    # Disconnected AND while Connecting: cold-boot NTP-pool resolution is
    # daemon-owned (plain UDP/53 as root), not sysntpd -> dnsmasq.
    if [ "$BACKEND" = nft ]; then
        fw_dump | grep -qE 'meta skuid 0 .*dport 53 .*accept'
    else
        fw_dump | grep -- '-A NYM_OUTPUT' | grep -- '--dport 53' | grep -q -- '--uid-owner 0'
    fi
}
has_unscoped_dns_accept() {     # any port-53 OUTPUT accept NOT uid-scoped = leak
    if [ "$BACKEND" = nft ]; then
        fw_dump | grep -E 'dport 53 .*accept' | grep -qv 'skuid'
    else
        fw_dump | grep -- '-A NYM_OUTPUT' | grep -- '--dport 53' | grep -- '-j ACCEPT' | grep -qv -- '--uid-owner'
    fi
}
tstate() { "$VPNC" status 2>/dev/null | sed -n 's/^State: //p' | head -1; }
yn() { if "$@"; then echo yes; else echo no; fi; }

# ---- baseline: kill-switch on, disconnected ---------------------------------
echo "backend=$BACKEND  vpnc=$VPNC  sample=${SAMPLE_SECS}s  dumps=$OUT"
echo
echo "Ensuring kill-switch is ON ..."
"$VPNC" tunnel set --killswitch on >/dev/null 2>&1

echo "== Phase 0: Disconnected (expect kill-switch 'Blocked' policy) =="
"$VPNC" disconnect >/dev/null 2>&1
i=0; while [ "$i" -lt 30 ]; do [ "$(tstate)" = "Disconnected" ] && break; sleep 1; i=$((i+1)); done
fw_dump > "$OUT/blocked.txt"
table_in_blocked=$(yn fw_table_present); rootdns_in_blocked=$(yn has_root_scoped_dns)
unscopeddns_in_blocked=$(yn has_unscoped_dns_accept)
printf '  state=%s table=%s ntp=%s reject=%s rootdns=%s\n' \
    "$(tstate)" "$table_in_blocked" "$(yn has_ntp_hatch)" "$(yn has_final_reject)" \
    "$rootdns_in_blocked"
echo "  (no table => firewall open, daemon has no cached API endpoints yet)"
echo

# ---- connect, sampling each state -------------------------------------------
echo "== Phase 1-3: connect-v2, sampling tunnel state vs firewall =="
: > "$OUT/connecting.txt"; rm -f "$OUT/connecting.txt" "$OUT/connected.txt" "$OUT/error.txt"
"$VPNC" connect-v2 > "$OUT/connect.out" 2>&1 &

seen_connecting=no; ntp_in_connecting=no; rootdns_in_connecting=no
unscopeddns_in_connecting=no
seen_connected=no;  ntp_in_connected=no
seen_error=no
start=$(date +%s)
printf '  %-8s %-14s %-7s %-8s %-8s %-8s\n' TIME STATE NTP REJECT TUNNEL ROOTDNS
while :; do
    st=$(tstate); [ -z "$st" ] && st="(none)"
    ntp=$(yn has_ntp_hatch); rej=$(yn has_final_reject); tun=$(yn has_tunnel_allow)
    rdns=$(yn has_root_scoped_dns)
    printf '  %-8s %-14s %-7s %-8s %-8s %-8s\n' "$(date +%H:%M:%S)" "$st" "$ntp" "$rej" "$tun" "$rdns"
    case "$st" in
        Connecting*)
            seen_connecting=yes; [ "$ntp" = yes ] && ntp_in_connecting=yes
            [ "$rdns" = yes ] && rootdns_in_connecting=yes
            has_unscoped_dns_accept && unscopeddns_in_connecting=yes
            [ -f "$OUT/connecting.txt" ] || fw_dump > "$OUT/connecting.txt" ;;
        Connected*)
            seen_connected=yes; [ "$ntp" = yes ] && ntp_in_connected=yes
            [ -f "$OUT/connected.txt" ] || fw_dump > "$OUT/connected.txt" ;;
        Error*)
            seen_error=yes
            [ -f "$OUT/error.txt" ] || fw_dump > "$OUT/error.txt" ;;
    esac
    now=$(date +%s)
    # Stop a few seconds after reaching Connected, or on timeout.
    [ "$seen_connected" = yes ] && [ $((now - start)) -ge 3 ] && break
    [ $((now - start)) -ge "$SAMPLE_SECS" ] && break
    sleep 1
done
echo

# ---- verdict ----------------------------------------------------------------
echo "== Results =="
fail=0
note() { echo "  [note] $1"; }
ok()   { echo "  [PASS] $1"; }
bad()  { echo "  [FAIL] $1"; fail=1; }

if [ "$table_in_blocked" = yes ]; then
    if [ "$rootdns_in_blocked" = yes ]; then ok "Blocked DNS accepts uid-scoped to root (dnsmasq relay leak closed)"
    else bad "Blocked DNS accepts NOT uid-scoped -- dnsmasq-relayed LAN DNS leaks to the WAN"; fi
    if [ "$unscopeddns_in_blocked" = no ]; then ok "no unscoped port-53 accept while Blocked"
    else bad "unscoped port-53 OUTPUT accept found while Blocked -- LAN relay leak"; fi
else
    note "no kill-switch table while Disconnected -- root-scoping check skipped"
fi

if [ "$seen_connecting" = yes ]; then
    ok "observed Connecting state"
    if [ "$ntp_in_connecting" = yes ]; then ok "NTP escape hatch present while Connecting (C1)"
    else bad "NTP escape hatch MISSING while Connecting (C1 regression)"; fi
    if [ "$rootdns_in_connecting" = yes ]; then ok "DNS accepts uid-scoped to root while Connecting (daemon-owned bootstrap)"
    else bad "root-scoped DNS accepts MISSING while Connecting -- daemon cannot resolve mid-connect"; fi
    if [ "$unscopeddns_in_connecting" = no ]; then ok "no unscoped port-53 accept while Connecting (per-reconnect leak window closed)"
    else bad "unscoped port-53 OUTPUT accept found while Connecting -- LAN relay leak on every reconnect"; fi
else
    note "never caught a Connecting sample (window shorter than 1s, or instant failure) -- inspect $OUT/connect.out"
fi

if [ "$seen_connected" = yes ]; then
    ok "reached Connected"
    if [ "$ntp_in_connected" = no ]; then ok "NTP hatch absent when Connected (NTP rides the tunnel)"
    else note "NTP hatch present when Connected -- unexpected (only Connecting/Blocked should have it)"; fi
    if has_tunnel_allow; then ok "tunnel-interface egress allowed when Connected"
    else note "no tunnel-interface accept seen in the Connected dump"; fi
else
    note "never reached Connected -- check gateway selection / $OUT/connect.out"
fi

[ "$seen_error" = yes ] && note "tunnel entered Error during the run (see $OUT/error.txt)"

echo
echo "Per-state rule dumps written to: $OUT/{blocked,connecting,connected,error}.txt"
echo "Current state: $(tstate)"
[ "$fail" = 0 ] && echo "Overall: PASS" || echo "Overall: FAIL"
exit "$fail"
