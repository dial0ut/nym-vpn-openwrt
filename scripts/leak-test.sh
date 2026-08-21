#!/bin/sh
# DNS leak harness for the nym-vpn kill switch. Complements
# test-firewall-states.sh: that script checks the *rules*, this one checks
# the *packets*. The original leak (dnsmasq re-originating LAN queries as
# router OUTPUT) had rules that looked correct — only a WAN-side capture
# showed it. This automates that capture.
#
# Method: fire DNS queries for unique canary hostnames from every
# leak-relevant origin (LAN client direct, LAN client via router dnsmasq,
# router-local dnsmasq relay) across the tunnel states (Blocked, Connecting,
# Connected), while tcpdump watches the router's WAN for ports 53/853. A
# canary name appearing on the WAN in any protected state is a leak. A final
# positive-control phase (kill switch off, disconnected) requires the
# canaries TO appear — proving the capture works — so a broken harness
# fails loudly instead of passing silently.
#
# Runs on a dev machine, orchestrating over ssh:
#   scripts/leak-test.sh <router-ssh-host> [lan-client-ssh-host]
# The router needs: nym-vpnc, tcpdump, an account able to connect.
# The optional LAN client needs: dig. Without it, coverage drops to the
# router-relay origin (still the class the original leak used).
#
# Env: SKIP_CONTROL=1   skip the killswitch-off positive control
#      CONNECT_WAIT=90  seconds to wait for Connected
set -u

ROUTER="${1:-}"
CLIENT="${2:-}"
[ -n "$ROUTER" ] || { echo "Usage: $0 <router-ssh-host> [lan-client-ssh-host]" >&2; exit 2; }
CONNECT_WAIT="${CONNECT_WAIT:-90}"
RUN_ID="$(date +%s)$$"
OUT="${OUT:-/tmp/nym-leak-test.$RUN_ID}"
mkdir -p "$OUT"
CAP=/tmp/nym-leak-capture.txt

rsh() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$ROUTER" "$@"; }
csh() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$CLIENT" "$@"; }

fail=0
ok()   { echo "  [PASS] $1"; }
bad()  { echo "  [FAIL] $1"; fail=1; }
note() { echo "  [note] $1"; }
die()  { echo "FATAL: $1" >&2; cleanup; exit 3; }

# Canary names: unique per run and per phase, under example.com (reserved,
# no wildcard), so hits in the capture are attributable and inert. RUN_ID
# comes FIRST so that "lk<run>-<phase>" is a grep-able prefix regardless of
# what origin tag follows — the first version had phase and origin fused
# before the run id, the asserts matched nothing, and only the positive
# control exposed it. Keep prefix and asserts in lockstep.
canary() { echo "lk$RUN_ID-$1-$2.leak-test.example.com"; }

# ---- probes ------------------------------------------------------------------
# Every probe swallows resolution results on purpose: whether the query
# SUCCEEDS is not the signal (dig prints errors to stdout; resolvers differ).
# The only signal is whether the canary shows up in the WAN capture.
probe_router_relay() {  # $1=phase — the moejoe path: dnsmasq re-origination
    i=1; while [ $i -le 4 ]; do
        rsh "nslookup $(canary "$1-relay" $i) 127.0.0.1 >/dev/null 2>&1" || true
        i=$((i+1))
    done
}
probe_client() {        # $1=phase — LAN client via router dnsmasq + direct
    [ -n "$CLIENT" ] || return 0
    i=1; while [ $i -le 4 ]; do
        csh "dig +time=1 +tries=1 @$LAN_IP $(canary "$1-cvia" $i) >/dev/null 2>&1; \
             dig +time=1 +tries=1 @1.1.1.1 $(canary "$1-cdir" $i) >/dev/null 2>&1" || true
        i=$((i+1))
    done
}
probes() { probe_router_relay "$1"; probe_client "$1"; }

# Leak check: give in-flight packets a moment, then grep the live capture.
assert_no_canary() {    # $1=phase  $2=description
    sleep 2
    hits=$(rsh "grep -c 'lk$RUN_ID-$1-' $CAP 2>/dev/null" || true)
    hits="${hits:-0}"
    if [ "$hits" -eq 0 ]; then ok "no canary on WAN: $2"
    else bad "$hits canary packet(s) on WAN during $2 — DNS LEAK"; fi
}

tstate() { rsh "/usr/bin/nym-vpnc status 2>/dev/null | head -1 | sed 's/^State: //'"; }
wait_state() {          # $1=prefix  $2=timeout
    t=0; while [ $t -lt "$2" ]; do
        case "$(tstate)" in "$1"*) return 0;; esac
        t=$((t+2)); sleep 2
    done
    return 1
}

cleanup() {
    rsh "kill \$(cat /tmp/nym-leak-tcpdump.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/nym-leak-tcpdump.pid" 2>/dev/null || true
    # Restore what we changed. Connection state is restored best-effort;
    # the kill switch is always re-set to its original value.
    if [ "${KS_WAS:-}" = "true" ]; then rsh "nym-vpnc tunnel set --killswitch on  >/dev/null 2>&1" || true
    elif [ "${KS_WAS:-}" = "false" ]; then rsh "nym-vpnc tunnel set --killswitch off >/dev/null 2>&1" || true; fi
    if [ "${WAS_CONNECTED:-no}" = yes ]; then rsh "nym-vpnc connect-v2 >/dev/null 2>&1 &" || true
    else rsh "nym-vpnc disconnect >/dev/null 2>&1" || true; fi
    rsh "cat $CAP 2>/dev/null" > "$OUT/wan-capture.txt" 2>/dev/null || true
    rsh "rm -f $CAP" 2>/dev/null || true
}
trap cleanup INT TERM

# ---- preflight ---------------------------------------------------------------
echo "== Preflight =="
rsh "command -v tcpdump >/dev/null" || die "tcpdump missing on router"
rsh "command -v nym-vpnc >/dev/null" || die "nym-vpnc missing on router"
if [ -n "$CLIENT" ]; then csh "command -v dig >/dev/null" || die "dig missing on client"; fi

WAN_IF=$(rsh "ubus call network.interface.wan status 2>/dev/null | grep -o '\"l3_device\": \"[^\"]*\"' | cut -d'\"' -f4")
[ -n "$WAN_IF" ] || WAN_IF=$(rsh "ip route show default | head -1 | sed 's/.* dev \([^ ]*\).*/\1/'")
[ -n "$WAN_IF" ] || die "cannot determine WAN interface"
LAN_IP=$(rsh "uci -q get network.lan.ipaddr")
KS_WAS=$(rsh "grep -o '\"killswitch\": [a-z]*' /etc/nym/nym-vpnd.json 2>/dev/null | grep -o '[a-z]*\$'")
case "$(tstate)" in Connected*) WAS_CONNECTED=yes;; *) WAS_CONNECTED=no;; esac
echo "  router=$ROUTER client=${CLIENT:-'(none — router-relay coverage only)'}"
echo "  wan=$WAN_IF lan_ip=${LAN_IP:-?} killswitch=$KS_WAS state_was=$([ $WAS_CONNECTED = yes ] && echo connected || echo down)"
echo "  artifacts=$OUT"

# WAN capture for the whole run. Plaintext DNS is what the known leak classes
# emit (dnsmasq relays speak plain 53); 853 is included to catch a DoT
# surprise. -l so grep sees packets as they land.
rsh "rm -f $CAP; tcpdump -n -l -i $WAN_IF 'port 53 or port 853' > $CAP 2>/dev/null & echo \$! > /tmp/nym-leak-tcpdump.pid"
sleep 2
rsh "kill -0 \$(cat /tmp/nym-leak-tcpdump.pid)" || die "tcpdump did not start on $WAN_IF"

rsh "nym-vpnc tunnel set --killswitch on >/dev/null 2>&1"

# ---- phase 1: Blocked (killswitch on, disconnected) ---------------------------
echo "== Phase 1: Blocked =="
rsh "nym-vpnc disconnect >/dev/null 2>&1"
wait_state "Disconnected" 20 || note "router did not report Disconnected; continuing"
probes p1
assert_no_canary p1 "Blocked (killswitch on, disconnected)"

# ---- phase 2: Connecting window ------------------------------------------------
# Fire probes continuously while the state machine transitions — the
# per-reconnect window is exactly where the pre-1.34.0 hatch leaked.
echo "== Phase 2: Connecting =="
rsh "nym-vpnc connect-v2 >/dev/null 2>&1 &"
end=$(( $(date +%s) + CONNECT_WAIT ))
while [ "$(date +%s)" -lt $end ]; do
    case "$(tstate)" in Connected*) break;; esac
    probes p2
done
assert_no_canary p2 "Connecting window"

# ---- phase 3: Connected --------------------------------------------------------
echo "== Phase 3: Connected =="
if wait_state "Connected" 10; then
    probes p3
    assert_no_canary p3 "Connected (client DNS must ride the tunnel)"
    if [ -n "$CLIENT" ]; then
        # Routing positive control: the client must actually resolve through
        # the tunnel, otherwise "no canary on WAN" just means DNS is broken.
        if csh "dig +time=3 +tries=2 @$LAN_IP example.com +short 2>/dev/null | grep -qE '^[0-9a-f.:]+\$'"; then
            ok "client resolves through the tunnel (probes are actually flowing)"
        else bad "client cannot resolve while Connected — probe path broken, phase results unreliable"; fi
    fi
else
    bad "never reached Connected within ${CONNECT_WAIT}s — Connected-phase coverage missing"
fi

# ---- phase 4: positive control -------------------------------------------------
# Kill switch off + disconnected: canaries MUST hit the WAN. If they don't,
# the capture never worked and every PASS above is meaningless.
if [ "${SKIP_CONTROL:-0}" = 1 ]; then
    note "positive control skipped (SKIP_CONTROL=1) — silence above is unverified"
else
    echo "== Phase 4: positive control (killswitch off — canaries must appear) =="
    rsh "nym-vpnc disconnect >/dev/null 2>&1"
    wait_state "Disconnected" 20 || true
    rsh "nym-vpnc tunnel set --killswitch off >/dev/null 2>&1"
    sleep 3
    probes ctl
    sleep 2
    hits=$(rsh "grep -c 'lk$RUN_ID-ctl-' $CAP 2>/dev/null" || true)
    if [ "${hits:-0}" -gt 0 ]; then ok "positive control: $hits canary packet(s) seen with killswitch off — harness can see leaks"
    else bad "positive control FAILED: no canaries on WAN with killswitch off — capture is blind, all passes above are void"; fi
fi

# ---- verdict -------------------------------------------------------------------
cleanup
trap - INT TERM
echo
echo "WAN capture saved to $OUT/wan-capture.txt"
[ "$fail" = 0 ] && echo "Overall: PASS" || echo "Overall: FAIL"
exit "$fail"
