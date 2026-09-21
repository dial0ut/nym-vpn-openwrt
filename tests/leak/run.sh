#!/bin/bash
# Packet-level kill-switch evidence suite: failure injection under a WAN
# capture, with management-access and recovery gates.
#
#   BED=fw3-vm tests/leak/run.sh                 # all scenarios, in order
#   BED=fw4-ct tests/leak/run.sh 01-control 13-crash-loop
#   KEEP_BED=1 tests/leak/run.sh ...             # leave the VM/CTs running afterwards
#
# For every scenario: WAN capture on the Proxmox host (the router's WAN
# interface), LAN client probe loop (HTTPS egress to a pinned address + DNS
# via the router + DNS straight to the upstream resolver), router state
# watcher (1 s), an ssh session held open across the failure plus a wired
# TCP-connect loop from the hypervisor, inject the failure, wait, run the
# scenario's own checks (including recovery), stop, analyze the pcap.
#
# Verdict rules (see README.md for the table):
#   leak signals  = SYNs from the router's WAN address to the LAN probe target
#                   + plain DNS from the router to the upstream resolver
#                   + a LAN probe answered on the real egress address (LEAK:)
#   FAIL          = expect noleak and a signal fired, or the scenario reported
#                   not_recovered, or (when the scenario gates on it)
#                   management access was lost; expect leak and nothing fired
#   INCONCLUSIVE  = the capture cannot be trusted: tcpdump not running, an
#                   empty capture, no tunnel packets in a connected scenario,
#                   no positive control yet, a probe that failed for a reason
#                   other than being blocked, or a connected scenario that was
#                   not Connected before the injection
#   PASS          = none of the above
#   SKIP          = the bed cannot exercise the scenario (reason printed)
# Packets to destinations not attributable to the tunnel, the daemon's own
# hatches or the operator's ssh are listed as "unattributed" on every verdict
# and never silently accepted. The run exits non-zero on any FAIL or
# INCONCLUSIVE.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BED=${BED:-fw3-vm}
[ -f "$HERE/beds/$BED.env" ] || { echo "unknown bed '$BED' (beds/: $(ls "$HERE/beds" | sed 's/\.env$//' | tr '\n' ' '))" >&2; exit 2; }
# shellcheck disable=SC1090
. "$HERE/beds/$BED.env"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=verdict.sh
. "$HERE/verdict.sh"

TS=$(date -u +%Y%m%dT%H%M%SZ)
RES=${LEAK_RESULTS_DIR:-$HERE/results/$TS}   # set to resume into an earlier run directory
mkdir -p "$RES"
CONTROL_OK=${LEAK_CONTROL_OK:-}          # =1 to trust a positive control recorded in an earlier run

verdict() { # <scenario> <verdict> <summary>
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$RES/verdicts.txt"
    printf '%s\n%s\n' "$2" "$3" > "$RES/$1.verdict"
    printf '==> %-28s %-13s %s\n' "$1" "$2" "$3"
}

ensure_connected() {
    rt 'pidof nym-vpnd >/dev/null || /etc/init.d/nym-vpnd start
        i=0; while ! nym-vpnc status >/dev/null 2>&1 && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
        nym-vpnc status | head -1 | grep -q "^State: Connected" || nym-vpnc connect --wait >/dev/null 2>&1
        nym-vpnc status | head -1 | cut -c1-70'
    learn_gateways
}

# scenario helpers (the scenario files are sourced into this shell; their
# hooks run in tee pipelines, so every gate is a file, not a variable)
skip() { printf '%s\n' "$*" > "$RES/${SCENARIO_NAME}.skip"; }
note() { printf '%s\n' "$*" >> "$SCENARIO_NOTE_FILE"; }
recovered() { note "recovered: $*"; }
not_recovered() { note "NOT recovered: $*"; printf '%s\n' "$*" >> "$RES/${SCENARIO_NAME}.fail"; }
inconclusive() { note "inconclusive: $*"; printf '%s\n' "$*" >> "$RES/${SCENARIO_NAME}.inconclusive"; }

run_scenario() {
    local file=$1 name
    name=$(basename "$file" .sh)
    [ "$name" != 01-control ] || CONTROL_OK=""
    export SCENARIO_LOG="$RES/$name.log" SCENARIO_NOTE_FILE="$RES/$name.note" SCENARIO_PROBE_FILE="$RES/$name.probe"
    : > "$SCENARIO_LOG"
    : > "$SCENARIO_NOTE_FILE"
    : > "$SCENARIO_PROBE_FILE"
    rm -f "$RES/$name.fail" "$RES/$name.inconclusive" "$RES/$name.skip"
    scenario_expect=noleak     # noleak | leak (the firewall is expected to be open)
    scenario_connected=1       # the tunnel must be Connected before the injection
    scenario_tunnel_after=1    # =0: the injection removes the daemon, so no tunnel packets are expected afterwards
    scenario_mgmt=0            # =1: losing management access is a FAIL
    scenario_wait=15
    scenario_inject() { return 1; }
    scenario_pre() { :; }
    scenario_post() { :; }
    scenario_check() { :; }
    # shellcheck disable=SC1090
    . "$file"
    if ! scenario_pre 2>&1 | tee -a "$SCENARIO_LOG"; then
        inconclusive "scenario preparation failed"
    fi
    if [ -s "$RES/$name.skip" ]; then
        verdict "$name" SKIP "$(cat "$RES/$name.skip")"
        return
    fi
    if [ -s "$RES/$name.inconclusive" ]; then
        verdict "$name" INCONCLUSIVE "$(cat "$RES/$name.inconclusive")"
        scenario_post 2>&1 | tee -a "$SCENARIO_LOG"
        return
    fi
    learn_gateways
    log "entry=$LEAK_ENTRY exit=$LEAK_EXIT probe=$LEAK_PROBE_IP real=${LEAK_REAL_PUBLIC_IP:-unknown} operator=${LEAK_OPERATOR_IP:-unknown}"
    if [ "$scenario_connected" = 1 ]; then
        local st
        st=$(rt 'nym-vpnc status 2>/dev/null | head -1 | cut -c1-70')
        case "$st" in
            "State: Connected"*) log "precondition: $st" ;;
            *)
                verdict "$name" INCONCLUSIVE "not Connected before the injection: ${st:-no reply}"
                scenario_post 2>&1 | tee -a "$SCENARIO_LOG"
                return ;;
        esac
    fi
    cap_start "$name"
    probe_start
    watch_start
    mgmt_start
    sleep 3
    log "inject"
    if ! scenario_inject 2>&1 | tee -a "$SCENARIO_LOG"; then
        inconclusive "scenario injection failed"
    fi
    sleep "$scenario_wait"
    if ! scenario_check 2>&1 | tee -a "$SCENARIO_LOG"; then
        not_recovered "scenario check failed"
    fi
    mgmt_stop
    {
        echo "--- router watcher (1 s samples):"
        watch_stop | awk '{$1=""; print}' | uniq -c
        echo "--- LAN probe (1 s samples):"
        probe_stop | tee -a "$SCENARIO_PROBE_FILE" | awk '{$1=""; print}' | uniq -c
    } | tee -a "$SCENARIO_LOG"
    cap_stop
    cap_fetch "$name" "$RES/$name.pcap" || inconclusive "capture retrieval failed"
    learn_gateways
    LEAK_SYN=0 LEAK_DNS=0 LEAK_WG=0 UNATTRIBUTED=0 UNATTRIBUTED_LIST="" TOTAL=0
    analyze "$name" || inconclusive "capture analysis failed"
    # Capture liveness: an empty capture proves nothing, and one taken with
    # the tunnel up must contain the tunnel's own packets to the entry
    # gateway (or, for the control, the probe's SYNs).
    local cap=live
    if [ "${CAP_ALIVE:-0}" != 1 ]; then cap="dead(tcpdump not running)"
    elif [ "$TOTAL" -eq 0 ]; then cap="dead(total=0)"
    elif [ "$scenario_connected" = 1 ] && [ "$scenario_tunnel_after" = 1 ] && [ "$LEAK_WG" -eq 0 ] && [ "$LEAK_SYN" -eq 0 ]; then cap="dead(no wg to entry, no syn)"
    fi
    {
        echo "--- capture: total=$TOTAL wg_to_entry=$LEAK_WG leak_syn_to_probe=$LEAK_SYN dns_to_upstream=$LEAK_DNS unattributed=$UNATTRIBUTED liveness=$cap"
        [ -n "$UNATTRIBUTED_LIST" ] && printf '%s\n' "$UNATTRIBUTED_LIST"
    } | tee -a "$SCENARIO_LOG"
    local sig=$((LEAK_SYN + LEAK_DNS)) leaks failed v note summary
    leaks=$(grep -c 'egress=LEAK:' "$SCENARIO_PROBE_FILE")
    failed=$(grep -o 'egress=probe-failed[^ ]*' "$SCENARIO_PROBE_FILE" | sort | uniq -c | awk '{printf "%s x%s ", $2, $1}')
    note=$(tr '\n' ' ' < "$SCENARIO_NOTE_FILE")
    summary="syn=$LEAK_SYN dns=$LEAK_DNS lan_leak=$leaks unattributed=$UNATTRIBUTED total=$TOTAL capture=$cap mgmt=$(mgmt_ok && echo ok || echo lost)${note:+; $note}"
    evaluate_verdict
    [ "$scenario_expect" != leak ] || summary="expected open: $summary"
    verdict "$name" "$v" "$summary"
    scenario_post 2>&1 | tee -a "$SCENARIO_LOG"
}

if [ $# -gt 0 ]; then
    list=()
    for s in "$@"; do list+=("$HERE/scenarios/$s.sh"); done
else
    list=("$HERE"/scenarios/*.sh)
fi
# Reject misspelled selections before touching the bed; discard stale per-case verdicts.
for f in "${list[@]}"; do
    [ -f "$f" ] || { echo "scenario not found: $f" >&2; exit 2; }
done
for f in "${list[@]}"; do
    rm -f "$RES/$(basename "$f" .sh).verdict"
done
echo "bed: $BED  results: $RES"
bed_up || exit 2
ensure_connected
for f in "${list[@]}"; do
    SCENARIO_NAME=$(basename "$f" .sh)
    export SCENARIO_NAME
    run_scenario "$f"
    ensure_connected >/dev/null
done
echo
echo "== verdicts"
column -t -s'|' "$RES/verdicts.txt"
[ -n "${KEEP_BED:-}" ] || bed_down
if grep -qE '\|(FAIL|INCONCLUSIVE)\|' "$RES/verdicts.txt"; then exit 1; fi
check_results "${list[@]}"
