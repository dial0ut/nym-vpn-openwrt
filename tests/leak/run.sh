#!/bin/bash
# Packet-level kill-switch failure-injection suite (fw3 test bed).
#
#   tests/leak/run.sh                 # all scenarios, in order
#   tests/leak/run.sh 01-control 05-lock-lost
#   KEEP_BED=1 tests/leak/run.sh ...  # leave VM/CT running afterwards
#
# For every scenario: WAN capture on the Proxmox host (tap of the router VM),
# LAN client probe loop (HTTPS egress to a pinned address + DNS via the router
# + DNS straight to the upstream resolver), router state watcher (1 s), inject
# the failure, wait, run the scenario's own checks (including recovery), stop,
# analyze the pcap. Verdict rules:
#   leak signals  = SYNs from the router's WAN address to the LAN probe target
#                   + plain DNS from the router to the upstream resolver
#   PASS          = expect noleak and both signals are zero
#   FAIL          = expect noleak and a signal fired, or expect leak (positive
#                   control) and nothing fired
#   INCONCLUSIVE  = the positive control did not fire, so the capture cannot
#                   be trusted to detect a leak; every later verdict inherits it
#   SKIP          = the bed cannot exercise the scenario (reason printed)
# Packets to destinations not attributable to the tunnel, the daemon's own
# hatches or the operator's ssh are listed as "unattributed" on every verdict
# and never silently accepted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

TS=$(date -u +%Y%m%dT%H%M%SZ)
RES=${LEAK_RESULTS_DIR:-$HERE/results/$TS}   # set to resume into an earlier run directory
mkdir -p "$RES"
CONTROL_OK=${LEAK_CONTROL_OK:-}          # =1 to trust a positive control recorded in an earlier run

verdict() { # <scenario> <verdict> <summary>
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$RES/verdicts.txt"
    printf '%s\n%s\n' "$2" "$3" > "$RES/$1.verdict"
    printf '==> %-26s %-13s %s\n' "$1" "$2" "$3"
}

ensure_connected() {
    rt 'pidof nym-vpnd >/dev/null || /etc/init.d/nym-vpnd start
        i=0; while ! nym-vpnc status >/dev/null 2>&1 && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
        nym-vpnc status | head -1 | grep -q "^State: Connected" || nym-vpnc connect --wait >/dev/null 2>&1
        nym-vpnc status | head -1 | cut -c1-70'
    learn_gateways
}

run_scenario() {
    local file=$1 name
    name=$(basename "$file" .sh)
    export SCENARIO_LOG="$RES/$name.log" SCENARIO_NOTE_FILE="$RES/$name.note"
    : > "$SCENARIO_LOG"
    : > "$SCENARIO_NOTE_FILE"
    scenario_expect=noleak
    scenario_wait=15
    scenario_pre() { :; }
    scenario_post() { :; }
    scenario_check() { :; }
    # shellcheck disable=SC1090
    . "$file"
    if ! scenario_pre 2>&1 | tee -a "$SCENARIO_LOG"; then :; fi
    if [ -s "$RES/$name.skip" ]; then
        verdict "$name" SKIP "$(cat "$RES/$name.skip")"
        return
    fi
    learn_gateways
    log "entry=$LEAK_ENTRY exit=$LEAK_EXIT probe=$LEAK_PROBE_IP operator=$LEAK_OPERATOR_IP"
    cap_start "$name"
    probe_start
    watch_start
    sleep 3
    log "inject"
    scenario_inject 2>&1 | tee -a "$SCENARIO_LOG"
    sleep "$scenario_wait"
    scenario_check 2>&1 | tee -a "$SCENARIO_LOG"
    {
        echo "--- router watcher (1 s samples):"
        watch_stop | awk '{$1=""; print}' | uniq -c
        echo "--- LAN probe (1 s samples):"
        probe_stop | awk '{$1=""; print}' | uniq -c
    } | tee -a "$SCENARIO_LOG"
    cap_stop
    cap_fetch "$name" "$RES/$name.pcap"
    learn_gateways
    analyze "$name"
    {
        echo "--- capture: total=$TOTAL leak_syn_to_probe=$LEAK_SYN dns_to_upstream=$LEAK_DNS unattributed=$UNATTRIBUTED"
        [ -n "$UNATTRIBUTED_LIST" ] && printf '%s\n' "$UNATTRIBUTED_LIST"
    } | tee -a "$SCENARIO_LOG"
    local sig=$((LEAK_SYN + LEAK_DNS)) v note
    note=$(tr '\n' ' ' < "$SCENARIO_NOTE_FILE")
    if [ "$scenario_expect" = leak ]; then
        if [ "$sig" -gt 0 ]; then v=PASS; CONTROL_OK=1; else v=FAIL; CONTROL_OK=""; fi
        verdict "$name" "$v" "positive control: syn=$LEAK_SYN dns=$LEAK_DNS (a leak MUST be visible here)"
    else
        if [ -z "$CONTROL_OK" ]; then v=INCONCLUSIVE
        elif [ "$sig" -gt 0 ]; then v=FAIL
        else v=PASS; fi
        verdict "$name" "$v" "syn=$LEAK_SYN dns=$LEAK_DNS unattributed=$UNATTRIBUTED${note:+; $note}"
    fi
    scenario_post 2>&1 | tee -a "$SCENARIO_LOG"
}

# scenario helpers
skip() { printf '%s\n' "$*" > "$RES/${SCENARIO_NAME}.skip"; }
note() { printf '%s\n' "$*" >> "$SCENARIO_NOTE_FILE"; }

echo "results: $RES"
bed_up || exit 2
ensure_connected
if [ $# -gt 0 ]; then
    list=()
    for s in "$@"; do list+=("$HERE/scenarios/$s.sh"); done
else
    list=("$HERE"/scenarios/*.sh)
fi
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
exit 0
