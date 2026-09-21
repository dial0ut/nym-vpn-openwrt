#!/bin/bash
# Verdict evaluation shared by the device runner and offline regression tests.
# Inputs are the runner's scenario settings, capture/probe counts and gate files.
# Outputs: v, summary, CONTROL_OK. Only 01-control can establish capture trust.
evaluate_verdict() {
    [ "$name" != 01-control ] || CONTROL_OK=""
    if [ -s "$RES/$name.fail" ]; then
        v=FAIL
    elif [ "$scenario_mgmt" = 1 ] && ! mgmt_ok; then
        v=FAIL
    elif [ "$scenario_expect" = noleak ] && { [ "$sig" -gt 0 ] || [ "$leaks" -gt 0 ]; }; then
        v=FAIL
    elif [ "$cap" != live ]; then
        v=INCONCLUSIVE
    elif [ -s "$RES/$name.inconclusive" ]; then
        v=INCONCLUSIVE
    elif [ -n "$failed" ]; then
        v=INCONCLUSIVE; summary="probe failed: $failed; $summary"
    elif ! grep -q 'egress=' "$SCENARIO_PROBE_FILE"; then
        v=INCONCLUSIVE; summary="no LAN probe results; $summary"
    elif [ "$scenario_expect" = leak ]; then
        if [ "$sig" -gt 0 ]; then
            v=PASS
            [ "$name" != 01-control ] || CONTROL_OK=1
        elif [ "$leaks" -gt 0 ]; then
            v=INCONCLUSIVE; summary="LAN leak without packet capture signal; $summary"
        else
            v=FAIL; summary="expected open but no leak signal; $summary"
        fi
    elif [ -z "$CONTROL_OK" ]; then
        v=INCONCLUSIVE; summary="no positive control yet; $summary"
    else
        v=PASS
    fi
}

# Every selected scenario must have produced a verdict during this invocation.
check_results() {
    local file name result rc=0
    for file in "$@"; do
        name=$(basename "$file" .sh)
        result=$(head -1 "$RES/$name.verdict" 2>/dev/null)
        case "$result" in
            PASS|SKIP) ;;
            FAIL|INCONCLUSIVE) rc=1 ;;
            *) echo "missing or invalid verdict: $name" >&2; rc=1 ;;
        esac
    done
    return "$rc"
}
