#!/bin/bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../verdict.sh
. "$HERE/verdict.sh"
RES=$(mktemp -d)
trap 'rm -rf "$RES"' EXIT
checks=0
mgmt_ok() { [ "$management" = ok ]; }
reset_case() {
    rm -f "$RES"/*
    name=01-control scenario_expect=leak scenario_mgmt=1 management=ok
    sig=4 leaks=1 cap=live failed="" summary=test CONTROL_OK=""
    SCENARIO_PROBE_FILE="$RES/probe"
    echo 'egress=LEAK:203.0.113.1' > "$SCENARIO_PROBE_FILE"
}
expect() {
    evaluate_verdict
    [ "$v" = "$1" ] && [ "$CONTROL_OK" = "$2" ] || {
        echo "FAIL $3: verdict=$v control=$CONTROL_OK"; exit 1;
    }
    checks=$((checks + 1))
}
reset_case; expect PASS 1 'valid positive control'
reset_case; cap='dead(tcpdump not running)'; CONTROL_OK=1; expect INCONCLUSIVE '' 'dead capture revokes old control'
reset_case; cap='dead(total=0)'; expect INCONCLUSIVE '' 'empty capture'
reset_case; failed=probe-failed; expect INCONCLUSIVE '' 'failed probe despite packet signal'
reset_case; : > "$SCENARIO_PROBE_FILE"; expect INCONCLUSIVE '' 'missing probe results'
reset_case; sig=0; expect INCONCLUSIVE '' 'LAN leak alone cannot validate capture'
reset_case; sig=0 leaks=0; expect FAIL '' 'control must detect traffic'
reset_case; echo failure > "$RES/$name.fail"; expect FAIL '' 'failed recovery'
reset_case; management=lost; expect FAIL '' 'lost management'
reset_case; echo invalid > "$RES/$name.inconclusive"; expect INCONCLUSIVE '' 'failed injection'
reset_case; name=16a-killswitch-off-reload; expect PASS '' 'other open cases cannot establish control'
reset_case; name=protected scenario_expect=noleak sig=0 leaks=0; expect INCONCLUSIVE '' 'protected case needs control'
reset_case; name=protected scenario_expect=noleak sig=0 leaks=0 CONTROL_OK=1; expect PASS 1 'protected case with valid evidence'
reset_case; name=protected scenario_expect=noleak sig=1 leaks=0 CONTROL_OK=1; expect FAIL 1 'captured leak'
reset_case; name=protected scenario_expect=noleak sig=0 leaks=1 CONTROL_OK=1; expect FAIL 1 'LAN leak'
reset_case; name=protected scenario_expect=noleak sig=0 leaks=0 CONTROL_OK=1 cap=dead; expect INCONCLUSIVE 1 'protected dead capture'
reset_case; name=protected scenario_expect=noleak sig=0 leaks=0 CONTROL_OK=1; echo failure > "$RES/$name.fail"; expect FAIL 1 'protected recovery failure'
reset_case
if check_results missing.sh 2>/dev/null; then echo 'missing result accepted'; exit 1; fi
printf 'PASS\n' > "$RES/one.verdict"
printf 'SKIP\n' > "$RES/two.verdict"
check_results one.sh two.sh
printf 'INCONCLUSIVE\n' > "$RES/two.verdict"
if check_results one.sh two.sh; then echo 'inconclusive result accepted'; exit 1; fi
printf 'garbage\n' > "$RES/two.verdict"
if check_results one.sh two.sh 2>/dev/null; then echo 'invalid result accepted'; exit 1; fi
echo "$checks verdict cases and 4 result-completeness checks passed"
