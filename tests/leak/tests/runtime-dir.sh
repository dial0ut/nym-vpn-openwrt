#!/bin/bash
# Exercise the scenario's backend-specific recovery gate without a router.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
failures=0
rt() { :; }
log() { :; }
sleep() { :; }
probes() { :; }
state() { echo "$observed"; }
lan_probe() { echo 'egress=blocked'; }
wait_state() { echo 1; }
recovered() { :; }
not_recovered() { failures=$((failures+1)); }
for LEAK_FW in fw3 fw4; do
    # shellcheck source=../scenarios/15-untrusted-runtime-dir.sh
    . "$HERE/scenarios/15-untrusted-runtime-dir.sh"
    if [ "$LEAK_FW" = fw3 ]; then
        [ "$scenario_expect" = noleak ]
    else
        [ "$scenario_expect" = leak ]
    fi
    observed='policy=no boot=yes marker=no'
    failures=0; scenario_check; [ "$failures" = 0 ]
    observed='policy=yes boot=no marker=no'
    failures=0; scenario_check
    if [ "$LEAK_FW" = fw3 ]; then [ "$failures" = 0 ]; else [ "$failures" = 1 ]; fi
    observed='policy=no boot=no marker=no'
    failures=0; scenario_check; [ "$failures" = 1 ]
    observed='policy=yes boot=yes marker=yes'
    failures=0; scenario_check; [ "$failures" = 1 ]
done
echo 'fw3/fw4 runtime-directory expectations and recovery gates passed'
