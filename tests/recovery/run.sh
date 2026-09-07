#!/bin/bash
# Recovery and management-access evidence suite (fw4 test bed).
#
#   ./run.sh            run all scenarios in order
#   ./run.sh 2 5        run selected scenarios
#
# Requires ssh access to the router (ROUTER), its LAN client (LAN) and the
# hypervisor owning the router's WAN interface (HOST); see lib.sh for the
# variables. Writes results/<scenario>.log, results/verdicts.log and pcaps
# under $CAP_DIR on the hypervisor. Leaves the router connected with the
# kill-switch on when done.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=scenarios.sh
source "$HERE/scenarios.sh"

if [ $# -eq 0 ]; then set -- 1 2 3 4 5 6 7 8; fi
for n in "$@"; do
    "s$n" || echo "scenario s$n returned $?" >&2
done
echo
echo "== verdicts =="
cat "$RESULTS/verdicts.log"
