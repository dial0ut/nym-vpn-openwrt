#!/usr/bin/env bash
# Top-level harness driver. Spawns one slot per line in versions.conf, runs
# them in parallel, waits, aggregates results into a single markdown report.
#
# Usage:
#   ./run.sh                # all versions in versions.conf
#   ./run.sh --serial       # one slot at a time (useful for debugging)
#   ./run.sh --slot 2       # only slot 2
#   ./run.sh --slot 1 --slot 3
#
# Reads .env from the same directory. Bails out if NYM_MNEMONIC is empty.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HARNESS_DIR" || exit 2

# ---- load .env ----
if [ ! -f "$HARNESS_DIR/.env" ]; then
    echo "error: $HARNESS_DIR/.env not found. Copy .env.example to .env and fill it in." >&2
    exit 2
fi
set -a
# shellcheck disable=SC1091
source "$HARNESS_DIR/.env"
set +a

: "${NYM_MNEMONIC:?NYM_MNEMONIC is empty in .env}"
: "${PROXMOX_HOST:=proxmox}"
export NYM_MNEMONIC PROXMOX_HOST

# ---- arg parse ----
SERIAL=0
SELECTED_SLOTS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --serial) SERIAL=1; shift ;;
        --slot)   SELECTED_SLOTS+=("$2"); shift 2 ;;
        -h|--help)
            sed -n '2,/^$/s/^# \?//p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ---- assemble run list from versions.conf ----
declare -a RUN_SLOTS=()
declare -a RUN_VERSIONS=()
while IFS=: read -r slot version; do
    case "$slot" in ''|'#'*) continue ;; esac
    if [ ${#SELECTED_SLOTS[@]} -gt 0 ]; then
        # shellcheck disable=SC2199
        case " ${SELECTED_SLOTS[@]} " in *" $slot "*) ;; *) continue ;; esac
    fi
    RUN_SLOTS+=("$slot")
    RUN_VERSIONS+=("$version")
done < "$HARNESS_DIR/versions.conf"

if [ ${#RUN_SLOTS[@]} -eq 0 ]; then
    echo "no slots selected" >&2
    exit 2
fi

# ---- results dir ----
TS=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_DIR="$HARNESS_DIR/runs/$TS"
mkdir -p "$RESULTS_DIR"
echo "results: $RESULTS_DIR"

# ---- prefetch templates (serial; avoids concurrent slot fetches racing
#      over the same shared alpine template).
# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/ctl.sh"
echo "prefetch: alpine template"
template_ensure_alpine >/dev/null
for version in "${RUN_VERSIONS[@]}"; do
    echo "prefetch: openwrt $version template"
    template_ensure_openwrt "$version" >/dev/null
done

# ---- launch slots ----
# Every slot's exit code is kept: a slot that dies before writing results is
# a failed run, not an empty row.
declare -A PIDS
declare -A SLOT_RC
for i in "${!RUN_SLOTS[@]}"; do
    slot="${RUN_SLOTS[$i]}"
    version="${RUN_VERSIONS[$i]}"
    echo "launching slot $slot ($version)"
    if [ "$SERIAL" -eq 1 ]; then
        rc=0
        "$HARNESS_DIR/run-slot.sh" "$slot" "$version" "$RESULTS_DIR" || rc=$?
        SLOT_RC[$slot]=$rc
    else
        "$HARNESS_DIR/run-slot.sh" "$slot" "$version" "$RESULTS_DIR" &
        PIDS[$slot]=$!
    fi
done

# ---- wait for parallel slots ----
if [ "$SERIAL" -eq 0 ]; then
    for slot in "${!PIDS[@]}"; do
        rc=0
        wait "${PIDS[$slot]}" || rc=$?
        SLOT_RC[$slot]=$rc
        echo "slot $slot done (rc=$rc)"
    done
fi

# ---- aggregate report ----
REPORT="$RESULTS_DIR/report.md"
{
    echo "# NymVPN OpenWrt Harness Report"
    echo ""
    echo "**Run:** $TS"
    echo "**Versions:** ${RUN_VERSIONS[*]}"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Slot | Version | Total | Pass | Fail | Skip |"
    echo "|-----:|:--------|------:|-----:|-----:|-----:|"
    total_pass=0
    total_fail=0
    total_skip=0
    slot_failures=0
    for i in "${!RUN_SLOTS[@]}"; do
        slot="${RUN_SLOTS[$i]}"
        version="${RUN_VERSIONS[$i]}"
        rf="$RESULTS_DIR/slot-${slot}.results"
        rc="${SLOT_RC[$slot]:-1}"
        if [ ! -s "$rf" ]; then
            # No results at all: the slot never got as far as a case. Count
            # it as a failure so an aborted run cannot look like a clean one.
            echo "| $slot | $version | (no results, slot rc=$rc) | - | 1 | - |"
            total_fail=$((total_fail + 1))
            slot_failures=$((slot_failures + 1))
            continue
        fi
        p=$(grep -c '^PASS|' "$rf" || true)
        f=$(grep -c '^FAIL|' "$rf" || true)
        s=$(grep -c '^SKIP|' "$rf" || true)
        t=$((p + f + s))
        total_pass=$((total_pass + p))
        total_fail=$((total_fail + f))
        total_skip=$((total_skip + s))
        if [ "$rc" -ne 0 ]; then
            slot_failures=$((slot_failures + 1))
            echo "| $slot | $version | $t | $p | $f | $s | slot rc=$rc |"
        else
            echo "| $slot | $version | $t | $p | $f | $s |"
        fi
    done
    echo ""
    echo "**Overall:** $total_pass passed, $total_fail failed, $total_skip skipped, $slot_failures slot(s) exited non-zero"
    echo ""
    echo "## Per-case results"
    echo ""
    for i in "${!RUN_SLOTS[@]}"; do
        slot="${RUN_SLOTS[$i]}"
        version="${RUN_VERSIONS[$i]}"
        rf="$RESULTS_DIR/slot-${slot}.results"
        echo "### Slot $slot — OpenWrt $version"
        echo ""
        if [ ! -f "$rf" ]; then
            echo "_no results file_"
            echo ""
            continue
        fi
        echo "| Status | Case | Time | Note |"
        echo "|:------:|:-----|-----:|:-----|"
        while IFS='|' read -r status name elapsed note; do
            echo "| $status | $name | ${elapsed}s | $note |"
        done < "$rf"
        echo ""
        echo "[log](slot-${slot}.log)"
        echo ""
    done
} > "$REPORT"

echo ""
echo "==== Report ===="
cat "$REPORT"
echo "================"
echo "full report: $REPORT"

# Exit nonzero if any case failed, any slot produced no results, or any slot
# runner exited non-zero.
if [ "$total_fail" -gt 0 ] || [ "$slot_failures" -gt 0 ]; then
    exit 1
fi
