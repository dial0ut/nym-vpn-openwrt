# shellcheck shell=bash
# Pass/fail recording. Source me.
#
# Each case appends one line to $RESULTS_FILE in the form:
#   STATUS|case_name|elapsed_seconds|note
# where STATUS is PASS / FAIL / SKIP.

set -euo pipefail

: "${RESULTS_FILE:?RESULTS_FILE must be set by the slot runner}"

_case_start_ts=0
_case_name=""

case_begin() {
    _case_name="$1"
    _case_start_ts=$(date +%s)
}

case_pass() {
    local elapsed=$(( $(date +%s) - _case_start_ts ))
    printf 'PASS|%s|%d|%s\n' "$_case_name" "$elapsed" "${1:-}" >> "$RESULTS_FILE"
}

case_fail() {
    local elapsed=$(( $(date +%s) - _case_start_ts ))
    printf 'FAIL|%s|%d|%s\n' "$_case_name" "$elapsed" "${1:-no reason given}" >> "$RESULTS_FILE"
}

case_skip() {
    local elapsed=$(( $(date +%s) - _case_start_ts ))
    printf 'SKIP|%s|%d|%s\n' "$_case_name" "$elapsed" "${1:-}" >> "$RESULTS_FILE"
}

# Boolean asserts. Each returns 0/1 and prints a one-line failure note.
assert_eq() {
    local expected="$1" actual="$2" what="$3"
    if [ "$expected" = "$actual" ]; then return 0; fi
    echo "  $what: expected '$expected', got '$actual'" >&2
    return 1
}

assert_match() {
    local pattern="$1" actual="$2" what="$3"
    if echo "$actual" | grep -qE "$pattern"; then return 0; fi
    echo "  $what: '$actual' did not match /$pattern/" >&2
    return 1
}

# Pass if `pct_sh CTID 'curl ...'` succeeds within timeout (i.e. reachable).
ct_reachable() {
    local ctid="$1" url="$2" timeout="${3:-5}"
    pct_sh "$ctid" "curl -fsS --max-time $timeout -o /dev/null '$url' >/dev/null 2>&1"
}

# Pass if the URL is NOT reachable (timeout or rejection).
ct_unreachable() {
    local ctid="$1" url="$2" timeout="${3:-5}"
    ! ct_reachable "$ctid" "$url" "$timeout"
}
