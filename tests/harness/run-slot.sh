#!/usr/bin/env bash
# Run all test cases for a single slot.
#
# Usage: run-slot.sh <slot> <openwrt_version> <results_dir>
#
# Behavior:
#   1. provision.sh brings up bridge + 3 CTs.
#   2. Install nym-vpn from the package feed inside the OpenWrt CT.
#   3. Register the account on the OpenWrt CT (NYM_MNEMONIC env).
#   4. Source each cases/*.sh in lexical order. Each case appends one
#      "STATUS|name|elapsed|note" line to results.txt and may print to
#      slot-<N>.log.
#   5. EXIT trap forgets the account (server-side device slot freed) and
#      tears down the slot.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SLOT="${1:?slot index required}"
VERSION="${2:?openwrt version required}"
RESULTS_DIR="${3:?results dir required}"

# Per-slot artifacts
LOG_FILE="$RESULTS_DIR/slot-${SLOT}.log"
RESULTS_FILE="$RESULTS_DIR/slot-${SLOT}.results"
: > "$RESULTS_FILE"
exec >>"$LOG_FILE" 2>&1

echo "==> slot $SLOT version $VERSION started at $(date -u +%FT%TZ)"

# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/ctl.sh"
# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/vpn.sh"
export RESULTS_FILE
# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/assert.sh"

# ---------- 1. provision ----------
echo "==> provisioning"
SUMMARY=$("$HARNESS_DIR/provision.sh" "$SLOT" "$VERSION") || {
    echo "provision failed; aborting slot"
    printf 'FAIL|provision|0|provision.sh exited nonzero\n' >> "$RESULTS_FILE"
    exit 1
}
echo "$SUMMARY"
# shellcheck disable=SC2046
eval $(echo "$SUMMARY" | grep -E '^(OPENWRT_CTID|CLIENT_CTID|DNS_CTID|LAN_GW|DNS_IP|CLIENT_IP|BRIDGE)=')
export OPENWRT_CTID CLIENT_CTID DNS_CTID LAN_GW DNS_IP CLIENT_IP BRIDGE SLOT VERSION

# Teardown trap — runs on success and on every failure path. Account forget
# frees the server-side device slot so the matrix can re-run.
cleanup() {
    local rc=$?
    echo "==> cleanup (exit rc=$rc)"
    vpn_account_forget "$OPENWRT_CTID" || true
    "$HARNESS_DIR/teardown.sh" "$SLOT" || true
    return "$rc"
}
trap cleanup EXIT INT TERM

# ---------- 2. install nym-vpn ----------
echo "==> installing nym-vpn (curl feed)"
case_begin install
if pct_sh "$OPENWRT_CTID" 'wget -qO- https://packages.dial0ut.org/install.sh | sh >/dev/null 2>&1'; then
    case_pass "$(pct_sh "$OPENWRT_CTID" 'nym-vpnc --version 2>&1' | head -1)"
else
    case_fail "install script failed"
    exit 1
fi

# ---------- 3. start daemon ----------
echo "==> starting daemon"
case_begin daemon-up
if vpn_daemon_start "$OPENWRT_CTID"; then
    case_pass
else
    case_fail "daemon did not come up"
    exit 1
fi

# ---------- 4. register account ----------
echo "==> registering account"
case_begin account-set
if vpn_account_set "$OPENWRT_CTID" && vpn_wait_ready "$OPENWRT_CTID" 120; then
    case_pass
else
    case_fail "account did not reach ReadyToConnect within 120s"
    vpn_dump "$OPENWRT_CTID"
    exit 1
fi

# ---------- 5. run cases ----------
echo "==> running cases"
shopt -s nullglob
for case_file in "$HARNESS_DIR"/cases/*.sh; do
    case_name=$(basename "$case_file" .sh)
    echo "---- $case_name ----"
    # shellcheck disable=SC1090
    if ! ( source "$case_file" ); then
        echo "($case_name) returned non-zero, continuing"
    fi
done

echo "==> slot $SLOT finished at $(date -u +%FT%TZ)"
