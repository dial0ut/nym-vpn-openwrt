#!/usr/bin/env bash
# Run all test cases for a single slot.
#
# Usage: run-slot.sh <slot> <openwrt_version> <results_dir>
#
# Behavior:
#   1. provision.sh brings up bridge + 3 CTs (OpenWrt router, LAN client,
#      DNS logger). The OpenWrt CT runs procd as init.
#   2. Install nym-vpn inside the OpenWrt CT from the package under test
#      (see "Package selection" below). The package's postinst enables and
#      starts the daemon through /etc/init.d/nym-vpnd, i.e. under procd —
#      nothing here launches the daemon by hand.
#   3. Wait for the daemon and assert procd owns it (`ubus call service list`).
#   4. Register the account on the OpenWrt CT (NYM_MNEMONIC env).
#   5. Source each cases/*.sh in lexical order. Each case records exactly
#      one "STATUS|name|elapsed|note" line (STATUS: PASS, FAIL or SKIP) and
#      may print to slot-<N>.log. A case that exits before recording is a
#      FAIL; a selected case that recorded nothing is MISSING. Both make the
#      slot exit non-zero.
#   6. EXIT trap forgets the account (server-side device slot freed) and
#      tears down the slot.
#
# Package selection (env, all optional; see .env.example):
#   NYM_PKG_FILE            one file for every slot (overrides the rest)
#   NYM_PKG_APK / NYM_PKG_IPK
#                           chosen by OpenWrt version: 25.x and later use apk,
#                           older releases use ipk
#   NYM_PKG_APK_PREV / NYM_PKG_IPK_PREV
#                           when set, the slot installs this OLDER package
#                           first and cases/10-upgrade.sh upgrades it to the
#                           package under test while polling the kill-switch
#   NYM_FEED_INSTALL_URL    fallback when no package is given: the public
#                           feed's install script (not the revision under test)

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
# The sourced helpers turn on set -e; this runner must keep going after a
# failing step so that it can record the failure.
set +e

# ---------- package selection ----------
pkg_for_version() {
    # $1 = "current" or "prev"; prints the package path or nothing.
    local which="$1" major="${VERSION%%.*}"
    if [ "$which" = current ] && [ -n "${NYM_PKG_FILE:-}" ]; then
        echo "$NYM_PKG_FILE"; return
    fi
    local fmt=ipk
    [ "$major" -ge 25 ] && fmt=apk
    local var="NYM_PKG_${fmt^^}"
    [ "$which" = prev ] && var="${var}_PREV"
    echo "${!var:-}"
}
PKG_CURRENT="$(pkg_for_version current)"
PKG_PREV="$(pkg_for_version prev)"
export PKG_CURRENT PKG_PREV

# ---------- 1. provision ----------
echo "==> provisioning"
SUMMARY=$("$HARNESS_DIR/provision.sh" "$SLOT" "$VERSION") || {
    echo "provision failed; aborting slot"
    printf 'FAIL|provision|0|provision.sh exited nonzero\n' >> "$RESULTS_FILE"
    "$HARNESS_DIR/teardown.sh" "$SLOT" || true
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
case_begin install
initial_pkg="${PKG_PREV:-$PKG_CURRENT}"
if [ -n "$initial_pkg" ]; then
    echo "==> installing nym-vpn from $initial_pkg"
    if vpn_pkg_install "$OPENWRT_CTID" "$initial_pkg"; then
        case_pass "$(vpn_version "$OPENWRT_CTID") from $(basename "$initial_pkg")"
    else
        case_fail "package install failed: $(basename "$initial_pkg")"
        exit 1
    fi
else
    echo "==> installing nym-vpn (feed install script — NOT the revision under test)"
    if pct_sh "$OPENWRT_CTID" "wget -qO- '${NYM_FEED_INSTALL_URL:-https://packages.dial0ut.org/install.sh}' | sh >/dev/null 2>&1"; then
        case_pass "$(vpn_version "$OPENWRT_CTID") from public feed"
    else
        case_fail "install script failed"
        exit 1
    fi
fi

# ---------- 3. daemon under procd ----------
echo "==> waiting for the daemon procd started"
case_begin daemon-up
if vpn_daemon_wait "$OPENWRT_CTID" 30; then
    if vpn_daemon_under_procd "$OPENWRT_CTID"; then
        case_pass "procd instance running, pid $(pct_sh "$OPENWRT_CTID" 'pidof nym-vpnd')"
    else
        case_fail "daemon answers but procd does not list it as running"
        vpn_dump "$OPENWRT_CTID"
        exit 1
    fi
else
    case_fail "daemon did not come up under procd within 30s"
    vpn_dump "$OPENWRT_CTID"
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
# Every case must leave exactly one STATUS|name|... line behind. A case that
# exits early (set -e in a helper, a killed ssh) would otherwise leave no line,
# and the verdict below only sees explicit FAIL lines — so an aborted case is
# recorded as a FAIL here, with its exit code, instead of vanishing.
shopt -s nullglob
for case_file in "$HARNESS_DIR"/cases/*.sh; do
    case_name=$(basename "$case_file" .sh)
    # cases call case_begin with the file name minus its ordering prefix
    result_name="${case_name#[0-9]*-}"
    echo "---- $case_name ----"
    lines_before=$(grep -c . "$RESULTS_FILE" || true)
    rc=0
    # shellcheck disable=SC1090
    ( source "$case_file" ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "($case_name) exited $rc"
        if [ "$(grep -c . "$RESULTS_FILE" || true)" -eq "$lines_before" ]; then
            printf 'FAIL|%s|0|exited %d before recording a result\n' "$result_name" "$rc" >> "$RESULTS_FILE"
        fi
    fi
done

# Second net: one result line per selected case, whatever path it took. A
# case that left nothing is MISSING (not run, not skipped, not failed — the
# harness cannot say what happened), which fails the run like a FAIL does.
for case_file in "$HARNESS_DIR"/cases/*.sh; do
    result_name="$(basename "$case_file" .sh)"; result_name="${result_name#[0-9]*-}"
    n=$(grep -c "^[A-Z]*|${result_name}|" "$RESULTS_FILE" || true)
    if [ "$n" -eq 0 ]; then
        printf 'MISSING|%s|0|selected case recorded no result\n' "$result_name" >> "$RESULTS_FILE"
    elif [ "$n" -gt 1 ]; then
        printf 'FAIL|%s|0|case recorded %d results, expected one\n' "$result_name" "$n" >> "$RESULTS_FILE"
    fi
done

echo "==> slot $SLOT finished at $(date -u +%FT%TZ)"
if grep -qE '^(FAIL|MISSING)\|' "$RESULTS_FILE"; then
    exit 1
fi
