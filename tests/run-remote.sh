#!/bin/bash
# Convenience wrapper to run the NymVPN test suite from your laptop.
# Handles: device cleanup (local) -> sync scripts -> run tests (remote) -> fetch results.
#
# Usage:
#   NYM_MNEMONIC="..." ./tests/run-remote.sh [run-tests.sh options]
#
# Examples:
#   NYM_MNEMONIC="..." ./tests/run-remote.sh --release v1.26.1
#   NYM_MNEMONIC="..." ./tests/run-remote.sh --feed x86_64 aarch64
#   NYM_MNEMONIC="..." ./tests/run-remote.sh --release v1.26.1 --skip-cleanup
#
# Environment:
#   NYM_MNEMONIC    - 24-word account mnemonic (required)
#   TEST_HOST       - SSH host for the QEMU test machine (default: proxmox)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_HOST="${TEST_HOST:-omarchy}"
REMOTE_DIR="/opt/nym-vpn-test"

: "${NYM_MNEMONIC:?NYM_MNEMONIC environment variable must be set}"

# Parse our own flags (pass everything else through to run-tests.sh)
SKIP_CLEANUP=false
PASSTHROUGH_ARGS=()

for arg in "$@"; do
    if [[ "$arg" == "--skip-cleanup" ]]; then
        SKIP_CLEANUP=true
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done

# ---------------------------------------------------------------------------
# Step 1: Device cleanup (runs locally — needs Chromium/Playwright)
# ---------------------------------------------------------------------------

if ! $SKIP_CLEANUP; then
    echo "==> Step 1: Cleaning up registered Nym devices..."
    cd "${SCRIPT_DIR}/device-cleanup"

    if [[ ! -d node_modules ]]; then
        npm install
        npx playwright install chromium
    fi

    if NYM_MNEMONIC="$NYM_MNEMONIC" npx playwright test; then
        echo "==> Device cleanup complete"
    else
        echo "==> WARNING: Device cleanup failed (continuing anyway)"
    fi

    cd "$SCRIPT_DIR"
else
    echo "==> Skipping device cleanup (--skip-cleanup)"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Sync test scripts to remote host
# ---------------------------------------------------------------------------

echo "==> Step 2: Syncing test scripts to ${TEST_HOST}:${REMOTE_DIR}/"
rsync -az --delete \
    --exclude='node_modules' \
    --exclude='test-results' \
    --exclude='screenshots' \
    --exclude='results' \
    --exclude='images' \
    "${SCRIPT_DIR}/" "${TEST_HOST}:${REMOTE_DIR}/"

echo ""

# ---------------------------------------------------------------------------
# Step 3: Run tests on remote host
# ---------------------------------------------------------------------------

echo "==> Step 3: Running tests on ${TEST_HOST}..."
echo ""

# shellcheck disable=SC2029
ssh -t "$TEST_HOST" \
    "NYM_MNEMONIC='${NYM_MNEMONIC}' bash ${REMOTE_DIR}/run-tests.sh ${PASSTHROUGH_ARGS[*]}"

TEST_EXIT=$?
echo ""

# ---------------------------------------------------------------------------
# Step 4: Fetch results
# ---------------------------------------------------------------------------

echo "==> Step 4: Fetching results..."
mkdir -p "${SCRIPT_DIR}/results"
rsync -az "${TEST_HOST}:${REMOTE_DIR}/results/" "${SCRIPT_DIR}/results/"

LATEST=$(ls -t "${SCRIPT_DIR}/results/" 2>/dev/null | head -1)
if [[ -n "$LATEST" ]]; then
    echo ""
    echo "==> Results saved to: tests/results/${LATEST}/"
    echo ""
    cat "${SCRIPT_DIR}/results/${LATEST}/report.md"
fi

exit $TEST_EXIT
