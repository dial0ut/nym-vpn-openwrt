#!/usr/bin/env bash
# Destroy a test slot's three CTs and the dedicated LAN bridge.
#
# Usage: teardown.sh <slot>
# Idempotent: missing resources are silently skipped.

set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/ctl.sh"

SLOT="${1:?slot index required}"
BRIDGE="vmbr-test${SLOT}"

for ctid in "5${SLOT}0" "5${SLOT}1" "5${SLOT}2"; do
    ct_destroy "$ctid"
done

bridge_destroy "$BRIDGE"
