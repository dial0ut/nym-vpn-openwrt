#!/bin/bash
# Fail when a Cargo.lock records a [patch] entry cargo did not use. An unused
# patch does nothing and says so only as a build warning: the bls12_381
# patch sat unused for months that way, and a tier-3 crate patch that misses
# its version would ship the unpatched crate.
#
# Usage: scripts/ci/check-cargo-patches.sh <Cargo.lock>
#   CI runs it on the committed lock; the tier-3 build runs it on the lock
#   cargo rewrote after patch-crates.sh added its [patch.crates-io].
set -euo pipefail

lock="${1:?usage: $0 <Cargo.lock>}"
[ -f "$lock" ] || { echo "error: $lock not found" >&2; exit 1; }

if grep -q '^\[\[patch\.unused\]\]' "$lock"; then
    echo "::error::$lock lists [patch] entries cargo did not use:" >&2
    awk '/^\[\[patch\.unused\]\]/ { p = 1; next } /^\[/ { p = 0 } p && NF' "$lock" >&2
    exit 1
fi
echo "cargo patches: none unused in $lock"
