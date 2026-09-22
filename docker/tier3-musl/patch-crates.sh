#!/bin/bash
# Build-time patching for Tier 3 targets
#
# Patches crates from the cargo registry cache at build time instead of
# maintaining full crate copies in the repo. Version-agnostic — automatically
# finds whatever version cargo resolved.
#
# Usage:
#   ./patch-crates.sh [--ecash-only] <cargo-home> <target> <cargo-toml-path>
#
# Arguments:
#   --ecash-only    Only the in-place nym ecash fix, on 32-bit targets; no
#                   crate copies, Cargo.toml untouched. For the Tier 2 build
#                   (scripts/cross-compile-dynamic.sh). Run it after
#                   `cargo fetch`, so the nym git checkout exists.
#   cargo-home      Path to CARGO_HOME (e.g., /root/.cargo)
#   target          Rust target triple (e.g., mips-unknown-linux-musl)
#   cargo-toml-path Path to workspace Cargo.toml to append [patch.crates-io]
#
# The script will:
#   1. Find each crate in the cargo registry cache
#   2. Copy it to /tmp/patches/<crate-version>/
#   3. Apply sed patches to the copy
#   4. Append [patch.crates-io] entries to the workspace Cargo.toml

set -euo pipefail

# Every log line goes to stderr: several helpers hand a path back on stdout
# through $(...), where a log line would corrupt the path or swallow an
# error message (scripts/log.sh writes to stdout).
log_info() { echo -e "\033[0;32m[PATCH]\033[0m $1" >&2; }
log_error() { echo -e "\033[0;31m[PATCH ERROR]\033[0m $1" >&2; }

PATCH_MODE=all
if [ "${1:-}" = "--ecash-only" ]; then
    PATCH_MODE=ecash
    shift
fi
CARGO_HOME="${CARGO_HOME:-${1:-}}"
TARGET="${TARGET:-${2:-}}"
CARGO_TOML="${CARGO_TOML:-${3:-}}"
PATCH_DIR="${PATCH_DIR:-/tmp/patches}"

# Which patches a target needs follows from what rustc says the target
# lacks, not from a list of triple names that can miss one (armv7 and i686
# shipped without the ecash fix that way). load_target_cfg runs once in
# main, outside any pipeline, so a rustc failure stops the script instead
# of reading as "not needed".
TARGET_CFG=""
load_target_cfg() {
    if ! TARGET_CFG=$(rustc --print cfg --target "$TARGET") || [ -z "$TARGET_CFG" ]; then
        log_error "rustc cannot describe target '$TARGET'"
        exit 1
    fi
}

# Every 32-bit target: ecash serialises usize lengths, 4 bytes there.
needs_ecash_patch() {
    grep -qx 'target_pointer_width="32"' <<< "$TARGET_CFG"
}

# Targets without 64-bit atomics (mips, armv5te): std has no
# AtomicU64/AtomicI64 there, so those crates switch to portable-atomic.
needs_atomic_patches() {
    ! grep -qx 'target_has_atomic="64"' <<< "$TARGET_CFG"
}

# Get the version of a crate from Cargo.lock.
get_lock_version() {
    local name="$1"
    local cargo_lock_dir
    cargo_lock_dir=$(dirname "$CARGO_TOML")
    if [ -f "$cargo_lock_dir/Cargo.lock" ]; then
        awk '/^name = "'"$name"'"/{getline; if ($1 == "version") print $3}' \
            "$cargo_lock_dir/Cargo.lock" | tr -d '"' | head -1
    fi
}

# Download a crate from crates.io and extract to PATCH_DIR.
download_crate() {
    local name="$1"
    local version="$2"
    local dest="$PATCH_DIR/${name}-${version}"
    local url="https://crates.io/api/v1/crates/${name}/${version}/download"

    log_info "  downloading ${name}-${version} from crates.io..."
    mkdir -p "$PATCH_DIR"
    curl -fsSL "$url" | tar xz -C "$PATCH_DIR"
    if [ -d "$dest" ]; then
        echo "$dest"
    else
        log_error "Failed to download ${name}-${version}"
        return 1
    fi
}

# Find a crate directory in the cargo registry cache: exactly the version
# Cargo.lock resolved, or that version downloaded from crates.io (a fresh
# container where cargo fetch did not unpack it). Never another version: a
# patch for a version the lock does not use would be silently unused.
find_crate() {
    local name="$1"
    local version
    version=$(get_lock_version "$name")
    if [ -z "$version" ]; then
        log_error "'${name}' is not in Cargo.lock; nothing to patch"
        return 1
    fi

    local found=""
    if [ -d "$CARGO_HOME/registry/src" ]; then
        found=$(find "$CARGO_HOME/registry/src" -maxdepth 2 -name "${name}-${version}" -type d | head -1)
    fi
    if [ -z "$found" ]; then
        found=$(download_crate "$name" "$version") || return 1
    fi

    echo "$found"
}

# Copy a crate from the registry to PATCH_DIR and return the patch path.
# If the source is already in PATCH_DIR (downloaded from crates.io), skip copy.
copy_crate() {
    local src="$1"
    local dest="$PATCH_DIR/$(basename "$src")"
    if [ "$src" != "$dest" ]; then
        rm -rf "$dest"
        mkdir -p "$PATCH_DIR"
        cp -R "$src" "$dest"
    fi
    # Remove .cargo-checksum.json so cargo doesn't complain
    rm -f "$dest/.cargo-checksum.json"
    echo "$dest"
}

# Add portable-atomic dependency to a crate's Cargo.toml.
add_portable_atomic_dep() {
    local cargo_toml="$1/Cargo.toml"
    if grep -q 'portable-atomic' "$cargo_toml"; then
        log_info "  portable-atomic already present"
        return
    fi
    # Append after [dependencies] or at end of file
    cat >> "$cargo_toml" << 'EOF'

[dependencies.portable-atomic]
version = "1"
EOF
    log_info "  added portable-atomic dependency"
}

# Portable in-place sed (works on both macOS and GNU/Linux)
_sed_i() {
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

# ============================================================================
# Patch: boringtun
# ============================================================================
# Problem: Uses std::sync::atomic::AtomicU64 in rate_limiter.rs (same origin as gotatun)
# Fix: Import AtomicU64 from portable-atomic instead
patch_boringtun() {
    local dir="$1"
    log_info "Patching boringtun..."

    local f="$dir/src/noise/rate_limiter.rs"
    if grep -q 'std::sync::atomic.*AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicU64, Ordering};|use std::sync::atomic::Ordering;\nuse portable_atomic::AtomicU64;|' "$f"
        log_info "  patched src/noise/rate_limiter.rs"
    fi

    add_portable_atomic_dep "$dir"
}

# ============================================================================
# Patch: coarsetime
# ============================================================================
# Problem: Uses std::sync::atomic::AtomicU64 which doesn't exist on 32-bit
# Fix: Import AtomicU64 from portable-atomic instead
patch_coarsetime() {
    local dir="$1"
    log_info "Patching coarsetime..."

    local f
    for f in "$dir/src/clock.rs" "$dir/src/instant.rs"; do
        if grep -q 'std::sync::atomic.*AtomicU64' "$f"; then
            # Replace the combined import with separate lines
            _sed_i 's|use std::sync::atomic::{AtomicU64, Ordering};|use std::sync::atomic::Ordering;|' "$f"
            # Add portable-atomic import after the Ordering import
            _sed_i '/^use std::sync::atomic::Ordering;/a\
use portable_atomic::AtomicU64;' "$f"
            log_info "  patched $(basename "$f")"
        fi
    done

    add_portable_atomic_dep "$dir"
}

# ============================================================================
# Patch: prometheus
# ============================================================================
# Problem: Uses std::sync::atomic::{AtomicI64, AtomicU64} which don't exist on 32-bit
# Fix: Import both from portable-atomic instead
patch_prometheus() {
    local dir="$1"
    log_info "Patching prometheus..."

    # atomic64.rs: AtomicI64 + AtomicU64 aliased from std
    local f="$dir/src/atomic64.rs"
    if grep -q 'std::sync::atomic.*AtomicI64.*AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicI64 as StdAtomicI64, AtomicU64 as StdAtomicU64, Ordering};|use std::sync::atomic::Ordering;|' "$f"
        _sed_i '/^use std::sync::atomic::Ordering;/a\
use portable_atomic::{AtomicI64 as StdAtomicI64, AtomicU64 as StdAtomicU64};' "$f"
        log_info "  patched src/atomic64.rs"
    fi

    # histogram.rs: AtomicU64 as StdAtomicU64 from std (multi-line import)
    f="$dir/src/histogram.rs"
    if grep -q 'AtomicU64 as StdAtomicU64' "$f"; then
        _sed_i 's|atomic::{AtomicU64 as StdAtomicU64, Ordering},|atomic::Ordering,|' "$f"
        # Add portable-atomic import after the std::sync block
        _sed_i '/^use std::time/i\
use portable_atomic::AtomicU64 as StdAtomicU64;' "$f"
        log_info "  patched src/histogram.rs"
    fi

    # timer.rs: AtomicU64 from std (used directly, not aliased)
    f="$dir/src/timer.rs"
    if grep -q 'std::sync::atomic.*AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};|use std::sync::atomic::{AtomicBool, Ordering};\nuse portable_atomic::AtomicU64;|' "$f"
        log_info "  patched src/timer.rs"
    fi

    add_portable_atomic_dep "$dir"
}

# ============================================================================
# Patch: opentelemetry_sdk
# ============================================================================
# Problem: Uses std::sync::atomic::{AtomicI64, AtomicU64} in metrics module
# Fix: Import both from portable-atomic instead
patch_opentelemetry_sdk() {
    local dir="$1"
    log_info "Patching opentelemetry_sdk..."

    # metrics/internal/mod.rs: AtomicI64 + AtomicU64 in import with AtomicBool and AtomicUsize
    local f="$dir/src/metrics/internal/mod.rs"
    if [ -f "$f" ] && grep -q 'AtomicI64\|AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};|use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};\nuse portable_atomic::{AtomicI64, AtomicU64};|' "$f"
        log_info "  patched src/metrics/internal/mod.rs"
    fi

    # logs/logger_provider.rs: standalone AtomicU64 import
    f="$dir/src/logs/logger_provider.rs"
    if [ -f "$f" ] && grep -q 'std::sync::atomic::AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::AtomicU64;|use portable_atomic::AtomicU64;|' "$f"
        log_info "  patched src/logs/logger_provider.rs"
    fi

    add_portable_atomic_dep "$dir"
}

# ============================================================================
# Patch: gotatun (git dependency)
# ============================================================================
# Problem: Uses std::sync::atomic::AtomicU64 in noise module (rate_limiter, session)
# Fix: Import AtomicU64 from portable-atomic instead
# Note: gotatun is a git dependency, so we patch it in-place in the git checkout
patch_gotatun() {
    local dir="$1"
    log_info "Patching gotatun..."

    local f
    for f in "$dir/gotatun/src/noise/rate_limiter.rs" "$dir/gotatun/src/noise/session.rs"; do
        if [ -f "$f" ] && grep -q 'std::sync::atomic.*AtomicU64' "$f"; then
            _sed_i 's|use std::sync::atomic::{AtomicU64, Ordering};|use std::sync::atomic::Ordering;\nuse portable_atomic::AtomicU64;|' "$f"
            log_info "  patched $(echo "$f" | grep -o 'noise/.*')"
        fi
    done

    # Add portable-atomic dependency to the gotatun sub-crate
    local cargo_toml="$dir/gotatun/Cargo.toml"
    if [ -f "$cargo_toml" ]; then
        add_portable_atomic_dep "$dir/gotatun"
    fi
}

# The checkout of the revision Cargo.lock pins for <package>, from the
# repository whose checkout directories are named <repo>-<hash>. Fails
# rather than guess: patching another checkout patches nothing cargo builds.
find_git_checkout() {
    local package="$1" repo="$2"
    local cargo_lock
    cargo_lock="$(dirname "$CARGO_TOML")/Cargo.lock"
    local rev=""
    if [ -f "$cargo_lock" ]; then
        # source = "git+https://...#<full-rev>", within the package's entry
        rev=$(awk -v want="name = \"$package\"" '
                $0 == want { found = 1; next }
                found && /^\[\[package\]\]/ { exit }
                found && /^source = "git\+/ { print; exit }' "$cargo_lock" \
            | grep -o '#[a-f0-9]*' | tr -d '#') || true
    fi
    if [ -z "$rev" ]; then
        log_error "no git revision for '${package}' in $cargo_lock"
        return 1
    fi

    local found=""
    if [ -d "$CARGO_HOME/git/checkouts" ]; then
        # <repo>-<16 hex>/<short rev>: "nym-" alone would also match
        # another repository whose name starts with "nym-".
        found=$(find "$CARGO_HOME/git/checkouts" -mindepth 2 -maxdepth 2 -type d \
            -regextype posix-extended \
            -regex ".*/${repo}-[0-9a-f]{16}/${rev:0:7}[0-9a-f]*" | head -1)
    fi
    if [ -z "$found" ]; then
        log_error "no ${repo} checkout of ${rev:0:7} under $CARGO_HOME/git/checkouts (run cargo fetch first)"
        return 1
    fi
    echo "$found"
}

# Find the gotatun git checkout directory in CARGO_HOME.
find_gotatun() {
    find_git_checkout gotatun gotatun
}

# ============================================================================
# Patch: nym-compact-ecash (git dependency)
# ============================================================================
# Problem: VerificationKeyAuth::to_bytes() and SecretKeyAuth::to_bytes() use
#          usize::to_le_bytes() to serialize vector lengths. On 32-bit this
#          produces 4 bytes, but from_bytes() and the gateway (64-bit) expect
#          8 bytes (u64). This causes ZK proof challenge hash mismatch and
#          "the provided ticket failed to get verified" on all 32-bit platforms.
# Fix: Cast usize to u64 before calling to_le_bytes()
# A miss here still compiles and only fails at the gateway, so the patch
# checks its own result and stops the build unless both casts are in place.
patch_nym_ecash() {
    local dir="$1"
    log_info "Patching nym-compact-ecash (usize -> u64 in to_bytes)..."

    local f="$dir/common/nym_offline_compact_ecash/src/scheme/keygen.rs"
    if [ ! -f "$f" ]; then
        log_error "  keygen.rs not found at $f"
        exit 1
    fi

    if grep -q '&ys_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&ys_len\.to_le_bytes()|\&(ys_len as u64).to_le_bytes()|' "$f"
        log_info "  patched SecretKeyAuth::to_bytes()"
    fi

    if grep -q '&beta_g1_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&beta_g1_len\.to_le_bytes()|\&(beta_g1_len as u64).to_le_bytes()|' "$f"
        log_info "  patched VerificationKeyAuth::to_bytes()"
    fi

    local len
    for len in ys_len beta_g1_len; do
        if ! grep -qF "&(${len} as u64).to_le_bytes()" "$f"; then
            log_error "  ecash patch did not apply: no '(${len} as u64).to_le_bytes()' in $f"
            log_error "  the upstream code changed; update patch_nym_ecash"
            exit 1
        fi
    done
    # Any other usize length serialised the same way would break the same way.
    if grep -nE '&[a-z_]+_len\.to_le_bytes\(\)' "$f"; then
        log_error "  keygen.rs still serialises a usize length (above); update patch_nym_ecash"
        exit 1
    fi
}

# ============================================================================
# Patch: nym-gateway-client (git dependency)
# ============================================================================
# Problem: Uses std::sync::atomic::AtomicI64 which doesn't exist on 32-bit
# Fix: Import AtomicI64 from portable-atomic instead
patch_nym_gateway_client() {
    local dir="$1"
    log_info "Patching nym-gateway-client (AtomicI64 -> portable-atomic)..."

    local f="$dir/common/client-libs/gateway-client/src/bandwidth.rs"
    if [ ! -f "$f" ]; then
        log_error "  bandwidth.rs not found at $f"
        exit 1
    fi

    if grep -q 'std::sync::atomic.*AtomicI64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};|use std::sync::atomic::{AtomicBool, Ordering};\nuse portable_atomic::AtomicI64;|' "$f"
        log_info "  patched bandwidth.rs"
    fi

    # Add portable-atomic dependency to gateway-client's Cargo.toml
    local cargo_toml="$dir/common/client-libs/gateway-client/Cargo.toml"
    if [ -f "$cargo_toml" ]; then
        add_portable_atomic_dep "$dir/common/client-libs/gateway-client"
    fi
}

# ============================================================================
# Patch: nym-lp (git dependency)
# ============================================================================
# Problem: Uses std::sync::atomic::AtomicU64 which doesn't exist on 32-bit
# Fix: Import AtomicU64 from portable-atomic instead
patch_nym_lp() {
    local dir="$1"
    log_info "Patching nym-lp (AtomicU64 -> portable-atomic)..."

    local f="$dir/common/nym-lp/src/session.rs"
    if [ ! -f "$f" ]; then
        log_error "  session.rs not found at $f"
        exit 1
    fi

    if grep -q 'std::sync::atomic.*AtomicU64' "$f"; then
        _sed_i 's|use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};|use std::sync::atomic::{AtomicBool, Ordering};\nuse portable_atomic::AtomicU64;|' "$f"
        log_info "  patched session.rs"
    fi

    # Add portable-atomic dependency to nym-lp's Cargo.toml
    local cargo_toml="$dir/common/nym-lp/Cargo.toml"
    if [ -f "$cargo_toml" ]; then
        add_portable_atomic_dep "$dir/common/nym-lp"
    fi
}

# Find the nym git checkout directory in CARGO_HOME (the nym crates share
# one checkout; nym-compact-ecash pins its revision).
find_nym() {
    find_git_checkout nym-compact-ecash nym
}

# ============================================================================
# Patch: schemars
# ============================================================================
# Problem: autocfg probe fails on Docker volume mounts -> indexmap compiles in
#          no_std mode -> schemars expects different IndexMap generic signature
# Fix: Always use BTreeMap, remove IndexMap cfg-gated type aliases
patch_schemars() {
    local dir="$1"
    log_info "Patching schemars..."

    local f="$dir/src/lib.rs"
    # Remove cfg guards on BTreeMap aliases and delete IndexMap aliases entirely
    _sed_i '/#\[cfg(not(feature = "preserve_order"))\]/d' "$f"
    _sed_i '/#\[cfg(feature = "preserve_order")\]/d' "$f"
    _sed_i '/indexmap::IndexMap/d' "$f"
    _sed_i '/indexmap::map::Entry/d' "$f"

    log_info "  patched src/lib.rs"
}

# ============================================================================
# Main
# ============================================================================
# The nym ecash fix, in place in the nym git checkout. Every 32-bit target
# needs it, Tier 2 (armv7, i686) as much as Tier 3.
apply_nym_ecash_patch() {
    if ! needs_ecash_patch; then
        log_info "64-bit target: ecash serialises 8-byte lengths already"
        return
    fi
    log_info "32-bit target detected — applying the ecash usize fix"
    local nym_dir
    nym_dir=$(find_nym)
    patch_nym_ecash "$nym_dir"
}

main() {
    if [ -z "$CARGO_HOME" ] || [ -z "$TARGET" ] || [ -z "$CARGO_TOML" ]; then
        echo "Usage: $0 [--ecash-only] <cargo-home> <target> <cargo-toml-path>" >&2
        echo "  Or set CARGO_HOME, TARGET, CARGO_TOML environment variables" >&2
        exit 1
    fi

    load_target_cfg

    if [ "$PATCH_MODE" = ecash ]; then
        log_info "=== ecash patch for target: ${TARGET} ==="
        apply_nym_ecash_patch
        return
    fi

    log_info "=== Build-time crate patching for target: ${TARGET} ==="
    mkdir -p "$PATCH_DIR"

    # The entries below go into a new [patch.crates-io] table, and TOML
    # allows only one. Skipping here once disabled every tier-3 patch.
    if grep -q '^\[patch\.crates-io\]' "$CARGO_TOML"; then
        log_error "$CARGO_TOML already has a [patch.crates-io] table; merge its entries into this script's or patch from a fresh copy"
        exit 1
    fi

    # Determine which patches to apply
    local patches=""

    # schemars: needed for all Tier 3 targets (autocfg/indexmap issue)
    local schemars_src schemars_dir
    schemars_src=$(find_crate "schemars")
    schemars_dir=$(copy_crate "$schemars_src")
    patch_schemars "$schemars_dir"
    patches="schemars = { path = \"$schemars_dir\" }"

    # coarsetime, prometheus, ...: only where std has no AtomicU64
    if needs_atomic_patches; then
        log_info "No 64-bit atomics — applying portable-atomic patches"

        local coarsetime_src coarsetime_dir
        coarsetime_src=$(find_crate "coarsetime")
        coarsetime_dir=$(copy_crate "$coarsetime_src")
        patch_coarsetime "$coarsetime_dir"

        local prometheus_src prometheus_dir
        prometheus_src=$(find_crate "prometheus")
        prometheus_dir=$(copy_crate "$prometheus_src")
        patch_prometheus "$prometheus_dir"

        local boringtun_src boringtun_dir
        boringtun_src=$(find_crate "boringtun")
        boringtun_dir=$(copy_crate "$boringtun_src")
        patch_boringtun "$boringtun_dir"

        local otel_sdk_src otel_sdk_dir
        otel_sdk_src=$(find_crate "opentelemetry_sdk")
        otel_sdk_dir=$(copy_crate "$otel_sdk_src")
        patch_opentelemetry_sdk "$otel_sdk_dir"

        patches="${patches}
coarsetime = { path = \"$coarsetime_dir\" }
prometheus = { path = \"$prometheus_dir\" }
boringtun = { path = \"$boringtun_dir\" }
opentelemetry_sdk = { path = \"$otel_sdk_dir\" }"

        # gotatun: git dependency — patch in-place in git checkout
        local gotatun_dir
        gotatun_dir=$(find_gotatun)
        patch_gotatun "$gotatun_dir"

        # nym crates: git dependency — patch in-place in git checkout
        local nym_dir
        nym_dir=$(find_nym)
        patch_nym_gateway_client "$nym_dir"
        patch_nym_lp "$nym_dir"
    fi

    apply_nym_ecash_patch

    # Append [patch.crates-io] to Cargo.toml
    cat >> "$CARGO_TOML" << PATCH_EOF

# Tier 3 build-time patches (applied by patch-crates.sh)
[patch.crates-io]
${patches}
PATCH_EOF

    log_info "Cargo.toml patched successfully"
    log_info "Patch directory: $PATCH_DIR"
}

# Allow sourcing for testing individual functions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
