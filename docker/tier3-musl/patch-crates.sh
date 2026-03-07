#!/bin/bash
# Build-time patching for Tier 3 targets
#
# Patches crates from the cargo registry cache at build time instead of
# maintaining full crate copies in the repo. Version-agnostic — automatically
# finds whatever version cargo resolved.
#
# Usage:
#   ./patch-crates.sh <cargo-home> <target> <cargo-toml-path>
#
# Arguments:
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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[PATCH]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[PATCH]${NC} $1" >&2; }
log_error() { echo -e "${RED}[PATCH]${NC} $1" >&2; }

CARGO_HOME="${CARGO_HOME:-${1:-}}"
TARGET="${TARGET:-${2:-}}"
CARGO_TOML="${CARGO_TOML:-${3:-}}"
PATCH_DIR="/tmp/patches"

is_32bit_target() {
    [[ "$TARGET" == mips* ]] || [[ "$TARGET" == armv5te* ]]
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

# Find a crate directory in the cargo registry cache by name.
# Uses Cargo.lock to determine the exact version. Falls back to downloading
# from crates.io if not found in the registry (e.g., fresh Docker container
# where cargo fetch hasn't fully populated the cache).
find_crate() {
    local name="$1"
    local version
    version=$(get_lock_version "$name")

    local found=""
    if [ -n "$version" ]; then
        # Look for exact version match in registry cache
        found=$(find "$CARGO_HOME/registry/src" -maxdepth 2 -name "${name}-${version}" -type d 2>/dev/null | head -1)
    fi

    # Fallback: find any version in registry cache
    if [ -z "$found" ]; then
        found=$(find "$CARGO_HOME/registry/src" -maxdepth 2 -name "${name}-*" -type d 2>/dev/null \
            | grep -E "/${name}-[0-9]" \
            | sort -V \
            | tail -1)
    fi

    # Final fallback: download from crates.io
    if [ -z "$found" ]; then
        if [ -n "$version" ]; then
            found=$(download_crate "$name" "$version")
        else
            log_error "Could not find '${name}' in cargo registry and no version in Cargo.lock"
            return 1
        fi
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

# Find the gotatun git checkout directory in CARGO_HOME.
# Uses Cargo.lock to determine the exact revision.
find_gotatun() {
    local cargo_lock_dir
    cargo_lock_dir=$(dirname "$CARGO_TOML")
    local rev=""
    if [ -f "$cargo_lock_dir/Cargo.lock" ]; then
        # Extract git rev from: source = "git+https://...#<full-rev>"
        rev=$(awk '/^name = "gotatun"/{found=1} found && /^source =.*gotatun/{print; exit}' \
            "$cargo_lock_dir/Cargo.lock" | grep -o '#[a-f0-9]*' | tr -d '#')
    fi

    local short_rev="${rev:0:7}"
    if [ -n "$short_rev" ]; then
        local found
        found=$(find "$CARGO_HOME/git/checkouts" -maxdepth 2 -type d -name "${short_rev}*" \
            -path "*/gotatun-*/*" 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            echo "$found"
            return
        fi
    fi

    # Fallback: use most recent checkout
    find "$CARGO_HOME/git/checkouts/gotatun-"*/  -maxdepth 1 -type d 2>/dev/null \
        | grep -v '\.git' | tail -1
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
patch_nym_ecash() {
    local dir="$1"
    log_info "Patching nym-compact-ecash (usize -> u64 in to_bytes)..."

    local f="$dir/common/nym_offline_compact_ecash/src/scheme/keygen.rs"
    if [ ! -f "$f" ]; then
        log_warn "  keygen.rs not found at $f — skipping"
        return
    fi

    if grep -q '&ys_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&ys_len\.to_le_bytes()|\&(ys_len as u64).to_le_bytes()|' "$f"
        log_info "  patched SecretKeyAuth::to_bytes()"
    fi

    if grep -q '&beta_g1_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&beta_g1_len\.to_le_bytes()|\&(beta_g1_len as u64).to_le_bytes()|' "$f"
        log_info "  patched VerificationKeyAuth::to_bytes()"
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
        log_warn "  bandwidth.rs not found at $f — skipping"
        return
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

# Find the nym git checkout directory in CARGO_HOME.
find_nym() {
    local cargo_lock_dir
    cargo_lock_dir=$(dirname "$CARGO_TOML")
    local rev=""
    if [ -f "$cargo_lock_dir/Cargo.lock" ]; then
        rev=$(awk '/^name = "nym-compact-ecash"/{found=1} found && /^source =.*nymtech\/nym/{print; exit}' \
            "$cargo_lock_dir/Cargo.lock" | grep -o '#[a-f0-9]*' | tr -d '#')
    fi

    local short_rev="${rev:0:7}"
    if [ -n "$short_rev" ]; then
        local found
        found=$(find "$CARGO_HOME/git/checkouts" -maxdepth 2 -type d -name "${short_rev}*" \
            -path "*/nym-*/*" 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            echo "$found"
            return
        fi
    fi

    # Fallback: use most recent checkout
    find "$CARGO_HOME/git/checkouts/nym-"*/  -maxdepth 1 -type d 2>/dev/null \
        | grep -v '\.git' | tail -1
}

# ============================================================================
# Patch: nym-compact-ecash (git dependency, patched in-place)
# ============================================================================
# Problem: VerificationKeyAuth::to_bytes() and SecretKeyAuth::to_bytes() use
#          usize::to_le_bytes() which produces 4 bytes on 32-bit but the
#          gateway (64-bit) expects 8 bytes. This causes ZK proof challenge
#          hash mismatch: "the provided ticket failed to get verified".
# Fix: Cast usize to u64 before to_le_bytes()
patch_nym_ecash() {
    local dir="$1"
    log_info "Patching nym-compact-ecash (usize -> u64 in to_bytes)..."

    local f="$dir/common/nym_offline_compact_ecash/src/scheme/keygen.rs"
    if [ ! -f "$f" ]; then
        log_warn "  keygen.rs not found at $f — skipping"
        return
    fi

    if grep -q '&ys_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&ys_len\.to_le_bytes()|\&(ys_len as u64).to_le_bytes()|' "$f"
        log_info "  patched SecretKeyAuth::to_bytes()"
    fi

    if grep -q '&beta_g1_len\.to_le_bytes()' "$f"; then
        _sed_i 's|&beta_g1_len\.to_le_bytes()|\&(beta_g1_len as u64).to_le_bytes()|' "$f"
        log_info "  patched VerificationKeyAuth::to_bytes()"
    fi
}

# Find the nym git checkout directory in CARGO_HOME.
find_nym() {
    local cargo_lock_dir
    cargo_lock_dir=$(dirname "$CARGO_TOML")
    local rev=""
    if [ -f "$cargo_lock_dir/Cargo.lock" ]; then
        rev=$(awk '/^name = "nym-compact-ecash"/{found=1} found && /^source =.*nym/{print; exit}' \
            "$cargo_lock_dir/Cargo.lock" | grep -o '#[a-f0-9]*' | tr -d '#')
    fi

    local short_rev="${rev:0:7}"
    if [ -n "$short_rev" ]; then
        local found
        found=$(find "$CARGO_HOME/git/checkouts" -maxdepth 2 -type d -name "${short_rev}*" \
            -path "*/nym-*/*" 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            echo "$found"
            return
        fi
    fi

    find "$CARGO_HOME/git/checkouts/nym-"*/  -maxdepth 1 -type d 2>/dev/null \
        | grep -v '\.git' | tail -1
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
main() {
    if [ -z "$CARGO_HOME" ] || [ -z "$TARGET" ] || [ -z "$CARGO_TOML" ]; then
        echo "Usage: $0 <cargo-home> <target> <cargo-toml-path>" >&2
        echo "  Or set CARGO_HOME, TARGET, CARGO_TOML environment variables" >&2
        exit 1
    fi

    log_info "=== Build-time crate patching for target: ${TARGET} ==="
    mkdir -p "$PATCH_DIR"

    if grep -q '\[patch.crates-io\]' "$CARGO_TOML"; then
        log_warn "Cargo.toml already has [patch.crates-io] — skipping"
        exit 0
    fi

    # Determine which patches to apply
    local patches=""

    # schemars: needed for all Tier 3 targets (autocfg/indexmap issue)
    local schemars_src schemars_dir
    schemars_src=$(find_crate "schemars")
    schemars_dir=$(copy_crate "$schemars_src")
    patch_schemars "$schemars_dir"
    patches="schemars = { path = \"$schemars_dir\" }"

    # coarsetime + prometheus: needed only for 32-bit targets (no AtomicU64)
    if is_32bit_target; then
        log_info "32-bit target detected — applying portable-atomic patches"

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
        if [ -n "$gotatun_dir" ]; then
            patch_gotatun "$gotatun_dir"
        else
            log_warn "gotatun git checkout not found — skipping (may fail to compile)"
        fi

        # nym crates: git dependency — patch in-place in git checkout
        local nym_dir
        nym_dir=$(find_nym)
        if [ -n "$nym_dir" ]; then
            patch_nym_ecash "$nym_dir"
            patch_nym_gateway_client "$nym_dir"
        else
            log_warn "nym git checkout not found — skipping nym patches"
        fi
    fi

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
