#!/bin/bash
# Build script for Tier 3 musl targets (mips, mipsel, riscv64)
# Solves the autocfg/indexmap probe failure on Docker volume mounts
#
# The Problem:
#   - autocfg probes fail on Docker volume mounts (no extended file attributes)
#   - This causes indexmap to compile in no_std mode
#   - schemars expects std mode with different IndexMap signature
#
# Solution: Copy source to local filesystem (supports xattrs), build, copy back

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Source and build directories
MOUNT_DIR="/home/rust/src"
BUILD_DIR="/tmp/nym-build"
MUSL_PREFIX="/usr/local/musl"

# Detect target from environment or compiler
# Note: riscv64 compiler triplet is "riscv64-unknown-linux-musl" but Rust target is "riscv64gc-unknown-linux-musl"
if [ -z "${TARGET:-}" ]; then
    if command -v mipsel-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="mipsel-unknown-linux-musl"
        COMPILER_TRIPLET="mipsel-unknown-linux-musl"
    elif command -v mips-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="mips-unknown-linux-musl"
        COMPILER_TRIPLET="mips-unknown-linux-musl"
    elif command -v riscv64-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="riscv64gc-unknown-linux-musl"
        COMPILER_TRIPLET="riscv64-unknown-linux-musl"
    elif command -v armv5te-unknown-linux-musleabi-gcc &> /dev/null; then
        TARGET="armv5te-unknown-linux-musleabi"
        COMPILER_TRIPLET="armv5te-unknown-linux-musleabi"
    else
        log_error "No Tier 3 target compiler found"
        exit 1
    fi
else
    # If TARGET is set via env, derive COMPILER_TRIPLET
    if [[ "$TARGET" == "riscv64gc-unknown-linux-musl" ]]; then
        COMPILER_TRIPLET="riscv64-unknown-linux-musl"
    else
        COMPILER_TRIPLET="$TARGET"
    fi
fi

log_info "=== Building for Tier 3 target: ${TARGET} ==="
log_info "=== Using local filesystem to fix autocfg probe ==="

# Ensure we're using nightly
log_info "Setting up nightly Rust with rust-src..."
source "$HOME/.cargo/env" 2>/dev/null || true
rustup default nightly
rustup component add rust-src

# Step 1: Copy source to local filesystem
log_info "Copying source to local filesystem (fixes autocfg xattr issue)..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Use rsync for efficient copy, exclude target dir and git
rsync -a --exclude='target' --exclude='.git' --exclude='*.git' \
    "$MOUNT_DIR/" "$BUILD_DIR/"

log_info "Source copied to $BUILD_DIR"

# Step 2: Build native dependencies (libmnl, libnftnl)
log_info "Building native dependencies..."

LIBMNL_VERSION="1.0.4"
LIBNFTNL_VERSION="1.2.1"
DEPS_DIR="/tmp/deps-build"

mkdir -p "$DEPS_DIR"

# Build libmnl if not present
if [ ! -f "${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/libmnl.a" ]; then
    log_info "Building libmnl ${LIBMNL_VERSION}..."
    cd "$DEPS_DIR"
    curl -fsSL "https://www.netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VERSION}.tar.bz2" -o libmnl.tar.bz2
    tar xjf libmnl.tar.bz2
    cd "libmnl-${LIBMNL_VERSION}"
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="-fPIC" ./configure \
        --host="${COMPILER_TRIPLET}" \
        --prefix="${MUSL_PREFIX}/${COMPILER_TRIPLET}" \
        --enable-static --disable-shared --quiet
    make -j$(nproc) > /dev/null
    make install > /dev/null
    log_info "libmnl installed"
else
    log_info "libmnl already installed"
fi

# Build libnftnl if not present
if [ ! -f "${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/libnftnl.a" ]; then
    log_info "Building libnftnl ${LIBNFTNL_VERSION}..."
    cd "$DEPS_DIR"
    curl -fsSL "https://www.netfilter.org/projects/libnftnl/files/libnftnl-${LIBNFTNL_VERSION}.tar.bz2" -o libnftnl.tar.bz2
    tar xjf libnftnl.tar.bz2
    cd "libnftnl-${LIBNFTNL_VERSION}"
    PKG_CONFIG_PATH="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/pkgconfig" \
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="-fPIC" ./configure \
        --host="${COMPILER_TRIPLET}" \
        --prefix="${MUSL_PREFIX}/${COMPILER_TRIPLET}" \
        --enable-static --disable-shared --quiet
    make -j$(nproc) > /dev/null
    make install > /dev/null
    log_info "libnftnl installed"
else
    log_info "libnftnl already installed"
fi

# Step 3: Build nym-vpn
cd "$BUILD_DIR/nym-vpn-core"

# Tier 3 Target Patches
# ====================
# Pre-patched crates are stored in docker/tier3-musl/patches/
# These patches fix:
#   - schemars: Use BTreeMap instead of IndexMap (avoids generic args mismatch)
#   - coarsetime: Use portable-atomic for AtomicU64 (32-bit MIPS doesn't have native AtomicU64)
#   - prometheus: Use portable-atomic for AtomicU64

PATCH_SRC="$BUILD_DIR/docker/tier3-musl/patches"

log_info "Using pre-patched crates from $PATCH_SRC"

# Add patches to Cargo.toml
if ! grep -q '\[patch.crates-io\]' Cargo.toml; then
    log_info "Adding [patch.crates-io] section..."

    if [[ "$TARGET" == mips* ]] || [[ "$TARGET" == armv5te* ]]; then
        # 32-bit targets (MIPS, ARMv5TE) need portable-atomic patches for AtomicU64/AtomicI64
        # Replace all nym git dependencies to use the tier3 fork
        log_info "Replacing nym git URLs with tier3-portable-atomic fork..."
        sed -i 's|git = "https://github.com/nymtech/nym"|git = "https://github.com/dial0ut/nym"|g' Cargo.toml
        sed -i 's|branch = "develop"|branch = "feat/tier3-portable-atomic"|g' Cargo.toml

        cat >> Cargo.toml << PATCH_EOF

# Tier 3 target build-std compatibility patches
[patch.crates-io]
schemars = { path = "$PATCH_SRC/schemars-0.8.22" }
coarsetime = { path = "$PATCH_SRC/coarsetime-0.1.36" }
prometheus = { path = "$PATCH_SRC/prometheus-0.14.0" }
PATCH_EOF
    else
        # 64-bit targets only need schemars patch
        cat >> Cargo.toml << PATCH_EOF

# Tier 3 target build-std compatibility patch
[patch.crates-io]
schemars = { path = "$PATCH_SRC/schemars-0.8.22" }
PATCH_EOF
    fi
    log_info "Cargo.toml patched"
else
    log_info "Cargo.toml already has patch section"
fi

# Set up environment
# Note: PKG_CONFIG_PATH and lib dirs use COMPILER_TRIPLET (actual toolchain paths)
# but Cargo env vars use TARGET (Rust target name)
export PKG_CONFIG_PATH="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1

TARGET_UNDERSCORE="${TARGET//-/_}"
export CC_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-gcc"
export AR_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-ar"

# Set linker - will be overridden for targets that need rust-lld (RISC-V, ARMv5TE)
if [[ "$TARGET" != riscv64* ]] && [[ "$TARGET" != armv5te* ]]; then
    export CARGO_TARGET_${TARGET_UNDERSCORE^^}_LINKER="${COMPILER_TRIPLET}-gcc"
fi

# Find the musl lib directory containing crt1.o
MUSL_LIB_DIR="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib"
if [ ! -f "${MUSL_LIB_DIR}/crt1.o" ]; then
    # Try alternative location
    MUSL_LIB_DIR="${MUSL_PREFIX}/lib"
fi
log_info "Using musl lib dir: ${MUSL_LIB_DIR}"

# GCC lib directory (contains crtbegin.o, crtend.o, libgcc.a)
GCC_LIB_DIR="${MUSL_PREFIX}/lib/gcc/${COMPILER_TRIPLET}/11.2.0"
log_info "Using GCC lib dir: ${GCC_LIB_DIR}"

# Set linker flags to find C runtime files
# The linker needs to find:
#   - crt1.o, crti.o, crtn.o from musl (MUSL_LIB_DIR)
#   - crtbegin.o, crtend.o from gcc (GCC_LIB_DIR)
export RUSTFLAGS="-C link-arg=-L${MUSL_LIB_DIR} -C link-arg=-L${GCC_LIB_DIR}"

# RISC-V specific: Use rust-lld to avoid GCC 11.2 not understanding newer RISC-V extensions
# (zaamo, zalrsc, zca, zcd, etc. are not recognized by older binutils/GCC)
if [[ "$TARGET" == riscv64* ]]; then
    log_info "Using rust-lld linker for RISC-V (GCC 11.2 doesn't support newer Z extensions)..."
    # Use Rust's bundled LLD linker instead of the system GCC/ld
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER="rust-lld"
    export RUSTFLAGS="${RUSTFLAGS} -C linker-flavor=ld.lld"
fi

# Disable LTO for tier3 targets - full LTO with rust-lld is extremely memory intensive
# and will cause OOM kills. Use thin LTO as a compromise for smaller binary size.
log_info "Disabling full LTO (too memory intensive for cross-compilation)..."
export CARGO_PROFILE_RELEASE_LTO="thin"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="16"

# MIPS-specific flags
if [[ "$TARGET" == mips* ]]; then
    log_info "Setting MIPS-specific compiler flags..."
    export CFLAGS_${TARGET_UNDERSCORE}="-msoft-float"
    # Add soft-float to linker flags for MIPS
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-msoft-float"
fi

# ARMv5TE-specific flags (soft-float, no VFP/NEON)
if [[ "$TARGET" == armv5te* ]]; then
    log_info "Setting ARMv5TE-specific compiler flags (soft-float, no unwinding)..."
    # -msoft-float: use software floating point
    # -fno-exceptions -fno-unwind-tables: disable C++ exceptions and ARM unwinding (we use panic=abort)
    export CFLAGS_${TARGET_UNDERSCORE}="-msoft-float -mfloat-abi=soft -fno-exceptions -fno-unwind-tables"
    # Link against libgcc_eh for any remaining unwind symbols from pre-compiled code
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-lgcc_eh"
    # Linker is set via Dockerfile to use armv5te-gcc-wrapper which fixes CRT paths
fi

log_info "Building with -Z build-std..."
log_warn "This will take 15-30 minutes..."

cargo build \
    --target="${TARGET}" \
    --bins \
    --release \
    -Z build-std=std,panic_abort

# Step 4: Copy binaries back to mounted volume
log_info "Copying binaries back to mounted volume..."
BINARY_DIR="$BUILD_DIR/nym-vpn-core/target/${TARGET}/release"
OUTPUT_DIR="$MOUNT_DIR/nym-vpn-core/target/${TARGET}/release"

mkdir -p "$OUTPUT_DIR"
cp "$BINARY_DIR/nym-vpnd" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$BINARY_DIR/nym-vpnc" "$OUTPUT_DIR/" 2>/dev/null || true

log_info ""
log_info "=== BUILD COMPLETE ==="
log_info "Binaries at: nym-vpn-core/target/${TARGET}/release/"

# Verify
if [ -f "$OUTPUT_DIR/nym-vpnd" ]; then
    log_info "  nym-vpnd: $(du -h "$OUTPUT_DIR/nym-vpnd" | cut -f1)"
fi
if [ -f "$OUTPUT_DIR/nym-vpnc" ]; then
    log_info "  nym-vpnc: $(du -h "$OUTPUT_DIR/nym-vpnc" | cut -f1)"
fi

# Cleanup
rm -rf "$BUILD_DIR" "$DEPS_DIR"
log_info "Cleanup complete"
