#!/bin/bash
# Build script for Tier 3 musl targets (mips, mipsel, riscv64) — dynamic linking
# Produces dynamically linked binaries that depend on the target system's musl libc,
# libmnl, and libnftnl. Smaller binaries than static, standard for OpenWrt packages.
#
# Based on build-tier3.sh but removes all static linking machinery:
#   - No +crt-static, -static, -static-libgcc
#   - No GCC wrapper scripts (only needed for CRT path fixups in static mode)
#   - Shared libmnl/libnftnl instead of static
#   - Uses plain GCC as linker for all targets

set -euo pipefail

MOUNT_DIR="/home/rust/src"
source "$MOUNT_DIR/scripts/log.sh"
source "$MOUNT_DIR/scripts/versions.sh"
BUILD_DIR="/tmp/nym-build"
MUSL_PREFIX="/usr/local/musl"

# Detect target from environment or compiler
if [ -z "${TARGET:-}" ]; then
    if command -v mipsel-linux-muslsf-gcc &> /dev/null; then
        TARGET="mipsel-unknown-linux-musl"
        COMPILER_TRIPLET="mipsel-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    elif command -v mips-linux-muslsf-gcc &> /dev/null; then
        TARGET="mips-unknown-linux-musl"
        COMPILER_TRIPLET="mips-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    elif command -v mipsel-unknown-linux-musl-gcc &> /dev/null; then
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
    if [[ "$TARGET" == "riscv64gc-unknown-linux-musl" ]]; then
        COMPILER_TRIPLET="riscv64-unknown-linux-musl"
    elif [[ "$TARGET" == "mipsel-unknown-linux-musl" ]] && command -v mipsel-linux-muslsf-gcc &> /dev/null; then
        COMPILER_TRIPLET="mipsel-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    elif [[ "$TARGET" == "mips-unknown-linux-musl" ]] && command -v mips-linux-muslsf-gcc &> /dev/null; then
        COMPILER_TRIPLET="mips-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    else
        COMPILER_TRIPLET="$TARGET"
    fi
fi

log_info "=== Building for Tier 3 target: ${TARGET} (dynamic linking) ==="
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

rsync -a --exclude='target' --exclude='.git' --exclude='*.git' \
    "$MOUNT_DIR/" "$BUILD_DIR/"

log_info "Source copied to $BUILD_DIR"

# Step 2: Build native dependencies as shared libraries
log_info "Building native dependencies (shared)..."

DEPS_DIR="/tmp/deps-build"
mkdir -p "$DEPS_DIR"

# Set target-specific CFLAGS for native dependencies
NATIVE_CFLAGS="-fPIC"
if [[ "$TARGET" == mips* ]]; then
    NATIVE_CFLAGS="-fPIC -mips32r2 -msoft-float"
fi

# Build libmnl (shared)
if [ ! -f "${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/libmnl.so" ]; then
    log_info "Building libmnl ${LIBMNL_VERSION} (shared)..."
    cd "$DEPS_DIR"
    curl -fsSL "https://www.netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VERSION}.tar.bz2" -o libmnl.tar.bz2
    tar xjf libmnl.tar.bz2
    cd "libmnl-${LIBMNL_VERSION}"
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="${NATIVE_CFLAGS}" ./configure \
        --host="${COMPILER_TRIPLET}" \
        --prefix="${MUSL_PREFIX}/${COMPILER_TRIPLET}" \
        --enable-shared --disable-static --quiet
    make -j$(nproc) > /dev/null
    make install > /dev/null
    log_info "libmnl installed (shared)"
else
    log_info "libmnl already installed"
fi

# Build libnftnl (shared)
if [ ! -f "${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/libnftnl.so" ]; then
    log_info "Building libnftnl ${LIBNFTNL_VERSION} (shared)..."
    cd "$DEPS_DIR"
    curl -fsSL "https://www.netfilter.org/projects/libnftnl/files/libnftnl-${LIBNFTNL_VERSION}.tar.bz2" -o libnftnl.tar.bz2
    tar xjf libnftnl.tar.bz2
    cd "libnftnl-${LIBNFTNL_VERSION}"
    PKG_CONFIG_PATH="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/pkgconfig" \
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="${NATIVE_CFLAGS}" ./configure \
        --host="${COMPILER_TRIPLET}" \
        --prefix="${MUSL_PREFIX}/${COMPILER_TRIPLET}" \
        --enable-shared --disable-static --quiet
    make -j$(nproc) > /dev/null
    make install > /dev/null
    log_info "libnftnl installed (shared)"
else
    log_info "libnftnl already installed"
fi

# Step 3: Build nym-vpn
cd "$BUILD_DIR/nym-vpn-core"

PATCH_SCRIPT="$BUILD_DIR/docker/tier3-musl/patch-crates.sh"
log_info "Fetching dependencies..."
cargo fetch --target="${TARGET}" 2>/dev/null || true

log_info "Applying build-time crate patches..."
bash "$PATCH_SCRIPT" "$HOME/.cargo" "$TARGET" "$BUILD_DIR/nym-vpn-core/Cargo.toml"

# Set up environment
export PKG_CONFIG_PATH="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1

TARGET_UNDERSCORE="${TARGET//-/_}"
export CC_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-gcc"
export AR_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-ar"

# Use plain GCC as linker — no wrapper needed for dynamic linking
export CARGO_TARGET_${TARGET_UNDERSCORE^^}_LINKER="${COMPILER_TRIPLET}-gcc"

# === DYNAMIC LINKING ===
# -crt-static: opt out of Rust's default static linking for musl targets
export RUSTFLAGS="-C target-feature=-crt-static"

# Full LTO for maximum dead code elimination (matches Tier 2 profile)
log_info "Using full LTO + opt-level=z for cross-compilation..."
export CARGO_PROFILE_RELEASE_LTO="true"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"
export CARGO_PROFILE_RELEASE_OPT_LEVEL="z"
export CARGO_PROFILE_RELEASE_PANIC="abort"

# MIPS-specific flags
if [[ "$TARGET" == mips* ]]; then
    log_info "Setting MIPS-specific compiler flags..."
    export CFLAGS_${TARGET_UNDERSCORE}="-mips32r2 -msoft-float"
    export RUSTFLAGS="${RUSTFLAGS} -C target-feature=+mips32r2,+soft-float -C link-arg=-msoft-float"
fi

# RISC-V specific
if [[ "$TARGET" == riscv64* ]]; then
    log_info "Setting RISC-V compiler flags..."
fi

# ARMv5TE-specific flags
if [[ "$TARGET" == armv5te* ]]; then
    log_info "Setting ARMv5TE-specific compiler flags (soft-float)..."
    export CFLAGS_${TARGET_UNDERSCORE}="-msoft-float -mfloat-abi=soft"
fi

log_info "RUSTFLAGS=${RUSTFLAGS}"
log_info "Building with -Z build-std..."
log_warn "This will take 15-30 minutes..."

cargo build \
    --target="${TARGET}" \
    --bins \
    --release \
    -Z build-std=std,panic_abort

# Step 4: Strip binaries
log_info "Stripping binaries..."
BINARY_DIR="$BUILD_DIR/nym-vpn-core/target/${TARGET}/release"

if [ -f "$BINARY_DIR/nym-vpnd" ]; then
    ${COMPILER_TRIPLET}-strip "$BINARY_DIR/nym-vpnd"
fi
if [ -f "$BINARY_DIR/nym-vpnc" ]; then
    ${COMPILER_TRIPLET}-strip "$BINARY_DIR/nym-vpnc"
fi

# Step 5: Copy binaries back to mounted volume
log_info "Copying binaries back to mounted volume..."
OUTPUT_DIR="$MOUNT_DIR/nym-vpn-core/target/${TARGET}/release"

mkdir -p "$OUTPUT_DIR"
cp "$BINARY_DIR/nym-vpnd" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$BINARY_DIR/nym-vpnc" "$OUTPUT_DIR/" 2>/dev/null || true

log_info ""
log_info "=== BUILD COMPLETE ==="
log_info "Binaries at: nym-vpn-core/target/${TARGET}/release/"

if [ -f "$OUTPUT_DIR/nym-vpnd" ]; then
    log_info "  nym-vpnd: $(du -h "$OUTPUT_DIR/nym-vpnd" | cut -f1)"
fi
if [ -f "$OUTPUT_DIR/nym-vpnc" ]; then
    log_info "  nym-vpnc: $(du -h "$OUTPUT_DIR/nym-vpnc" | cut -f1)"
fi

log_info ""
log_info "These binaries are dynamically linked. The target device needs:"
log_info "  libc (musl), libmnl, libnftnl, kmod-tun"

# Cleanup
rm -rf "$BUILD_DIR" "$DEPS_DIR"
log_info "Cleanup complete"
