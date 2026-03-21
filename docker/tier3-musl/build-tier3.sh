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

MOUNT_DIR="/home/rust/src"
source "$MOUNT_DIR/scripts/log.sh"
source "$MOUNT_DIR/scripts/versions.sh"
BUILD_DIR="/tmp/nym-build"
MUSL_PREFIX="/usr/local/musl"

# Detect target from environment or compiler
# Note: Different toolchains use different triplet naming conventions:
#   - musl.cc soft-float: mipsel-linux-muslsf
#   - messense/musl-cross: mipsel-unknown-linux-musl
#   - Rust target: mipsel-unknown-linux-musl
if [ -z "${TARGET:-}" ]; then
    # Check for musl.cc soft-float toolchain first (preferred for MIPS)
    if command -v mipsel-linux-muslsf-gcc &> /dev/null; then
        TARGET="mipsel-unknown-linux-musl"
        COMPILER_TRIPLET="mipsel-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    elif command -v mips-linux-muslsf-gcc &> /dev/null; then
        TARGET="mips-unknown-linux-musl"
        COMPILER_TRIPLET="mips-linux-muslsf"
        MUSL_PREFIX="/opt/cross"
    # Fall back to messense-style triplets
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
    # If TARGET is set via env, derive COMPILER_TRIPLET
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

DEPS_DIR="/tmp/deps-build"

mkdir -p "$DEPS_DIR"

# Set target-specific CFLAGS for native dependencies
NATIVE_CFLAGS="-fPIC"
if [[ "$TARGET" == mips* ]]; then
    # MIPS 24Kc cores require mips32r2 ISA and have no FPU (soft-float)
    NATIVE_CFLAGS="-fPIC -mips32r2 -msoft-float"
fi

# Build libmnl if not present
if [ ! -f "${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/libmnl.a" ]; then
    log_info "Building libmnl ${LIBMNL_VERSION}..."
    cd "$DEPS_DIR"
    curl -fsSL "https://www.netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VERSION}.tar.bz2" -o libmnl.tar.bz2
    tar xjf libmnl.tar.bz2
    cd "libmnl-${LIBMNL_VERSION}"
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="${NATIVE_CFLAGS}" ./configure \
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
    CC="${COMPILER_TRIPLET}-gcc" CFLAGS="${NATIVE_CFLAGS}" ./configure \
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
# Patches are applied at build time by patch-crates.sh, which:
#   - Finds crates in the cargo registry cache (version-agnostic)
#   - Copies them to /tmp/patches/ and applies sed transformations
#   - schemars: Use BTreeMap instead of IndexMap (avoids generic args mismatch)
#   - coarsetime: Use portable-atomic for AtomicU64 (32-bit targets only)
#   - prometheus: Use portable-atomic for AtomicU64/AtomicI64 (32-bit targets only)

PATCH_SCRIPT="$BUILD_DIR/docker/tier3-musl/patch-crates.sh"
log_info "Fetching dependencies..."
cargo fetch --target="${TARGET}" 2>/dev/null || true

log_info "Applying build-time crate patches..."
bash "$PATCH_SCRIPT" "$HOME/.cargo" "$TARGET" "$BUILD_DIR/nym-vpn-core/Cargo.toml"

# Set up environment
# Note: PKG_CONFIG_PATH and lib dirs use COMPILER_TRIPLET (actual toolchain paths)
# but Cargo env vars use TARGET (Rust target name)
export PKG_CONFIG_PATH="${MUSL_PREFIX}/${COMPILER_TRIPLET}/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1

TARGET_UNDERSCORE="${TARGET//-/_}"
export CC_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-gcc"
export AR_${TARGET_UNDERSCORE}="${COMPILER_TRIPLET}-ar"

# Set linker - will be overridden for targets that need GCC wrapper (RISC-V, ARMv5TE, MIPS)
# These targets use +crt-static which requires wrapper to fix CRT paths
if [[ "$TARGET" != riscv64* ]] && [[ "$TARGET" != armv5te* ]] && [[ "$TARGET" != mips* ]]; then
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
# Try multiple GCC versions - musl.cc uses 14.x, messense uses 11.x
GCC_LIB_DIR=""
for gcc_ver in 14.2.0 14.1.0 13.2.0 11.2.0; do
    if [ -d "${MUSL_PREFIX}/lib/gcc/${COMPILER_TRIPLET}/${gcc_ver}" ]; then
        GCC_LIB_DIR="${MUSL_PREFIX}/lib/gcc/${COMPILER_TRIPLET}/${gcc_ver}"
        break
    fi
done
if [ -z "$GCC_LIB_DIR" ]; then
    GCC_LIB_DIR="${MUSL_PREFIX}/lib/gcc/${COMPILER_TRIPLET}/11.2.0"
fi
log_info "Using GCC lib dir: ${GCC_LIB_DIR}"

# Set linker flags to find C runtime files
# The linker needs to find:
#   - crt1.o, crti.o, crtn.o from musl (MUSL_LIB_DIR)
#   - crtbegin.o, crtend.o from gcc (GCC_LIB_DIR)
export RUSTFLAGS="-C link-arg=-L${MUSL_LIB_DIR} -C link-arg=-L${GCC_LIB_DIR}"

# RISC-V specific: Use GCC wrapper with lld backend
# GCC 11.2's binutils doesn't understand newer RISC-V extensions (zaamo, zalrsc, etc.)
# The Dockerfile:
#   1. Replaces all ld binaries with lld symlinks (so GCC uses lld)
#   2. Installs riscv64-gcc-wrapper that fixes CRT paths for lld
#   3. Creates empty libunwind.a stub
# The wrapper is needed because lld doesn't search -L paths for bare crt*.o files
if [[ "$TARGET" == riscv64* ]]; then
    log_info "Using GCC wrapper with lld backend for RISC-V..."
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER="/usr/local/bin/riscv64-gcc-wrapper"
    # +crt-static: statically link C runtime
    # -static: tell linker to produce static binary
    # -static-libgcc: link libgcc statically
    # -lgcc_eh: link exception handling (provides _Unwind_* symbols for backtrace)
    export RUSTFLAGS="${RUSTFLAGS} -C target-feature=+crt-static -C link-arg=-static -C link-arg=-static-libgcc -C link-arg=-lgcc_eh"
fi

# Disable LTO for tier3 targets - full LTO with rust-lld is extremely memory intensive
# and will cause OOM kills. Use thin LTO as a compromise for smaller binary size.
log_info "Disabling full LTO (too memory intensive for cross-compilation)..."
export CARGO_PROFILE_RELEASE_LTO="thin"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="16"

# Critical: Set panic=abort to eliminate unwinding code which pulls in libgcc_s
# Without this, even with -Z build-std=std,panic_abort, cargo still links unwinding code
# See: https://users.rust-lang.org/t/remove-unwind-routines-from-a-musl-linked-build/91634
export CARGO_PROFILE_RELEASE_PANIC="abort"

# MIPS-specific flags
if [[ "$TARGET" == mips* ]]; then
    log_info "Setting MIPS-specific compiler flags..."
    export CFLAGS_${TARGET_UNDERSCORE}="-mips32r2 -msoft-float"
    # Use GCC wrapper to fix CRT paths for +crt-static
    if [[ "$TARGET" == "mipsel-unknown-linux-musl" ]]; then
        export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="/usr/local/bin/mipsel-gcc-wrapper"
    else
        export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER="/usr/local/bin/mips-gcc-wrapper"
    fi
    # +crt-static: statically link C runtime
    # +mips32r2: target MIPS32 Release 2 ISA (required for 24Kc cores)
    # +soft-float: use software floating point (24Kc cores have no FPU)
    # -static: produce static binary
    # -static-libgcc: link libgcc statically
    # libgcc_eh needs pthread symbols which are in musl's libc.a
    # Use --start-group to resolve circular dependency: libgcc_eh -> libc (pthread)
    # Note: GNU ld ignores floating point ABI mismatch (just warns), unlike lld which errors
    export RUSTFLAGS="${RUSTFLAGS} -C target-feature=+crt-static,+mips32r2,+soft-float -C link-arg=-msoft-float -C link-arg=-static -C link-arg=-static-libgcc"
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-Wl,--start-group -C link-arg=-lgcc_eh -C link-arg=-lc -C link-arg=-Wl,--end-group"
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

# Step 4: Strip binaries for size optimization
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
