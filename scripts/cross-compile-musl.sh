#!/bin/bash
# Author: dial0ut
# Version: v0.0.4
# Cross-compile nym-vpnd for OpenWRT (musl targets)
# This script runs INSIDE the messense/rust-musl-cross container
# Supports both x86_64 and aarch64 host architectures
# Uses kernel WireGuard exclusively (no wireguard-go)
#
# Requirements:
#   - Linux kernel 5.6+ with WireGuard module on target system
#   - Run: modprobe wireguard (on target device)
#
# Usage from host:
#   docker run --rm -it -v "$(pwd)":/home/rust/src \
#     messense/rust-musl-cross:aarch64-musl \
#     bash /home/rust/src/scripts/cross-compile-musl.sh
#
# Or using alias:
#   nymwrt='docker run --rm -it -v "$(pwd)":/home/rust/src messense/rust-musl-cross:aarch64-musl'
#   nymwrt bash /home/rust/src/scripts/cross-compile-musl.sh
#
# Supported targets (Docker image tags):
#   messense/rust-musl-cross:aarch64-musl      # ARM 64-bit (Raspberry Pi 4, rockchip, mediatek)
#   messense/rust-musl-cross:armv7-musleabihf  # ARM v7 32-bit hard-float (bcm53xx, mvebu)
#   messense/rust-musl-cross:x86_64-musl       # x86 64-bit
#   messense/rust-musl-cross:i686-musl         # x86 32-bit (x86/generic)
#   messense/rust-musl-cross:mips-musl         # MIPS big-endian (ath79, lantiq, bcm47xx)
#   messense/rust-musl-cross:mipsel-musl       # MIPS little-endian (ramips, realtek)
#   messense/rust-musl-cross:riscv64gc-musl    # RISC-V 64-bit (d1, sifiveu, starfive)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - auto-detect target from available compiler
if [ -z "${TARGET:-}" ]; then
    if command -v arm-unknown-linux-musleabi-gcc &> /dev/null; then
        TARGET="arm-unknown-linux-musleabi"
    elif command -v armv7-unknown-linux-musleabihf-gcc &> /dev/null; then
        TARGET="armv7-unknown-linux-musleabihf"
    elif command -v aarch64-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="aarch64-unknown-linux-musl"
    elif command -v x86_64-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="x86_64-unknown-linux-musl"
    elif command -v i686-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="i686-unknown-linux-musl"
    elif command -v mips-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="mips-unknown-linux-musl"
    elif command -v mipsel-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="mipsel-unknown-linux-musl"
    elif command -v riscv64gc-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="riscv64gc-unknown-linux-musl"
    else
        TARGET="aarch64-unknown-linux-musl"  # Default fallback
    fi
fi
MUSL_PREFIX="/usr/local/musl/${TARGET}"
LIBMNL_VERSION="1.0.4"
LIBNFTNL_VERSION="1.2.1"
BUILD_DIR="/tmp/musl-build"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_arch() {
    local arch=$(uname -m)
    log_info "Container architecture: $arch"
    log_info "Target triple: $TARGET"
}

install_system_deps() {
    log_info "Installing system dependencies..."

    # Check Rust version - edition 2024 requires Rust 1.85+
    local current_version=$(rustc --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local required_version="1.85"
    log_info "Current Rust: $current_version, Required: $required_version+"

    if [ "$(printf '%s\n' "$required_version" "$current_version" | sort -V | head -n1)" != "$required_version" ]; then
        log_info "Rust $current_version is too old, reinstalling latest stable..."
        rustup self uninstall -y 2>/dev/null || true
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        source "$HOME/.cargo/env"
        log_info "Updated to: $(rustc --version)"
    fi

    # Ensure the cross-compilation target is installed
    log_info "Adding Rust target: ${TARGET}..."
    rustup target add "${TARGET}" || true

    # Check if critical tools are installed
    local missing_deps=()

    command -v pkg-config &> /dev/null || missing_deps+=("pkg-config")
    command -v curl &> /dev/null || missing_deps+=("curl")
    command -v wget &> /dev/null || missing_deps+=("wget")
    command -v unzip &> /dev/null || missing_deps+=("unzip")

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_info "Installing: ${missing_deps[*]}"
        apt-get update -qq
        apt-get install -y -qq pkg-config curl wget unzip
    else
        log_info "All system dependencies already installed"
    fi

    # Install protoc from pre-compiled binary (apt version too old for proto3 optional)
    if ! command -v protoc &> /dev/null; then
        log_info "Installing protoc 30.2..."
        PB_REL="https://github.com/protocolbuffers/protobuf/releases"
        curl -LO "$PB_REL/download/v30.2/protoc-30.2-linux-x86_64.zip"
        unzip -q protoc-30.2-linux-x86_64.zip -d "$HOME/.local"
        rm protoc-30.2-linux-x86_64.zip
        export PATH="$PATH:$HOME/.local/bin"
        log_info "protoc version: $(protoc --version)"
    fi
}

compile_libmnl() {
    log_info "Compiling libmnl ${LIBMNL_VERSION} for ${TARGET}..."

    # Check if already installed
    if [ -f "${MUSL_PREFIX}/lib/libmnl.a" ]; then
        log_info "libmnl already compiled, skipping..."
        return 0
    fi

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    local tarball="libmnl-${LIBMNL_VERSION}.tar.bz2"
    if [ ! -f "$tarball" ]; then
        log_info "Downloading libmnl..."
        curl -fsSL "https://www.netfilter.org/projects/libmnl/files/${tarball}" -o "${tarball}"
    fi

    log_info "Extracting libmnl..."
    tar xjf "${tarball}"
    cd "libmnl-${LIBMNL_VERSION}"

    log_info "Configuring libmnl..."
    CC="${TARGET}-gcc" \
    CFLAGS="-fPIC" \
    ./configure \
        --host="${TARGET}" \
        --prefix="${MUSL_PREFIX}" \
        --enable-static \
        --disable-shared \
        --quiet

    log_info "Building libmnl..."
    make -j$(nproc) > /dev/null

    log_info "Installing libmnl..."
    make install > /dev/null

    log_info "libmnl compiled successfully"
}

compile_libnftnl() {
    log_info "Compiling libnftnl ${LIBNFTNL_VERSION} for ${TARGET}..."

    # Check if already installed
    if [ -f "${MUSL_PREFIX}/lib/libnftnl.a" ]; then
        log_info "libnftnl already compiled, skipping..."
        return 0
    fi

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    local tarball="libnftnl-${LIBNFTNL_VERSION}.tar.bz2"
    if [ ! -f "$tarball" ]; then
        log_info "Downloading libnftnl..."
        curl -fsSL "https://www.netfilter.org/projects/libnftnl/files/${tarball}" -o "${tarball}"
    fi

    log_info "Extracting libnftnl..."
    tar xjf "${tarball}"
    cd "libnftnl-${LIBNFTNL_VERSION}"

    log_info "Configuring libnftnl..."
    PKG_CONFIG_PATH="${MUSL_PREFIX}/lib/pkgconfig" \
    CC="${TARGET}-gcc" \
    CFLAGS="-fPIC" \
    ./configure \
        --host="${TARGET}" \
        --prefix="${MUSL_PREFIX}" \
        --enable-static \
        --disable-shared \
        --quiet

    log_info "Building libnftnl..."
    make -j$(nproc) > /dev/null

    log_info "Installing libnftnl..."
    make install > /dev/null

    log_info "libnftnl compiled successfully"
}

verify_pkg_config() {
    log_info "Verifying pkg-config setup..."

    export PKG_CONFIG_PATH="${MUSL_PREFIX}/lib/pkgconfig"

    if pkg-config --exists libmnl; then
        log_info "✓ libmnl found via pkg-config"
        pkg-config --libs --cflags libmnl
    else
        log_error "✗ libmnl NOT found via pkg-config"
        exit 1
    fi

    if pkg-config --exists libnftnl; then
        log_info "✓ libnftnl found via pkg-config"
        pkg-config --libs --cflags libnftnl
    else
        log_error "✗ libnftnl NOT found via pkg-config"
        exit 1
    fi
}

build_nym_vpnd() {
    log_info "Building nym-vpnd for ${TARGET}..."

    cd /home/rust/src/nym-vpn-core

    # For soft-float ARM, use ARMv5TE with portable-atomic for BCM5301X (no VFP/NEON)
    if [[ "$TARGET" == "arm-unknown-linux-musleabi" ]]; then
        log_info "Using ARMv5TE with portable-atomic for BCM5301X compatibility..."

        # Install armv5te target
        log_info "Installing armv5te-unknown-linux-musleabi Rust target..."
        rustup target add armv5te-unknown-linux-musleabi || true

        # Override TARGET to use ARMv5TE
        # Note: We keep MUSL_PREFIX pointing to arm-unknown-linux-musleabi
        # since that's where the C libraries were installed
        TARGET="armv5te-unknown-linux-musleabi"
        log_info "Using Rust target: ${TARGET} (ARMv5TE soft-float, will use portable-atomic)"
        log_info "C libraries path remains: ${MUSL_PREFIX}"

        # Configure Cargo to use the arm-musleabi toolchain for armv5te target
        export CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_LINKER=arm-unknown-linux-musleabi-gcc
        export CC_armv5te_unknown_linux_musleabi=arm-unknown-linux-musleabi-gcc
        export AR_armv5te_unknown_linux_musleabi=arm-unknown-linux-musleabi-ar
        log_info "Configured Cargo to use arm-unknown-linux-musleabi toolchain for armv5te target"
    fi

    # Clean build artifacts from other targets to avoid confusion
    log_info "Cleaning build artifacts from previous attempts..."
    rm -rf target/armv7-unknown-linux-musleabi 2>/dev/null || true
    rm -rf target/armv7-bcm5301x-linux-musleabi 2>/dev/null || true
    rm -rf target/armv5te-unknown-linux-musleabi 2>/dev/null || true
    rm -rf target/release/build/ring-*
    rm -rf target/x86_64-unknown-linux-gnu 2>/dev/null || true

    # Check disk space
    local free_space=$(df -h /home/rust/src | tail -1 | awk '{print $4}')
    log_info "Available disk space: $free_space"

    log_warn "This will take 10-15 minutes and requires at least 5GB free space..."

    # Set environment for cargo
    export PKG_CONFIG_PATH="${MUSL_PREFIX}/lib/pkgconfig"
    export PKG_CONFIG_ALLOW_CROSS=1

    # Add target-specific flags
    TARGET_UNDERSCORE="${TARGET//-/_}"

    # ARM targets need special handling for atomic operations
    if [[ "$TARGET" == "armv7-unknown-linux-musleabihf" ]] || [[ "$TARGET" == "arm-unknown-linux-musleabi" ]] || [[ "$TARGET" == "armv7-unknown-linux-musleabi" ]] || [[ "$TARGET" == "armv5te-unknown-linux-musleabi" ]]; then
        log_info "Adding ARM-specific linker flags for atomic operations..."
        export RUSTFLAGS="-C link-arg=-lgcc"
        log_info "RUSTFLAGS=${RUSTFLAGS}"

        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"

        # Only set soft-float for soft-float targets (NOT for musleabihf which is hard-float)
        if [[ "$TARGET" != "armv7-unknown-linux-musleabihf" ]]; then
            # Force ring to use portable C code instead of ARM assembly (no NEON/VFP)
            log_info "Setting soft-float flags for BCM5301X compatibility..."
            export CFLAGS_${TARGET_UNDERSCORE}="-msoft-float -mfloat-abi=soft"
        else
            log_info "Using hard-float ABI for armv7-musleabihf target"
        fi
    fi

    # MIPS targets may need specific flags
    if [[ "$TARGET" == "mips-unknown-linux-musl" ]] || [[ "$TARGET" == "mipsel-unknown-linux-musl" ]]; then
        log_info "Configuring for MIPS target..."
        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"
    fi

    # RISC-V targets
    if [[ "$TARGET" == "riscv64gc-unknown-linux-musl" ]]; then
        log_info "Configuring for RISC-V 64-bit target..."
        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"
    fi

    # i686 (32-bit x86) targets
    if [[ "$TARGET" == "i686-unknown-linux-musl" ]]; then
        log_info "Configuring for i686 (32-bit x86) target..."
        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"
    fi

    # Build with release profile
    log_info "Running: cargo build --target=${TARGET} --bins --release"
    cargo build \
        --target="${TARGET}" \
        --bins \
        --release

    local binary_dir="/home/rust/src/nym-vpn-core/target/${TARGET}/release"

    if [ -d "$binary_dir" ]; then
        log_info "✓ Build successful!"
        log_info "Binaries built:"

        # List all built binaries
        for binary in "$binary_dir"/nym-vpn*; do
            if [ -f "$binary" ] && [ -x "$binary" ] && [[ ! "$binary" =~ \.d$ ]]; then
                log_info "  - $(basename "$binary"): $(du -h "$binary" | cut -f1)"
            fi
        done

        # Verify static linking on nym-vpnd
        local vpnd_binary="$binary_dir/nym-vpnd"
        if [ -f "$vpnd_binary" ]; then
            if ldd "$vpnd_binary" 2>&1 | grep -q "not a dynamic executable"; then
                log_info "✓ Binaries are statically linked (good for OpenWRT)"
            else
                log_warn "Binaries have dynamic dependencies:"
                ldd "$vpnd_binary" || true
            fi
        fi
    else
        log_error "✗ Build failed - binary directory not found at: $binary_dir"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up build artifacts..."
    rm -rf "$BUILD_DIR"
    log_info "Cleanup complete"
}

main() {
    log_info "=== Cross-compiling nym-vpnd for OpenWRT/musl (${TARGET}) ==="
    log_info "=== Using KERNEL WireGuard (pure Rust netlink) ==="
    log_info ""

    check_arch
    install_system_deps
    compile_libmnl
    compile_libnftnl
    verify_pkg_config
    build_nym_vpnd

    log_info ""
    log_info "=== BUILD COMPLETE ==="
    log_info ""
    log_info "Your binaries are ready at:"
    log_info "  nym-vpn-core/target/${TARGET}/release/"
    log_info ""
    log_info "To copy to your OpenWRT device:"
    log_info "  scp nym-vpn-core/target/${TARGET}/release/nym-vpnd root@openwrt.lan:/usr/bin/"
    log_info "  scp nym-vpn-core/target/${TARGET}/release/nym-vpnc root@openwrt.lan:/usr/bin/"
    log_info ""
    log_info "IMPORTANT: Ensure WireGuard kernel module is loaded on target:"
    log_info "  modprobe wireguard"
    log_info ""
}

# Run main function
main "$@"
