#!/bin/bash
# Author: dial0ut
# Version: v0.0.1
# Cross-compile nym-vpnd for OpenWrt (dynamically linked musl targets)
# This script runs INSIDE the messense/rust-musl-cross container
#
# Unlike cross-compile-musl.sh (fully static), this produces dynamically linked
# binaries that depend on the target system's musl libc and libgcc_s. This is
# the standard approach for OpenWrt packages — smaller binaries, shared
# libraries get security updates via opkg, and no duplicate musl in each binary.
#
# Runtime dependencies (provided by OpenWrt packages):
#   libc          - musl libc (always present)
#   libgcc        - libgcc_s.so.1 (unwinding)
#   kmod-tun      - TUN kernel module
#
# Usage from host:
#   docker run --rm -it -v "$(pwd)":/home/rust/src \
#     messense/rust-musl-cross:aarch64-musl \
#     bash /home/rust/src/scripts/cross-compile-dynamic.sh
#
# Supported targets (Docker image tags):
#   messense/rust-musl-cross:x86_64-musl       # x86 64-bit
#   messense/rust-musl-cross:i686-musl         # x86 32-bit (x86/generic)
#   messense/rust-musl-cross:aarch64-musl      # ARM 64-bit (Raspberry Pi 4, rockchip, mediatek)
#   messense/rust-musl-cross:armv7-musleabihf  # ARM v7 32-bit hard-float (bcm53xx, mvebu)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/log.sh"
source "$SCRIPT_DIR/versions.sh"

# Configuration - auto-detect target from available compiler
if [ -z "${TARGET:-}" ]; then
    if command -v arm-unknown-linux-musleabi-gcc &> /dev/null; then
        TARGET="arm-unknown-linux-musleabi"
    elif command -v armv7-unknown-linux-musleabihf-gcc &> /dev/null; then
        TARGET="armv7-unknown-linux-musleabihf"
    elif command -v i686-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="i686-unknown-linux-musl"
    elif command -v aarch64-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="aarch64-unknown-linux-musl"
    elif command -v x86_64-unknown-linux-musl-gcc &> /dev/null; then
        TARGET="x86_64-unknown-linux-musl"
    else
        TARGET="aarch64-unknown-linux-musl"  # Default fallback
    fi
fi
MUSL_PREFIX="/usr/local/musl/${TARGET}"

check_arch() {
    local arch=$(uname -m)
    log_info "Container architecture: $arch"
    log_info "Target triple: $TARGET"
    log_info "Link mode: dynamic (shared libraries)"
}

install_system_deps() {
    log_info "Installing system dependencies..."

    # Check Rust version - the workspace MSRV (rust-version in Cargo.toml)
    local current_version=$(rustc --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local required_version="1.95"
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
        log_info "Installing protoc ${PROTOC_VERSION}..."
        PB_REL="https://github.com/protocolbuffers/protobuf/releases"
        curl -Lo "/tmp/protoc.zip" "$PB_REL/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
        unzip -q "/tmp/protoc.zip" -d "$HOME/.local"
        rm "/tmp/protoc.zip"
    fi
    # Always ensure protoc is in PATH (may have been installed in previous run)
    export PATH="$PATH:$HOME/.local/bin"
    log_info "protoc version: $(protoc --version)"
}

build_nym_vpnd() {
    log_info "Building nym-vpnd for ${TARGET} (dynamic linking)..."

    cd /home/rust/src/nym-vpn-core

    # For soft-float ARM, use ARMv5TE with portable-atomic for BCM5301X (no VFP/NEON)
    if [[ "$TARGET" == "arm-unknown-linux-musleabi" ]]; then
        log_info "Using ARMv5TE with portable-atomic for BCM5301X compatibility..."

        log_info "Installing armv5te-unknown-linux-musleabi Rust target..."
        rustup target add armv5te-unknown-linux-musleabi || true

        # Override TARGET to use ARMv5TE
        # Note: MUSL_PREFIX keeps pointing at the arm-unknown-linux-musleabi
        # toolchain sysroot
        TARGET="armv5te-unknown-linux-musleabi"
        log_info "Using Rust target: ${TARGET} (ARMv5TE soft-float, will use portable-atomic)"
        log_info "Sysroot remains: ${MUSL_PREFIX}"

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

    # Set environment for cargo
    export PKG_CONFIG_PATH="${MUSL_PREFIX}/lib/pkgconfig"
    export PKG_CONFIG_ALLOW_CROSS=1

    # Add target-specific flags
    TARGET_UNDERSCORE="${TARGET//-/_}"

    # === DYNAMIC LINKING ===
    # -crt-static: opt out of Rust's default static linking for musl targets
    # This links against the system's musl libc dynamically (ld-musl-*.so.1)
    export RUSTFLAGS="-C target-feature=-crt-static"

    # ARM targets need special handling for atomic operations
    if [[ "$TARGET" == "armv7-unknown-linux-musleabihf" ]] || [[ "$TARGET" == "arm-unknown-linux-musleabi" ]] || [[ "$TARGET" == "armv7-unknown-linux-musleabi" ]] || [[ "$TARGET" == "armv5te-unknown-linux-musleabi" ]]; then
        log_info "Adding ARM-specific linker flags for atomic operations..."
        export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-lgcc"

        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"

        # Only set soft-float for soft-float targets (NOT for musleabihf which is hard-float)
        if [[ "$TARGET" != "armv7-unknown-linux-musleabihf" ]]; then
            log_info "Setting soft-float flags for BCM5301X compatibility..."
            export CFLAGS_${TARGET_UNDERSCORE}="-msoft-float -mfloat-abi=soft"
        else
            log_info "Using hard-float ABI for armv7-musleabihf target"
        fi
    fi

    # i686 (32-bit x86) targets
    if [[ "$TARGET" == "i686-unknown-linux-musl" ]]; then
        log_info "Configuring for i686 (32-bit x86) target..."
        export CC_${TARGET_UNDERSCORE}="${TARGET}-gcc"
        export AR_${TARGET_UNDERSCORE}="${TARGET}-ar"
    fi

    # aarch64: no need to disable outline atomics for dynamic linking —
    # the symbols resolve from the system's libgcc at runtime

    # Append extra RUSTFLAGS if provided (e.g., for CPU-specific builds like cortex-a9)
    if [ -n "${RUSTFLAGS_EXTRA:-}" ]; then
        log_info "Adding extra RUSTFLAGS: ${RUSTFLAGS_EXTRA}"
        export RUSTFLAGS="${RUSTFLAGS} ${RUSTFLAGS_EXTRA}"
    fi

    log_info "RUSTFLAGS=${RUSTFLAGS}"

    # 32-bit targets need the nym ecash usize fix (patch-crates.sh decides
    # from the target). It edits the nym git checkout, so fetch first.
    log_info "Fetching dependencies..."
    cargo fetch --target="${TARGET}"
    bash "$SCRIPT_DIR/../docker/tier3-musl/patch-crates.sh" --ecash-only \
        "${CARGO_HOME:-$HOME/.cargo}" "$TARGET" "$PWD/Cargo.toml"
    # The ecash fix edits a git checkout in place, and cargo never re-checks a
    # git dependency's sources: drop any artifact built before the patch.
    cargo clean --release --target="${TARGET}" -p nym-compact-ecash

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

    else
        log_error "✗ Build failed - binary directory not found at: $binary_dir"
        exit 1
    fi
}

main() {
    log_info "=== Cross-compiling nym-vpnd for OpenWrt/musl (${TARGET}) ==="
    log_info "=== Dynamic linking — depends on system musl and libgcc_s ==="
    log_info ""

    check_arch
    install_system_deps
    build_nym_vpnd

    log_info ""
    log_info "=== BUILD COMPLETE ==="
    log_info ""
    log_info "Your binaries are ready at:"
    log_info "  nym-vpn-core/target/${TARGET}/release/"
    log_info ""
    log_info "These binaries are dynamically linked. The target OpenWrt device needs:"
    log_info "  - libc (musl — always present on OpenWrt)"
    log_info "  - libgcc (libgcc_s.so.1)"
    log_info "  - kmod-tun (opkg install kmod-tun)"
    log_info ""
}

# Run main function
main "$@"
