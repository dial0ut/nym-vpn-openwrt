#!/bin/bash
# Full pipeline: build binaries for all architectures, package as .ipk, run tests.
# Runs entirely on a single machine with Docker and QEMU.
#
# Usage:
#   NYM_MNEMONIC="..." ./tests/build-and-test.sh [options] [arch1 arch2 ...]
#
# Options:
#   --dynamic           Build with dynamic linking (smaller binaries)
#   --skip-build        Skip build, use existing binaries in artifacts/
#   --skip-package      Skip packaging, use existing .ipk files in artifacts/packages/
#   --skip-cleanup      Skip Playwright device cleanup
#   --keep-vms          Don't destroy VMs after test (for debugging)
#   --help              Show this help
#
# If no architectures are specified, all 7 are built and tested.
#
# Examples:
#   NYM_MNEMONIC="..." ./tests/build-and-test.sh x86_64
#   NYM_MNEMONIC="..." ./tests/build-and-test.sh --dynamic
#   NYM_MNEMONIC="..." ./tests/build-and-test.sh --skip-build --skip-package x86_64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${SCRIPT_DIR}/configs/architectures.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

die() { log_error "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

DYNAMIC=false
SKIP_BUILD=false
SKIP_PACKAGE=false
SKIP_CLEANUP=false
KEEP_VMS=false
SELECTED_ARCHS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dynamic)      DYNAMIC=true; shift ;;
        --skip-build)   SKIP_BUILD=true; shift ;;
        --skip-package) SKIP_PACKAGE=true; shift ;;
        --skip-cleanup) SKIP_CLEANUP=true; shift ;;
        --keep-vms)     KEEP_VMS=true; shift ;;
        --help|-h)
            sed -n '2,/^$/s/^# \?//p' "$0"
            exit 0
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            valid=false
            for a in "${ARCHS[@]}"; do
                [[ "$a" == "$1" ]] && valid=true && break
            done
            $valid || die "Unknown architecture: $1 (valid: ${ARCHS[*]})"
            SELECTED_ARCHS+=("$1")
            shift
            ;;
    esac
done

if [[ ${#SELECTED_ARCHS[@]} -eq 0 ]]; then
    SELECTED_ARCHS=("${ARCHS[@]}")
fi

[[ -n "${NYM_MNEMONIC:-}" ]] || die "NYM_MNEMONIC environment variable not set"

# Get version from Cargo.toml
VERSION=$(grep '^version' "${REPO_ROOT}/nym-vpn-core/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')

ARTIFACTS_DIR="${REPO_ROOT}/artifacts"
PACKAGES_DIR="${ARTIFACTS_DIR}/packages"

# Map Rust arch → Rust target triple
declare -A ARCH_TARGET=(
    [x86_64]="x86_64-unknown-linux-musl"
    [i686]="i686-unknown-linux-musl"
    [aarch64]="aarch64-unknown-linux-musl"
    [armv7]="armv7-unknown-linux-musleabihf"
    [mips]="mips-unknown-linux-musl"
    [mipsel]="mipsel-unknown-linux-musl"
    [riscv64]="riscv64gc-unknown-linux-musl"
)

LINK_MODE="static"
$DYNAMIC && LINK_MODE="dynamic"

log_step "============================================"
log_step "  NymVPN Build + Test Pipeline"
log_step "============================================"
log_info "Version:       $VERSION"
log_info "Link mode:     $LINK_MODE"
log_info "Architectures: ${SELECTED_ARCHS[*]}"
log_step "============================================"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Build binaries
# ---------------------------------------------------------------------------

if ! $SKIP_BUILD; then
    log_step "Step 1: Building binaries..."
    mkdir -p "$ARTIFACTS_DIR"

    BUILD_FLAG=""
    $DYNAMIC && BUILD_FLAG="--dynamic"

    for arch in "${SELECTED_ARCHS[@]}"; do
        log_info "Building $arch ($LINK_MODE)..."
        "${REPO_ROOT}/scripts/build-musl.sh" $BUILD_FLAG "$arch"

        # Copy binaries to artifacts
        target="${ARCH_TARGET[$arch]}"
        bin_dir="${REPO_ROOT}/nym-vpn-core/target/${target}/release"

        if [[ ! -f "${bin_dir}/nym-vpnd" ]] || [[ ! -f "${bin_dir}/nym-vpnc" ]]; then
            die "[$arch] Build failed — binaries not found in ${bin_dir}"
        fi

        mkdir -p "${ARTIFACTS_DIR}/${arch}"
        cp "${bin_dir}/nym-vpnd" "${ARTIFACTS_DIR}/${arch}/"
        cp "${bin_dir}/nym-vpnc" "${ARTIFACTS_DIR}/${arch}/"

        log_info "[$arch] Binaries:"
        ls -lh "${ARTIFACTS_DIR}/${arch}/nym-vpnd" "${ARTIFACTS_DIR}/${arch}/nym-vpnc"
        echo ""
    done
else
    log_info "Step 1: Skipping build (--skip-build)"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 2: Package as .ipk
# ---------------------------------------------------------------------------

if ! $SKIP_PACKAGE; then
    log_step "Step 2: Packaging .ipk files..."
    mkdir -p "$PACKAGES_DIR"

    LUCI_DIR="${REPO_ROOT}/luci-app-nym-vpn"

    for arch in "${SELECTED_ARCHS[@]}"; do
        pkg_arch="${ARCH_PKG_ARCH[$arch]}"
        bin_dir="${ARTIFACTS_DIR}/${arch}"

        if [[ ! -f "${bin_dir}/nym-vpnd" ]]; then
            die "[$arch] Binaries not found in ${bin_dir} — run without --skip-build"
        fi

        log_info "[$arch] Packaging ${pkg_arch}..."
        "${REPO_ROOT}/scripts/ipk/build-ipk.sh" \
            "$VERSION" \
            "$pkg_arch" \
            "$bin_dir" \
            "$LUCI_DIR" \
            "$PACKAGES_DIR"

        echo ""
    done

    log_info "Packages built:"
    ls -lh "${PACKAGES_DIR}"/*.ipk
    echo ""
else
    log_info "Step 2: Skipping packaging (--skip-package)"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 3: Run tests
# ---------------------------------------------------------------------------

log_step "Step 3: Running tests..."

TEST_ARGS=(--packages "$PACKAGES_DIR")
$SKIP_CLEANUP && TEST_ARGS+=(--skip-cleanup)  # not used by run-tests.sh but harmless
$KEEP_VMS && TEST_ARGS+=(--keep-vms)

NYM_MNEMONIC="$NYM_MNEMONIC" "${SCRIPT_DIR}/run-tests.sh" \
    "${TEST_ARGS[@]}" \
    "${SELECTED_ARCHS[@]}"
