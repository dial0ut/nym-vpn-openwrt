#!/bin/bash
# Main test orchestrator for NymVPN OpenWrt multi-architecture testing.
# Runs on any Linux host with QEMU installed. Boots OpenWrt VMs per
# architecture, installs NymVPN, and runs the connection test sequence.
#
# Usage:
#   NYM_MNEMONIC="..." ./run-tests.sh [options] [arch1 arch2 ...]
#
# Options:
#   --feed              Install from packages.dial0ut.org feed
#   --packages <dir>    Install from local package directory
#   --release <tag>     Download and install from GitHub release
#   --skip-download     Skip OpenWrt image download (use cached)
#   --keep-vms          Don't destroy VMs after test (for debugging)
#   --help              Show this help
#
# If no architectures are specified, all 7 are tested.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load libraries
source "${SCRIPT_DIR}/configs/architectures.sh"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/qemu.sh"
source "${SCRIPT_DIR}/lib/openwrt.sh"
source "${SCRIPT_DIR}/lib/vpn-test.sh"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

PACKAGE_MODE=""        # "feed", "packages", or "release"
PACKAGE_DIR=""         # For --packages
RELEASE_TAG=""         # For --release
SKIP_DOWNLOAD=false
KEEP_VMS=false
SELECTED_ARCHS=()

usage() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --feed)
            PACKAGE_MODE="feed"
            shift
            ;;
        --packages)
            PACKAGE_MODE="packages"
            PACKAGE_DIR="$2"
            shift 2
            ;;
        --release)
            PACKAGE_MODE="release"
            RELEASE_TAG="$2"
            shift 2
            ;;
        --skip-download)
            SKIP_DOWNLOAD=true
            shift
            ;;
        --keep-vms)
            KEEP_VMS=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            # Validate architecture name
            local_valid=false
            for a in "${ARCHS[@]}"; do
                if [[ "$a" == "$1" ]]; then
                    local_valid=true
                    break
                fi
            done
            if ! $local_valid; then
                die "Unknown architecture: $1 (valid: ${ARCHS[*]})"
            fi
            SELECTED_ARCHS+=("$1")
            shift
            ;;
    esac
done

# Defaults
if [[ ${#SELECTED_ARCHS[@]} -eq 0 ]]; then
    SELECTED_ARCHS=("${ARCHS[@]}")
fi

if [[ -z "$PACKAGE_MODE" ]]; then
    die "Specify package source: --feed, --packages <dir>, or --release <tag>"
fi

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

[[ -n "${NYM_MNEMONIC:-}" ]] || die "NYM_MNEMONIC environment variable not set"

log_info "============================================"
log_info "  NymVPN OpenWrt Multi-Arch Test Suite"
log_info "============================================"
log_info "Package mode:  $PACKAGE_MODE"
log_info "Architectures: ${SELECTED_ARCHS[*]}"
log_info "OpenWrt:       $OPENWRT_VERSION"
log_info "============================================"
echo ""

# Check for required tools
require_commands jq wget

# Ensure working directories exist
ensure_dirs

# ---------------------------------------------------------------------------
# Download OpenWrt images
# ---------------------------------------------------------------------------

if ! $SKIP_DOWNLOAD; then
    log_step "Downloading OpenWrt images..."
    for arch in "${SELECTED_ARCHS[@]}"; do
        download_openwrt_image "$arch"
    done
    echo ""
fi

# ---------------------------------------------------------------------------
# Run tests sequentially
# ---------------------------------------------------------------------------

declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TS=$(timestamp)
RESULTS_DIR="${SCRIPT_DIR}/results/${TS}"
mkdir -p "$RESULTS_DIR"

# Trap to clean up VMs on unexpected exit
cleanup_on_exit() {
    if ! $KEEP_VMS; then
        log_warn "Cleaning up VMs..."
        stop_all_vms 2>/dev/null || true
    fi
}
trap cleanup_on_exit EXIT

for arch in "${SELECTED_ARCHS[@]}"; do
    echo ""
    log_step "========== Testing: ${arch} =========="
    LOG_FILE="${RESULTS_DIR}/${arch}.log"

    # Prepare fresh image
    prepare_vm_image "$arch"

    # Start VM
    if ! start_vm "$arch" 2>&1 | tee -a "$LOG_FILE"; then
        log_error "[$arch] Failed to start VM"
        RESULTS[$arch]="FAIL:vm_start"
        ((FAIL_COUNT++))
        continue
    fi

    # Wait for SSH
    if ! wait_for_ssh "$arch" 180 2>&1 | tee -a "$LOG_FILE"; then
        RESULTS[$arch]="FAIL:ssh_timeout"
        ((FAIL_COUNT++))
        $KEEP_VMS || stop_vm "$arch" 2>/dev/null || true
        continue
    fi

    # First-boot configuration
    setup_openwrt_vm "$arch" 2>&1 | tee -a "$LOG_FILE"

    # Install package
    case "$PACKAGE_MODE" in
        feed)
            if ! install_package_feed "$arch" 2>&1 | tee -a "$LOG_FILE"; then
                RESULTS[$arch]="FAIL:install"
                ((FAIL_COUNT++))
                $KEEP_VMS || stop_vm "$arch" 2>/dev/null || true
                continue
            fi
            ;;
        packages)
            pkg_arch="${ARCH_PKG_ARCH[$arch]}"
            pkg_file=""
            pkg_file=$(find "$PACKAGE_DIR" -name "*${pkg_arch}*" -type f | head -1)
            if [[ -z "$pkg_file" ]]; then
                log_error "[$arch] No package found for $pkg_arch in $PACKAGE_DIR"
                RESULTS[$arch]="FAIL:no_package"
                ((FAIL_COUNT++))
                $KEEP_VMS || stop_vm "$arch" 2>/dev/null || true
                continue
            fi
            if ! install_package_file "$arch" "$pkg_file" 2>&1 | tee -a "$LOG_FILE"; then
                RESULTS[$arch]="FAIL:install"
                ((FAIL_COUNT++))
                $KEEP_VMS || stop_vm "$arch" 2>/dev/null || true
                continue
            fi
            ;;
        release)
            if ! install_package_release "$arch" "$RELEASE_TAG" 2>&1 | tee -a "$LOG_FILE"; then
                RESULTS[$arch]="FAIL:install"
                ((FAIL_COUNT++))
                $KEEP_VMS || stop_vm "$arch" 2>/dev/null || true
                continue
            fi
            ;;
    esac

    # Run VPN test
    if run_vpn_test "$arch" 2>&1 | tee -a "$LOG_FILE"; then
        RESULTS[$arch]="PASS"
        ((PASS_COUNT++))
    else
        RESULTS[$arch]="FAIL"
        ((FAIL_COUNT++))
    fi

    # Stop VM
    if ! $KEEP_VMS; then
        stop_vm "$arch" 2>/dev/null || true
    fi

    log_step "========== ${arch}: ${RESULTS[$arch]} =========="
done

# ---------------------------------------------------------------------------
# Generate report
# ---------------------------------------------------------------------------

REPORT="${RESULTS_DIR}/report.md"

{
    echo "# NymVPN OpenWrt Test Report"
    echo ""
    echo "**Date:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Package source:** ${PACKAGE_MODE}${RELEASE_TAG:+ ($RELEASE_TAG)}${PACKAGE_DIR:+ ($PACKAGE_DIR)}"
    echo "**OpenWrt version:** ${OPENWRT_VERSION}"
    echo ""
    echo "## Results"
    echo ""
    echo "| Architecture | Pkg Arch | Result |"
    echo "|---|---|---|"
    for arch in "${SELECTED_ARCHS[@]}"; do
        r="${RESULTS[$arch]:-SKIP}"
        pkg_arch="${ARCH_PKG_ARCH[$arch]}"
        echo "| ${arch} | ${pkg_arch} | ${r} |"
    done
    echo ""
    echo "**Summary:** ${PASS_COUNT} passed, ${FAIL_COUNT} failed, ${#SELECTED_ARCHS[@]} total"
    echo ""
    echo "## Logs"
    echo ""
    for arch in "${SELECTED_ARCHS[@]}"; do
        echo "- [${arch}](${arch}.log)"
    done
} > "$REPORT"

echo ""
log_step "============================================"
log_step "  Test Report"
log_step "============================================"
cat "$REPORT"
echo ""
log_info "Full report: ${REPORT}"
log_info "Logs: ${RESULTS_DIR}/"

# Exit with failure if any test failed
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
