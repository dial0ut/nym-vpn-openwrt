#!/bin/bash
# Shared functions for the NymVPN OpenWrt test infrastructure.
# Provides logging, SSH helpers, and utility functions.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }

die() {
    log_error "$1"
    exit 1
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

IMAGE_DIR="${HOME}/nym-test/images"
SCRATCH_DIR="${HOME}/nym-test/scratch"
PID_DIR="/var/run"

# ---------------------------------------------------------------------------
# SSH helpers — all VMs use localhost + port forwarding
# ---------------------------------------------------------------------------

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

# Run a command on a test VM via SSH.
# Usage: vm_ssh <arch> <command...>
vm_ssh() {
    local arch="$1"
    shift
    local port="${ARCH_SSH_PORT[$arch]}"
    ssh $SSH_OPTS -p "$port" root@localhost "$@"
}

# Copy a file into a test VM.
# Usage: vm_scp <arch> <local_path> <remote_path>
vm_scp() {
    local arch="$1"
    local port="${ARCH_SSH_PORT[$arch]}"
    scp $SSH_OPTS -P "$port" "$2" "root@localhost:${3}"
}

# Wait until SSH is available on a VM.
# Usage: wait_for_ssh <arch> [timeout_seconds]
wait_for_ssh() {
    local arch="$1"
    local timeout="${2:-180}"
    local start
    start=$(date +%s)

    log_info "[$arch] Waiting for SSH (timeout: ${timeout}s)..."
    while true; do
        if vm_ssh "$arch" "echo ready" >/dev/null 2>&1; then
            log_info "[$arch] SSH is up"
            return 0
        fi
        local elapsed=$(( $(date +%s) - start ))
        if [[ "$elapsed" -ge "$timeout" ]]; then
            log_error "[$arch] SSH timeout after ${timeout}s"
            return 1
        fi
        sleep 3
    done
}

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

require_commands() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

ensure_dirs() {
    mkdir -p "$IMAGE_DIR" "$SCRATCH_DIR"
}

timestamp() {
    date +%Y%m%d-%H%M%S
}
