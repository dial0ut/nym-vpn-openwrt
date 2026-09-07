#!/bin/bash
# QEMU VM lifecycle management for NymVPN test infrastructure.
# All architectures use direct qemu-system-* invocation with user-mode networking.
# x86 targets get KVM acceleration automatically if /dev/kvm is available.

# Check if KVM is available on this host.
has_kvm() {
    [[ -w /dev/kvm ]]
}

# ---------------------------------------------------------------------------
# VM Start
# ---------------------------------------------------------------------------

# Start a QEMU VM for the given architecture.
# Usage: start_vm <arch>
start_vm() {
    local arch="$1"
    local qemu_bin="${ARCH_QEMU_BIN[$arch]}"
    local machine="${ARCH_QEMU_MACHINE[$arch]}"
    local cpu="${ARCH_QEMU_CPU[$arch]}"
    local mem="${ARCH_MEMORY[$arch]}"
    local ssh_port="${ARCH_SSH_PORT[$arch]}"
    local pidfile="${PID_DIR}/nym-test-${arch}.pid"

    # Kill any existing instance
    stop_vm "$arch" 2>/dev/null || true

    # -nographic puts the guest console on stdio, which QEMU refuses to combine
    # with -daemonize ("-nographic cannot be used with -daemonize"). Detach the
    # display instead and write the serial console to a file next to the logs;
    # nothing here reads the console, wait_for_ssh polls the guest.
    local serial_log="${RESULTS_DIR:-$SCRATCH_DIR}/${arch}-serial.log"
    log_info "[$arch] Starting VM (${qemu_bin}, ssh=localhost:${ssh_port}, console=${serial_log})..."

    local -a kvm_opts=()
    # Enable KVM for x86 if available
    if [[ "$arch" == "x86_64" || "$arch" == "i686" ]] && has_kvm; then
        kvm_opts=(-enable-kvm)
        cpu="host"
        log_info "[$arch] KVM acceleration enabled"
    fi

    # Flags every architecture shares; the case below adds boot media and NIC.
    local -a common_opts=(
        -machine "$machine" -cpu "$cpu" -m "${mem}M"
        -display none -monitor none -serial "file:${serial_log}"
        -netdev "user,id=net0,hostfwd=tcp::${ssh_port}-:22"
        -daemonize -pidfile "$pidfile"
    )
    local -a arch_opts=()

    case "$arch" in
        x86_64|i686)
            arch_opts=(
                -drive "file=${SCRATCH_DIR}/${arch}.img,format=raw,if=virtio"
                -device "virtio-net-pci,netdev=net0"
            )
            ;;

        aarch64)
            local bios
            bios=$(find_firmware \
                /usr/share/edk2/aarch64/QEMU_EFI.fd \
                /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
                /usr/share/AAVMF/AAVMF_CODE.fd \
                /usr/share/qemu/edk2-aarch64-code.fd)
            arch_opts=(
                -bios "$bios"
                -drive "file=${SCRATCH_DIR}/${arch}.img,format=raw,if=virtio"
                -device "virtio-net-pci,netdev=net0"
            )
            ;;

        armv7)
            arch_opts=(
                -drive "file=${SCRATCH_DIR}/${arch}.img,format=raw,if=virtio"
                -device "virtio-net-pci,netdev=net0"
            )
            ;;

        mips|mipsel)
            arch_opts=(
                -kernel "${SCRATCH_DIR}/${arch}.elf"
                -device "pcnet,netdev=net0"
            )
            ;;

        riscv64)
            local bios
            bios=$(find_firmware \
                /usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin \
                /usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin)
            arch_opts=(
                -bios "$bios"
                -drive "file=${SCRATCH_DIR}/${arch}.img,format=raw,if=virtio"
                -device "virtio-net-pci,netdev=net0"
            )
            ;;

        *)
            die "[$arch] No QEMU configuration defined"
            ;;
    esac

    "$qemu_bin" "${kvm_opts[@]}" "${common_opts[@]}" "${arch_opts[@]}"

    log_info "[$arch] VM started (pid: $(cat "$pidfile" 2>/dev/null || echo '?'))"
}

# ---------------------------------------------------------------------------
# VM Stop
# ---------------------------------------------------------------------------

# Stop a QEMU VM.
# Usage: stop_vm <arch>
stop_vm() {
    local arch="$1"
    local pidfile="${PID_DIR}/nym-test-${arch}.pid"

    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "[$arch] Stopping VM (pid $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    fi
}

# Stop all test VMs.
# Usage: stop_all_vms
stop_all_vms() {
    log_info "Stopping all test VMs..."
    for arch in "${ARCHS[@]}"; do
        stop_vm "$arch" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Find the first existing firmware file from a list of candidates.
# Usage: find_firmware <path1> <path2> ...
find_firmware() {
    for path in "$@"; do
        if [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    die "Firmware not found. Tried: $*"
}
