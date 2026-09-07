#!/bin/bash
# Architecture definitions for NymVPN OpenWrt test infrastructure.
# All architectures run as direct QEMU VMs with user-mode networking.
# x86 targets get KVM acceleration if /dev/kvm is available.
#
# armv5te is excluded — no QEMU-bootable OpenWrt target exists for it.

OPENWRT_VERSION="${OPENWRT_VERSION:-23.05.5}"
OPENWRT_MIRROR="https://downloads.openwrt.org/releases"

# Ordered list of testable architectures
ARCHS=(x86_64 i686 aarch64 armv7 mips mipsel riscv64)

# OpenWrt build target paths (target/subtarget)
declare -A ARCH_OPENWRT_TARGET=(
    [x86_64]="x86/64"
    [i686]="x86/generic"
    [aarch64]="armsr/armv8"
    [armv7]="armsr/armv7"
    [mips]="malta/be"
    [mipsel]="malta/le"
    [riscv64]="qemu/riscv64"
)

# QEMU machine type (-machine flag)
declare -A ARCH_QEMU_MACHINE=(
    [x86_64]="pc"
    [i686]="pc"
    [aarch64]="virt"
    [armv7]="virt"
    [mips]="malta"
    [mipsel]="malta"
    [riscv64]="virt"
)

# QEMU CPU model (-cpu flag)
declare -A ARCH_QEMU_CPU=(
    [x86_64]="max"
    [i686]="max"
    [aarch64]="cortex-a53"
    [armv7]="cortex-a15"
    [mips]="24Kf"
    [mipsel]="24Kf"
    [riscv64]="rv64"
)

# QEMU system binary name
declare -A ARCH_QEMU_BIN=(
    [x86_64]="qemu-system-x86_64"
    [i686]="qemu-system-i386"
    [aarch64]="qemu-system-aarch64"
    [armv7]="qemu-system-arm"
    [mips]="qemu-system-mips"
    [mipsel]="qemu-system-mipsel"
    [riscv64]="qemu-system-riscv64"
)

# VM memory in MB
declare -A ARCH_MEMORY=(
    [x86_64]=256
    [i686]=256
    [aarch64]=256
    [armv7]=256
    [mips]=128
    [mipsel]=128
    [riscv64]=256
)

# SSH port forwarding (host port → guest :22)
declare -A ARCH_SSH_PORT=(
    [x86_64]=2200
    [i686]=2201
    [aarch64]=2202
    [armv7]=2203
    [mips]=2204
    [mipsel]=2205
    [riscv64]=2206
)

# Image type: "disk" (ext4-combined.img) or "initramfs" (vmlinux-initramfs.elf)
declare -A ARCH_IMAGE_TYPE=(
    [x86_64]="disk"
    [i686]="disk"
    [aarch64]="disk"
    [armv7]="disk"
    [mips]="initramfs"
    [mipsel]="initramfs"
    [riscv64]="disk"
)

# VPN connect timeout in seconds (emulated archs are slower)
declare -A ARCH_CONNECT_TIMEOUT=(
    [x86_64]=120
    [i686]=120
    [aarch64]=180
    [armv7]=180
    [mips]=300
    [mipsel]=300
    [riscv64]=180
)

# OpenWrt package architecture name (for feed/package matching)
declare -A ARCH_PKG_ARCH=(
    [x86_64]="x86_64"
    [i686]="i386_pentium4"
    [aarch64]="aarch64_generic"
    [armv7]="arm_cortex-a15_neon-vfpv4"
    [mips]="mips_24kc"
    [mipsel]="mipsel_24kc"
    [riscv64]="riscv64_riscv64"
)
