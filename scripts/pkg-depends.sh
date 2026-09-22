#!/bin/bash
# The package's runtime dependencies, one list for both formats. Sourced by
# scripts/ipk/build-ipk.sh and scripts/apk/build-apk.sh.
#
#   nym_pkg_depends <openwrt_arch> opkg   -> "libc (>= 1.2), kmod-tun, ..."
#   nym_pkg_depends <openwrt_arch> apk    -> "libc>=1.2 kmod-tun ..."

NYM_PKG_DEPENDS=(
    libc
    kmod-tun                  # TUN device for userspace WireGuard
    libmnl
    libnftnl
    kmod-ipt-conntrack-extra  # conntrack marking for inbound exemptions on fw3
    luci-base
    rpcd
)

# The 32-bit builds import musl 1.2's time64 symbols (sqlite, aws-lc and
# libdbus call the time functions), so they need libc >= 1.2: OpenWrt 22.03
# and later. OpenWrt's libc package is versioned by its musl (21.02: 1.1.24).
NYM_PKG_LIBC_MIN_32BIT="1.2"

# 0 for a 32-bit OpenWrt architecture, 1 for a 64-bit one; an unknown name
# stops the build rather than guess.
nym_pkg_arch_is_32bit() {
    case "$1" in
        aarch64_*|x86_64|riscv64_*|mips64_*|mips64el_*) return 1 ;;
        arm_*|i386_*|mips_*|mipsel_*) return 0 ;;
        *)
            echo "Error: unknown OpenWrt architecture '$1' (add it to scripts/pkg-depends.sh)" >&2
            exit 1
            ;;
    esac
}

nym_pkg_depends() {
    local arch="$1" format="$2" dep libc_min=""
    local -a deps=()
    if nym_pkg_arch_is_32bit "$arch"; then
        libc_min="$NYM_PKG_LIBC_MIN_32BIT"
    fi
    for dep in "${NYM_PKG_DEPENDS[@]}"; do
        if [ "$dep" = libc ] && [ -n "$libc_min" ]; then
            case "$format" in
                opkg) dep="libc (>= $libc_min)" ;;
                apk) dep="libc>=$libc_min" ;;
            esac
        fi
        deps+=("$dep")
    done
    case "$format" in
        opkg)
            local joined
            joined=$(printf '%s, ' "${deps[@]}")
            printf '%s\n' "${joined%, }"
            ;;
        apk) printf '%s\n' "${deps[*]}" ;;
        *)
            echo "Error: nym_pkg_depends: format must be opkg or apk, not '$format'" >&2
            exit 1
            ;;
    esac
}

# Refuse to package an ELF binary under an architecture of the other word
# size: the libc constraint above is keyed on the architecture name.
nym_pkg_check_elf_class() {
    local arch="$1" bin="$2" magic class
    magic=$(head -c 4 "$bin" | od -A n -t x1 | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || return 0
    class=$(od -A n -t u1 -j 4 -N 1 "$bin" | tr -d ' \n')
    if nym_pkg_arch_is_32bit "$arch"; then
        [ "$class" = 1 ] && return 0
    else
        [ "$class" = 2 ] && return 0
    fi
    echo "Error: $bin is ELF class $class (1 = 32-bit, 2 = 64-bit), which does not match $arch" >&2
    exit 1
}
