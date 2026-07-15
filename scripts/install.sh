#!/bin/sh
# NymVPN installer for OpenWrt
# Usage: curl -fsSL <url> | sh
#
# Environment variables:
#   NYM_VERSION  - Version to install (default: latest)
#   NYM_ARCH     - Override architecture detection

set -e

FEED_URL="https://packages.dial0ut.org"

# Colors (disabled if not tty)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

info()  { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
step()  { printf "${BLUE}==>${NC} %s\n" "$1"; }

die() { error "$1"; exit 1; }

download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        die "Neither curl nor wget found"
    fi
}

detect_pkg_manager() {
    if command -v opkg >/dev/null 2>&1; then
        echo "opkg"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        die "No supported package manager found (need opkg or apk)"
    fi
}

detect_arch() {
    if [ -n "$NYM_ARCH" ]; then
        echo "$NYM_ARCH"
        return
    fi

    local pkg_mgr="$1"
    local arch=""

    # Prefer DISTRIB_ARCH from OpenWrt release info — it has the specific
    # variant (e.g., aarch64_generic) that matches our package names.
    # apk --print-arch only returns the base arch (e.g., aarch64).
    if [ -f /etc/openwrt_release ]; then
        arch=$(. /etc/openwrt_release; echo "$DISTRIB_ARCH")
    fi

    # Fallback to package manager if DISTRIB_ARCH not available
    if [ -z "$arch" ]; then
        case "$pkg_mgr" in
            opkg)
                arch=$(opkg print-architecture | awk '{print $2, $3}' | sort -k2 -n | tail -1 | awk '{print $1}')
                ;;
            apk)
                arch=$(apk --print-arch)
                ;;
        esac
    fi

    [ -n "$arch" ] || die "Could not detect architecture"
    echo "$arch"
}

get_version() {
    if [ -n "$NYM_VERSION" ]; then
        echo "$NYM_VERSION"
        return
    fi

    local version=""
    if command -v curl >/dev/null 2>&1; then
        version=$(curl -fsSL "${FEED_URL}/latest")
    elif command -v wget >/dev/null 2>&1; then
        version=$(wget -qO- "${FEED_URL}/latest")
    fi

    [ -n "$version" ] || die "Failed to get latest version"
    echo "$version"
}

main() {
    echo ""
    printf "${BLUE}NymVPN Installer${NC}\n"
    echo ""

    [ "$(id -u)" -eq 0 ] || die "This script must be run as root"

    step "Detecting system..."
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    info "Package manager: $pkg_mgr"

    local arch
    arch=$(detect_arch "$pkg_mgr")
    info "Architecture: $arch"

    step "Getting latest version..."
    local version
    version=$(get_version)
    # strip leading 'v' for the package filename
    local ver_num="${version#v}"
    info "Version: $ver_num"

    local ext
    case "$pkg_mgr" in
        opkg) ext="ipk" ;;
        apk)  ext="apk" ;;
    esac

    local filename="nym-vpn_${ver_num}_${arch}.${ext}"
    local feed_type
    case "$pkg_mgr" in
        opkg) feed_type="opkg" ;;
        apk)  feed_type="apk" ;;
    esac
    local url="${FEED_URL}/${feed_type}/${arch}/${filename}"

    step "Downloading ${filename}..."
    download "$url" "/tmp/${filename}"

    # Refresh package lists so dependencies (kmod-tun, luci-base, ...) can be
    # resolved from the OpenWrt feeds when installing the local package.
    step "Updating package lists..."
    case "$pkg_mgr" in
        opkg) opkg update || warn "opkg update failed; dependency installation may fail" ;;
        apk)  apk update || warn "apk update failed; dependency installation may fail" ;;
    esac

    step "Installing..."
    case "$pkg_mgr" in
        opkg) opkg install "/tmp/${filename}" ;;
        apk)  apk add --allow-untrusted "/tmp/${filename}" ;;
    esac

    rm -f "/tmp/${filename}"

    # Belt and braces: nym-vpnd cannot create its tunnel without the TUN
    # driver. If the module isn't present (e.g. older package versions that
    # failed to declare the dependency), install it explicitly.
    if [ ! -e /dev/net/tun ] && ! grep -q '^tun ' /proc/modules 2>/dev/null; then
        warn "TUN device not available; installing kmod-tun..."
        case "$pkg_mgr" in
            opkg) opkg install kmod-tun ;;
            apk)  apk add kmod-tun ;;
        esac
    fi

    echo ""
    printf "${GREEN}NymVPN installed successfully!${NC}\n"
    echo ""
    echo "Open LuCI to configure: http://$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')/cgi-bin/luci/admin/services/nym-vpn"
    echo ""
}

main "$@"
