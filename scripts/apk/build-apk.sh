#!/bin/bash
# Build APK package for OpenWrt 25.x+ (apk package manager)
#
# Usage: build-apk.sh <version> <openwrt_arch> <binary_dir> <luci_dir> [output_dir]
#
# Arguments:
#   version      - Package version (e.g., "1.23.2")
#   openwrt_arch - OpenWrt architecture (e.g., "x86_64")
#   binary_dir   - Directory containing nym-vpnd and nym-vpnc binaries
#   luci_dir     - Path to LuCI app directory (luci-app-nym-vpn)
#   output_dir   - Output directory for APK (default: current directory)
#
# APK format (Alpine/OpenWrt apk-tools):
#   A gzipped tar containing:
#     .PKGINFO       - Package metadata (key = value)
#     .post-install  - Post-install script (optional)
#     .pre-deinstall - Pre-removal script (optional)
#     <data files>   - Files at their final install paths

set -euo pipefail

# --- Argument parsing ---
if [ $# -lt 4 ]; then
    echo "Usage: $0 <version> <openwrt_arch> <binary_dir> <luci_dir> [output_dir]"
    echo ""
    echo "Arguments:"
    echo "  version      - Package version (e.g., '1.23.2')"
    echo "  openwrt_arch - OpenWrt architecture (e.g., 'x86_64')"
    echo "  binary_dir   - Directory containing nym-vpnd and nym-vpnc binaries"
    echo "  luci_dir     - Path to LuCI app directory (luci-app-nym-vpn)"
    echo "  output_dir   - Output directory for APK (default: current directory)"
    exit 1
fi

VERSION="$1"
OPENWRT_ARCH="$2"
BINARY_DIR="$3"
LUCI_DIR="$4"
OUTPUT_DIR="${5:-.}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IPK_SCRIPT_DIR="$REPO_ROOT/scripts/ipk"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# --- Validation ---
echo "=== Validating inputs ==="

if [ ! -f "$BINARY_DIR/nym-vpnd" ]; then
    echo "Error: nym-vpnd not found in $BINARY_DIR"
    exit 1
fi

if [ ! -f "$BINARY_DIR/nym-vpnc" ]; then
    echo "Error: nym-vpnc not found in $BINARY_DIR"
    exit 1
fi

if [ ! -d "$LUCI_DIR/htdocs" ]; then
    echo "Error: LuCI directory invalid (missing htdocs/): $LUCI_DIR"
    exit 1
fi

if [ ! -f "$LUCI_DIR/root/etc/init.d/nym-vpnd" ]; then
    echo "Error: Init script not found in LuCI repo: $LUCI_DIR/root/etc/init.d/nym-vpnd"
    exit 1
fi

echo "Version:      $VERSION"
echo "Architecture: $OPENWRT_ARCH"
echo "Binaries:     $BINARY_DIR"
echo "LuCI:         $LUCI_DIR"
echo "Output:       $OUTPUT_DIR"

# --- Setup build directory ---
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# APK packages have data files directly at their install paths (no nested data/ dir)
DATA_DIR="$BUILD_DIR"

# === DATA: Binaries ===
echo "=== Adding binaries ==="
mkdir -p "$DATA_DIR/usr/sbin" "$DATA_DIR/usr/bin"
cp "$BINARY_DIR/nym-vpnd" "$DATA_DIR/usr/sbin/"
cp "$BINARY_DIR/nym-vpnc" "$DATA_DIR/usr/bin/"
chmod 755 "$DATA_DIR/usr/sbin/nym-vpnd" "$DATA_DIR/usr/bin/nym-vpnc"

# === DATA: LuCI frontend ===
echo "=== Adding LuCI frontend ==="

# View file
mkdir -p "$DATA_DIR/www/luci-static/resources/view/nym-vpn"
cp "$LUCI_DIR/htdocs/luci-static/resources/view/nym-vpn/"*.js \
   "$DATA_DIR/www/luci-static/resources/view/nym-vpn/"

# Module files (rpc, ui, countries, assets, theme)
mkdir -p "$DATA_DIR/www/luci-static/resources/nym-vpn"
cp "$LUCI_DIR/htdocs/luci-static/resources/nym-vpn/"*.js \
   "$DATA_DIR/www/luci-static/resources/nym-vpn/"

# === DATA: RPC backend ===
echo "=== Adding RPC backend ==="
mkdir -p "$DATA_DIR/usr/libexec/rpcd"
cp "$LUCI_DIR/root/usr/libexec/rpcd/nym-vpn" "$DATA_DIR/usr/libexec/rpcd/"
chmod 755 "$DATA_DIR/usr/libexec/rpcd/nym-vpn"

# === DATA: Menu and ACL config ===
echo "=== Adding menu and ACL config ==="
mkdir -p "$DATA_DIR/usr/share/luci/menu.d"
mkdir -p "$DATA_DIR/usr/share/rpcd/acl.d"
cp "$LUCI_DIR/root/usr/share/luci/menu.d/luci-app-nym-vpn.json" \
   "$DATA_DIR/usr/share/luci/menu.d/"
cp "$LUCI_DIR/root/usr/share/rpcd/acl.d/luci-app-nym-vpn.json" \
   "$DATA_DIR/usr/share/rpcd/acl.d/"

# === DATA: Init script ===
echo "=== Adding init script ==="
mkdir -p "$DATA_DIR/etc/init.d"
cp "$LUCI_DIR/root/etc/init.d/nym-vpnd" "$DATA_DIR/etc/init.d/"
chmod 755 "$DATA_DIR/etc/init.d/nym-vpnd"

# === DATA: Config and UCI defaults ===
echo "=== Adding config and UCI defaults ==="
mkdir -p "$DATA_DIR/etc/config"
mkdir -p "$DATA_DIR/etc/uci-defaults"
mkdir -p "$DATA_DIR/var/lib/nym-vpn"

cp "$IPK_SCRIPT_DIR/nym-vpn.conf" "$DATA_DIR/etc/config/nym-vpn"

# LuCI UCI defaults (if present in LuCI repo)
if [ -f "$LUCI_DIR/root/etc/uci-defaults/luci-app-nym-vpn" ]; then
    cp "$LUCI_DIR/root/etc/uci-defaults/luci-app-nym-vpn" "$DATA_DIR/etc/uci-defaults/"
    chmod 755 "$DATA_DIR/etc/uci-defaults/luci-app-nym-vpn"
fi

# === DATA: Firewall include scripts ===
echo "=== Adding firewall scripts ==="
mkdir -p "$DATA_DIR/usr/share/nym-vpn"

FW_SCRIPTS_DIR="$REPO_ROOT/nym-vpn-core/crates/nym-firewall/scripts"
if [ -f "$FW_SCRIPTS_DIR/fw3-include.sh" ]; then
    cp "$FW_SCRIPTS_DIR/fw3-include.sh" "$DATA_DIR/usr/share/nym-vpn/"
    chmod 755 "$DATA_DIR/usr/share/nym-vpn/fw3-include.sh"
fi
if [ -f "$FW_SCRIPTS_DIR/fw4-include.sh" ]; then
    cp "$FW_SCRIPTS_DIR/fw4-include.sh" "$DATA_DIR/usr/share/nym-vpn/"
    chmod 755 "$DATA_DIR/usr/share/nym-vpn/fw4-include.sh"
fi

# === DATA: Feed signing public key ===
echo "=== Adding feed signing key ==="
FEED_KEY="$REPO_ROOT/scripts/feed/dial0ut.pub"
if [ -f "$FEED_KEY" ]; then
    mkdir -p "$DATA_DIR/etc/apk/keys"
    cp "$FEED_KEY" "$DATA_DIR/etc/apk/keys/dial0ut.pub"
fi

# === METADATA: .PKGINFO ===
echo "=== Generating .PKGINFO ==="

# Calculate installed size in bytes
INSTALLED_SIZE=$(du -sb "$DATA_DIR" | cut -f1)

cat > "$BUILD_DIR/.PKGINFO" <<EOF
pkgname = nym-vpn
pkgver = ${VERSION}-r0
pkgdesc = NymVPN for OpenWrt - Privacy VPN using the Nym mixnet
url = https://github.com/dial0ut/nym-vpn-openwrt
size = ${INSTALLED_SIZE}
arch = ${OPENWRT_ARCH}
license = GPL-3.0
origin = nym-vpn
maintainer = Nym Technologies <support@nymtech.net>
depend = libc
depend = kmod-tun
depend = luci-base
depend = rpcd
EOF

echo ".PKGINFO:"
cat "$BUILD_DIR/.PKGINFO"

# === SCRIPTS: .post-install ===
echo "=== Adding install scripts ==="
cp "$IPK_SCRIPT_DIR/postinst" "$BUILD_DIR/.post-install"
chmod 755 "$BUILD_DIR/.post-install"

# === SCRIPTS: .pre-deinstall ===
cp "$IPK_SCRIPT_DIR/prerm" "$BUILD_DIR/.pre-deinstall"
chmod 755 "$BUILD_DIR/.pre-deinstall"

# === Build APK ===
echo "=== Building APK ==="

OUTPUT_FILE="$OUTPUT_DIR/nym-vpn_${VERSION}_${OPENWRT_ARCH}.apk"

# APK format: gzipped tar with .PKGINFO first, then scripts, then data files
# The order matters: metadata files must come before data files
(
    cd "$BUILD_DIR"
    # Build file list: .PKGINFO first, then scripts, then all data
    {
        echo "./.PKGINFO"
        [ -f ".post-install" ] && echo "./.post-install"
        [ -f ".pre-deinstall" ] && echo "./.pre-deinstall"
        find . -mindepth 1 \
               -not -name '.PKGINFO' \
               -not -name '.post-install' \
               -not -name '.pre-deinstall' \
               \( -type f -o -type l -o -type d \) | sort
    } | tar -czf "$OUTPUT_FILE" --no-recursion -T -
)

echo ""
echo "=== Build complete ==="
ls -lh "$OUTPUT_FILE"
echo ""
echo "Install on OpenWrt 25.x+ with:"
echo "  apk add --allow-untrusted $OUTPUT_FILE"
