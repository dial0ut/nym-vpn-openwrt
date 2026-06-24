#!/bin/bash
# Build APK package for OpenWrt 25.x+ (apk package manager)
#
# Usage: build-apk.sh <version> <openwrt_arch> <binary_dir> [luci_dir] [output_dir]
#
#   luci_dir defaults to luci-app-nym-vpn/ in this repo.
#
# Uses apk mkpkg from apk-tools 3.x (via Docker Alpine) to produce
# properly formatted packages compatible with OpenWrt 25's apk-tools.

set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <version> <openwrt_arch> <binary_dir> [luci_dir] [output_dir]"
    exit 1
fi

VERSION="$1"
OPENWRT_ARCH="$2"
BINARY_DIR="$3"
LUCI_DIR="${4:-}"
OUTPUT_DIR="${5:-.}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LUCI_DIR="${LUCI_DIR:-$REPO_ROOT/luci-app-nym-vpn}"
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

# --- Setup build directories ---
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

DATA_DIR="$BUILD_DIR/data"
SCRIPTS_DIR="$BUILD_DIR/scripts"
mkdir -p "$DATA_DIR" "$SCRIPTS_DIR"

# === DATA: Binaries ===
echo "=== Adding binaries ==="
mkdir -p "$DATA_DIR/usr/sbin" "$DATA_DIR/usr/bin"
cp "$BINARY_DIR/nym-vpnd" "$DATA_DIR/usr/sbin/"
cp "$BINARY_DIR/nym-vpnc" "$DATA_DIR/usr/bin/"
chmod 755 "$DATA_DIR/usr/sbin/nym-vpnd" "$DATA_DIR/usr/bin/nym-vpnc"

# === DATA: LuCI frontend ===
echo "=== Adding LuCI frontend ==="
mkdir -p "$DATA_DIR/www/luci-static/resources/view/nym-vpn"
cp "$LUCI_DIR/htdocs/luci-static/resources/view/nym-vpn/"*.js \
   "$DATA_DIR/www/luci-static/resources/view/nym-vpn/"

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

# === Install scripts ===
echo "=== Preparing install scripts ==="
cp "$IPK_SCRIPT_DIR/postinst" "$SCRIPTS_DIR/postinst"
chmod 755 "$SCRIPTS_DIR/postinst"
cp "$IPK_SCRIPT_DIR/prerm" "$SCRIPTS_DIR/prerm"
chmod 755 "$SCRIPTS_DIR/prerm"

# === Build APK using apk mkpkg ===
echo "=== Building APK ==="

OUTPUT_FILE="$OUTPUT_DIR/nym-vpn_${VERSION}_${OPENWRT_ARCH}.apk"

# Common metadata arguments for apk mkpkg
MKPKG_INFO_ARGS=(
    -I "name:nym-vpn"
    -I "version:${VERSION}-r0"
    -I "description:NymVPN for OpenWrt - Privacy VPN using the Nym mixnet"
    -I "url:https://github.com/dial0ut/nym-vpn-openwrt"
    -I "arch:${OPENWRT_ARCH}"
    -I "license:GPL-3.0"
    -I "origin:nym-vpn"
    -I "maintainer:dial0ut"
    -I "depends:libc"
    -I "depends:kmod-tun"
    -I "depends:libmnl"
    -I "depends:libnftnl"
    -I "depends:luci-base"
    -I "depends:rpcd"
)

if command -v apk >/dev/null 2>&1 && apk mkpkg --help >/dev/null 2>&1; then
    # Native apk-tools 3.x available (e.g., Alpine build host or CI)
    echo "Using native apk mkpkg"
    apk mkpkg \
        "${MKPKG_INFO_ARGS[@]}" \
        -s "post-install:${SCRIPTS_DIR}/postinst" \
        -s "pre-deinstall:${SCRIPTS_DIR}/prerm" \
        -F "$DATA_DIR" \
        -o "$OUTPUT_FILE"
elif command -v docker >/dev/null 2>&1; then
    # Use Docker Alpine container for apk mkpkg
    echo "Using Docker Alpine for apk mkpkg"
    docker run --rm \
        -v "$DATA_DIR:/work/data:ro" \
        -v "$SCRIPTS_DIR:/work/scripts:ro" \
        -v "$OUTPUT_DIR:/work/out" \
        alpine:latest \
        apk mkpkg \
            -I "name:nym-vpn" \
            -I "version:${VERSION}-r0" \
            -I "description:NymVPN for OpenWrt - Privacy VPN using the Nym mixnet" \
            -I "url:https://github.com/dial0ut/nym-vpn-openwrt" \
            -I "arch:${OPENWRT_ARCH}" \
            -I "license:GPL-3.0" \
            -I "origin:nym-vpn" \
            -I "maintainer:dial0ut" \
            -I "depends:libc" \
            -I "depends:kmod-tun" \
            -I "depends:libmnl" \
            -I "depends:libnftnl" \
            -I "depends:luci-base" \
            -I "depends:rpcd" \
            -s "post-install:/work/scripts/postinst" \
            -s "pre-deinstall:/work/scripts/prerm" \
            -F /work/data \
            -o /work/out/output.apk

    mv "$OUTPUT_DIR/output.apk" "$OUTPUT_FILE"
else
    echo "Error: Neither apk mkpkg nor docker found."
    echo "Install Docker or run on Alpine to build APK packages."
    exit 1
fi

echo ""
echo "=== Build complete ==="
ls -lh "$OUTPUT_FILE"
echo ""
echo "Install on OpenWrt 25.x+ with:"
echo "  apk add --allow-untrusted $OUTPUT_FILE"
