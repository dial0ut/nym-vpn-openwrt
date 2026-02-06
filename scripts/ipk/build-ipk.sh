#!/bin/bash
# Build IPK package for OpenWrt
#
# Usage: build-ipk.sh <version> <openwrt_arch> <binary_dir> <luci_dir> [output_dir]
#
# Arguments:
#   version      - Package version (e.g., "1.21.0")
#   openwrt_arch - OpenWrt architecture (e.g., "aarch64_generic")
#   binary_dir   - Directory containing nym-vpnd and nym-vpnc binaries
#   luci_dir     - Path to cloned nym-vpn-luci repository
#   output_dir   - Output directory for IPK (default: current directory)
#
# Example:
#   ./build-ipk.sh 1.21.0 aarch64_generic ./artifacts ../nym-vpn-luci .

set -euo pipefail

# --- Argument parsing ---
if [ $# -lt 4 ]; then
    echo "Usage: $0 <version> <openwrt_arch> <binary_dir> <luci_dir> [output_dir]"
    echo ""
    echo "Arguments:"
    echo "  version      - Package version (e.g., '1.21.0')"
    echo "  openwrt_arch - OpenWrt architecture (e.g., 'aarch64_generic')"
    echo "  binary_dir   - Directory containing nym-vpnd and nym-vpnc binaries"
    echo "  luci_dir     - Path to cloned nym-vpn-luci repository"
    echo "  output_dir   - Output directory for IPK (default: current directory)"
    exit 1
fi

VERSION="$1"
OPENWRT_ARCH="$2"
BINARY_DIR="$3"
LUCI_DIR="$4"
OUTPUT_DIR="${5:-.}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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

if [ ! -f "$SCRIPT_DIR/control.template" ]; then
    echo "Error: control.template not found in $SCRIPT_DIR"
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

mkdir -p "$BUILD_DIR"/{control,data}

# === DATA: Binaries ===
echo "=== Adding binaries ==="
mkdir -p "$BUILD_DIR/data/usr/sbin" "$BUILD_DIR/data/usr/bin"
cp "$BINARY_DIR/nym-vpnd" "$BUILD_DIR/data/usr/sbin/"
cp "$BINARY_DIR/nym-vpnc" "$BUILD_DIR/data/usr/bin/"
chmod 755 "$BUILD_DIR/data/usr/sbin/nym-vpnd" "$BUILD_DIR/data/usr/bin/nym-vpnc"

# === DATA: LuCI frontend ===
echo "=== Adding LuCI frontend ==="

# View file
mkdir -p "$BUILD_DIR/data/www/luci-static/resources/view/nym-vpn"
cp "$LUCI_DIR/htdocs/luci-static/resources/view/nym-vpn/"*.js \
   "$BUILD_DIR/data/www/luci-static/resources/view/nym-vpn/"

# Module files (rpc, ui, countries, assets, theme)
mkdir -p "$BUILD_DIR/data/www/luci-static/resources/nym-vpn"
cp "$LUCI_DIR/htdocs/luci-static/resources/nym-vpn/"*.js \
   "$BUILD_DIR/data/www/luci-static/resources/nym-vpn/"

# === DATA: RPC backend ===
echo "=== Adding RPC backend ==="
mkdir -p "$BUILD_DIR/data/usr/libexec/rpcd"
cp "$LUCI_DIR/root/usr/libexec/rpcd/nym-vpn" "$BUILD_DIR/data/usr/libexec/rpcd/"
chmod 755 "$BUILD_DIR/data/usr/libexec/rpcd/nym-vpn"

# === DATA: Menu and ACL config ===
echo "=== Adding menu and ACL config ==="
mkdir -p "$BUILD_DIR/data/usr/share/luci/menu.d"
mkdir -p "$BUILD_DIR/data/usr/share/rpcd/acl.d"
cp "$LUCI_DIR/root/usr/share/luci/menu.d/luci-app-nym-vpn.json" \
   "$BUILD_DIR/data/usr/share/luci/menu.d/"
cp "$LUCI_DIR/root/usr/share/rpcd/acl.d/luci-app-nym-vpn.json" \
   "$BUILD_DIR/data/usr/share/rpcd/acl.d/"

# === DATA: Init script ===
echo "=== Adding init script ==="
mkdir -p "$BUILD_DIR/data/etc/init.d"
cp "$LUCI_DIR/root/etc/init.d/nym-vpnd" "$BUILD_DIR/data/etc/init.d/"
chmod 755 "$BUILD_DIR/data/etc/init.d/nym-vpnd"

# === DATA: Config and UCI defaults ===
echo "=== Adding config and UCI defaults ==="
mkdir -p "$BUILD_DIR/data/etc/config"
mkdir -p "$BUILD_DIR/data/etc/uci-defaults"
mkdir -p "$BUILD_DIR/data/var/lib/nym-vpn"

cp "$SCRIPT_DIR/nym-vpn.conf" "$BUILD_DIR/data/etc/config/nym-vpn"
cp "$SCRIPT_DIR/uci-defaults/99-nym-vpn-wireguard" "$BUILD_DIR/data/etc/uci-defaults/"
chmod 755 "$BUILD_DIR/data/etc/uci-defaults/99-nym-vpn-wireguard"

# LuCI UCI defaults (if present in LuCI repo)
if [ -f "$LUCI_DIR/root/etc/uci-defaults/luci-app-nym-vpn" ]; then
    cp "$LUCI_DIR/root/etc/uci-defaults/luci-app-nym-vpn" "$BUILD_DIR/data/etc/uci-defaults/"
    chmod 755 "$BUILD_DIR/data/etc/uci-defaults/luci-app-nym-vpn"
fi

# === DATA: Firewall include scripts ===
echo "=== Adding firewall scripts ==="
mkdir -p "$BUILD_DIR/data/usr/share/nym-vpn"

FW_SCRIPTS_DIR="$REPO_ROOT/nym-vpn-core/crates/nym-firewall/scripts"
if [ -f "$FW_SCRIPTS_DIR/fw3-include.sh" ]; then
    cp "$FW_SCRIPTS_DIR/fw3-include.sh" "$BUILD_DIR/data/usr/share/nym-vpn/"
    chmod 755 "$BUILD_DIR/data/usr/share/nym-vpn/fw3-include.sh"
fi
if [ -f "$FW_SCRIPTS_DIR/fw4-include.sh" ]; then
    cp "$FW_SCRIPTS_DIR/fw4-include.sh" "$BUILD_DIR/data/usr/share/nym-vpn/"
    chmod 755 "$BUILD_DIR/data/usr/share/nym-vpn/fw4-include.sh"
fi

# === CONTROL: Generate from template ===
echo "=== Generating control file ==="
INSTALLED_SIZE=$(du -sk "$BUILD_DIR/data" | cut -f1)

sed -e "s/{{VERSION}}/$VERSION/" \
    -e "s/{{ARCH}}/$OPENWRT_ARCH/" \
    -e "s/{{SIZE}}/$INSTALLED_SIZE/" \
    "$SCRIPT_DIR/control.template" > "$BUILD_DIR/control/control"

# Validate control file
if ! grep -q "^Package:" "$BUILD_DIR/control/control"; then
    echo "Error: Generated control file is invalid (missing Package field)"
    cat "$BUILD_DIR/control/control"
    exit 1
fi
if ! grep -q "^Depends:" "$BUILD_DIR/control/control"; then
    echo "Error: Generated control file is invalid (missing Depends field)"
    cat "$BUILD_DIR/control/control"
    exit 1
fi

echo "Control file:"
cat "$BUILD_DIR/control/control"

# === CONTROL: conffiles ===
if [ -f "$SCRIPT_DIR/conffiles" ]; then
    cp "$SCRIPT_DIR/conffiles" "$BUILD_DIR/control/"
fi

# === CONTROL: Install scripts ===
echo "=== Adding install scripts ==="
cp "$SCRIPT_DIR/postinst" "$BUILD_DIR/control/"
cp "$SCRIPT_DIR/prerm" "$BUILD_DIR/control/"
chmod 755 "$BUILD_DIR/control/postinst" "$BUILD_DIR/control/prerm"

# === Build IPK ===
echo "=== Building IPK ==="
(cd "$BUILD_DIR/control" && tar -czf ../control.tar.gz .)
(cd "$BUILD_DIR/data" && tar -czf ../data.tar.gz .)
echo "2.0" > "$BUILD_DIR/debian-binary"

OUTPUT_FILE="$OUTPUT_DIR/nym-vpn_${VERSION}_${OPENWRT_ARCH}.ipk"
(cd "$BUILD_DIR" && tar -czf "$OUTPUT_FILE" ./debian-binary ./control.tar.gz ./data.tar.gz)

echo ""
echo "=== Build complete ==="
ls -lh "$OUTPUT_FILE"
echo ""
echo "To inspect contents:"
echo "  tar -tzf $OUTPUT_FILE"
echo "  tar -xzf $OUTPUT_FILE && tar -tzf data.tar.gz"
