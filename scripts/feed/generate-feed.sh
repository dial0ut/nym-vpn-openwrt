#!/bin/bash
# Generate package feed indices for OpenWrt
#
# Generates both opkg (Packages/Packages.gz) and apk (APKINDEX.tar.gz) feeds.
# No external tools needed — indices are generated directly.
#
# Usage: generate-feed.sh <format> <packages_dir>
#
# Arguments:
#   format       - "opkg" or "apk"
#   packages_dir - Directory containing .ipk or .apk files
#
# Examples:
#   generate-feed.sh opkg ./feed/opkg    # Process *.ipk files
#   generate-feed.sh apk  ./feed/apk     # Process *.apk files

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <opkg|apk> <packages_dir>"
    exit 1
fi

FORMAT="$1"
PACKAGES_DIR="$2"

if [ ! -d "$PACKAGES_DIR" ]; then
    echo "Error: $PACKAGES_DIR is not a directory"
    exit 1
fi

# Detect checksum commands (Linux vs macOS)
sha256() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$1" | cut -d' ' -f1; }
md5()    { md5sum "$1" 2>/dev/null | cut -d' ' -f1 || command md5 -q "$1"; }
filesize() { stat -c%s "$1" 2>/dev/null || stat -f%z "$1"; }

#
# opkg feed: Packages / Packages.gz
#
generate_opkg_feed() {
    local ext="ipk"

    # Organize files by architecture
    for pkg in "$PACKAGES_DIR"/*.$ext; do
        [ -f "$pkg" ] || continue
        local filename=$(basename "$pkg")
        local arch=$(echo "$filename" | sed "s/^nym-vpn_[^_]*_\\(.*\\)\\.${ext}\$/\\1/")
        if [ -z "$arch" ] || [ "$arch" = "$filename" ]; then
            echo "Warning: Could not extract architecture from $filename, skipping"
            continue
        fi
        mkdir -p "$PACKAGES_DIR/$arch"
        cp "$pkg" "$PACKAGES_DIR/$arch/"
        echo "  $arch/$filename"
    done

    # Generate index per architecture
    for arch_dir in "$PACKAGES_DIR"/*/; do
        [ -d "$arch_dir" ] || continue
        local arch=$(basename "$arch_dir")
        local packages_file="$arch_dir/Packages"
        echo "Generating opkg index for $arch..."
        > "$packages_file"

        for pkg in "$arch_dir"/*.$ext; do
            [ -f "$pkg" ] || continue
            local filename=$(basename "$pkg")
            local size=$(filesize "$pkg")
            local sum=$(sha256 "$pkg")
            local md5sum=$(md5 "$pkg")

            # Extract control from IPK (gzipped tar of control.tar.gz + data.tar.gz)
            local tmpdir=$(mktemp -d)
            (
                cd "$tmpdir"
                tar xzf "$pkg" 2>/dev/null || gzip -dc "$pkg" | tar xf -
                [ -f control.tar.gz ] && (tar xzf control.tar.gz 2>/dev/null || gzip -dc control.tar.gz | tar xf -)
            )

            if [ ! -f "$tmpdir/control" ]; then
                echo "Warning: Could not extract control from $filename"
                rm -rf "$tmpdir"
                continue
            fi

            # Read fields
            local pkg_name=$(grep "^Package:" "$tmpdir/control" | sed 's/^Package: *//')
            local pkg_version=$(grep "^Version:" "$tmpdir/control" | sed 's/^Version: *//')
            local pkg_arch=$(grep "^Architecture:" "$tmpdir/control" | sed 's/^Architecture: *//')
            local pkg_depends=$(grep "^Depends:" "$tmpdir/control" | sed 's/^Depends: *//')
            local pkg_section=$(grep "^Section:" "$tmpdir/control" | sed 's/^Section: *//')
            local pkg_maintainer=$(grep "^Maintainer:" "$tmpdir/control" | sed 's/^Maintainer: *//')
            local pkg_installed_size=$(grep "^Installed-Size:" "$tmpdir/control" | sed 's/^Installed-Size: *//')
            local pkg_description=$(grep "^Description:" "$tmpdir/control" | sed 's/^Description: *//')
            local pkg_description_cont=$(sed -n '/^Description:/,/^[^ ]/{ /^Description:/d; /^[^ ]/d; p; }' "$tmpdir/control")
            rm -rf "$tmpdir"

            {
                echo "Package: $pkg_name"
                echo "Version: $pkg_version"
                echo "Depends: $pkg_depends"
                echo "Section: $pkg_section"
                echo "Architecture: $pkg_arch"
                [ -n "$pkg_maintainer" ] && echo "Maintainer: $pkg_maintainer"
                [ -n "$pkg_installed_size" ] && echo "Installed-Size: $pkg_installed_size"
                echo "Filename: $filename"
                echo "Size: $size"
                echo "MD5Sum: $md5sum"
                echo "SHA256sum: $sum"
                echo "Description: $pkg_description"
                [ -n "$pkg_description_cont" ] && echo "$pkg_description_cont"
                echo ""
            } >> "$packages_file"

            echo "  Added: $pkg_name $pkg_version ($pkg_arch)"
        done

        gzip -k -f "$packages_file"
        echo "  Generated: $arch/Packages + Packages.gz"
    done
}

#
# apk feed: APKINDEX.tar.gz
#
generate_apk_feed() {
    local ext="apk"

    # Organize files by architecture
    for pkg in "$PACKAGES_DIR"/*.$ext; do
        [ -f "$pkg" ] || continue
        local filename=$(basename "$pkg")
        local arch=$(echo "$filename" | sed "s/^nym-vpn_[^_]*_\\(.*\\)\\.${ext}\$/\\1/")
        if [ -z "$arch" ] || [ "$arch" = "$filename" ]; then
            echo "Warning: Could not extract architecture from $filename, skipping"
            continue
        fi
        mkdir -p "$PACKAGES_DIR/$arch"
        cp "$pkg" "$PACKAGES_DIR/$arch/"
        echo "  $arch/$filename"
    done

    # Generate APKINDEX per architecture
    for arch_dir in "$PACKAGES_DIR"/*/; do
        [ -d "$arch_dir" ] || continue
        local arch=$(basename "$arch_dir")
        echo "Generating apk index for $arch..."

        local index_file="$arch_dir/APKINDEX"
        > "$index_file"

        for pkg in "$arch_dir"/*.$ext; do
            [ -f "$pkg" ] || continue
            local filename=$(basename "$pkg")
            local size=$(filesize "$pkg")
            local sum=$(sha256 "$pkg")

            # Extract .PKGINFO from APK (gzipped tar with .PKGINFO as first entry)
            local tmpdir=$(mktemp -d)
            (cd "$tmpdir" && tar xzf "$pkg" .PKGINFO 2>/dev/null || gzip -dc "$pkg" | tar xf - .PKGINFO 2>/dev/null) || true

            if [ ! -f "$tmpdir/.PKGINFO" ]; then
                echo "Warning: Could not extract .PKGINFO from $filename"
                rm -rf "$tmpdir"
                continue
            fi

            local pkg_name=$(grep "^pkgname" "$tmpdir/.PKGINFO" | head -1 | sed 's/^pkgname = *//')
            local pkg_version=$(grep "^pkgver" "$tmpdir/.PKGINFO" | head -1 | sed 's/^pkgver = *//')
            local pkg_desc=$(grep "^pkgdesc" "$tmpdir/.PKGINFO" | head -1 | sed 's/^pkgdesc = *//')
            local pkg_url=$(grep "^url" "$tmpdir/.PKGINFO" | head -1 | sed 's/^url = *//')
            local pkg_license=$(grep "^license" "$tmpdir/.PKGINFO" | head -1 | sed 's/^license = *//')
            local pkg_arch_val=$(grep "^arch" "$tmpdir/.PKGINFO" | head -1 | sed 's/^arch = *//')
            local pkg_installed_size=$(grep "^size" "$tmpdir/.PKGINFO" | head -1 | sed 's/^size = *//')
            local pkg_maintainer=$(grep "^maintainer" "$tmpdir/.PKGINFO" | head -1 | sed 's/^maintainer = *//')
            # Collect all depend= lines
            local pkg_depends=$(grep "^depend" "$tmpdir/.PKGINFO" | sed 's/^depend = *//' | tr '\n' ' ' | sed 's/ $//')
            rm -rf "$tmpdir"

            # APKINDEX entry format (single-letter keys)
            {
                echo "C:Q1$(echo -n "$sum" | head -c 24)"
                echo "P:$pkg_name"
                echo "V:$pkg_version"
                echo "A:$pkg_arch_val"
                echo "S:$size"
                echo "I:$pkg_installed_size"
                echo "T:$pkg_desc"
                echo "U:$pkg_url"
                echo "L:$pkg_license"
                [ -n "$pkg_maintainer" ] && echo "m:$pkg_maintainer"
                [ -n "$pkg_depends" ] && echo "D:$pkg_depends"
                echo ""
            } >> "$index_file"

            echo "  Added: $pkg_name $pkg_version ($pkg_arch_val)"
        done

        # Create APKINDEX.tar.gz (must contain APKINDEX file)
        (cd "$arch_dir" && tar czf APKINDEX.tar.gz APKINDEX)
        rm -f "$index_file"
        echo "  Generated: $arch/APKINDEX.tar.gz"
    done
}

# Main
echo "=== Generating $FORMAT feed ==="
echo ""

case "$FORMAT" in
    opkg)
        generate_opkg_feed
        ;;
    apk)
        generate_apk_feed
        ;;
    *)
        echo "Error: Unknown format '$FORMAT'. Use 'opkg' or 'apk'."
        exit 1
        ;;
esac

echo ""
echo "Feed generation complete."
