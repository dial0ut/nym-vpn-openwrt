#!/bin/bash
# Generate package feed indices for OpenWrt
#
# Generates opkg (Packages/Packages.gz) and apk (packages.adb) feeds.
# APK feeds use apk mkndx (via Docker Alpine or native apk-tools 3.x).
#
# Usage: generate-feed.sh <format> <packages_dir> [signing_key]
#
# Arguments:
#   format       - "opkg" or "apk"
#   packages_dir - Directory containing .ipk or .apk files
#   signing_key  - (optional) Path to RSA private key for signing
#
# Examples:
#   generate-feed.sh opkg ./feed/opkg
#   generate-feed.sh opkg ./feed/opkg /path/to/key.pem
#   generate-feed.sh apk  ./feed/apk  /path/to/key.pem

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <opkg|apk> <packages_dir> [signing_key]"
    exit 1
fi

FORMAT="$1"
PACKAGES_DIR="$2"
SIGNING_KEY="${3:-}"

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
            local abs_pkg
            abs_pkg="$(cd "$(dirname "$pkg")" && pwd)/$(basename "$pkg")"
            local tmpdir=$(mktemp -d)
            (
                cd "$tmpdir"
                tar xzf "$abs_pkg"
                [ -f control.tar.gz ] && tar xzf control.tar.gz
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

        # Sign with usign/signify (Ed25519, opkg-compatible)
        if [ -n "$SIGNING_KEY" ]; then
            if command -v usign >/dev/null 2>&1; then
                usign -S -m "$packages_file" -s "$SIGNING_KEY"
            elif command -v signify-openbsd >/dev/null 2>&1; then
                signify-openbsd -S -s "$SIGNING_KEY" -m "$packages_file"
            elif command -v signify >/dev/null 2>&1; then
                signify -S -s "$SIGNING_KEY" -m "$packages_file"
            else
                echo "  Warning: No usign/signify found, skipping signature"
            fi
            if [ -f "$packages_file.sig" ]; then
                echo "  Signed: $arch/Packages.sig"
            fi
        fi
    done
}

#
# apk feed: packages.adb (v3 ADB index, generated by apk mkndx)
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

    # Generate packages.adb per architecture using apk mkndx
    for arch_dir in "$PACKAGES_DIR"/*/; do
        [ -d "$arch_dir" ] || continue
        local arch=$(basename "$arch_dir")
        local abs_arch_dir
        abs_arch_dir="$(cd "$arch_dir" && pwd)"
        echo "Generating apk index for $arch..."

        # Collect .apk files for this architecture
        local apk_files=()
        for pkg in "$abs_arch_dir"/*.$ext; do
            [ -f "$pkg" ] || continue
            apk_files+=("$pkg")
        done

        if [ ${#apk_files[@]} -eq 0 ]; then
            echo "  No packages found, skipping"
            continue
        fi

        # apk embeds the *basename* of the signing key into the index
        # signature; the device must have a public key of the same name in
        # /etc/apk/keys/. Keep the basename stable so it matches the public
        # key we ship (scripts/feed/dial0ut-apk.pem → /etc/apk/keys/).
        local key_name=""
        [ -n "$SIGNING_KEY" ] && key_name="$(basename "$SIGNING_KEY")"

        if command -v apk >/dev/null 2>&1 && apk mkndx --help >/dev/null 2>&1; then
            # Native apk-tools available
            echo "  Using native apk mkndx"
            local native_sign_args=""
            [ -n "$SIGNING_KEY" ] && native_sign_args="--sign-key $SIGNING_KEY"
            apk mkndx --allow-untrusted $native_sign_args \
                -o "$abs_arch_dir/packages.adb" \
                "${apk_files[@]}"
        elif command -v docker >/dev/null 2>&1; then
            # Use Docker Alpine
            echo "  Using Docker Alpine for apk mkndx"
            local docker_args=(-v "$abs_arch_dir:/work/pkgs")
            local sign_args=""
            if [ -n "$SIGNING_KEY" ]; then
                # Mount under the key's real basename so the embedded key
                # name matches the public key shipped on-device.
                docker_args+=(-v "$SIGNING_KEY:/work/$key_name:ro")
                sign_args="--sign-key /work/$key_name"
            fi

            # Build list of package paths inside container
            local container_pkgs=()
            for f in "${apk_files[@]}"; do
                container_pkgs+=("/work/pkgs/$(basename "$f")")
            done

            docker run --rm "${docker_args[@]}" alpine:latest \
                apk mkndx --allow-untrusted $sign_args \
                    -o /work/pkgs/packages.adb \
                    "${container_pkgs[@]}"
        else
            echo "Error: Neither apk mkndx nor docker found."
            exit 1
        fi

        if [ -f "$abs_arch_dir/packages.adb" ]; then
            echo "  Generated: $arch/packages.adb ($(filesize "$abs_arch_dir/packages.adb") bytes)"
        else
            echo "Error: Failed to generate packages.adb for $arch"
            exit 1
        fi
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
