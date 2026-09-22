#!/bin/bash
# Stage the .ipk and the .apk from the same (dummy) binaries and fail when
# their payloads differ: a file, mode or content one package ships and the
# other does not, a changed install script, or different dependencies.
# build-ipk.sh and build-apk.sh stage the payload separately, and drift
# between them has shipped before (214e4dc5: apk without the boot guard).
#
# Builds nothing: both builders stop after staging (NYM_PKG_STAGE_DIR).
# Needs no Rust toolchain; the firewall helpers are checked in.
#
# Usage: scripts/ci/check-pkg-payload.sh [openwrt_arch...]
#   default arches: one 64-bit and one 32-bit (the depends differ by width)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Paths only one format carries, by design. Everything else must match.
IPK_ONLY_RE='^\./etc/opkg(/keys(/[0-9a-f]{16})?)?$|^\./etc/apk/keys/dial0ut\.pub$'
APK_ONLY_RE='^\./lib/apk(/packages(/nym-vpn\.conffiles(_static)?)?)?$|^\./etc/apk/keys/dial0ut-apk\.pem$'

mkdir -p "$WORK/bin"
for b in nym-vpnd nym-vpnc; do
    printf '#!/bin/sh\necho %s\n' "$b" > "$WORK/bin/$b"
    chmod 755 "$WORK/bin/$b"
done

# "<mode> <path>" for every entry of a staged tree, minus one format's
# expected extras.
listing() {
    local root="$1" skip_re="$2"
    (cd "$root" && find . -mindepth 1 -printf '%m %p\n') \
        | sort -k2 \
        | SKIP_RE="$skip_re" awk '$2 !~ ENVIRON["SKIP_RE"]'
}

# Dependencies as one sorted "name[op version]" per line.
ipk_depends() {
    awk -F': ' '/^Depends:/ {print $2}' "$1/control/control" \
        | tr ',' '\n' | tr -d ' ()' | sed '/^$/d' | sort
}
apk_depends() {
    awk '/^depends:/ {sub(/^depends:/, ""); print}' "$1/info" \
        | tr ' ' '\n' | sed '/^$/d' | sort
}

fail=0
arches=("$@")
[ ${#arches[@]} -gt 0 ] || arches=(x86_64 arm_cortex-a7_neon-vfpv4)

for arch in "${arches[@]}"; do
    echo "=== $arch ==="
    ipk="$WORK/$arch/ipk"
    apk="$WORK/$arch/apk"
    NYM_PKG_STAGE_DIR="$ipk" "$REPO_ROOT/scripts/ipk/build-ipk.sh" \
        0.0.0 "$arch" "$WORK/bin" >"$WORK/$arch-ipk.log" 2>&1 \
        || { cat "$WORK/$arch-ipk.log"; exit 1; }
    NYM_PKG_STAGE_DIR="$apk" "$REPO_ROOT/scripts/apk/build-apk.sh" \
        0.0.0 "$arch" "$WORK/bin" >"$WORK/$arch-apk.log" 2>&1 \
        || { cat "$WORK/$arch-apk.log"; exit 1; }

    if ! diff -u --label ipk --label apk \
        <(listing "$ipk/data" "$IPK_ONLY_RE") \
        <(listing "$apk/data" "$APK_ONLY_RE"); then
        echo "::error::ipk and apk payloads differ for $arch (files or modes above)"
        fail=1
    fi

    # Same file, same bytes.
    while read -r _ path; do
        [ -f "$ipk/data/$path" ] || continue
        if ! cmp -s "$ipk/data/$path" "$apk/data/$path"; then
            echo "::error::$path differs between ipk and apk ($arch)"
            fail=1
        fi
    done < <(listing "$ipk/data" "$IPK_ONLY_RE")

    # Install scripts: the apk hooks are the ipk's, pre-upgrade the prerm
    # with PKG_UPGRADE=1 exported.
    for s in postinst prerm; do
        if ! cmp -s "$ipk/control/$s" "$apk/scripts/$s"; then
            echo "::error::$s differs between ipk and apk ($arch)"
            fail=1
        fi
    done
    if ! diff -q <(tail -n +2 "$ipk/control/prerm") \
        <(tail -n +3 "$apk/scripts/preupgrade") >/dev/null \
        || [ "$(sed -n 2p "$apk/scripts/preupgrade")" != "export PKG_UPGRADE=1" ]; then
        echo "::error::apk preupgrade is not prerm with PKG_UPGRADE=1 ($arch)"
        fail=1
    fi

    if ! cmp -s "$ipk/control/conffiles" \
        "$apk/data/lib/apk/packages/nym-vpn.conffiles"; then
        echo "::error::ipk and apk mark different conffiles ($arch)"
        fail=1
    fi

    if ! diff -u --label ipk-depends --label apk-depends \
        <(ipk_depends "$ipk") <(apk_depends "$apk"); then
        echo "::error::ipk and apk depend on different packages for $arch"
        fail=1
    fi
    echo "depends: $(ipk_depends "$ipk" | paste -sd' ')"
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "ipk and apk payloads match"
