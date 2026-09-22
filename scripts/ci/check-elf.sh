#!/bin/bash
# Check release binaries against the oldest OpenWrt they are packaged for.
#
#   - NEEDED libraries: only libc.so and libgcc_s.so.1, the two the package
#     depends on (libc, libgcc). Anything else would be a library the router
#     may not have.
#   - x86_64 and aarch64: imported GLOBAL symbols must exist in musl 1.1.24,
#     OpenWrt 21.02, the oldest release those packages support. The list is
#     the export table of 21.02.7's x86_64 libc.so (musl-1.1.24-exports.txt).
#     libgcc_s provides the imports versioned @GCC_* (_Unwind_*, and the ARM
#     EHABI personality routines). WEAK imports may be missing by design.
#   - 32-bit: the same, except that musl 1.2's time64 symbols (__*64,
#     __*64_r) are allowed: their packages depend on libc >= 1.2
#     (scripts/pkg-depends.sh).
#   - Other 64-bit machines (riscv64) never ran 21.02; only NEEDED is checked.
#
# Usage: scripts/ci/check-elf.sh <binary>...
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORTS="$DIR/musl-1.1.24-exports.txt"
ALLOWED_NEEDED=(libc.so libgcc_s.so.1)
TIME64_RE='^__[a-z_]+64(_r)?$'
export LC_ALL=C

[ $# -gt 0 ] || { echo "usage: $0 <binary>..." >&2; exit 2; }
[ -s "$EXPORTS" ] || { echo "error: $EXPORTS missing" >&2; exit 2; }

fail=0
for bin in "$@"; do
    if ! header=$(readelf -h "$bin" 2>/dev/null) \
        || ! class=$(awk '/^ *Class:/ {print $2}' <<< "$header") || [ -z "$class" ]; then
        echo "::error::$bin is not an ELF file"
        fail=1
        continue
    fi
    machine=$(sed -n 's/^ *Machine: *//p' <<< "$header")
    echo "=== $bin ($class, $machine)"

    while IFS= read -r lib; do
        [ -n "$lib" ] || continue
        case " ${ALLOWED_NEEDED[*]} " in
            *" $lib "*) ;;
            *)
                echo "::error::$bin needs $lib; the package provides only ${ALLOWED_NEEDED[*]}"
                fail=1
                ;;
        esac
    done < <(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')

    case "$class/$machine" in
        ELF32/*|ELF64/*X86-64*|ELF64/AArch64) ;;
        *)
            echo "imports: not checked ($machine packages need OpenWrt 23.05+)"
            continue
            ;;
    esac

    missing=$(comm -23 \
        <(readelf --dyn-syms -W "$bin" \
            | awk '$7 == "UND" && $5 == "GLOBAL" && $8 !~ /@GCC_/ { sub(/@.*/, "", $8); print $8 }' \
            | grep -v '^_Unwind_' | sort -u) \
        <(sort -u "$EXPORTS"))
    if [ "$class" = ELF32 ]; then
        missing=$(printf '%s\n' "$missing" | grep -Ev "$TIME64_RE" || true)
    fi
    if [ -n "$missing" ]; then
        echo "::error::$bin imports symbols musl 1.1.24 does not export:"
        printf '  %s\n' $missing
        fail=1
    else
        echo "imports: all in musl 1.1.24$([ "$class" = ELF32 ] && echo ' (plus time64)')"
    fi
done

exit "$fail"
