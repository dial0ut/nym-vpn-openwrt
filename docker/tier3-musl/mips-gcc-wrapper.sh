#!/bin/bash
# GCC wrapper for MIPS that fixes CRT file paths and static linking
# When +crt-static is used, Rust passes bare crt*.o filenames
# that the linker can't find without full paths
#
# Key fixes for static linking:
# 1. Rust inserts -Wl,-Bdynamic which overrides -static with GNU ld
#    We strip -Bdynamic and add -Bstatic at the end to force static linking
# 2. Fix CRT file paths

MUSL_LIB=/usr/local/musl/mips-unknown-linux-musl/lib
GCC_LIB=/usr/local/musl/lib/gcc/mips-unknown-linux-musl/11.2.0

# Check if -static is in arguments
is_static=0
for arg in "$@"; do
    if [[ "$arg" == "-static" ]]; then
        is_static=1
        break
    fi
done

args=()
for arg in "$@"; do
    case "$arg" in
        # Fix CRT paths
        crt1.o)     args+=("${MUSL_LIB}/crt1.o") ;;
        crti.o)     args+=("${MUSL_LIB}/crti.o") ;;
        crtn.o)     args+=("${MUSL_LIB}/crtn.o") ;;
        crtbegin.o) args+=("${GCC_LIB}/crtbegin.o") ;;
        crtbeginT.o) args+=("${GCC_LIB}/crtbeginT.o") ;;
        crtend.o)   args+=("${GCC_LIB}/crtend.o") ;;
        # Strip -Bdynamic when building static (it breaks static linking with GNU ld)
        -Wl,-Bdynamic)
            if [[ $is_static -eq 0 ]]; then
                args+=("$arg")
            fi
            # Skip -Bdynamic when -static is present
            ;;
        *)          args+=("$arg") ;;
    esac
done

# Add -Bstatic at the end to ensure static linking (overrides any remaining dynamic refs)
if [[ $is_static -eq 1 ]]; then
    args+=("-Wl,-Bstatic")
fi

exec mips-unknown-linux-musl-gcc "${args[@]}"
