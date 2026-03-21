#!/bin/bash
# Unified GCC wrapper that fixes CRT file paths for static linking.
#
# When Rust uses +crt-static, it passes bare crt*.o filenames (crt1.o, crti.o, etc.)
# that the linker can't find without full paths. This wrapper replaces them.
#
# For MIPS targets, Rust also inserts -Wl,-Bdynamic which overrides -static with
# GNU ld. The wrapper strips -Bdynamic and adds -Bstatic when -static is present.
#
# Required environment variables (set by the Dockerfile):
#   GCC_WRAPPER_MUSL_LIB  - path to musl lib dir containing crt1.o, crti.o, crtn.o
#   GCC_WRAPPER_GCC_LIB   - path to GCC lib dir containing crtbegin.o, crtend.o
#   GCC_WRAPPER_CC         - actual GCC binary to exec

if [ -z "${GCC_WRAPPER_MUSL_LIB:-}" ] || [ -z "${GCC_WRAPPER_GCC_LIB:-}" ] || [ -z "${GCC_WRAPPER_CC:-}" ]; then
    echo "gcc-wrapper: GCC_WRAPPER_MUSL_LIB, GCC_WRAPPER_GCC_LIB, and GCC_WRAPPER_CC must be set" >&2
    exit 1
fi

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
        crt1.o)      args+=("${GCC_WRAPPER_MUSL_LIB}/crt1.o") ;;
        crti.o)      args+=("${GCC_WRAPPER_MUSL_LIB}/crti.o") ;;
        crtn.o)      args+=("${GCC_WRAPPER_MUSL_LIB}/crtn.o") ;;
        crtbegin.o)  args+=("${GCC_WRAPPER_GCC_LIB}/crtbegin.o") ;;
        crtbeginT.o) args+=("${GCC_WRAPPER_GCC_LIB}/crtbeginT.o") ;;
        crtend.o)    args+=("${GCC_WRAPPER_GCC_LIB}/crtend.o") ;;
        # Strip -Bdynamic when building static (it breaks static linking with GNU ld)
        -Wl,-Bdynamic)
            if [[ $is_static -eq 0 ]]; then
                args+=("$arg")
            fi
            ;;
        *)           args+=("$arg") ;;
    esac
done

# Add -Bstatic at the end to ensure static linking (overrides any remaining dynamic refs)
if [[ $is_static -eq 1 ]]; then
    args+=("-Wl,-Bstatic")
fi

exec "${GCC_WRAPPER_CC}" "${args[@]}"
