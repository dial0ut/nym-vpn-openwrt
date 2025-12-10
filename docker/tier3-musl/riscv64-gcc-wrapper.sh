#!/bin/bash
# GCC wrapper for RISC-V that fixes CRT file paths for lld
# When +crt-static is used, Rust passes bare crt*.o filenames
# lld (unlike GNU ld) doesn't search -L paths for these files
# This wrapper replaces bare filenames with full paths

MUSL_LIB=/usr/local/musl/riscv64-unknown-linux-musl/lib
GCC_LIB=/usr/local/musl/lib/gcc/riscv64-unknown-linux-musl/11.2.0

args=()
for arg in "$@"; do
    case "$arg" in
        crt1.o)     args+=("${MUSL_LIB}/crt1.o") ;;
        crti.o)     args+=("${MUSL_LIB}/crti.o") ;;
        crtn.o)     args+=("${MUSL_LIB}/crtn.o") ;;
        crtbegin.o) args+=("${GCC_LIB}/crtbegin.o") ;;
        crtbeginT.o) args+=("${GCC_LIB}/crtbeginT.o") ;;
        crtend.o)   args+=("${GCC_LIB}/crtend.o") ;;
        *)          args+=("$arg") ;;
    esac
done

exec riscv64-unknown-linux-musl-gcc "${args[@]}"
