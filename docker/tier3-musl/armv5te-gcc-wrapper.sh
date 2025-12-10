#!/bin/bash
# GCC wrapper for ARMv5TE that fixes CRT file paths
# Rust passes bare crt*.o filenames which the linker can't find
# This wrapper replaces them with full paths

MUSL_LIB=/usr/local/musl/armv5te-unknown-linux-musleabi/lib
GCC_LIB=/usr/local/musl/lib/gcc/armv5te-unknown-linux-musleabi/11.2.0

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

exec armv5te-unknown-linux-musleabi-gcc "${args[@]}"
