#!/bin/bash
# Central version definitions for all build scripts and Dockerfiles.
# Source this file instead of hardcoding versions.

export PROTOC_VERSION="30.2"
export KERNEL_VERSION="6.1.119"

# Nightly for the Tier 3 images (-Z build-std). Passed to their Dockerfiles as
# a build arg and re-asserted by build-tier3-dynamic.sh. Bump on purpose, never
# by accident: a release builds with exactly this toolchain.
export RUST_NIGHTLY="nightly-2026-09-22"

# apk mkpkg / apk mkndx (apk-tools 3) and the release feed smoke test.
export ALPINE_IMAGE="alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
