#!/bin/bash
# Wrapper script to cross-compile nym-vpnd for OpenWRT/musl targets
# Uses messense/rust-musl-cross Docker containers for Tier 2 targets
# Uses custom Docker images for Tier 3 targets (mips, mipsel, riscv64, armv5te)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ALL_TARGETS=(aarch64 x86_64 i686 armv7 mips mipsel riscv64 armv5te)

usage() {
    echo "Usage: $0 [--all] <target>"
    echo ""
    echo "Options:"
    echo "  --all      - Build all targets concurrently"
    echo ""
    echo "Tier 2 targets (standard images):"
    echo "  aarch64    - ARM 64-bit (Raspberry Pi 3+, modern routers)"
    echo "  x86_64     - x86 64-bit (VMs, PC Engines APU)"
    echo "  i686       - x86 32-bit"
    echo "  armv7      - ARM v7 32-bit hard-float (Linksys WRT, Netgear)"
    echo ""
    echo "Tier 3 targets (custom images, slower build):"
    echo "  mips       - MIPS big-endian (Atheros/Qualcomm routers)"
    echo "  mipsel     - MIPS little-endian (MediaTek routers, GL.iNet)"
    echo "  riscv64    - RISC-V 64-bit"
    echo "  armv5te    - ARMv5 (legacy devices)"
    echo ""
    echo "Examples:"
    echo "  $0 aarch64"
    echo "  $0 --all"
    echo "  $0 mipsel"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

# Parse options
BUILD_ALL=false
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --all) BUILD_ALL=true; shift ;;
        *) echo -e "${RED}Error: Unknown option '$1'${NC}"; usage ;;
    esac
done

if ! $BUILD_ALL && [ $# -eq 0 ]; then
    usage
fi

# Handle --all: launch one build per target concurrently
if $BUILD_ALL; then
    echo -e "${GREEN}Building ALL targets concurrently...${NC}"
    PIDS=()
    TARGETS=()
    LOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build-logs"
    mkdir -p "$LOG_DIR"

    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    for t in "${ALL_TARGETS[@]}"; do
        echo -e "${GREEN}Starting build: ${t}${NC} (log: build-logs/${t}.log)"
        $SELF "$t" > "${LOG_DIR}/${t}.log" 2>&1 &
        PIDS+=($!)
        TARGETS+=("$t")
    done

    echo ""
    echo -e "${YELLOW}Waiting for ${#PIDS[@]} builds...${NC}"
    FAILED=()
    for i in "${!PIDS[@]}"; do
        if wait "${PIDS[$i]}"; then
            echo -e "${GREEN}  ✓ ${TARGETS[$i]}${NC}"
        else
            echo -e "${RED}  ✗ ${TARGETS[$i]} (see build-logs/${TARGETS[$i]}.log)${NC}"
            FAILED+=("${TARGETS[$i]}")
        fi
    done

    echo ""
    if [ ${#FAILED[@]} -eq 0 ]; then
        echo -e "${GREEN}All ${#TARGETS[@]} builds succeeded!${NC}"
    else
        echo -e "${RED}${#FAILED[@]} build(s) failed: ${FAILED[*]}${NC}"
        exit 1
    fi
    exit 0
fi

TARGET_ARCH="$1"
TIER3=false

case "$TARGET_ARCH" in
    # Tier 2 targets - use stock messense images
    aarch64)
        DOCKER_IMAGE="messense/rust-musl-cross:aarch64-musl"
        ;;
    x86_64)
        DOCKER_IMAGE="messense/rust-musl-cross:x86_64-musl"
        ;;
    i686)
        DOCKER_IMAGE="messense/rust-musl-cross:i686-musl"
        ;;
    armv7)
        DOCKER_IMAGE="messense/rust-musl-cross:armv7-musleabihf"
        ;;
    # Tier 3 targets - use custom images
    mips)
        DOCKER_IMAGE="nym-musl-cross:mips-musl"
        DOCKERFILE="Dockerfile.mips"
        TIER3=true
        ;;
    mipsel)
        DOCKER_IMAGE="nym-musl-cross:mipsel-musl"
        DOCKERFILE="Dockerfile.mipsel"
        TIER3=true
        ;;
    riscv64)
        DOCKER_IMAGE="nym-musl-cross:riscv64-musl"
        DOCKERFILE="Dockerfile.riscv64"
        TIER3=true
        ;;
    armv5te)
        DOCKER_IMAGE="nym-musl-cross:armv5te-musl"
        DOCKERFILE="Dockerfile.armv5te"
        TIER3=true
        ;;
    *)
        echo -e "${RED}Error: Unknown target '${TARGET_ARCH}'${NC}"
        echo ""
        usage
        ;;
esac

echo -e "${GREEN}Building nym-vpn-core binaries for ${TARGET_ARCH} (dynamic linking)${NC}"
echo -e "${YELLOW}Docker image: ${DOCKER_IMAGE}${NC}"
if $TIER3; then
    echo -e "${YELLOW}Tier 3 target - using custom Docker image and build-std${NC}"
fi
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker not found${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Get the project root (nym-vpn-client directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${GREEN}Project root: ${PROJECT_ROOT}${NC}"

# For Tier 3 targets, build the custom Docker image if it doesn't exist
if $TIER3; then
    if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
        echo -e "${YELLOW}Building custom Docker image (one-time)...${NC}"
        docker build -f "${PROJECT_ROOT}/docker/tier3-musl/${DOCKERFILE}" \
            -t "${DOCKER_IMAGE}" \
            "${PROJECT_ROOT}/docker/tier3-musl"
        echo ""
    fi
fi

echo -e "${GREEN}Starting Docker container...${NC}"
echo ""

# Use -it for interactive terminals, just -t otherwise (e.g. when backgrounded)
DOCKER_TTY="-it"
if [ ! -t 0 ] || [ -n "${BENCH_MODE:-}" ]; then
    DOCKER_TTY="-t"
fi

# Run the cross-compilation inside Docker
if $TIER3; then
    docker run --rm $DOCKER_TTY \
        -v "${PROJECT_ROOT}:/home/rust/src" \
        "${DOCKER_IMAGE}" \
        /opt/build-tier3-dynamic.sh
else
    docker run --rm $DOCKER_TTY \
        -v "${PROJECT_ROOT}:/home/rust/src" \
        "${DOCKER_IMAGE}" \
        bash /home/rust/src/scripts/cross-compile-dynamic.sh
fi

echo ""
echo -e "${GREEN}Done!${NC}"
echo -e "${GREEN}Binaries at: nym-vpn-core/target/*/release/{nym-vpnd,nym-vpnc}${NC}"
