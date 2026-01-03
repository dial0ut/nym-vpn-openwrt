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

usage() {
    echo "Usage: $0 <target>"
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
    echo "Example:"
    echo "  $0 aarch64"
    echo "  $0 mipsel"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
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

echo -e "${GREEN}Building nym-vpn-core binaries for ${TARGET_ARCH} using kernel WireGuard${NC}"
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

# Run the cross-compilation inside Docker
if $TIER3; then
    # Tier 3: use build-tier3.sh (handles build-std, patches, etc.)
    docker run --rm -it \
        -v "${PROJECT_ROOT}:/home/rust/src" \
        "${DOCKER_IMAGE}" \
        /opt/build-tier3.sh
else
    # Tier 2: use cross-compile-musl.sh
    docker run --rm -it \
        -v "${PROJECT_ROOT}:/home/rust/src" \
        "${DOCKER_IMAGE}" \
        bash /home/rust/src/scripts/cross-compile-musl.sh
fi

echo ""
echo -e "${GREEN}Done!${NC}"
echo -e "${GREEN}Binaries at: nym-vpn-core/target/*/release/{nym-vpnd,nym-vpnc}${NC}"
