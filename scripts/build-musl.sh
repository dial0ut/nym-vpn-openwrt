#!/bin/bash
# Wrapper script to cross-compile nym-vpnd for OpenWRT/musl targets
# Uses messense/rust-musl-cross Docker containers

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <target>"
    echo ""
    echo "Supported targets:"
    echo "  aarch64    - ARM 64-bit (most modern routers, Raspberry Pi 3+)"
    echo "  x86_64     - x86 64-bit"
    echo "  armv7      - ARM v7 32-bit hard-float"
    echo "  mips       - MIPS routers"
    echo ""
    echo "Example:"
    echo "  $0 aarch64"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

TARGET_ARCH="$1"

case "$TARGET_ARCH" in
    aarch64)
        DOCKER_IMAGE="messense/rust-musl-cross:aarch64-musl"
        ;;
    x86_64)
        DOCKER_IMAGE="messense/rust-musl-cross:x86_64-musl"
        ;;
    armv7)
        DOCKER_IMAGE="messense/rust-musl-cross:armv7-musleabihf"
        ;;
    mips)
        DOCKER_IMAGE="messense/rust-musl-cross:mips-musl"
        ;;
    *)
        echo -e "${RED}Error: Unknown target '${TARGET_ARCH}'${NC}"
        echo ""
        usage
        ;;
esac

echo -e "${GREEN}Building nym-vpn-core binaries for ${TARGET_ARCH} using kernel WireGuard${NC}"
echo -e "${YELLOW}Docker image: ${DOCKER_IMAGE}${NC}"
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
echo -e "${GREEN}Starting Docker container...${NC}"
echo ""

# Run the cross-compilation inside Docker
docker run --rm -it \
    -v "${PROJECT_ROOT}:/home/rust/src" \
    "${DOCKER_IMAGE}" \
    bash /home/rust/src/scripts/cross-compile-musl.sh

echo ""
echo -e "${GREEN}Done!${NC}"
