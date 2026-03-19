# Building from Source

## Prerequisites

- Docker
- Git

All compilation happens inside Docker containers — no local Rust toolchain needed.

## Tier 2 Targets (Stable)

Supported architectures: `x86_64`, `i686`, `aarch64`, `armv7`

### Using the Build Script

```bash
# Build for a specific target
./scripts/build-musl.sh aarch64

# Build for x86_64
./scripts/build-musl.sh x86_64
```

The script selects the correct Docker image and runs `cross-compile-musl.sh` inside the container.

### Manual Docker Build

```bash
docker run --rm -v "$(pwd):/home/rust/src" \
  messense/rust-musl-cross:aarch64-musl \
  bash /home/rust/src/scripts/cross-compile-musl.sh
```

### What the Build Does

`cross-compile-musl.sh` (runs inside Docker):

1. Auto-detects target architecture from the available compiler
2. Builds `libmnl-1.0.4` and `libnftnl-1.2.1` from source (for nftables support)
3. Compiles `nym-vpnd` and `nym-vpnc` with `--release`
4. Verifies static linking (`ldd` check)

Output binaries are placed in `target/<triple>/release/`.

## Tier 3 Targets (Nightly)

Supported architectures: `mips`, `mipsel`, `riscv64`, `armv5te`

These require nightly Rust and `-Z build-std` for targets without prebuilt `std`.

### Build Infrastructure

Located in `docker/tier3-musl/`:

- Custom Dockerfiles per target
- GCC wrapper scripts for fixing CRT paths
- Patches for `schemars`, `coarsetime`, `prometheus` (portable-atomic)

### Building

```bash
cd docker/tier3-musl
./build-tier3.sh mips
```

The script:

1. Builds the Docker image if needed
2. Applies crate patches for 32-bit targets
3. Compiles with nightly + `-Z build-std`

## Build Output

| Binary | Typical Size | Purpose |
|--------|-------------|---------|
| `nym-vpnd` | ~57 MB | VPN daemon |
| `nym-vpnc` | ~5 MB | CLI client |

Both are statically linked MUSL binaries with no runtime dependencies.
