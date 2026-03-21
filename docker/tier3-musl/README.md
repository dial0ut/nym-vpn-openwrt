# Tier 3 musl Cross-Compilation

Docker images and build scripts for cross-compiling nym-vpn to Rust Tier 3 musl targets. Produces fully static, stripped binaries suitable for embedded Linux systems like OpenWrt routers.

## Supported Targets

| Target | Architecture | Use Case |
|--------|--------------|----------|
| `mips-unknown-linux-musl` | MIPS32 big-endian | Older routers (ath79, Atheros) |
| `mipsel-unknown-linux-musl` | MIPS32 little-endian | Many OpenWrt devices (ramips, MT7621) |
| `riscv64gc-unknown-linux-musl` | RISC-V 64-bit | RISC-V SBCs |
| `armv5te-unknown-linux-musleabi` | ARMv5TE | Legacy ARM devices |

## Quick Start

```bash
cd docker/tier3-musl

# Build Docker image (one-time setup)
docker build -t nym-musl-cross:mipsel-musl -f Dockerfile.mipsel .

# Run the build (from repository root)
cd /path/to/nym-vpn-client
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:mipsel-musl /opt/build-tier3.sh

# Binaries output:
# nym-vpn-core/target/mipsel-unknown-linux-musl/release/nym-vpnd
# nym-vpn-core/target/mipsel-unknown-linux-musl/release/nym-vpnc
```

## Building All Targets

```bash
cd docker/tier3-musl

# Build all Docker images
docker build -t nym-musl-cross:mips-musl -f Dockerfile.mips .
docker build -t nym-musl-cross:mipsel-musl -f Dockerfile.mipsel .
docker build -t nym-musl-cross:riscv64-musl -f Dockerfile.riscv64 .
docker build -t nym-musl-cross:armv5te-musl -f Dockerfile.armv5te .

# Run builds (from repository root)
cd /path/to/nym-vpn-client
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:mips-musl /opt/build-tier3.sh
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:mipsel-musl /opt/build-tier3.sh
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:riscv64-musl /opt/build-tier3.sh
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:armv5te-musl /opt/build-tier3.sh
```

## Build Output

Binaries are:
- **Fully statically linked** - no shared library dependencies (no libc.so, no ld-linux interpreter)
- **Stripped** - debug symbols removed for smaller size
- Ready to `scp` directly to target devices

Verify static linking:
```bash
file nym-vpn-core/target/mipsel-unknown-linux-musl/release/nym-vpnd
# Should show: "statically linked"

# Confirm no dynamic dependencies (should output nothing)
objdump -p nym-vpn-core/target/mipsel-unknown-linux-musl/release/nym-vpnd | grep -E "(NEEDED|INTERP)"
```

## Build Time

Expect 15-30 minutes per target due to:
- Compiling rust-std from source (`-Z build-std`)
- Cross-compiling native dependencies (libmnl, libnftnl)
- Full release build with thin LTO

## Technical Details

- **Tier 3 targets** require nightly Rust with `-Z build-std` (no pre-built std)
- **Static linking** uses GCC wrapper scripts to ensure fully static binaries
- **RISC-V** uses lld (GNU ld doesn't support newer extensions)
- **MIPS32** uses `portable-atomic` crate (no native 64-bit atomics)

## Directory Structure

```
docker/tier3-musl/
├── Dockerfile.mips           # MIPS big-endian image
├── Dockerfile.mipsel         # MIPS little-endian image
├── Dockerfile.riscv64        # RISC-V 64-bit image
├── Dockerfile.armv5te        # ARMv5TE image
├── build-tier3.sh            # Main build script (copied into images)
├── gcc-wrapper.sh            # Unified linker wrapper (parameterized via env vars)
├── patches/                  # Patched crates for Tier 3 compatibility
│   ├── schemars-0.8.22/      # Uses BTreeMap instead of IndexMap
│   ├── coarsetime-0.1.36/    # Uses portable-atomic for AtomicU64
│   └── prometheus-0.14.0/    # Uses portable-atomic for AtomicU64
└── README.md
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common build issues.
