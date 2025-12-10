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

### Why Tier 3 Requires Special Handling

Rust Tier 3 targets don't have pre-built standard libraries, so we must:
1. Use nightly Rust with `-Z build-std=std,panic_abort`
2. Patch certain crates for compatibility (schemars, coarsetime, prometheus)
3. Handle cross-compilation toolchain quirks

### The autocfg/indexmap Problem

Docker volume mounts don't support extended file attributes (xattrs), which causes `autocfg` probes to fail. This makes `indexmap` compile in `no_std` mode with a different API, breaking `schemars`.

Error:
```
error[E0107]: struct takes 3 generic arguments but 2 generic arguments were supplied
 --> schemars-0.8.22/src/lib.rs:12:32
pub type Map<K, V> = indexmap::IndexMap<K, V>;
```

**Solution**: The build script copies source to the container's local filesystem before building.

### Static Linking Fix

Rust's linker invocation includes `-Wl,-Bdynamic` which breaks static linking with GNU ld. The GCC wrapper scripts strip this flag and add `-Wl,-Bstatic` to ensure fully static binaries.

### RISC-V Linker

RISC-V uses lld instead of GNU ld because GCC 11.2's binutils doesn't understand newer RISC-V extensions (zaamo, zalrsc). The Dockerfile replaces ld with lld symlinks.

### 32-bit MIPS Atomic Support

MIPS32 lacks native 64-bit atomics. The build uses a patched `nym` fork (`dial0ut/nym` branch `feat/tier3-portable-atomic`) that uses the `portable-atomic` crate.

## Directory Structure

```
docker/tier3-musl/
├── Dockerfile.mips           # MIPS big-endian image
├── Dockerfile.mipsel         # MIPS little-endian image
├── Dockerfile.riscv64        # RISC-V 64-bit image
├── Dockerfile.armv5te        # ARMv5TE image
├── build-tier3.sh            # Main build script (copied into images)
├── mips-gcc-wrapper.sh       # Linker wrapper for MIPS
├── mipsel-gcc-wrapper.sh     # Linker wrapper for MIPSEL
├── riscv64-gcc-wrapper.sh    # Linker wrapper for RISC-V
├── armv5te-gcc-wrapper.sh    # Linker wrapper for ARMv5TE
├── patches/                  # Patched crates for Tier 3 compatibility
│   ├── schemars-0.8.22/      # Uses BTreeMap instead of IndexMap
│   ├── coarsetime-0.1.36/    # Uses portable-atomic for AtomicU64
│   └── prometheus-0.14.0/    # Uses portable-atomic for AtomicU64
└── README.md
```

## Troubleshooting

### "struct takes 3 generic arguments but 2 were supplied"
The autocfg probe failed. Make sure you're running from the repository root with the volume mount correctly set.

### Binary is dynamically linked
Rebuild the Docker image to get the latest GCC wrapper with the `-Bdynamic` fix:
```bash
docker build -t nym-musl-cross:mipsel-musl -f Dockerfile.mipsel .
```

### Undefined reference to `_Unwind_*` symbols
The build script should add `-lgcc_eh`. This is handled automatically for MIPS targets.

### Out of memory during build
The build uses thin LTO to reduce memory usage. If still failing, build on a machine with more RAM or add swap space.

### Floating point ABI mismatch (MIPS with lld)
MIPS uses GNU ld, not lld. The musl CRT files are compiled with hard-float but Rust uses soft-float. GNU ld warns but links; lld errors. Don't switch MIPS to lld.

## References

- [Rust Tier 3 targets](https://doc.rust-lang.org/nightly/rustc/platform-support.html)
- [indexmap issue #151](https://github.com/bluss/indexmap/issues/151) - autocfg xattr problem
- [portable-atomic](https://github.com/taiki-e/portable-atomic) - Atomic support for targets without native atomics
