# Building from Source

## Prerequisites

- Docker
- Git

All compilation happens inside Docker containers. No local Rust toolchain is needed.

## Tier 2 Targets (Stable)

Supported architectures: `x86_64`, `i686`, `aarch64`, `armv7`

### Using the Build Script

```bash
./scripts/build-musl.sh aarch64
```

The dispatcher script (`build-musl.sh`) selects the correct Docker image and runs `cross-compile-musl.sh` inside the container.

| Target | Docker Image |
|--------|-------------|
| aarch64 | `messense/rust-musl-cross:aarch64-musl` |
| x86_64 | `messense/rust-musl-cross:x86_64-musl` |
| i686 | `messense/rust-musl-cross:i686-musl` |
| armv7 | `messense/rust-musl-cross:armv7-musleabihf` |

### Manual Docker Build

```bash
docker run --rm -v "$(pwd):/home/rust/src" \
  messense/rust-musl-cross:aarch64-musl \
  bash /home/rust/src/scripts/cross-compile-musl.sh
```

### What the Build Does

`cross-compile-musl.sh` runs inside Docker and performs the following:

1. Auto-detects the target architecture from the available cross-compiler
2. Validates Rust version (requires 1.85+ for edition 2024)
3. Installs system dependencies: `pkg-config`, `curl`, `protoc` 30.2
4. Builds `libmnl-1.0.4` and `libnftnl-1.2.1` from source with `--enable-static --disable-shared`
5. Compiles `nym-vpnd` and `nym-vpnc` with `--release`
6. Verifies static linking with `ldd`

**Target-specific compiler flags:**

| Target | Extra Flags | Reason |
|--------|-------------|--------|
| ARM (soft-float) | `-msoft-float -mfloat-abi=soft` | ring library workaround |
| ARM (hard-float) | `-C link-arg=-lgcc` | Atomic operations |
| aarch64 | `-mno-outline-atomics` | GCC 10+ outline atomics break static MUSL builds |

Output binaries land in `nym-vpn-core/target/<triple>/release/`.

## Tier 3 Targets (Nightly)

Supported architectures: `mips`, `mipsel`, `riscv64`, `armv5te`

These require nightly Rust and `-Z build-std` because there are no prebuilt `std` libraries for these targets.

### Build Infrastructure

Located in `docker/tier3-musl/`:

- Custom Dockerfiles per target with musl.cc toolchains
- GCC wrapper scripts that fix CRT object paths for static linking
- Patch scripts for crates that lack `portable-atomic` support on 32-bit targets

### Building

```bash
cd docker/tier3-musl
./build-tier3.sh mips
```

### What the Tier 3 Build Does

`build-tier3.sh` solves a specific problem: autocfg probes fail on Docker volume mounts due to missing extended file attributes, causing crates to compile in `no_std` mode incorrectly. The script works around this by copying the source to a local filesystem inside the container.

1. Auto-detects the target and compiler triplet from available GCC commands
2. Switches to nightly Rust and installs `rust-src`
3. Copies the source tree to `/tmp/nym-build`
4. Builds `libmnl` and `libnftnl` with target-specific CFLAGS
5. Applies crate patches via `patch-crates.sh`:
    - `schemars`: Uses `BTreeMap` instead of `IndexMap`
    - `coarsetime`: Uses `portable-atomic` for `AtomicU64`
    - `prometheus`: Uses `portable-atomic` for `AtomicU64`/`AtomicI64`
6. Builds with `cargo build --release -Z build-std=std,panic_abort`
7. Strips binaries with the target-specific `strip`
8. Copies binaries back to the mounted volume

**Target-specific RUSTFLAGS:**

| Target | Key Flags |
|--------|-----------|
| MIPS | `+mips32r2,+soft-float`, circular linker group for `libgcc_eh` + `libc` |
| RISC-V | `+crt-static`, uses lld due to outdated binutils |
| ARMv5TE | `-C link-arg=-lgcc_eh` for exception handling |

**Build profile tuning:** Tier 3 uses `thin` LTO (full LTO causes OOM), 16 codegen units, and `panic=abort` to reduce binary size.

## Build Output

| Binary | Typical Size | Purpose |
|--------|-------------|---------|
| `nym-vpnd` | ~16–33 MB (arch-dependent) | VPN daemon |
| `nym-vpnc` | ~2–3 MB | CLI client |

Sizes vary by architecture: `nym-vpnd` is ~16 MB on armv5te/riscv64, ~22 MB on mips, ~28–29 MB on aarch64/armv7/i686, and ~33 MB on x86_64. Compressed `.ipk`/`.apk` packages are ~9–15 MB.

Both are statically linked MUSL binaries with no runtime dependencies beyond the kernel.
