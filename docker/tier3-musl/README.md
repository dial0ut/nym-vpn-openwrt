# Tier 3 Target Docker Images

Custom Docker images for building nym-vpn for Rust Tier 3 musl targets.

## Supported Targets

| Target | Architecture | Use Case |
|--------|-------------|----------|
| `mips-unknown-linux-musl` | MIPS Big-Endian | ath79 (TP-Link, Netgear) |
| `mipsel-unknown-linux-musl` | MIPS Little-Endian | ramips (MT7621, GL.iNet) |
| `riscv64gc-unknown-linux-musl` | RISC-V 64-bit | Future OpenWrt devices |

## The Problem

Tier 3 targets require `-Z build-std` (nightly only) to compile the Rust standard library from source. However, when building inside Docker with a mounted volume, the `autocfg` crate fails to detect `std` support because:

1. Docker volume mounts don't support extended file attributes (xattrs)
2. `autocfg` uses xattrs for its probe mechanism
3. Without proper probe results, `indexmap` compiles in `no_std` mode
4. This changes `IndexMap<K, V>` to `IndexMap<K, V, S>` (3 generic args instead of 2)
5. `schemars` expects the `std` signature, causing compilation failure

Error message:
```
error[E0107]: struct takes 3 generic arguments but 2 generic arguments were supplied
 --> schemars-0.8.22/src/lib.rs:12:32
pub type Map<K, V> = indexmap::IndexMap<K, V>;
```

## The Solution

These custom images copy the source code to the container's local filesystem (which supports xattrs), build there, and copy the binaries back.

## Building the Images

```bash
cd docker/tier3-musl

# Build all images
docker build -t nym-musl-cross:mips-musl -f Dockerfile.mips .
docker build -t nym-musl-cross:mipsel-musl -f Dockerfile.mipsel .
docker build -t nym-musl-cross:riscv64gc-musl -f Dockerfile.riscv64 .
```

## Usage

```bash
# From the repository root
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:mips-musl /opt/build-tier3.sh
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:mipsel-musl /opt/build-tier3.sh
docker run --rm -v "$(pwd)":/home/rust/src nym-musl-cross:riscv64gc-musl /opt/build-tier3.sh
```

Binaries will be at: `nym-vpn-core/target/<target>/release/`

## Build Time

Expect 15-30 minutes per target due to:
- Compiling rust-std from source
- Cross-compiling native dependencies (libmnl, libnftnl)
- Full release build with LTO

## References

- [indexmap issue #151](https://github.com/bluss/indexmap/issues/151) - Original autocfg xattr problem
- [Rust Tier 3 targets](https://doc.rust-lang.org/nightly/rustc/platform-support.html) - Platform support docs
