# Building from Source

You need Docker and Git. Everything compiles inside containers — no local Rust toolchain.

Binaries link dynamically against the target's musl libc, `libmnl` and `libnftnl`, which is the
normal arrangement for OpenWrt packages: smaller binaries, and the shared libraries get security
updates through the package manager instead of being frozen into every build.

## Tier 2 (stable Rust)

`x86_64`, `i686`, `aarch64`, `armv7`.

```bash
./scripts/build-musl.sh aarch64
```

`build-musl.sh` picks the Docker image and runs `cross-compile-dynamic.sh` inside it.

| Target | Docker image |
|--------|-------------|
| aarch64 | `messense/rust-musl-cross:aarch64-musl` |
| x86_64 | `messense/rust-musl-cross:x86_64-musl` |
| i686 | `messense/rust-musl-cross:i686-musl` |
| armv7 | `messense/rust-musl-cross:armv7-musleabihf` |

Without the wrapper:

```bash
docker run --rm -v "$(pwd):/home/rust/src" \
  -e TARGET=aarch64-unknown-linux-musl \
  messense/rust-musl-cross:aarch64-musl \
  bash /home/rust/src/scripts/cross-compile-dynamic.sh
```

Inside the container, `cross-compile-dynamic.sh`:

1. Detects the target from the available cross-compiler, unless `TARGET` is set
2. Installs `pkg-config`, `curl`, and `protoc` 30.2 — the apt `protoc` is too old for
   `proto3 optional`
3. Builds `libmnl` and `libnftnl` from source as shared libraries
   (`--enable-shared --disable-static`, `CFLAGS=-fPIC`)
4. Builds `nym-vpnd` and `nym-vpnc` with `cargo build --bins --release`

Binaries land in `nym-vpn-core/target/<triple>/release/`.

Rust defaults to static linking on musl targets, so the build opts out explicitly:

```
RUSTFLAGS="-C target-feature=-crt-static"
```

Two target families need more:

| Target | Flags | Why |
|--------|-------|-----|
| ARM hard-float (`musleabihf`) | `-C link-arg=-lgcc` | atomics |
| ARM soft-float (BCM5301X) | `-msoft-float -mfloat-abi=soft`, armv5te target | no VFP/NEON; uses `portable-atomic` |

Extra flags can be appended per build via `RUSTFLAGS_EXTRA`, which is how CPU-specific variants
like cortex-a9 get built.

## Tier 3 (nightly Rust)

`mips`, `mipsel`, `riscv64`, `armv5te`. No prebuilt `std` exists for these, so they need nightly
and `-Z build-std`.

```bash
cd docker/tier3-musl
./build-tier3.sh mips
```

`docker/tier3-musl/` holds a Dockerfile per target with musl.cc toolchains, plus patch scripts for
crates that lack `portable-atomic` support on 32-bit.

`build-tier3-dynamic.sh` — the script CI runs inside those images — exists mainly to work around
one thing: autocfg probes fail on Docker volume mounts because extended file attributes are
missing, and crates silently compile in `no_std` mode as a result. Copying the source to a local
filesystem inside the container fixes it.

1. Detects target and compiler triplet from the available GCC
2. Switches to nightly, installs `rust-src`
3. Copies the tree to `/tmp/nym-build`
4. Builds `libmnl` and `libnftnl` with target CFLAGS
5. Applies crate patches via `patch-crates.sh`:
    - `schemars` — `BTreeMap` instead of `IndexMap`
    - `coarsetime` — `portable-atomic` for `AtomicU64`
    - `prometheus` — `portable-atomic` for `AtomicU64`/`AtomicI64`
6. `cargo build --release -Z build-std=std,panic_abort`
7. Strips with the target `strip`
8. Copies binaries back to the mounted volume

Plain GCC is used as the linker. The CRT-path wrapper scripts in `docker/tier3-musl/` are only
needed when Rust passes bare `crt*.o` filenames, which it does not do here.

| Target | Extra flags |
|--------|-------------|
| MIPS | `-C target-feature=+mips32r2,+soft-float -C link-arg=-msoft-float`, `CFLAGS=-mips32r2 -msoft-float` |
| ARMv5TE | `CFLAGS=-msoft-float -mfloat-abi=soft` |
| RISC-V | none beyond the defaults |

Tier 3 overrides the release profile: full LTO, one codegen unit, `opt-level=z`, `panic=abort`.
Tier 2 uses the profile from `Cargo.toml` — same settings but `opt-level=2`. Leave that at 2:
`opt-level=3` OOM-crashes the CI runners.

## Output

As of v1.33.1:

| Binary | Size |
|--------|------|
| `nym-vpnd` | 18–33 MB |
| `nym-vpnc` | 2.1–3.1 MB |

`nym-vpnd` is smallest on armv5te and riscv64 (~18 MB), ~24 MB on mips and mipsel, and 31–33 MB
on aarch64, armv7, i686 and x86_64. Packaged `.ipk`/`.apk` compress to roughly half that.

Runtime dependencies are `libc`, `libmnl`, `libnftnl` and `kmod-tun`, all declared by the package.
