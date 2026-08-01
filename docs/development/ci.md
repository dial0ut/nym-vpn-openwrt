# CI/CD

Two workflows: `release-musl.yml` builds and ships releases, `docs.yml` deploys this site.

## Release

`release-musl.yml`, triggered by pushing a `v*` tag, or manually with a `tag` input.

Manual dispatch builds and packages but **does not release** — the `release` and `publish-feed`
jobs are gated on `startsWith(github.ref, 'refs/tags/')`, which a `workflow_dispatch` run does not
satisfy. Use it to test a build, not to ship one.

### 1. Verify release invariants

Everything else depends on this job, so a release that violates any of it never starts building:

- the tag exists
- `nym-vpn-core/Cargo.toml` at that tag has a `version` matching the tag minus its `v`
- the tagged commit is an ancestor of **both** `origin/develop` and `origin/openwrt`
- `CHANGELOG.md` at that tag has a `## [VERSION]` section

### 2. Tier 2 binaries

Four parallel builds on stock `messense/rust-musl-cross` images:

| Target | Image |
|--------|-------|
| x86_64 | `messense/rust-musl-cross:x86_64-musl` |
| i686 | `messense/rust-musl-cross:i686-musl` |
| aarch64 | `messense/rust-musl-cross:aarch64-musl` |
| armv7 | `messense/rust-musl-cross:armv7-musleabihf` |

Each sets up an 8 GB swap file — LTO linking needs it and the runners do not have the RAM — runs
`cross-compile-dynamic.sh`, and produces `nym-vpnd-{arch}`, `nym-vpnc-{arch}`,
`nym-vpn-{arch}.tar.gz` and SHA256 sums.

### 3. Tier 3 binaries

Four parallel builds on custom images from `docker/tier3-musl/`:

| Target | Dockerfile |
|--------|-----------|
| mips | `Dockerfile.mips` |
| mipsel | `Dockerfile.mipsel` |
| riscv64 | `Dockerfile.riscv64` |
| armv5te | `Dockerfile.armv5te` |

Each builds its image, then runs `build-tier3-dynamic.sh` inside it with nightly Rust and
`-Z build-std`. Same 8 GB swap.

### 4. Package

Waits on both build jobs, then runs 21 parallel packaging jobs mapping 8 binary targets onto 21
OpenWrt architecture variants:

| Binary | OpenWrt architectures |
|--------|----------------------|
| aarch64 | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a53_neon-vfpv4`, `aarch64_cortex-a72` |
| x86_64 | `x86_64` |
| i686 | `i386_pentium4`, `i386_pentium-mmx` |
| armv7 | `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a7_vfpv4`, `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_neon`, `arm_cortex-a9_vfpv3-d16`, `arm_cortex-a15_neon-vfpv4` |
| mips | `mips_24kc` |
| mipsel | `mipsel_24kc`, `mips_siflower` |
| riscv64 | `riscv64_riscv64` |
| armv5te | `arm_arm926ej-s` |

Each job downloads its binary artifact and runs `build-ipk.sh` then `build-apk.sh` against the
in-repo `luci-app-nym-vpn/` directory. Output is `nym-vpn_{version}_{openwrt_arch}.ipk` and
`.apk`, uploaded as `pkg-{openwrt_arch}`.

### 5. GitHub release

Tagged commits only. The release body's changelog is **extracted from `CHANGELOG.md`** — an awk
pass that prints the `## [VERSION]` section up to the next `## [`. There is no commit-message
parsing. An empty extraction fails the job, which is the second place a missing changelog section
gets caught.

Marked prerelease if the tag contains `beta`, `alpha` or `rc`. Attaches all 8 daemon binaries, 8
CLI binaries, tarballs, checksums, every IPK and APK, and `scripts/install.sh`.

### 6. Publish the feed

Tagged commits only, after the release exists. `generate-feed.sh` sorts packages into per-arch
directories by parsing the architecture out of each filename, then builds an index per directory:

- **opkg** — `Packages` and `Packages.gz`, signed with usign/signify to `Packages.sig`
- **apk** — `packages.adb`, built by `apk mkndx`

Signing keys come from the `DIAL0UT_OPKG` and `DIAL0UT_APK` secrets, written to `/tmp` and removed
in an `always()` step.

Everything is then synced to Cloudflare R2 with `--delete`, alongside `install.sh` and a `latest`
file holding the version tag — which is how the installer finds the current release.

```text
packages.dial0ut.org/
├── install.sh
├── latest
├── opkg/
│   ├── aarch64_generic/
│   │   ├── nym-vpn_1.33.1_aarch64_generic.ipk
│   │   ├── Packages
│   │   ├── Packages.gz
│   │   └── Packages.sig
│   └── ...
└── apk/
    ├── aarch64_generic/
    │   ├── nym-vpn_1.33.1_aarch64_generic.apk
    │   └── packages.adb
    └── ...
```

## Feed signing

The two formats sign differently, so each package ships its own public key — copied into the
keystore at **build time** by `build-ipk.sh` / `build-apk.sh`, not in `postinst`.

**opkg** uses usign/signify (Ed25519). `scripts/feed/dial0ut.pub` is installed to
`/etc/opkg/keys/` under a filename that is the key's **fingerprint**, because that is how usign
looks keys up.

**apk** uses an ECDSA P-256 key via `apk mkndx --sign-key`, and matches a signature to a key in
`/etc/apk/keys/` **by basename**. So the CI private key and the shipped public key must share the
name `dial0ut-apk.pem`. Get that wrong and every install fails verification — which is exactly
what happened before v1.30.1, when the signify key was shipped to apk's keystore instead.

The apk repository line must point directly at the index (`.../apk/$ARCH/packages.adb`), not at
the directory. Given a bare directory, apk appends `$ARCH/APKINDEX.tar.gz` and 404s.

## Release artifacts

| Artifact | Count | Example |
|----------|-------|---------|
| Daemon binaries | 8 | `nym-vpnd-aarch64` |
| CLI binaries | 8 | `nym-vpnc-aarch64` |
| Tarballs | 8 | `nym-vpn-aarch64.tar.gz` |
| SHA256 checksums | 24 | `nym-vpnd-aarch64.sha256` |
| IPK packages | 21 | `nym-vpn_1.33.1_aarch64_generic.ipk` |
| APK packages | 21 | `nym-vpn_1.33.1_aarch64_generic.apk` |
| Install script | 1 | `install.sh` |

## Docs

`docs.yml` runs `mkdocs gh-deploy --force` on any push to the **`openwrt`** branch that touches
`docs/**` or `mkdocs.yml`. Pushing docs changes to `develop` deploys nothing.
