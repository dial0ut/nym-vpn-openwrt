# CI/CD

Five workflows: `ci.yml` and `docs-check.yml` check development changes, `release-musl.yml`
builds and ships releases, `build.yml` is the cross-build both of those call, and `docs.yml`
deploys this site.

## Development checks

`ci.yml` runs on pushes to `develop` that touch more than docs and Markdown, on pull requests
targeting `develop`, and on manual dispatch:

- **test** — ShellCheck over the root-run scripts, then
  `cargo test --workspace --locked --no-fail-fast` on the latest stable with the required native
  libraries and unprivileged ICMP sockets enabled.
- **cross** — `build.yml` for armv7 and mipsel: one target per build path (the stock Tier 2
  image, and a Tier 3 image with nightly `-Z build-std` and no 64-bit atomics). These are full
  release builds with the ELF check, so the binaries they upload can go straight onto a router.
- **workflow lint** — zizmor over `.github/workflows/`.

`docs-check.yml` runs `mkdocs build --strict` when `docs/` or `mkdocs.yml` change.

`scripts/release.sh` will not tag a commit whose `ci.yml` run on `develop` is missing, still
running or not green, so a release tag is never the first build of either build path.

Device-level integration and leak testing runs on the maintainers' own lab rigs and is not part
of the repository or these workflows. Cross-compilation proves a target builds, not that it works on a
router. Device validation must identify the tested package and scenarios, including any
skipped or inconclusive cases.

## Release

`release-musl.yml`, triggered by pushing a `v*` tag, or manually with a `tag` input.

Manual dispatch is a dry run of the same pipeline from that tag: it builds, packages, and builds
and smoke-tests an **unsigned** feed, then stops. The `release` and `publish-feed` jobs are gated
on `startsWith(github.ref, 'refs/tags/')`, which a `workflow_dispatch` run does not satisfy, and
only a tag run signs.

### 1. Verify release invariants

Everything else depends on this job, so a release that violates any of it never starts building:

- the tag exists
- `nym-vpn-core/Cargo.toml` at that tag has a `version` matching the tag minus its `v`
- the tagged commit is an ancestor of **both** `origin/develop` and `origin/openwrt`
- `CHANGELOG.md` at that tag has a `## [VERSION]` section

It also decides whether this is a pre-release: any version with a `-` suffix (`1.36.0-rc1`).

### 2. Build

`build.yml` with every target in `scripts/ci/targets.json`, checked out at the tag. Each job
runs in a pinned image, checks the ELF imports, and uploads `nym-vpnd-{arch}`, `nym-vpnc-{arch}`,
`nym-vpn-{arch}.tar.gz` and SHA256 sums.

| Target | Image | Toolchain |
|--------|-------|-----------|
| x86_64, i686, aarch64, armv7 | `messense/rust-musl-cross`, digest in `targets.json` | the image's stable |
| mips, mipsel, riscv64, armv5te | `docker/tier3-musl/Dockerfile.*`, built per run | `RUST_NIGHTLY` (`scripts/versions.sh`) |

Each sets up an 8 GB swap file first: LTO linking needs it and the runners do not have the RAM.

### 3. Package

One job that runs `build-ipk.sh` then `build-apk.sh` for each OpenWrt architecture listed under
its binary in `targets.json`, against the tag's `luci-app-nym-vpn/`, and fails unless there is
one `.ipk` and one `.apk` per architecture:

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

Output is `nym-vpn_{version}_{openwrt_arch}.ipk` and `.apk`, uploaded as one `packages`
artifact.

### 4. Build and smoke-test the feed

Before anything is public. `generate-feed.sh` sorts packages into per-arch directories by
parsing the architecture out of each filename, then builds an index per directory:

- **opkg** — `Packages` and `Packages.gz`, signed with usign/signify to `Packages.sig`
- **apk** — `packages.adb`, built by `apk mkndx`, with each package under the name `apk` fetches
  (`nym-vpn-<ver>-r0.apk`) and the one `install.sh` links to (`nym-vpn_<ver>_<arch>.apk`)

Signing keys come from the `DIAL0UT_OPKG` and `DIAL0UT_APK` secrets, written to `/tmp` and removed
in an `always()` step straight after indexing. The job then fails unless every architecture has
an index (and, on a tag, a `Packages.sig`), and runs a real `apk` client against the feed served
locally: `apk update && apk fetch --arch <arch> nym-vpn` for every architecture, trusting only
the public key shipped on-device. The feed is uploaded as the `feed` artifact.

### 5. GitHub release

Tagged commits only. The release body's changelog is **extracted from `CHANGELOG.md`** — an awk
pass that prints the `## [VERSION]` section up to the next `## [`. There is no commit-message
parsing. An empty extraction fails the job, which is the second place a missing changelog section
gets caught.

Marked prerelease if verify said so. Attaches all 8 daemon binaries, 8 CLI binaries, tarballs,
checksums, every IPK and APK, and `scripts/install.sh`.

### 6. Publish the feed

Tagged non-pre-release commits only, after the release exists, one at a time (a `publish-feed`
concurrency group). It checks the remote tags again and publishes only if this tag is still the
newest release, so a re-run of an old release or two tags in quick succession cannot roll the feed
back.

`scripts/feed/publish-r2.sh` then uploads the feed to Cloudflare R2, then `install.sh` and a
`latest` file holding the version tag — which is how the installer finds the current release — and
only then deletes whatever under `opkg/` and `apk/` this release does not have. Installs keep
working throughout. It finishes by checking that R2 holds exactly the feed that was built, keys
and sizes, and refuses to publish an empty feed. Nothing else in the bucket (`toolchains/`) is
touched.

It does not use `aws s3 sync --delete`: sync assumes both listings come back in byte order, R2
lists `Packages` after `Packages.gz` and `Packages.sig`, and v1.35.0's sync uploaded and deleted
each `Packages` at once, losing it in 12 of the 21 opkg directories.

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
    │   ├── nym-vpn-1.33.1-r0.apk
    │   ├── nym-vpn_1.33.1_aarch64_generic.apk
    │   └── packages.adb
    └── ...
```

## Pinned toolchains

A release builds with exactly what the last CI run used. Nothing on the build path floats, and
nothing bumps itself: every pin below changes by hand.

| What | Where |
|------|-------|
| Actions | SHA in each `uses:` |
| Tier 3 base images | digest in `docker/tier3-musl/Dockerfile.*` |
| mips/mipsel GCC toolchains | `TOOLCHAIN_SHA256` in their Dockerfiles |
| Tier 2 images | digest in `scripts/ci/targets.json` |
| Tier 3 nightly | `RUST_NIGHTLY` in `scripts/versions.sh` |
| Alpine (apk mkpkg, mkndx, smoke test) | `ALPINE_IMAGE` in `scripts/versions.sh` |

CI builds only armv7 and mipsel. After bumping something another target uses, build that target
before tagging: add it to `arches` in `ci.yml` for that push, or build it locally.

The test job alone runs on the latest stable, as an early warning for the next toolchain.

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

`docs.yml` runs `mkdocs gh-deploy --force --strict`, with the same `docs/requirements.txt` as
`docs-check.yml`, on any push to the **`openwrt`** branch that touches `docs/**` or `mkdocs.yml`.
Pushing docs changes to `develop` deploys nothing.
