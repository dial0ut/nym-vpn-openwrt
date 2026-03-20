# CI/CD

## Workflows

### Release (`release-musl.yml`)

**Trigger:** Push a tag matching `v*` or manual dispatch with a `tag` input.

#### Job 1: Build Tier 2 Binaries

Runs 4 parallel builds using stock `messense/rust-musl-cross` Docker images:

| Target | Docker Image |
|--------|-------------|
| x86_64 | `messense/rust-musl-cross:x86_64-musl` |
| i686 | `messense/rust-musl-cross:i686-musl` |
| aarch64 | `messense/rust-musl-cross:aarch64-musl` |
| armv7 | `messense/rust-musl-cross:armv7-musleabihf` |

Each build:

1. Sets up an 8 GB swap file for LTO linking
2. Runs `cross-compile-musl.sh` inside the container
3. Produces `nym-vpnd-{arch}`, `nym-vpnc-{arch}`, `nym-vpn-{arch}.tar.gz`, and SHA256 checksums

#### Job 2: Build Tier 3 Binaries

Runs 2 parallel builds using custom Docker images from `docker/tier3-musl/`:

| Target | Dockerfile |
|--------|-----------|
| mips | `Dockerfile.mips` |
| mipsel | `Dockerfile.mipsel` |

Each build compiles the custom Docker image, then runs `build-tier3.sh` inside it with nightly Rust and `-Z build-std`.

#### Job 3: Package (IPK + APK)

Depends on both build jobs. Runs 18 parallel packaging jobs that map the 6 binary targets to 18 OpenWrt architecture variants:

| Binary Target | OpenWrt Architectures |
|---------------|----------------------|
| aarch64 | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a53_neon-vfpv4`, `aarch64_cortex-a72` |
| x86_64 | `x86_64` |
| i686 | `i386_pentium4`, `i386_pentium-mmx` |
| armv7 | `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a7_vfpv4`, `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_neon`, `arm_cortex-a9_vfpv3-d16`, `arm_cortex-a15_neon-vfpv4` |
| mips | `mips_24kc` |
| mipsel | `mipsel_24kc`, `mips_siflower` |

Each job:

1. Downloads the matching binary from the build artifact
2. Clones the LuCI frontend, trying the matching release tag first, falling back to main
3. Builds an `.ipk` via `scripts/ipk/build-ipk.sh`
4. Builds an `.apk` via `scripts/apk/build-apk.sh`

Output naming: `nym-vpn_{version}_{openwrt_arch}.ipk` and `.apk`

#### Job 4: Create GitHub Release

Runs only on tagged commits. Collects all artifacts and:

1. Generates a changelog by grouping commits since the previous tag into **Features** (`feat:`), **Bug Fixes** (`fix:`), and **Other Changes**
2. Creates a GitHub release, marked prerelease if the tag contains `beta`, `alpha`, or `rc`
3. Attaches all binaries, tarballs, checksums, IPKs, APKs, and the install script

#### Job 5: Publish Package Feed

Runs only on tagged commits, after the release is created.

1. Generates an opkg feed index (`Packages`, `Packages.gz`) per architecture
2. Generates an apk feed index (`APKINDEX.tar.gz`) per architecture
3. Signs both feeds with an RSA key
4. Uploads everything to Cloudflare R2 at `packages.dial0ut.org`

Feed structure on R2:

```text
packages.dial0ut.org/
├── opkg/
│   ├── aarch64_generic/
│   │   ├── nym-vpn_1.23.0_aarch64_generic.ipk
│   │   ├── Packages
│   │   ├── Packages.gz
│   │   └── Packages.sig
│   ├── x86_64/
│   │   └── ...
│   └── ...
└── apk/
    ├── aarch64_generic/
    │   ├── nym-vpn_1.23.0_aarch64_generic.apk
    │   └── APKINDEX.tar.gz (signed)
    └── ...
```

## Feed Signing

Package feeds are signed with RSA to prevent tampering. The public key (`scripts/feed/dial0ut.pub`) is included in the IPK/APK package and installed to `/etc/opkg/keys/` or `/etc/apk/keys/` during `postinst`.

**opkg signing:** The `Packages` index file is signed with `openssl dgst -sha256`, producing a detached `Packages.sig`.

**apk signing:** The `APKINDEX` is signed with `openssl dgst -sha1`, and the signature is embedded inside `APKINDEX.tar.gz` as `.SIGN.RSA.dial0ut.pub`.

## Release Artifacts

A complete release includes:

| Artifact | Count | Example |
|----------|-------|---------|
| Daemon binaries | 6 | `nym-vpnd-aarch64` |
| CLI binaries | 6 | `nym-vpnc-aarch64` |
| Tarballs | 6 | `nym-vpn-aarch64.tar.gz` |
| SHA256 checksums | 18 | `nym-vpnd-aarch64.sha256` |
| IPK packages | 18 | `nym-vpn_1.23.0_aarch64_generic.ipk` |
| APK packages | 18 | `nym-vpn_1.23.0_aarch64_generic.apk` |
| Install script | 1 | `install.sh` |
