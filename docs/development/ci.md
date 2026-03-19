# CI/CD

## Workflows

### Release (`release-musl.yml`)

**Trigger:** `v*` tag push or manual dispatch

**Steps:**

1. Builds binaries for 4 Tier 2 targets in parallel
2. Builds binaries for Tier 3 targets (mips, mipsel) with nightly Rust
3. Packages IPKs for 19 OpenWrt architecture variants
4. Creates a GitHub release with binaries, tarballs, checksums, and IPKs

**Architecture variants:**

| Base Target | IPK Architectures |
|-------------|------------------|
| aarch64 | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a53_neon-vfpv4`, `aarch64_cortex-a72` |
| x86_64 | `x86_64` |
| i686 | `i386_pentium4`, `i386_pentium-mmx` |
| armv7 | `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a7_vfpv4`, `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_neon`, `arm_cortex-a9_vfpv3-d16`, `arm_cortex-a15_neon-vfpv4` |
| mips | `mips_24kc`, `mips_siflower` |
| mipsel | `mipsel_24kc` |
