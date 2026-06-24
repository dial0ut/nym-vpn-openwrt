# Supported Devices

## Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OpenWrt | 18.06+ | 23.05+ |
| RAM | 128 MB | 256 MB+ |
| Storage | 40 MB free | 128 MB+ |
| Kernel module | `kmod-tun` | `kmod-tun` |

!!! note
    Devices with 128 MB RAM should enable [zram swap](troubleshooting.md#not-enough-ram-oom-crash) for stable operation.

## Supported Architectures

Any OpenWrt device matching a supported architecture can install via `.ipk`. Binary packages are built for 21 architecture variants:

**Stable (Tier 2):**

- `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a53_neon-vfpv4`, `aarch64_cortex-a72`
- `x86_64`
- `i386_pentium4`, `i386_pentium-mmx`
- `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a7_vfpv4`
- `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_neon`, `arm_cortex-a9_vfpv3-d16`
- `arm_cortex-a15_neon-vfpv4`

**Experimental (Tier 3 — nightly Rust):**

- `mips_24kc`, `mips_siflower`
- `mipsel_24kc`
- `riscv64_riscv64`
- `arm_arm926ej-s`

## Choosing a Device

For the best NymVPN experience, look for:

1. **256 MB+ RAM** — avoids OOM issues
2. **aarch64 or x86_64** — Tier 2 stable builds
3. **OpenWrt 23.05+ support** — nftables firewall (fw4)
4. **USB or large flash** — room for the ~18–36 MB binaries (arch-dependent)
