# Supported Devices

## Requirements

| | Minimum | Comfortable |
|-------------|---------|-------------|
| OpenWrt | 18.06+ | 23.05+ |
| RAM | 128 MB | 256 MB+ |
| Storage | 40 MB free | 128 MB+ |
| Kernel module | `kmod-tun` | `kmod-tun` |

!!! note
    At 128 MB RAM, enable [zram swap](troubleshooting.md#not-enough-ram-oom-crash) before you
    connect. Without it, bringing up both WireGuard tunnels can OOM.

## Architectures

Any OpenWrt device on one of these can install the package. 21 variants are built:

**Tier 2 — stable Rust:**

- `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a53_neon-vfpv4`, `aarch64_cortex-a72`
- `x86_64`
- `i386_pentium4`, `i386_pentium-mmx`
- `arm_cortex-a5_vfpv4`, `arm_cortex-a7`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a7_vfpv4`
- `arm_cortex-a8_vfpv3`, `arm_cortex-a9`, `arm_cortex-a9_neon`, `arm_cortex-a9_vfpv3-d16`
- `arm_cortex-a15_neon-vfpv4`

**Tier 3 — nightly Rust, experimental:**

- `mips_24kc`, `mips_siflower`
- `mipsel_24kc`
- `riscv64_riscv64`
- `arm_arm926ej-s`

## Buying for this

In rough order of how much it matters:

1. **256 MB+ RAM** — the difference between working and OOM
2. **aarch64 or x86_64** — Tier 2, stable toolchain, best throughput
3. **OpenWrt 23.05+** — nftables/fw4, which is the better-tested firewall path here
4. **Room in flash** — the binaries are 18–36 MB installed, architecture dependent
