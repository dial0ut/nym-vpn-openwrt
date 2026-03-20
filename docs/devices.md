# Supported Devices

## Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OpenWrt | 18.06+ | 23.05+ |
| RAM | 128 MB | 256 MB+ |
| Storage | 70 MB free | 128 MB+ |
| Kernel module | `kmod-tun` | `kmod-tun` |

!!! note
    Devices with 128 MB RAM should enable [zram swap](troubleshooting.md#not-enough-ram-oom-crash) for stable operation.

## Tested Devices

| Device | Architecture | RAM | Notes |
|--------|-------------|-----|-------|
| x86_64 VM / Proxmox | x86_64 | varies | Best for testing |
| FriendlyARM NanoPi R4S | aarch64_generic | 1 GB / 4 GB | Popular travel router |
| FriendlyARM NanoPi R5S | aarch64_generic | 2 GB / 4 GB | Powerful home router |
| GL.iNet MT6000 (Flint 2) | aarch64_cortex-a53 | 1 GB | WiFi 6, good performance |
| Banana Pi BPI-R3 | aarch64_cortex-a53 | 2 GB | Development board |
| Linksys MX4200v2 (Atlas 6) | arm_cortex-a7_neon-vfpv4 | 512 MB | WiFi 6 mesh |
| GL.iNet B1300 | arm_cortex-a7_neon-vfpv4 | 256 MB | Compact, affordable |
| ASUS RT-AC58U | arm_cortex-a7_neon-vfpv4 | 128 MB | Needs zram swap |
| Linksys WRT1900ACS | arm_cortex-a9 | 512 MB | Classic hackable router |
| Turris Omnia | arm_cortex-a9 | 1 GB / 2 GB | Open-source router |
| Netgear R7000 | arm_cortex-a9 | 256 MB | Broadcom, widely available |
| ASUS RT-AC68U | arm_cortex-a9 | 256 MB | Broadcom, popular |
| GL.iNet GL-AR750S (Slate) | mips_24kc | 128 MB | Travel router, needs zram |
| GL.iNet GL-MT1300 (Beryl) | mipsel_24kc | 256 MB | Travel router |

### IPK Architectures Available

Any OpenWrt device matching a supported architecture can install via `.ipk`. Binary packages are built for 19 architecture variants:

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

## Choosing a Device

For the best NymVPN experience, look for:

1. **256 MB+ RAM** — avoids OOM issues
2. **aarch64 or x86_64** — Tier 2 stable builds
3. **OpenWrt 23.05+ support** — nftables firewall (fw4)
4. **USB or large flash** — room for the ~62 MB binaries
