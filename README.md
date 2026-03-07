<div align="center">

<img src=".github/assets/nymwrt.svg" alt="NymVPN for OpenWrt" width="400">

# NymVPN for OpenWrt

**Privacy-preserving VPN for OpenWrt routers**

Routes all LAN traffic through the [Nym mixnet](https://nymtech.net/) with WireGuard tunneling, Amnezia obfuscation, and a LuCI web interface.

[![GitHub Release](https://img.shields.io/github/v/release/dial0ut/nym-vpn-openwrt?style=flat-square&color=blue)](https://github.com/dial0ut/nym-vpn-openwrt/releases)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-green.svg?style=flat-square)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-18.06%2B-00B5E2?style=flat-square&logo=openwrt&logoColor=white)](https://openwrt.org/)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/dial0ut/nym-vpn-openwrt/release-musl.yml?style=flat-square&label=build)](https://github.com/dial0ut/nym-vpn-openwrt/actions)

Built from the [nym-vpn-client](https://github.com/nymtech/nym-vpn-client) codebase, stripped to Linux-only, with a pure Rust userspace WireGuard backend and OpenWrt-native firewall integration.

</div>

---

## Features

- **Pure Rust WireGuard** — Userspace tunnel via [gotatun](https://github.com/mullvad/gotatun), no kernel module needed (only `kmod-tun`)
- **Amnezia obfuscation** — Full AmneziaWG protocol support at the UDP transport layer
- **Dual firewall backends** — iptables (fw3) for OpenWrt 18.06–21.02, nftables (fw4) for 22.03+
- **LuCI web interface** — Dark-themed dashboard with connection status, gateway selection, and account management
- **Static MUSL binaries** — Single-binary deployment, no runtime dependencies beyond libc
- **15 architecture variants** — Pre-built IPK packages for every major OpenWrt target

## Quick Start

### Install from IPK

Pre-built `.ipk` packages are available on the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page.

```sh
# Download the IPK for your architecture (example: aarch64_generic)
wget https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/nym-vpn_aarch64_generic.ipk

# Install
opkg install nym-vpn_aarch64_generic.ipk
```

> **Dependencies:** `libc`, `kmod-tun`, `luci-base`, `rpcd`

### Build from Source

```sh
# Clone
git clone https://github.com/dial0ut/nym-vpn-openwrt.git
cd nym-vpn-openwrt

# Build for a target architecture (aarch64, armv7, x86_64, i686)
./scripts/build-musl.sh aarch64

# Package as IPK
./scripts/ipk/build-ipk.sh aarch64
```

This runs a Docker container with `messense/rust-musl-cross`, cross-compiles `nym-vpnd` and `nym-vpnc` as fully static MUSL binaries, and builds `libmnl` + `libnftnl` from source for nftables support.

Output binaries land in `nym-vpn-core/target/<triple>/release/`.

## Package Contents

| Path | Description |
|------|-------------|
| `/usr/sbin/nym-vpnd` | VPN daemon |
| `/usr/bin/nym-vpnc` | CLI client |
| `/www/luci-static/resources/view/nym-vpn/` | LuCI frontend |
| `/usr/libexec/rpcd/nym-vpn` | RPC backend (21 methods) |
| `/etc/init.d/nym-vpnd` | procd init script |
| `/etc/config/nym-vpn` | UCI configuration |

## Service Management

```sh
# Start/stop/restart the daemon
/etc/init.d/nym-vpnd start
/etc/init.d/nym-vpnd stop
/etc/init.d/nym-vpnd restart

# Enable/disable on boot
/etc/init.d/nym-vpnd enable
/etc/init.d/nym-vpnd disable
```

## Supported Architectures

| Tier | Architectures | Status |
|------|--------------|--------|
| **Tier 2** | x86_64, aarch64, armv7, i686 | Active — CI builds on every release |
| **Tier 3** | mips, mipsel, riscv64, armv5te | Infrastructure preserved, not actively built |

Tier 2 targets use pre-built `messense/rust-musl-cross` Docker images. Tier 3 targets require custom Docker images with nightly Rust and `-Z build-std`.

## Project Structure

```
nym-vpn-openwrt/
├── nym-vpn-core/              # Rust workspace — VPN daemon, CLI, firewall, WireGuard
├── luci-app-nym-vpn/          # LuCI web frontend
├── scripts/                   # Build, packaging, and install scripts
├── docker/                    # Cross-compilation Docker images (Tier 3)
└── .github/workflows/         # CI — release builds + firmware images
```

## License

[GPLv3](LICENSE)
