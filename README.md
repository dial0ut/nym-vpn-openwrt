# NymVPN for OpenWrt

Privacy-preserving VPN for OpenWrt routers. Routes all LAN traffic through the [Nym mixnet](https://nymtech.net/) with WireGuard tunneling, Amnezia obfuscation, and a LuCI web interface.

Built from the [nym-vpn-client](https://github.com/nymtech/nym-vpn-client) codebase, stripped to Linux-only, with a pure Rust userspace WireGuard backend and OpenWrt-native firewall integration.

## Quick Install

```sh
curl -fsSL https://sh.dialout.net | sh
```

Auto-detects architecture (x86_64, aarch64, armv7, i686) and init system (procd/systemd). Downloads the latest release, installs binaries, and starts the service.

Environment variables:
- `NYM_VERSION` — pin a specific version (default: latest)
- `NYM_ARCH` — override architecture detection
- `NYM_NO_START` — set to `1` to skip starting the service

After installation, access the web interface at `http://<router-ip>/cgi-bin/luci/admin/vpn/nym-vpn`.

## IPK Package

Pre-built `.ipk` packages are available on the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page for 15 OpenWrt architecture variants.

```sh
# Download the IPK for your architecture (example: aarch64_generic)
wget https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/nym-vpn_aarch64_generic.ipk

# Install
opkg install nym-vpn_aarch64_generic.ipk
```

Dependencies: `libc`, `kmod-tun`, `luci-base`, `rpcd`.

## Pre-built Firmware Images

Full OpenWrt firmware images with NymVPN pre-installed are available for select devices. Trigger a build via the `build-openwrt-images.yml` workflow.

Supported devices include: FriendlyARM NanoPi R4S/R5S, GL.iNet MT6000/B1300/AR750S/MT1300, Banana Pi R3, Linksys MX4200v2/WRT1900ACS, ASUS RT-AC58U/RT-AC68U, Turris Omnia, Netgear R7000, and x86_64 generic.

## Building from Source

### Prerequisites

- Docker
- Git

### Build binaries

```sh
# Clone
git clone https://github.com/dial0ut/nym-vpn-openwrt.git
cd nym-vpn-openwrt

# Build for a target architecture (aarch64, armv7, x86_64, i686)
./scripts/build-musl.sh aarch64
```

This runs a Docker container with `messense/rust-musl-cross`, cross-compiles `nym-vpnd` and `nym-vpnc` as fully static MUSL binaries, and builds `libmnl` + `libnftnl` from source for nftables support.

Output binaries land in `nym-vpn-core/target/<triple>/release/`.

### Build IPK package

```sh
# After building binaries:
./scripts/ipk/build-ipk.sh aarch64
```

### Package contents

| Path | Description |
|------|-------------|
| `/usr/sbin/nym-vpnd` | VPN daemon |
| `/usr/bin/nym-vpnc` | CLI client |
| `/www/luci-static/resources/view/nym-vpn/` | LuCI frontend |
| `/usr/libexec/rpcd/nym-vpn` | RPC backend (21 methods) |
| `/etc/init.d/nym-vpnd` | procd init script |
| `/etc/config/nym-vpn` | UCI configuration |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  LuCI Web UI                     │
│              (JavaScript frontend)               │
└──────────────┬───────────────────────────────────┘
               │ ubus / JSON-RPC
┌──────────────▼───────────────────────────────────┐
│             rpcd backend (shell)                 │
│         /usr/libexec/rpcd/nym-vpn                │
└──────────────┬───────────────────────────────────┘
               │ CLI
┌──────────────▼───────────────────────────────────┐
│  nym-vpnc (CLI client) ──gRPC──▶ nym-vpnd        │
│                                  (VPN daemon)    │
└──────────────────────────┬───────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌────────────┐  ┌─────────────┐  ┌────────────┐
   │  gotatun   │  │ nym-firewall│  │  Nym mixnet │
   │ (WireGuard)│  │ (fw3/fw4)   │  │  (5-hop)    │
   └────────────┘  └─────────────┘  └────────────┘
```

## Key Components

### Userspace WireGuard (gotatun)

Pure Rust WireGuard implementation via [mullvad/gotatun](https://github.com/mullvad/gotatun). No kernel module required — only `kmod-tun` for the TUN device.

- Replaces both `wireguard-go` (Go FFI issues with MUSL) and `kmod-wireguard` (kernel module dependency)
- Single Rust toolchain — no Go required for cross-compilation
- Built-in [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscation at the UDP transport layer (header remapping + junk packet injection)

### OpenWrt Firewall Integration

Native support for both OpenWrt firewall frameworks:

| Framework | OpenWrt Version | Backend |
|-----------|----------------|---------|
| fw3 | 18.06 – 21.02 | iptables (`iptables-restore`) |
| fw4 | 22.03+ | nftables (`nft -f`) |

Auto-detected at runtime. Implements kill-switch rules, DNS leak protection, LAN bypass, and NAT masquerade.

### LuCI Web Interface

Full-featured management UI with:

- Real-time connection status with animated indicators
- Gateway selection by country with performance metrics
- Account management and key rotation
- Tunnel configuration (2-hop / 5-hop modes, IPv6)
- LAN access control policy
- Daemon monitoring and control

## Usage

### CLI

```sh
# Store account mnemonic
nym-vpnc account store-mnemonic

# Connect (5-hop mixnet mode)
nym-vpnc connect

# Connect (2-hop WireGuard mode)
nym-vpnc connect --mode wireguard

# Select entry/exit gateways by country
nym-vpnc connect --entry-country CH --exit-country DE

# Check status
nym-vpnc status

# Disconnect
nym-vpnc disconnect
```

### Service management

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
| Tier 2 | x86_64, aarch64, armv7, i686 | Active — CI builds on every release |
| Tier 3 | mips, mipsel, riscv64, armv5te | Infrastructure preserved, not actively built |

Tier 2 targets use pre-built `messense/rust-musl-cross` Docker images. Tier 3 targets require custom Docker images with nightly Rust and `-Z build-std`.

## Repository Structure

```
nym-vpn-openwrt/
├── nym-vpn-core/              # Rust workspace (26 crates, Linux-only)
│   └── crates/
│       ├── nym-vpnd/          # VPN daemon
│       ├── nym-vpnc/          # CLI client
│       ├── nym-vpn-lib/       # Core library
│       ├── nym-wg-gotatun/    # Userspace WireGuard + AmneziaWG
│       ├── nym-firewall/      # fw3/fw4 backends
│       └── ...
├── luci-app-nym-vpn/          # LuCI web interface
├── scripts/
│   ├── build-musl.sh          # Build dispatcher
│   ├── cross-compile-musl.sh  # Cross-compilation (runs in Docker)
│   ├── install.sh             # curl-to-sh installer
│   └── ipk/                   # IPK packaging
├── docker/tier3-musl/         # Tier 3 cross-compilation
└── .github/workflows/         # CI/CD pipelines
```

## Upstream Sync

This repository tracks [nymtech/nym-vpn-client](https://github.com/nymtech/nym-vpn-client) with the following customizations:

- `nym-wg-gotatun/` — userspace WireGuard backend (not upstream)
- `nym-firewall/src/openwrt/` — fw3/fw4 firewall backends (not upstream)
- `luci-app-nym-vpn/` — LuCI web interface (not upstream)
- All non-Linux platform code removed (macOS, Windows, iOS, Android)
- `wireguard-go` replaced by `gotatun` (no Go dependency)

## License

[GPLv3](LICENSE)
