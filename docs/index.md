# NymVPN for OpenWrt

**Privacy-first VPN for OpenWrt routers, powered by the Nym mixnet.**

NymVPN routes your entire network's traffic through the [Nym mixnet](https://nymtech.net/), providing network-level privacy for every device connected to your router — no per-device app required.

## Key Features

- **Router-level privacy** — all connected devices are protected automatically
- **Mixnet routing** — traffic is mixed through multiple hops, preventing traffic analysis
- **Pure Rust WireGuard** — userspace WireGuard via [gotatun](https://github.com/mullvad/gotatun), no kernel modules needed
- **AmneziaWG obfuscation** — defeats deep packet inspection that blocks standard WireGuard
- **LuCI web interface** — manage connections, gateways, and settings from your browser
- **OpenWrt fw3/fw4 support** — firewall integration for both iptables and nftables
- **Wide device support** — runs on x86_64, ARM, and MIPS routers

## Quick Install

```bash
curl -sL https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/install.sh | sh
```

Or download the `.ipk` package for your architecture from the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page and install with:

```bash
opkg install nym-vpn_*.ipk
```

## Requirements

| Requirement | Minimum |
|-------------|---------|
| OpenWrt | 18.06+ |
| RAM | 128 MB (256 MB recommended) |
| Storage | 70 MB free |
| Kernel module | `kmod-tun` |

## How It Works

```
┌─────────┐     ┌──────────┐     ┌───────────┐     ┌──────────┐     ┌──────────┐
│ LAN     │────▶│ OpenWrt  │────▶│ Entry     │────▶│ Exit     │────▶│ Internet │
│ Clients │     │ + NymVPN │     │ Gateway   │     │ Gateway  │     │          │
└─────────┘     └──────────┘     └───────────┘     └──────────┘     └──────────┘
                   nym-vpnd        WireGuard         WireGuard
                   nym-vpnc        Tunnel 1          Tunnel 2
```

Traffic from LAN clients is captured by the router's firewall, routed into the first WireGuard tunnel to an entry gateway, mixed through the Nym mixnet, and exits through a second WireGuard tunnel at the exit gateway.

## Next Steps

- [Installation Guide](getting-started/installation.md) — detailed setup instructions
- [Quick Start](getting-started/quickstart.md) — connect in under 5 minutes
- [LuCI Interface](guide/luci.md) — manage NymVPN from your browser
- [Supported Devices](devices.md) — check if your router is compatible
