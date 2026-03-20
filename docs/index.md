# NymVPN for OpenWrt

**Protect every device on your network — no apps required.**

Install NymVPN on your OpenWrt router and every device that connects — phones, laptops, smart TVs, everything — gets [mixnet](https://nymtech.net/) privacy automatically. No per-device setup, no apps to manage.

Unlike a traditional VPN, the Nym mixnet routes traffic through multiple hops so that no single point in the network can see both who you are and what you're accessing.

## Quick install

```bash
curl -sL https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/install.sh | sh
```

Or grab the `.ipk` (or `.apk` for OpenWrt 24.10+) for your architecture from the [latest release](https://github.com/dial0ut/nym-vpn-openwrt/releases) and install manually.

## Requirements

| | Minimum |
|--|---------|
| OpenWrt | 18.06+ |
| RAM | 128 MB (256 MB recommended) |
| Storage | 70 MB free |
| Kernel module | `kmod-tun` |

Runs on x86_64, ARM, and MIPS routers. See [Supported Devices](devices.md) for a full list.

## Next steps

- [Installation Guide](getting-started/installation.md) — detailed setup instructions
- [Quick Start](getting-started/quickstart.md) — connect in under 5 minutes
- [LuCI Interface](guide/luci.md) — manage NymVPN from your browser
- [Supported Devices](devices.md) — check if your router is compatible
