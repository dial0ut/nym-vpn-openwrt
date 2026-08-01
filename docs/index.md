# NymVPN for OpenWrt

Run the Nym mixnet on your router, so every device on the LAN is behind it.

## Install

```bash
curl -fsSL https://packages.dial0ut.org/install.sh | sh
```

Or download the `.ipk` (`.apk` on OpenWrt 25.x+) for your architecture from the
[latest release](https://github.com/dial0ut/nym-vpn-openwrt/releases) and install it by hand.

!!! note "No package for your architecture?"
    Ask for it in a [GitHub issue](https://github.com/dial0ut/nym-vpn-openwrt/issues) or the
    [forum thread](https://forum.nym.com/t/open-call-bring-nymvpn-to-openwrt/1945).

## Requirements

| | Minimum |
|--|---------|
| OpenWrt | 18.06+ |
| RAM | 128 MB (256 MB comfortable) |
| Storage | 40 MB free |
| Kernel module | `kmod-tun` |

Builds exist for x86_64, ARM, MIPS and RISC-V. Full list under [Supported Devices](devices.md).

## Next

- [Installation](getting-started/installation.md) — manual install, uninstall, dependencies
- [Quick Start](getting-started/quickstart.md) — account to connected tunnel
- [LuCI Interface](guide/luci.md) — what every card in the web UI does
- [Supported Devices](devices.md) — is your router on the list
