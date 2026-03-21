<div align="center">

<img src=".github/assets/nymwrt.svg" alt="NymVPN for OpenWrt" width="400">

# NymVPN | OpenWrt

[![GitHub Release](https://img.shields.io/github/v/release/dial0ut/nym-vpn-openwrt?style=flat-square&color=blue)](https://github.com/dial0ut/nym-vpn-openwrt/releases)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-green.svg?style=flat-square)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-18.06%2B-00B5E2?style=flat-square&logo=openwrt&logoColor=white)](https://openwrt.org/)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)


**Privacy-preserving VPN for OpenWrt routers**

Built from the [nym-vpn-client](https://github.com/nymtech/nym-vpn-client) codebase with OpenWrt-native integrations.

[Documentation](https://docs.dial0ut.org)

</div>

---

## Install

```sh
curl -fsSL https://packages.dial0ut.org/install.sh | sh
```

Detects your package manager (`opkg` or `apk`) and architecture, downloads the latest release, and installs it.

Or grab the `.ipk` / `.apk` for your architecture from the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page.

## Build from Source

```sh
git clone https://github.com/dial0ut/nym-vpn-openwrt.git
cd nym-vpn-openwrt

# Build for a target architecture (aarch64, armv7, x86_64, i686)
./scripts/build-musl.sh aarch64
```

Cross-compiles `nym-vpnd` and `nym-vpnc` as fully static MUSL binaries inside Docker. Output lands in `nym-vpn-core/target/<triple>/release/`.

## Supported Architectures

| Tier | Architectures |
|------|--------------|
| **Tier 2** | x86_64, aarch64, armv7, i686 |
| **Tier 3** | mips, mipsel |

## License

[GPLv3](LICENSE)
