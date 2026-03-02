# NymVPN for OpenWrt

Privacy-preserving VPN for OpenWrt routers. Routes all LAN traffic through the [Nym mixnet](https://nymtech.net/) with WireGuard tunneling, Amnezia obfuscation, and a LuCI web interface.

Built from the [nym-vpn-client](https://github.com/nymtech/nym-vpn-client) codebase, stripped to Linux-only, with a pure Rust userspace WireGuard backend and OpenWrt-native firewall integration.


## IPK Package

Pre-built `.ipk` packages are available on the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page for 15 OpenWrt architecture variants.

```sh
# Download the IPK for your architecture (example: aarch64_generic)
wget https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/nym-vpn_aarch64_generic.ipk

# Install
opkg install nym-vpn_aarch64_generic.ipk
```

Dependencies: `libc`, `kmod-tun`, `luci-base`, `rpcd`.


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

## License

[GPLv3](LICENSE)
