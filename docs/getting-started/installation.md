# Installation

## Method 1: One-Line Installer

The fastest way to install on a running OpenWrt device:

```bash
curl -sL https://github.com/dial0ut/nym-vpn-openwrt/releases/latest/download/install.sh | sh
```

The installer automatically:

- Detects your CPU architecture
- Downloads the correct binaries
- Creates `/dev/net/tun` if missing
- Installs and enables the `nym-vpnd` service
- Restarts `rpcd` for LuCI integration

## Method 2: IPK Package

Download the `.ipk` for your architecture from [GitHub Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases).

### Find Your Architecture

```bash
opkg print-architecture | grep -v all | tail -1 | awk '{print $2}'
```

Common mappings:

| Router | Architecture |
|--------|-------------|
| x86_64 VMs, Proxmox | `x86_64` |
| NanoPi R4S/R5S | `aarch64_generic` |
| GL.iNet MT6000 | `aarch64_cortex-a53` |
| Banana Pi R3 | `aarch64_cortex-a53` |
| Linksys MX4200v2 | `arm_cortex-a7_neon-vfpv4` |
| GL.iNet B1300 | `arm_cortex-a7_neon-vfpv4` |
| ASUS RT-AC58U | `arm_cortex-a7_neon-vfpv4` |
| GL.iNet GL-AR750S | `mips_24kc` |

### Install

```bash
# Transfer to router
scp nym-vpn_*.ipk root@192.168.1.1:/tmp/

# Install on router
opkg install /tmp/nym-vpn_*.ipk
```

## Post-Install

### Verify Installation

```bash
# Check daemon is running
/etc/init.d/nym-vpnd status

# Check CLI is available
nym-vpnc status
```

### Access LuCI Interface

Navigate to your router's web interface (typically `http://192.168.1.1`) and look for **NymVPN** in the navigation menu.

### Set Up Your Account

You need a Nym account credential to connect. See [Quick Start](quickstart.md) for account setup.

## Dependencies

The IPK package declares these dependencies:

| Package | Purpose |
|---------|---------|
| `libc` | Standard C library |
| `kmod-tun` | TUN device kernel module |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC daemon for LuCI backend |

These are installed automatically when using `opkg install`.

## Uninstall

```bash
opkg remove nym-vpn
```

Or manually:

```bash
/etc/init.d/nym-vpnd stop
/etc/init.d/nym-vpnd disable
rm -f /usr/sbin/nym-vpnd /usr/bin/nym-vpnc
rm -rf /www/luci-static/resources/view/nym-vpn
rm -rf /www/luci-static/resources/nym-vpn
rm -f /usr/libexec/rpcd/nym-vpn
rm -f /etc/init.d/nym-vpnd
rm -f /usr/share/luci/menu.d/luci-app-nym-vpn.json
rm -f /usr/share/rpcd/acl.d/luci-app-nym-vpn.json
/etc/init.d/rpcd restart
```
