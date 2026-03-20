# Installation

## Method 1: One-Line Installer

The fastest way to install on a running OpenWrt device:

```bash
curl -fsSL https://packages.dial0ut.org/install.sh | sh
```

The installer detects your package manager (`opkg` or `apk`), queries it for your CPU architecture, downloads the matching package from the latest GitHub release, and installs it.

## Method 2: Manual Package Install

### Find Your Architecture

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    opkg print-architecture
    ```

    The highest-priority line (largest number in the third column) is your architecture. For example:

    ```
    arch all 1
    arch noarch 1
    arch aarch64_cortex-a53 10
    ```

    Here the architecture is `aarch64_cortex-a53`.

=== "apk (OpenWrt 25.x+)"

    ```bash
    apk --print-arch
    ```

    This prints your architecture directly, e.g. `aarch64`.

### Download and Install

Download the `.ipk` or `.apk` for your architecture from [GitHub Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases), then install:

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    # Transfer to router
    scp nym-vpn_*.ipk root@192.168.1.1:/tmp/

    # Install on router
    opkg install /tmp/nym-vpn_*.ipk
    ```

=== "apk (OpenWrt 25.x+)"

    ```bash
    # Transfer to router
    scp nym-vpn_*.apk root@192.168.1.1:/tmp/

    # Install on router
    apk add --allow-untrusted /tmp/nym-vpn_*.apk
    ```

!!! note "Architecture not available?"
    If there is no package for your architecture, [open an issue on GitHub](https://github.com/dial0ut/nym-vpn-openwrt/issues) or post in the [forum thread](https://forum.nym.com/t/open-call-bring-nymvpn-to-openwrt/1945) with the architecture you need added.

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

The package declares these dependencies (installed automatically):

| Package | Purpose |
|---------|---------|
| `libc` | Standard C library |
| `kmod-tun` | TUN device kernel module |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC daemon for LuCI backend |

## Uninstall

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    opkg remove nym-vpn
    ```

=== "apk (OpenWrt 25.x+)"

    ```bash
    apk del nym-vpn
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
