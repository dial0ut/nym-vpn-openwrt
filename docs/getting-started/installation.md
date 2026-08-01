# Installation

## One-line installer

```bash
curl -fsSL https://packages.dial0ut.org/install.sh | sh
```

It detects your package manager (`opkg` or `apk`), asks it for the CPU architecture, pulls the
matching package from the latest GitHub release, and installs it.

## Manual install

### Find your architecture

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    opkg print-architecture
    ```

    Take the line with the highest priority — the largest number in the third column:

    ```
    arch all 1
    arch noarch 1
    arch aarch64_cortex-a53 10
    ```

    Here it is `aarch64_cortex-a53`.

=== "apk (OpenWrt 25.x+)"

    ```bash
    apk --print-arch
    ```

    Prints the architecture directly, e.g. `aarch64`.

### Download and install

Grab the matching package from [GitHub Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases):

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    scp nym-vpn_*.ipk root@192.168.1.1:/tmp/
    opkg install /tmp/nym-vpn_*.ipk
    ```

=== "apk (OpenWrt 25.x+)"

    ```bash
    scp nym-vpn_*.apk root@192.168.1.1:/tmp/
    apk add --allow-untrusted /tmp/nym-vpn_*.apk
    ```

## After installing

Check the daemon came up and the CLI can reach it:

```bash
/etc/init.d/nym-vpnd status
nym-vpnc status
```

**NymVPN** appears in the LuCI navigation menu at your router's web interface (usually
`http://192.168.1.1`). If the page loads but every action fails with *"No related RPC reply"*,
see [Troubleshooting](../troubleshooting.md#no-related-rpc-reply-on-glinet-devices) — GL.iNet
routers need port 8080.

You need a Nym account before you can connect. [Quick Start](quickstart.md) covers that.

## Dependencies

Pulled in automatically:

| Package | Why |
|---------|-----|
| `libc` | musl libc |
| `kmod-tun` | TUN device — userspace WireGuard needs it |
| `libmnl` | netlink |
| `libnftnl` | nftables netlink |
| `kmod-ipt-conntrack-extra` | conntrack marking for inbound exemptions on fw3 |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC backend the LuCI app talks to |

## Uninstall

=== "opkg (OpenWrt ≤24.10)"

    ```bash
    opkg remove nym-vpn
    ```

=== "apk (OpenWrt 25.x+)"

    ```bash
    apk del nym-vpn
    ```

If the package database is broken and you have to do it by hand:

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

Stop the daemon first. The init script tears down the kill-switch firewall table on stop; delete
the binary out from under a running daemon and you can be left with no internet.
