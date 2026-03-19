# IPK Packaging

IPK is the package format used by OpenWrt's `opkg` package manager.

## Building an IPK

```bash
./scripts/ipk/build-ipk.sh
```

The script assembles an `.ipk` from compiled binaries and LuCI frontend assets.

## Package Contents

| Path | Source |
|------|--------|
| `/usr/sbin/nym-vpnd` | Compiled daemon binary |
| `/usr/bin/nym-vpnc` | Compiled CLI binary |
| `/www/luci-static/resources/view/nym-vpn/` | LuCI JS frontend |
| `/www/luci-static/resources/nym-vpn/` | LuCI JS modules |
| `/usr/libexec/rpcd/nym-vpn` | RPC backend script |
| `/etc/init.d/nym-vpnd` | procd init script |
| `/etc/config/nym-vpn` | Default UCI config |
| `/usr/share/luci/menu.d/luci-app-nym-vpn.json` | LuCI menu entry |
| `/usr/share/rpcd/acl.d/luci-app-nym-vpn.json` | RPC ACL definitions |

## Dependencies

Declared in `scripts/ipk/control.template`:

| Package | Purpose |
|---------|---------|
| `libc` | Standard C library |
| `kmod-tun` | TUN device kernel module |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC daemon |

## Install Scripts

### postinst

Runs after package installation:

- Creates `/dev/net/tun` if missing
- Enables the `nym-vpnd` service
- Restarts `rpcd` to load new RPC methods

### prerm

Runs before package removal:

- Stops `nym-vpnd`
- Cleans up firewall chains
- Removes UCI config

### conffiles

Marks `/etc/config/nym-vpn` as upgrade-safe — the file is preserved during `sysupgrade`.
