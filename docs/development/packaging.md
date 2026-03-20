# Packaging

NymVPN is distributed as `.ipk` packages for OpenWrt ≤24.10 (`opkg`), and `.apk` packages for OpenWrt 25.x+ (`apk`). Both are built using a similar process.

## Building an IPK

```bash
./scripts/ipk/build-ipk.sh <version> <openwrt_arch> <binary_dir> <luci_dir> [output_dir]
```

For example:

```bash
./scripts/ipk/build-ipk.sh 1.23.0 aarch64_generic ./binaries ./luci-app-nym-vpn
```

The script validates all required files exist, assembles the package structure, calculates installed size, generates the control file from the template, and produces `nym-vpn_{version}_{arch}.ipk`.

## IPK Structure

```text
nym-vpn_1.23.0_aarch64_generic.ipk (tar.gz)
├── debian-binary          # Contains "2.0"
├── control.tar.gz
│   ├── control            # Package metadata (generated from template)
│   ├── conffiles          # Marks /etc/config/nym-vpn as upgrade-safe
│   ├── postinst           # Post-install hook
│   └── prerm              # Pre-removal hook
└── data.tar.gz
    ├── usr/sbin/nym-vpnd
    ├── usr/bin/nym-vpnc
    ├── usr/libexec/rpcd/nym-vpn
    ├── www/luci-static/resources/view/nym-vpn/*.js
    ├── www/luci-static/resources/nym-vpn/*.js
    ├── etc/init.d/nym-vpnd
    ├── etc/config/nym-vpn
    ├── usr/share/luci/menu.d/luci-app-nym-vpn.json
    ├── usr/share/rpcd/acl.d/luci-app-nym-vpn.json
    ├── usr/share/nym-vpn/fw3-include.sh
    ├── usr/share/nym-vpn/fw4-include.sh
    └── etc/opkg/keys/dial0ut.pub
```

## Dependencies

Declared in `scripts/ipk/control.template`:

| Package | Purpose |
|---------|---------|
| `libc` | Standard C library |
| `kmod-tun` | TUN device kernel module for userspace WireGuard |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC daemon for LuCI backend communication |

## Install Scripts

### postinst

Runs after package installation and performs four steps:

1. **TUN device creation** -- creates `/dev/net/tun` (major 10, minor 200) if it does not exist
2. **Package feed registration** -- detects the package manager and adds the `packages.dial0ut.org` feed:
    - OpenWrt 25.x+ (apk): writes to `/etc/apk/repositories.d/nym-vpn.list`
    - OpenWrt ≤24.10 (opkg): appends to `/etc/opkg/customfeeds.conf`
3. **Service enablement** -- enables `nym-vpnd` for boot, starts it immediately, restarts `rpcd` to load new RPC ACL definitions
4. **User notification** -- prints the appropriate upgrade command (`opkg upgrade` or `apk upgrade`)

### prerm

Runs before package removal:

1. **Service shutdown** -- stops `nym-vpnd` and disables boot autostart
2. **Firewall cleanup** -- removes all NymVPN firewall rules:
    - fw4: deletes `inet nym` table and removes embedded rules from fw4 chains
    - fw3: removes jump rules from hook chains, flushes and deletes `NYM_INPUT`, `NYM_OUTPUT`, `NYM_FORWARD` chains, removes NAT masquerade rules
3. **UCI cleanup** -- deletes `firewall.nym_vpn` include and `nym-vpn` config sections
4. **Data cleanup** -- removes `/var/lib/nym-vpn`

### conffiles

Marks `/etc/config/nym-vpn` as a configuration file. On package upgrade, modified versions are preserved and new defaults are written to a `.new` file, preventing accidental loss of user settings.

## Default Configuration

The default UCI config (`scripts/ipk/nym-vpn.conf`) installed to `/etc/config/nym-vpn`:

```text
config nym-vpn 'settings'
    option enabled '0'
    option network 'mainnet'
```

The service starts disabled by default. Users enable it through the LuCI interface or CLI.
