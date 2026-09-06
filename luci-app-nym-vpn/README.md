# luci-app-nym-vpn

LuCI web interface for NymVPN on OpenWrt. Wraps the `nym-vpnc` CLI to control the `nym-vpnd` daemon via rpcd/ubus.

## Features

- Connect/disconnect with real-time status polling and animated indicators
- Account management (mnemonic login, key rotation)
- Gateway selection by country or specific node with performance indicators
- Tunnel configuration (2-hop WireGuard / 5-hop mixnet, IPv6)
- LAN access control policy
- Daemon monitoring and restart

## Requirements

- OpenWrt 21.02 or later
- `luci-base`
- `rpcd`
- `nym-vpnd` and `nym-vpnc` binaries installed

## Installation

The recommended method is via the `.ipk` package from the [Releases](https://github.com/dial0ut/nym-vpn-openwrt/releases) page, which bundles both the Rust binaries and LuCI frontend.

For development, files can be copied manually:

```bash
# Copy from the luci-app-nym-vpn directory
scp -r root/* root@router:/
scp -r htdocs/luci-static/resources/nym-vpn/* root@router:/www/luci-static/resources/nym-vpn/
scp -r htdocs/luci-static/resources/view/nym-vpn/* root@router:/www/luci-static/resources/view/nym-vpn/

# Set permissions and restart services
ssh root@router 'chmod +x /usr/libexec/rpcd/nym-vpn /etc/init.d/nym-vpnd && /etc/init.d/rpcd restart'
```

Access at: `http://<router-ip>/cgi-bin/luci/admin/vpn/nym-vpn`

## Architecture

```
LuCI frontend (config.js)
    ↓ ubus / JSON-RPC
rpcd backend (/usr/libexec/rpcd/nym-vpn)
    ↓ shell (nym-vpnc CLI)
nym-vpnc ──gRPC──▶ nym-vpnd
```

## File Layout

| File | Description |
|------|-------------|
| `htdocs/.../view/nym-vpn/config.js` | Main view — status ring, gateway selection, settings cards |
| `htdocs/.../nym-vpn/rpc.js` | LuCI RPC client wrapper (21 methods) |
| `htdocs/.../nym-vpn/theme.js` | CSS-in-JS dark theme and animations |
| `htdocs/.../nym-vpn/ui.js` | Uptime formatting, modals, toasts, localStorage helpers |
| `htdocs/.../nym-vpn/countries.js` | ISO-2 → flag emoji + country name mappings |
| `htdocs/.../nym-vpn/assets.js` | SVG logos |
| `root/usr/libexec/rpcd/nym-vpn` | rpcd backend — 21 RPC methods, input validation |
| `root/etc/init.d/nym-vpnd` | procd service (respawn, graceful disconnect on stop) |
| `root/etc/uci-defaults/luci-app-nym-vpn` | First-boot setup (enable service, register the firewall include) |
| `root/usr/share/luci/menu.d/luci-app-nym-vpn.json` | LuCI menu entry (VPN → Nym VPN) |
| `root/usr/share/rpcd/acl.d/luci-app-nym-vpn.json` | ubus ACL (11 read + 10 write methods) |

## Development

```bash
# Disable LuCI caching on the router
uci set luci.ccache.enable=0 && uci commit luci

# After editing files, clear cache and restart rpcd
rm -rf /tmp/luci-modulecache/* /tmp/luci-indexcache*
/etc/init.d/rpcd restart
```
