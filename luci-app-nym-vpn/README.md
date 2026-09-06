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
LuCI frontend (view/nym-vpn/config.js + nym-vpn/ module tree)
    ↓ ubus / JSON-RPC
rpcd bridge (nym-vpnc rpcd, registered as /usr/libexec/rpcd/nym-vpn)
    ↓ gRPC
nym-vpnd
```

## Frontend structure

The page is composed from LuCI-native modules under
`htdocs/luci-static/resources/nym-vpn/`. Each file is a LuCI class
(`'require ...'` header, `return baseclass.extend({...})`) that LuCI's loader
resolves by dotted name, so `'require nym-vpn.cards.dns as dnsCard'` loads
`nym-vpn/cards/dns.js`. No bundler, no build step.

| Module | Role |
|--------|------|
| `view/nym-vpn/config.js` | The page: `load()` fetches the init batch, `render()` seeds the store and appends the cards in order |
| `nym-vpn/rpc.js` | Low-level `rpc.declare` wrappers, one per ubus method |
| `nym-vpn/api.js` | Everything the page asks the bridge, plus normalisation of the replies (`'on'/'off'` vs booleans, `entry_family` vs `entry.family`, the bounded `tentative_gateways` check, gateway list caching) |
| `nym-vpn/store.js` | Page state (init data, live status, daemon state, the settings other cards consult), the 5 s status / 10 s daemon polls, and an `on(event, fn)` bus (`status`, `daemon`, `account-recheck`) |
| `nym-vpn/components/` | `card` (expandable shell), `toggle` (switch row + save-or-revert), `select`, `modal`, `toast`, `gateway-picker` (country dropdown, server list, saved-selection restore) |
| `nym-vpn/flows/` | `connect` (selection guard → `gateway_set` → `tentative_gateways` → warn/relax → connect, plus disconnect/cancel and tunnel-error handling), `daemon` (start/stop/restart with the disconnect confirmation) |
| `nym-vpn/cards/` | One module per card, each `render(store, api)` → element: `connection`, `tunnel-settings` (hosts `inbound-services` and `split-tunneling`), `mixnet-tuning`, `dns`, `account`, `service`, `diagnostics`, `logs` |
| `nym-vpn/theme.js`, `ui.js`, `countries.js`, `assets.js` | CSS-in-JS theme, small formatting/clipboard helpers, country names and flags, inline SVG |

Cards never reach into each other's DOM: shared state goes through the store,
shared behaviour through components and flows. `modal` and `toast` are module
singletons (LuCI instantiates every module once), so any card can `require`
them directly.

### Hot-deploying to a router

Copy the module tree and the view, then make LuCI forget its caches:

```bash
cd luci-app-nym-vpn/htdocs/luci-static/resources
scp -r nym-vpn/. root@router:/www/luci-static/resources/nym-vpn/
scp view/nym-vpn/config.js root@router:/www/luci-static/resources/view/nym-vpn/
ssh root@router 'rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/*'
```

Then hard-refresh the page (Ctrl/Cmd+Shift+R) — LuCI caches module sources
in the browser under the resource version, so a plain reload may keep the old
file. A single edited module can be copied on its own to the matching path
(`nym-vpn/cards/dns.js` → `/www/luci-static/resources/nym-vpn/cards/dns.js`).

### Tests

`tests/` holds a jsdom harness that loads the real modules through a small
emulation of LuCI's loader and drives the page with a scripted rpc:

```bash
cd luci-app-nym-vpn/tests
npm install
npm test          # parse-check every module, then the behavioural checks
```

## File Layout

| File | Description |
|------|-------------|
| `htdocs/.../view/nym-vpn/config.js` | The page composer (see Frontend structure) |
| `htdocs/.../nym-vpn/` | Module tree: api, store, components/, flows/, cards/, theme, ui, countries, assets |
| `root/usr/libexec/rpcd/nym-vpn` | rpcd bridge registration (`nym-vpnc rpcd`) |
| `root/etc/init.d/nym-vpnd` | procd service (respawn, graceful disconnect on stop) |
| `root/etc/uci-defaults/luci-app-nym-vpn` | First-boot setup (enable service, register the firewall include) |
| `root/usr/share/luci/menu.d/luci-app-nym-vpn.json` | LuCI menu entry (VPN → Nym VPN) |
| `root/usr/share/rpcd/acl.d/luci-app-nym-vpn.json` | ubus ACL (read and write method lists) |
| `tests/` | jsdom behavioural harness (dev only, not packaged) |

## Development

```bash
# Disable LuCI caching on the router
uci set luci.ccache.enable=0 && uci commit luci

# After editing files, clear cache and restart rpcd
rm -rf /tmp/luci-modulecache/* /tmp/luci-indexcache*
/etc/init.d/rpcd restart
```
