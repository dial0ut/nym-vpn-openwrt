# nym-vpn-luci

LuCI web interface for Nym VPN on OpenWRT.

## Description

This package provides a web interface for managing Nym VPN connections through the LuCI framework. It wraps the `nym-vpnc` CLI to control the `nym-vpnd` daemon.

## Features

- Connect/disconnect with real-time status updates
- Account management (login, logout, key rotation)
- Gateway selection by country or specific node
- Tunnel configuration (IPv6, 2-hop/5-hop modes)
- LAN access control

## Requirements

- OpenWRT 21.02 or later
- LuCI (luci-base)
- nym-vpnd daemon
- nym-vpnc CLI client

## Installation

### OpenWRT Build System

```bash
# Add to your feeds
cp -r luci-app-nym-vpn feeds/luci/applications/

# Update and install
./scripts/feeds update luci
./scripts/feeds install luci-app-nym-vpn

# Build
make package/luci-app-nym-vpn/compile
```

### Manual Installation

```bash
# Copy files to router
scp -r root/* root@router:/
scp -r htdocs/* root@router:/www/

# Set permissions
ssh root@router 'chmod +x /usr/libexec/rpcd/nym-vpn /etc/init.d/nym-vpnd'

# Restart services
ssh root@router '/etc/init.d/nym-vpnd enable && /etc/init.d/nym-vpnd start && /etc/init.d/rpcd restart'
```

Access at: `http://router-ip/cgi-bin/luci/admin/vpn/nym-vpn`

## Architecture

```
LuCI (JavaScript)
    ↓ ubus/JSON-RPC
rpcd backend (/usr/libexec/rpcd/nym-vpn)
    ↓ shell
nym-vpnc → nym-vpnd
```

## Development

```bash
# Disable LuCI caching
uci set luci.ccache.enable=0 && uci commit luci

# After changes
rm -rf /tmp/luci-modulecache/* /tmp/luci-indexcache*
/etc/init.d/rpcd restart
```

