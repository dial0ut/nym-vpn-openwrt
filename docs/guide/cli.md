# CLI Usage

`nym-vpnc` is the command-line client that communicates with the `nym-vpnd` daemon via gRPC.

## Connection

```bash
# Connect with default settings
nym-vpnc connect-v2

# Disconnect
nym-vpnc disconnect

# Check connection status
nym-vpnc status
```

## Gateway Management

```bash
# View current gateway selection
nym-vpnc gateway get

# List gateways by type (mixnet-entry, mixnet-exit, wg)
nym-vpnc gateway list mixnet-exit

# Set entry/exit gateways by country
nym-vpnc gateway set --entry-country DE --exit-country CH

# Set a specific gateway by ID
nym-vpnc gateway set --exit-id <base58-gateway-id>

# Auto-select with random gateways
nym-vpnc gateway set --entry-random --exit-random
```

## Account

```bash
# Import account recovery phrase
nym-vpnc account set "your twenty four word mnemonic phrase here"

# View account info
nym-vpnc account get

# Remove stored credentials
nym-vpnc account forget

# Rotate WireGuard keys
nym-vpnc account rotate-keys
```

## Tunnel Settings

```bash
# View tunnel configuration
nym-vpnc tunnel get

# Configure tunnel options
nym-vpnc tunnel set --ipv6 on --two-hop on

# Disable kill-switch (for PBR compatibility)
nym-vpnc tunnel set --killswitch off

# Re-enable kill-switch
nym-vpnc tunnel set --killswitch on
```

## Network Settings

```bash
# View current network (mainnet, canary)
nym-vpnc network get

# Set network
nym-vpnc network set mainnet
```

## LAN Policy

```bash
# View current LAN policy
nym-vpnc lan get

# Allow LAN device access while connected
nym-vpnc lan set allow

# Block LAN device access while connected
nym-vpnc lan set block
```

## DNS

```bash
# View DNS configuration
nym-vpnc dns get

# Set custom DNS servers
nym-vpnc dns set 1.1.1.1 9.9.9.9

# Enable/disable custom DNS
nym-vpnc dns enable
nym-vpnc dns disable

# Clear custom DNS servers
nym-vpnc dns clear
```

## Ad Blocking

```bash
# View ad-blocking status
nym-vpnc ad-block get

# Enable/disable ad-blocking
nym-vpnc ad-block set enabled
nym-vpnc ad-block set disabled
```

## Daemon Control

```bash
# Check daemon status
nym-vpnc info

# Via init script
/etc/init.d/nym-vpnd start
/etc/init.d/nym-vpnd stop
/etc/init.d/nym-vpnd restart
/etc/init.d/nym-vpnd status
```

The service is managed by procd with automatic respawn (up to 5 times within a 3600s window). On stop, the init script calls `nym-vpnc disconnect` to clean up firewall rules and tunnels.

```bash
# Enable/disable auto-start on boot
/etc/init.d/nym-vpnd enable
/etc/init.d/nym-vpnd disable
```

## Configuration

Settings are stored in `/etc/config/nym-vpn` (UCI format, preserved across firmware upgrades). Settings are managed through `nym-vpnc` or the LuCI interface — direct UCI editing is not recommended.

```bash
# View current config
uci show nym-vpn
```

## Logs

```bash
# View daemon logs
logread -e nym-vpnd

# Follow logs in real time
logread -e nym-vpnd -f
```
