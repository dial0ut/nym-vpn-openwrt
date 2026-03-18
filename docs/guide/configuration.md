# Configuration

NymVPN uses UCI (Unified Configuration Interface) for persistent configuration on OpenWrt.

## Config File

The main configuration file is `/etc/config/nym-vpn`. This file is marked as a `conffile`, meaning it survives firmware upgrades via `sysupgrade`.

## Viewing Configuration

```bash
uci show nym-vpn
```

## Key Settings

Settings are managed through `nym-vpnc` commands or the LuCI interface, which update the UCI config automatically. Direct UCI editing is possible but not recommended for most users.

## Policy-Based Routing (PBR)

NymVPN can be used with `luci-app-pbr` or other policy-based routing tools to selectively route traffic through the VPN tunnel.

### Setup

1. Disable the kill-switch:
   ```bash
   nym-vpnc tunnel set --killswitch off
   ```
   Or toggle it off in LuCI under **Tunnel Settings > Kill-Switch**.

2. Reconnect the VPN. The tunnel interface will be active but no default route or firewall rules are installed.

3. Install and configure PBR to route specific traffic through the tunnel interface (typically `tun0` or `tun1`).

### What the kill-switch controls

| Setting | Kill-switch on (default) | Kill-switch off |
|---------|------------------------|-----------------|
| Firewall rules | Applied — blocks leaks | Skipped |
| Default route (0.0.0.0/0) | Installed in table 333 | Skipped |
| Tunnel interface | Active | Active |
| VPN connection | Active | Active |

### Important notes

- The tunnel interface names are kernel-assigned (`tun0`, `tun1`). Check `nym-vpnc status` after connecting to see the current names.
- With the kill-switch off, traffic **will leak** outside the VPN unless PBR rules are configured.
- Changing the kill-switch setting requires a reconnect.

## Logs

### Daemon Logs

```bash
# View daemon log output
logread -e nym-vpnd

# Follow logs in real time
logread -e nym-vpnd -f
```

### System Log

```bash
# Full system log (includes firewall, networking)
logread | tail -100
```

## Service Management

The `nym-vpnd` service is managed by procd with automatic respawn:

- **Respawn window:** 3600 seconds
- **Respawn timeout:** 5 seconds
- **Max respawns:** 5

```bash
# Enable auto-start on boot
/etc/init.d/nym-vpnd enable

# Disable auto-start
/etc/init.d/nym-vpnd disable
```

On service stop, the init script automatically calls `nym-vpnc disconnect` to clean up firewall rules and tunnels.
