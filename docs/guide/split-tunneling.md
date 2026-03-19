# Split Tunneling with PBR

NymVPN supports split tunneling through OpenWrt's Policy-Based Routing (PBR) package. This lets you choose which traffic goes through the VPN and which goes direct.

**Common use cases:**

- Route only specific devices through the VPN
- Bypass the VPN for banking or streaming sites
- Route all traffic through VPN except local services

## Prerequisites

- NymVPN installed and working
- `luci-app-pbr` installed:

```bash
opkg update && opkg install luci-app-pbr
```

## Step 1: Disable the Kill-Switch

The kill-switch forces all traffic through the VPN. PBR needs to make its own routing decisions, so disable it:

```bash
nym-vpnc tunnel set --killswitch off
```

Or in LuCI: **NymVPN > Tunnel Settings > Kill-Switch** toggle off.

Reconnect the VPN after changing this setting.

!!! warning
    With the kill-switch off, traffic not routed through the VPN by PBR will go direct.

## Step 2: Create a VPN Interface

PBR needs a named network interface. NymVPN creates `nym0` (entry tunnel) and `nym1` (exit tunnel in 2-hop mode). For routing user traffic, use `nym1` in 2-hop mode or `nym0` in mixnet mode.

```bash
uci set network.nymvpn=interface
uci set network.nymvpn.proto='none'
uci set network.nymvpn.device='nym1'   # Use nym0 for mixnet mode
uci commit network
/etc/init.d/network restart
```

Or in LuCI: **Network > Interfaces > Add new interface** — name it `nymvpn`, protocol `Unmanaged`, device `nym1`.

## Step 3: Configure PBR Rules

Open **Services > Policy Routing** in LuCI, or use UCI commands.

### Route Specific Devices Through VPN

```bash
uci add pbr policy
uci set pbr.@policy[-1].name='Laptop via VPN'
uci set pbr.@policy[-1].src_addr='192.168.1.100'
uci set pbr.@policy[-1].interface='nymvpn'
uci commit pbr
/etc/init.d/pbr restart
```

### Route Everything Except Streaming Through VPN

```bash
# All traffic through VPN
uci add pbr policy
uci set pbr.@policy[-1].name='All via VPN'
uci set pbr.@policy[-1].src_addr='0.0.0.0/0'
uci set pbr.@policy[-1].interface='nymvpn'

# Exception: streaming goes direct
uci add pbr policy
uci set pbr.@policy[-1].name='Netflix direct'
uci set pbr.@policy[-1].dest_addr='netflix.com'
uci set pbr.@policy[-1].interface='wan'

uci commit pbr
/etc/init.d/pbr restart
```

### Route by Port

```bash
uci add pbr policy
uci set pbr.@policy[-1].name='Web via VPN'
uci set pbr.@policy[-1].dest_port='80 443'
uci set pbr.@policy[-1].interface='nymvpn'
uci commit pbr
/etc/init.d/pbr restart
```

## Troubleshooting

```bash
# Check PBR status
/etc/init.d/pbr status

# Verify the interface is up
ifstatus nymvpn

# Check routing tables
ip rule show
ip route show table all | grep nym
```
