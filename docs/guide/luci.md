# LuCI Web Interface

The NymVPN LuCI app provides a browser-based interface for managing your VPN connection.

## Accessing the Interface

Navigate to your router's IP (typically `http://192.168.1.1`) and click **NymVPN** in the navigation menu.

## Status Overview

The main view shows:

- **Connection status ring** — animated indicator (green = connected, pulsing = connecting, gray = disconnected)
- **Connection uptime** — time since the tunnel was established
- **Mixnet hop chain** — visual representation of your traffic path through entry and exit gateways

## Cards

### Tunnel Settings

Configure tunnel behavior:

- **IPv6** — enable or disable IPv6 support (on/off)
- **Two-Hop Mode** — toggle between 2-hop (faster) and 5-hop mixnet routing (on/off)
- **Kill-Switch** — block all non-tunnel WAN egress (on/off). This is *only* a firewall block; traffic is routed through the tunnel whenever connected regardless of this setting. Turn it off to allow WAN fallback or [split-tunnel carve-outs](split-tunneling.md). Shows a warning when disabled. Requires reconnect to take effect.

### Inbound Services

Declare port-forwarded services that bypass the tunnel for reply traffic, so a router-hosted (LuCI, SSH) or LAN-hosted (Jellyfin, NAS) service stays reachable from the WAN while the kill-switch is on.

- Pick `TCP` or `UDP`, type the port, optionally a label, **Save** (or `Enter`).
- Rows show `● Active` when the kill-switch is on, `● Inert` when off (exemptions only matter while the kill-switch is enforcing — with it off there is no block to exempt).
- `×` removes an entry.

For LAN-hosted services, set up the OpenWrt port forward in **Network → Firewall → Port Forwards** first, then add the exemption here using the **WAN-side** port. See [Inbound Services](inbound-services.md) for the full mechanism and recipes.

### Local Network

Control LAN device access while connected to the VPN:

- **Allow LAN** — LAN devices can access each other and local services
- **Block LAN** — LAN device access is blocked for maximum isolation

### DNS & Ad Blocking

- **Custom DNS** — enable and set custom DNS servers (space-separated IPs)
- **Ad Blocking** — enable or disable DNS-based ad blocking

### Account

Manage your Nym account:

- **Logged in** — shows identity and account state, with **Rotate Keys** and **Logout** buttons
- **Logged out** — recovery phrase input field with **Login** button

### Service Management

- **Daemon Status** — shows whether `nym-vpnd` is running or stopped
- **Restart Daemon** — restart the service

### Footer

Displays the daemon version and current network name (mainnet/canary).

## Notifications

- **Toast messages** — brief status updates that auto-dismiss
- **Modals** — confirmations for destructive actions (disconnect, forget account)
