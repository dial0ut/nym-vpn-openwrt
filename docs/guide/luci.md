# LuCI Web Interface

Your router's IP (usually `http://192.168.1.1`), then **NymVPN** in the navigation menu.

The main view shows a connection status ring (green connected, pulsing connecting, grey
disconnected), uptime since the tunnel came up, and the hop chain through entry and exit gateways.

## Tunnel Settings

**IPv6** — off by default. Most exit gateways have no IPv6 egress, and IPv6 that gets tunnelled
and then dropped makes dual-stack clients stall on every new connection. Turn it on only if your
exit demonstrably carries IPv6.

**Two-Hop Mode** — 2-hop (faster) versus 5-hop mixnet routing.

**Kill-Switch** — blocks all non-tunnel WAN egress. It is *only* a firewall block: traffic is
routed into the tunnel whenever connected regardless of this setting. Turn it off to allow WAN
fallback. You do **not** need to turn it off for
[split-tunnel carve-outs](split-tunneling.md) — those work with it on. Takes effect on reconnect.

## Mixnet Tuning

Sphinx knobs, 5-hop mode only. These trade anonymity for latency — the defaults are the private
end. Turning off delays or cover traffic makes traffic analysis easier.

- **Disable Poisson Delays** — send real traffic immediately instead of on a randomised schedule
- **Disable Background Cover Traffic** — stop sending decoys
- **Cover traffic delay** — 0–200 ms; blank leaves it as is
- **Mixing delay per hop** — 0–200 ms; blank leaves it as is
- **Sending delay** — 5–50 ms; blank leaves it as is

## Inbound Services

Ports whose reply traffic bypasses the tunnel, so a service on the router (LuCI, SSH) or on the
LAN (Jellyfin, a NAS) stays reachable from the WAN with the kill-switch on.

Pick `TCP` or `UDP`, type the port, optionally a label, **Save** (or `Enter`). `×` removes a row.

Rows read `● Active` when the kill-switch is on and `● Inert` when it is off — an exemption is
only meaningful while there is a block to be exempt from.

For a LAN-hosted service, create the port forward in **Network → Firewall → Port Forwards** first,
then add the exemption here using the **WAN-side** port.
[Inbound Services](inbound-services.md) has the recipes.

## Split Tunneling

Carve specific devices or domains out to the WAN. Devices are stored by MAC, so they survive an
IP change; domains need `dnsmasq-full`. See [Split Tunneling](split-tunneling.md) for the
caveats — particularly that an excluded device's DNS still goes through the tunnel.

## Local Network

**Allow LAN** lets LAN devices reach each other and local services while connected. **Block LAN**
isolates them.

## DNS & Ad Blocking

**Custom DNS** — enable, then set servers as space-separated IPs. **Ad Blocking** — on or off.

If the custom DNS setting appears to do nothing, dnsmasq is probably set to ignore its resolv
file; see [Custom DNS setting has no
effect](../troubleshooting.md#custom-dns-setting-has-no-effect).

## Privacy

**Anonymous Statistics** — whether the daemon sends anonymous, aggregated usage statistics to
Nym. On by default. Reports only travel through the tunnel while connected; nothing is sent
while disconnected unless disconnected reporting was turned on from the CLI (`nym-vpnc
network-stats`), in which case the card says so. Turn it off to send nothing at all.

While the daemon is up but not connected, it also keeps its own background traffic low: the
account state is re-checked every 30 minutes instead of every 2, and the hourly network
discovery check is suspended. Both catch up the moment you connect, so this does not slow a
connect down.

## Account

Logged in: identity and account state, with **Rotate Keys** and **Logout**. Logged out: recovery
phrase field and **Login**.

## Service Management

Whether `nym-vpnd` is running, and a **Restart Daemon** button.

The footer shows the daemon version and current network (mainnet or canary).

## Notifications

Toasts for status updates, modals to confirm anything destructive — disconnecting, forgetting an
account.
