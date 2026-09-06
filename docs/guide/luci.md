# LuCI Web Interface

Your router's IP (usually `http://192.168.1.1`), then **NymVPN** in the navigation menu.

The main view shows a connection status ring (green connected, pulsing connecting, grey
disconnected), uptime since the tunnel came up, and the hop chain through entry and exit gateways.
While connected, each gateway also shows its operator family when the directory knows one; if
entry and exit turn out to share a family, both are marked **Same operator family** in amber.

While disconnected, the two side panels are the gateway pickers; they take most of the hero's
width, with the status ring in a narrow column between them (above them on screens narrower than
about 960 px, and everything stacks in one column below about 700 px). Choose a country (the
dropdown shows how many gateways each has, or **Random**), then a row in the list under it. Every
row in a list has the same height, so the list scans as a grid. The first row,
**Any Gateway (Random)**, leaves the pick within that country to the daemon; each row below is one
gateway: its name (long names wrap to two lines; hover for the full text), a performance tier at
the right — `HIGH`, `MEDIUM`, `LOW`, `OFFLINE` or `N/A`, with a green / amber / red / grey dot — a
telemetry line with the load, the 24-hour uptime and the city, and, when the directory knows one,
the operator family on its own line, so you can avoid picking two servers from the same operator
by hand. Rows are sorted best tier first; the selected row is outlined in green.

Below the connection hero the settings come as expandable cards, in this order: **Tunnel
Settings**, **Split Tunneling**, **Mixnet Tuning**, **DNS & Ad Blocking**, **Account**, **Service
Management**, **Diagnostics**, **Daemon Logs**.

## Tunnel Settings

Switches save the moment they are flipped. Rows marked with a small `reconnect` tag take effect
on the next connect; the rest apply at once. The card is in three groups.

### Protection

**Kill-Switch** (`reconnect`) — first in the card. Blocks all non-tunnel WAN egress. It is *only*
a firewall block: traffic is routed into the tunnel whenever connected regardless of this
setting. Turn it off to allow WAN fallback; while it is off the row shows an amber line
reminding you that LAN traffic can leave the router in the clear whenever the tunnel is down.
You do **not** need to turn it off for [split-tunnel exclusions](split-tunneling.md) — those
work with it on. Greyed out while the legacy PBR switch in the Split Tunneling card is on, since
the two are mutually exclusive.

**Inbound Services** — nested directly under the kill-switch, and shown only while it is on.
Ports whose reply traffic bypasses the tunnel, so a service on the router (LuCI, SSH) or on the
LAN (Jellyfin, a NAS) stays reachable from the WAN with the kill-switch on. Pick `TCP` or `UDP`,
type the port, optionally a label, **Add** (or `Enter`). `×` removes a row. Rows read `● Active`
while the kill-switch is on and `● Inert` when it is off — an exemption is only meaningful while
there is a block to be exempt from. For a LAN-hosted service, create the port forward in
**Network → Firewall → Port Forwards** first, then add the exemption here using the **WAN-side**
port. [Inbound Services](inbound-services.md) has the recipes.

**Gateway Independence** (`reconnect`) — on by default. Entry and exit must be run by different
operators (*node families* in the NymVPN apps), sit in different networks (ASNs) and in different
subnets. One operator seeing both ends of the tunnel could link your traffic going in and coming
out, which is what the two hops are there to prevent; with this on, the daemon refuses such a
pair. Turn it off to allow any combination.

**Server Family Reminders** — on by default. When you press **Connect**, the page first asks the
daemon which entry/exit pair it would pick for your selection. If that pair fails the
independence criteria, a warning — *The selected servers are in the same operator family!* —
offers **Connect anyway**, which connects with the criteria relaxed for that connection only
(the setting above is untouched), or **Change servers**, which returns you to the pickers. With
reminders off the connection goes ahead relaxed and a notice says so. The check is bounded to a
few seconds and never blocks connecting: if the daemon cannot answer, the connect proceeds as
usual and any refusal shows up as a status error with the same two choices.

**Always On** — a watchdog that reconnects when the tunnel drops: soft reconnects first, then a
daemon restart with growing backoff. It polls the tunnel at the chosen interval (**Check every**,
30 s by default) and is also woken by the router's WAN link events, so when the WAN comes back
after an outage or a PPPoE re-dial the tunnel is checked immediately, followed by a few quick
re-checks while the daemon catches up. A link change also resets the retry escalation, since a
daemon restart cannot fix a WAN that is down. `wan` and `wan6` count as WAN, as does any
interface in the `wan` firewall zone or carrying a default route. Its log lines are tagged
`nym-watchdog` in `logread`.

### Transport

**Two-Hop Mode** (`reconnect`) — 2-hop WireGuard (faster) versus 5-hop mixnet routing.

**Circumvention Transports** (`reconnect`) — wraps the entry gateway connection in a QUIC
transport to get past censorship. Two-hop mode only; while it is on, entry gateways that cannot
carry it sink to the bottom of the picker, greyed out with a dashed border and an amber `No CT`
tag under their tier, and cannot be selected.

**Stealth API Connect** — the same switch as in the NymVPN apps. The daemon normally reaches the
Nym API (account, gateway directory, discovery) directly and only falls back to *cover domains*
(domain fronting through a CDN) when a direct request fails. On, every API request goes through
the cover domains from the start. Use it where the API hosts are blocked; API calls — gateway
lists, account sync, the setup phase of a connect — get slower. API traffic only, so it applies
immediately. If the network environment publishes no cover domains the row says so and the
switch has no effect.

**IPv6** (`reconnect`) — off by default. Most exit gateways have no IPv6 egress, and IPv6 that
gets tunnelled and then dropped makes dual-stack clients stall on every new connection. Turn it
on only if your exit demonstrably carries IPv6.

## Split Tunneling

Two ways of sending some traffic around the VPN. Everything not carved out stays in the tunnel,
and the kill-switch keeps covering it.

**Exclusions** — carve specific devices or domains out to the WAN. Devices are stored by MAC, so
they survive an IP change; domains need `dnsmasq-full` (the card says so, with the `opkg`
command, when it is missing). Each row has its own on/off switch and a `×`. See
[Split Tunneling](split-tunneling.md) for the caveats — particularly that an excluded device's
DNS still goes through the tunnel.

**Legacy Split Tunneling (PBR)** (`reconnect`) — under *Policy-based routing*. Hands routing to
`luci-app-pbr`: only the traffic PBR selects goes through the VPN, everything else uses the WAN in
the clear. It is mutually exclusive with the kill-switch and the exclusion list, so switching it
on greys the kill-switch in Tunnel Settings and replaces the exclusion list with a note saying
PBR owns the routing. Switch it off to get both back (the kill-switch stays off until you turn
it on again).

## Mixnet Tuning

Sphinx knobs, 5-hop mode only. These trade anonymity for latency — the defaults are the private
end. Turning off delays or cover traffic makes traffic analysis easier.

- **Disable Poisson Delays** — send real traffic immediately instead of on a randomised schedule
- **Disable Background Cover Traffic** — stop sending decoys
- **Cover traffic delay** — 0–200 ms; blank leaves it as is
- **Mixing delay per hop** — 0–200 ms; blank leaves it as is
- **Sending delay** — 5–50 ms; blank leaves it as is

The switches save at once; the three delays apply with **Apply Tuning**.

## DNS & Ad Blocking

**Custom DNS** — enable, then add servers one at a time (IPv4 or IPv6); `×` removes one. **Ad
Blocking** — on or off.

If the custom DNS setting appears to do nothing, dnsmasq is probably set to ignore its resolv
file; the card says so in amber, and [Custom DNS setting has no
effect](../troubleshooting.md#custom-dns-setting-has-no-effect) has the fix.

## Account

Logged in: device identity (with a copy button) and account state, with **Rotate keys** and
**Sign out**. Logged out: recovery phrase field and **Login**. If the daemon reports a stuck or
stale account, the card offers **Reset account state** as a last resort.

## Service Management

Whether `nym-vpnd` is running and enabled at boot, with **Start**, **Restart** and **Stop**.

## Diagnostics

**Run Diagnostic** runs the daemon's connectivity self-test — DNS resolution, the Nym VPN API
over HTTP, the selected gateway's TCP/WebSocket handshake — and lists each probe as PASS or
FAIL. **Skip DNS** and **Skip HTTP** leave those sections out.

## Daemon Logs

A live tail of `nym-vpnd` entries from the system log, started when the card is expanded. Pick
how many lines, how often to refresh, and a level filter (**Errors only** or errors with ±10 /
±30 lines of context); pause, resume and copy to the clipboard.

The footer shows the daemon version and current network (mainnet or canary).

## Notifications

Toasts for status updates, modals to confirm anything destructive — disconnecting, forgetting an
account — or risky, such as connecting through two gateways of the same operator family.
