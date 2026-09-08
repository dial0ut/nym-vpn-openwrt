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

Switches save the moment they are flipped. Each row states in a few words what the switch does;
the small ⓘ button after the title unfolds the full explanation under the row (the page remembers
which ones you leave open) and ends in a **Learn more** link to the matching section below. Rows
marked with a small `reconnect` tag take effect on the next connect; the rest apply at once.

### Protection

#### Always On

Keeps the tunnel up while the router is on. The daemon itself does the work, so there is no
poller and no interval to pick: it connects when it starts, waiting for a default route rather
than probing for one (the WAN may still be coming up, PPPoE may still be dialling), reconnects
after drops and WAN outages the moment the route is back, retries error states with a growing
backoff — moving off gateways that keep failing — and forces a fresh gateway selection if a
connect drags on for ten minutes. Firewall, routing or DNS failures that repeat for about five
minutes make the daemon hand over to procd, which restarts it with the kill-switch still in
place.

The line under the switch says what it is doing: *Active*, *Waiting for network*, *Retrying in
N s (attempt K)*, *Paused — disconnected by you* after you press **Disconnect** (the setting stays
on and the next connect or reboot resumes it), or *Stopped: …* for errors that need you to change
something first — an account problem, or a pinned entry/exit pair that fails the independence
criteria. Fixing the configuration, a renewed subscription or pressing **Connect** resumes it. Its
log lines are prefixed `always-on:` in the daemon log (`logread -e nym-vpnd`). The same switch is
`nym-vpnc tunnel set --always-on on|off`.

#### Kill-Switch

`reconnect` — first in the card. Blocks all non-tunnel WAN egress. It is *only* a firewall block:
traffic is routed into the tunnel whenever connected regardless of this setting. Turn it off to
allow WAN fallback; while it is off the row shows an amber line reminding you that LAN traffic
can leave the router in the clear whenever the tunnel is down. You do **not** need to turn it off
for [split-tunnel exclusions](split-tunneling.md) — those work with it on. Greyed out while the
legacy PBR switch in the Split Tunneling card is on, since the two are mutually exclusive.

#### Inbound Services

Nested directly under the kill-switch, and shown only while it is on. Ports whose reply traffic
bypasses the tunnel, so a service on the router (LuCI, SSH) or on the LAN (Jellyfin, a NAS) stays
reachable from the WAN with the kill-switch on. **+ Add exemption** in the group's title bar opens
the form (it is already open while the list is empty): pick `TCP` or `UDP`, type the port,
optionally a label, **Add** (or `Enter`). `×` removes a row. Rows read `● Active` while the kill-switch is on
and `● Inert` when it is off — an exemption is only meaningful while there is a block to be exempt
from. For a LAN-hosted service, create the port forward in **Network → Firewall → Port Forwards**
first, then add the exemption here using the **WAN-side** port.
[Inbound Services](inbound-services.md) has the recipes.

#### Gateway Independence

`reconnect` — on by default. Entry and exit must be run by different operators (*node families*
in the NymVPN apps), sit in different networks (ASNs) and in different subnets. One operator
seeing both ends of the tunnel could link your traffic going in and coming out, which is what the
two hops are there to prevent; with this on, the daemon refuses such a pair. Turn it off to allow
any combination.

#### Server Family Reminders

On by default. When you press **Connect**, the page first asks the daemon which entry/exit pair it
would pick for your selection. If that pair fails the independence criteria, a warning — *The
selected servers are in the same operator family!* — offers **Connect anyway**, which connects
with the criteria relaxed for that connection only (the setting above is untouched), or **Change
servers**, which returns you to the pickers. With reminders off the connection goes ahead relaxed
and a notice says so. The check is bounded to a few seconds and never blocks connecting: if the
daemon cannot answer, the connect proceeds as usual and any refusal shows up as a status error
with the same two choices.

### Transport

#### Two-Hop Mode

`reconnect` — 2-hop WireGuard instead of 5-hop mixnet routing. Faster, with less mixing: your
packets are not delayed and blended with cover traffic on the way, so the two hops still hide
your address from the exit but offer weaker protection against traffic analysis.

#### Circumvention Transports

`reconnect` — wraps the entry gateway connection in a QUIC transport to get past censorship.
Two-hop mode only; while it is on, entry gateways that cannot carry it sink to the bottom of the
picker, greyed out with a dashed border and an amber `No CT` tag under their tier, and cannot be
selected.

#### Stealth API Connect

The same switch as in the NymVPN apps. The daemon normally reaches the Nym API (account, gateway
directory, discovery) directly and only falls back to *cover domains* (domain fronting through a
CDN) when a direct request fails. On, every API request goes through the cover domains from the
start. Use it where the API hosts are blocked; API calls — gateway lists, account sync, the setup
phase of a connect — get slower. API traffic only, so it applies immediately. If the network
environment publishes no cover domains the row says so and the switch has no effect.

#### IPv6

`reconnect` — off by default. Most exit gateways have no IPv6 egress, and IPv6 that gets
tunnelled and then dropped makes dual-stack clients stall on every new connection. Turn it on
only if your exit demonstrably carries IPv6.

## Split Tunneling

Two ways of sending some traffic around the VPN. Everything not carved out stays in the tunnel,
and the kill-switch keeps covering it.

### Exclusions

Carve specific devices or domains out to the WAN. Devices are stored by MAC, so they survive an IP
change; domain rules need clients to use this router for DNS, and need `dnsmasq-full` (the card
says so, with the `opkg` command, when it is missing). Each row has its own on/off switch and a
`×`. See [Split Tunneling](split-tunneling.md) for the caveats — particularly that an excluded
device's DNS still goes through the tunnel.

### Legacy Split Tunneling (PBR)

`reconnect` — under *Policy-based routing*. Hands routing to `luci-app-pbr`: only the traffic PBR
selects goes through the VPN, everything else uses the WAN in the clear. It is mutually exclusive
with the kill-switch and the exclusion list, so switching it on greys the kill-switch in Tunnel
Settings and replaces the exclusion list with a note saying PBR owns the routing. Switch it off to
get both back (the kill-switch stays off until you turn it on again).

## Mixnet Tuning

Sphinx knobs, 5-hop mode only. These trade anonymity for latency — the defaults are the private
end. Turning off delays or cover traffic makes traffic analysis easier.

- **Disable Poisson Delays** — send real traffic immediately instead of on a randomised schedule.
  Much faster, less private.
- **Disable Background Cover Traffic** — stop sending decoys. Saves bandwidth and CPU, less
  private.
- **Cover traffic delay** — 0–200 ms; blank leaves it as is
- **Mixing delay per hop** — 0–200 ms; blank leaves it as is
- **Sending delay** — 5–50 ms; blank leaves it as is

The switches save at once; the three delays apply with **Apply Tuning**.

## DNS & Ad Blocking

### Custom DNS

Enable, then add servers one at a time (IPv4 or IPv6); `×` removes one. The servers replace the
VPN's default resolvers for every client that uses the router for DNS, and the queries ride the
tunnel while connected.

If the custom DNS setting appears to do nothing, dnsmasq is probably set to ignore its resolv
file (`noresolv`, as set by AdGuard Home, https-dns-proxy or stubby); the card says so in amber,
and [Custom DNS setting has no effect](../troubleshooting.md#custom-dns-setting-has-no-effect)
has the fix.

### Ad Blocking

Blocks ads, trackers and malware domains at the DNS level, on the resolvers the tunnel uses.

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
