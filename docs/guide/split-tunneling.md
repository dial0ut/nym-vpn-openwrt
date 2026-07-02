# Split Tunneling

By default, **all** LAN traffic is routed through the VPN tunnel whenever NymVPN is
connected — this happens regardless of the kill-switch. Split tunneling is the act of
**carving specific traffic back out to the WAN** so it bypasses the tunnel.

!!! note "This changed in recent versions"
    Earlier builds tied the in-tunnel default route to the kill-switch: turning the
    kill-switch *off* also stopped routing traffic into the tunnel, so you had to add
    traffic back *in* with PBR. By default that is no longer the case — routing into the
    tunnel is now always on when connected, the kill-switch **only** controls whether
    non-tunnel WAN egress is blocked, and split tunneling is **exclusion**-based.

    If you specifically want the old **inclusive** behaviour back (route only what you
    select, via PBR), enable [Legacy split tunneling](#legacy-split-tunneling-inclusive-pbr).

!!! note "Looking to expose a service to the WAN?"
    This page covers **outbound** exclusions — sending selected LAN clients or destinations
    around the VPN. If you want a **port-forwarded service** (LuCI, SSH, a self-hosted site)
    to stay reachable from the WAN while the kill-switch is on, see
    [Inbound Services](inbound-services.md) instead. That is a separate mechanism and does
    not require disabling the kill-switch.

**Common use cases:**

- Send one device (e.g. a smart TV) straight to the WAN, everything else via VPN
- Bypass the VPN for a banking or streaming destination
- Route all traffic through the VPN *except* a few carve-outs

## Managed exclusions (LuCI)

The simplest way to manage carve-outs is the built-in UI — no nft, no marks, no extra
packages for device rules. In LuCI go to **NymVPN → Tunnel Settings → Split Tunneling** and add:

- **Devices** — pick a LAN client from the DHCP-lease dropdown. Stored by MAC, so it survives
  the client's IP changing.
- **Domains** — type a hostname (e.g. `example.com`). The router resolves it and steers the
  answer IPs (v4 and v6) out the WAN. Domain rules need `dnsmasq-full` (the base `dnsmasq`
  lacks nftset support); the panel detects this and tells you if it's missing. Clients must use
  this router as their DNS resolver.

Each exclusion has an enable toggle, so you can keep a rule around without it being active. The
panel works while connected and applies immediately. **The kill-switch can stay on:** excluded
traffic always uses the WAN, while everything else remains protected — including during reconnects
(see [How it works](#how-it-works)).

Under the hood this just writes the same `0x14e` mark rules described below into a managed
drop-in (`/etc/nftables.d/30-nym-split.nft`) plus dnsmasq `nftset` lines, then reloads. The rest
of this page documents that mechanism for advanced/manual setups and for `pbr` users.

## How it works

When connected, the daemon installs:

- a default route into the tunnel (`0.0.0.0/0` in the tunnel routing table), and
- a catch-all policy rule (priority 200) sending all **unmarked** traffic to that table.

It also installs a **bypass rule** at priority 90:

```
ip rule:  from all fwmark 0x14e lookup main      # pri 90  -> real WAN
          from all lookup main suppress_prefixlength 0   # pri 100
          from all not fwmark 0x14d lookup <tunnel>      # pri 200 -> tunnel
```

So the recipe for an exclusion is simple: **mark the packets you want to bypass with
fwmark `0x14e`.** They hit the priority-90 rule, get looked up in the main table, and
egress the real WAN (NAT'd by the normal `wan` zone masquerade). Everything you don't
mark stays in the tunnel.

`0x14e` is the daemon's **bypass mark** (the same mark used internally to pin
inbound-service replies to the WAN). It is distinct from the tunnel mark `0x14d`.

The kill-switch firewall **honours `0x14e`**: its forward chain accepts marked traffic out
the WAN unconditionally, while still rejecting every other non-tunnel egress. So the
routing and firewall layers agree — marked = bypass, unmarked = tunnel-or-blocked. This is
safe because `0x14e` is router-internal netfilter metadata: a LAN client cannot set it on
its own packets, so only the deliberate router rules below (or the managed UI) ever carry it.

## Works with the kill-switch on

Unlike earlier versions, split tunneling **no longer requires turning the kill-switch
off**. With the kill-switch on:

- your carve-outs (marked `0x14e`) egress the WAN, and
- everything else stays blocked unless it's in the tunnel — including during reconnects,
  when the tunnel is briefly down. Non-excluded clients never leak.

!!! warning
    Carve-out traffic egresses the WAN **in the clear** (it deliberately bypasses the VPN).
    That is the point of an exclusion — just be aware those specific devices/destinations
    are not protected by the tunnel. Everything you don't mark stays protected.

## Manual: mark the traffic to exclude

If you'd rather not use the LuCI panel, the reliable, package-free method is an nftables
drop-in that marks matching packets in the `prerouting` (mangle) hook, before the routing
decision for forwarded traffic.

Create `/etc/nftables.d/30-nymvpn-split.nft`:

```nft
chain nymvpn_split {
    type filter hook prerouting priority mangle - 1; policy accept;

    # --- examples: keep the ones you need ---

    # One device straight to the WAN
    ip saddr 192.168.1.100 meta mark set 0x14e

    # A whole LAN subnet to the WAN
    # ip saddr 192.168.50.0/24 meta mark set 0x14e

    # A destination port to the WAN (e.g. plain DNS)
    # udp dport 53 meta mark set 0x14e

    # A destination network to the WAN
    # ip daddr 203.0.113.0/24 meta mark set 0x14e
}
```

Apply it:

```bash
/etc/init.d/firewall restart
```

Reply traffic returns automatically via connection tracking (the WAN zone's
`established,related` accept), so you only need to mark the outbound direction.

That's it — marked flows go direct, everything else stays in the tunnel.

## Using the `pbr` package instead

The OpenWrt [`pbr`](https://docs.openwrt.melmac.net/pbr/) package can also drive this, but
note the model has inverted: **the base is now all-via-VPN**, so you no longer add an
"All via VPN" policy. You only add **exclusions to the WAN** — and those exclusions must
take effect *before* the daemon's catch-all rule (priority 200), or rule 200 will claim
the traffic for the tunnel first.

The robust way to guarantee that ordering is to have PBR mark excluded flows with the
bypass mark `0x14e` (which is honoured at priority 90) rather than relying on a plain
`interface 'wan'` policy. If you point a policy directly at `wan` without marking, verify
with the troubleshooting commands below that it actually egresses the WAN — depending on
your `pbr` resolver/priority settings it may be intercepted by rule 200 and tunnelled.

```bash
opkg update && opkg install pbr luci-app-pbr
```

## Legacy split tunneling (inclusive / PBR)

Everything above is **exclusion**-based: all traffic is tunnelled and you carve specific
flows back out. Some setups want the opposite — **inclusive** routing, where *nothing* is
tunnelled by default and you pick the few clients/destinations that should go through the
VPN. That is what **Legacy split tunneling** restores.

Enable it in LuCI under **NymVPN → Tunnel Settings**, with the **Legacy Split Tunneling
(PBR)** toggle (directly above the kill-switch), or from the CLI:

```bash
nym-vpnc tunnel set --legacy-split-tunnel on
```

When enabled:

- The daemon **withholds the default route** into the tunnel (`0.0.0.0/0` / `::/0`). The
  tunnel still comes up, but nothing is routed into it until *you* send it there.
- You select what to route in with the OpenWrt [`pbr`](https://docs.openwrt.melmac.net/pbr/)
  package — per device, per destination, or per port — pointing those policies at the
  tunnel interface.
- It is **mutually exclusive** with the kill-switch and with the managed exclusion panel
  above. Turning it on forces the kill-switch off (the daemon enforces this regardless of
  the stored setting) and hides the exclusion list; your exclusion entries are preserved
  and reappear if you turn legacy mode back off.

!!! warning
    In this mode every client you do **not** route into the VPN reaches the internet over
    the normal WAN **in the clear**. There is no kill-switch backstop — that is the
    inherent trade-off of inclusive routing. Only use this if you deliberately want most
    traffic on the WAN and a selected subset in the tunnel.

```bash
opkg update && opkg install pbr luci-app-pbr
```

Then add policies routing your chosen sources/destinations to the tunnel device. Confirm
with `ip route get <dest> from <client>` that selected traffic resolves to the tunnel
device and everything else to the WAN.

## Troubleshooting

Confirm a carve-out actually leaves via the WAN (not the tunnel):

```bash
# What path does marked traffic from the client take?
ip route get 1.1.1.1 from 192.168.1.100 mark 0x14e   # -> via WAN gateway
ip route get 1.1.1.1 from 192.168.1.100              # -> dev nym1 (tunnel)

# Are the rules present?
ip rule show                       # expect pri 90 fwmark 0x14e, 100 suppress, 200 tunnel
ip route show table all | grep nym

# Watch the WAN to confirm the carve-out egresses there
tcpdump -i any -n "host 192.168.1.100 and not host <tunnel-gw>"
```

If marked traffic still goes through the tunnel, check that the mark is being set in
`prerouting` (forwarded packets are routed *after* that hook):

```bash
nft list chain inet fw4 nymvpn_split
```
