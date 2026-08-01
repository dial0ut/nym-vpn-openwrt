# Split Tunneling

When NymVPN is connected, **all** LAN traffic goes through the tunnel — kill-switch or not. Split
tunnelling means carving specific traffic back out to the WAN.

Typical reasons: send one device (a smart TV, a games console) straight to the WAN; bypass the VPN
for a bank or a streaming service that blocks it; keep everything tunnelled except a couple of
carve-outs.

!!! note "This changed in recent versions"
    Earlier builds tied the in-tunnel default route to the kill-switch, so turning the kill-switch
    off also stopped routing into the tunnel and you had to add traffic back *in* with PBR. That
    is no longer the default. Routing into the tunnel is always on when connected, the kill-switch
    **only** controls whether non-tunnel WAN egress is blocked, and split tunnelling is
    **exclusion**-based.

    To get the old **inclusive** behaviour back, see
    [Legacy split tunneling](#legacy-split-tunneling-inclusive-pbr).

!!! note "Trying to expose a service to the WAN?"
    This page is about **outbound** exclusions. To keep a **port-forwarded service** (LuCI, SSH, a
    self-hosted site) reachable from the WAN with the kill-switch on, you want
    [Inbound Services](inbound-services.md) — a separate mechanism, and it does not require
    disabling the kill-switch.

## Managed exclusions (LuCI)

**NymVPN → Tunnel Settings → Split Tunneling.** No nft, no marks, no extra packages for device
rules.

- **Devices** — pick a LAN client from the DHCP-lease dropdown. Stored by MAC, so it survives the
  client's IP changing. The rule is a literal `ether saddr <mac>` match, which means it only works
  for devices on the router's own L2 segment. Traffic arriving through a downstream router or
  repeater carries *that* device's MAC, so the exclusion either never matches or matches
  everything behind it.
- **Domains** — type a hostname (e.g. `example.com`); the router resolves it and steers the answer
  addresses (v4 and v6) out the WAN. Needs `dnsmasq-full` — base `dnsmasq` has no nftset support,
  and the panel will tell you if it is missing. Clients must be using this router as their
  resolver.

Each exclusion has its own enable toggle, so you can park a rule without deleting it. Changes
apply immediately, while connected.

**Leave the kill-switch on.** Excluded traffic uses the WAN, everything else stays protected —
including during reconnects, when the tunnel is briefly down. See [How it works](#how-it-works).

Under the hood this writes the same `0x14e` mark rules described below into a managed drop-in
(`/etc/nftables.d/30-nym-split.nft`) plus dnsmasq `nftset` lines, then reloads. The rest of this
page documents that mechanism for manual setups and `pbr` users.

### An excluded device's DNS still goes through the tunnel

Exclusions cover a device's own packets. They cannot cover its name lookups, because those never
become traffic we can mark: the query goes *to* the router, dnsmasq answers or forwards it, and
dnsmasq's own upstream query is router traffic following the default route into the tunnel.
dnsmasq cannot pick a different upstream per client, so every client shares one DNS path
regardless of exclusions.

In practice:

- **Local `.lan` names and ad-blocking keep working** for excluded devices — dnsmasq answers those
  itself, no upstream query involved.
- **Answers are chosen from the exit gateway's location**, while the device then connects from
  your real address. On unicast geo-DNS — Netflix, Akamai, non-anycast Fastly — an excluded
  streaming box can still be steered to a distant or wrong-region CDN. Cloudflare and Google
  anycast are unaffected.
- **Excluding a device does not keep its hostnames off the VPN.** If that was the point, DNS is
  the part that does not follow.

This is a deliberate trade. Routing an excluded device's DNS out the WAN would fix the
geolocation problem and cost that device local names and ad-blocking. [DNS](dns.md) has the full
picture.

### Domain rules apply to every client

A domain exclusion is destination-IP based, not per-device. The router resolves the name and puts
the answer addresses into an nftables set, which carves out traffic to those addresses from **all**
clients. For a domain behind a large shared front-end — Cloudflare, Fastly, Akamai shared IPs —
that can pull far more out of the tunnel than you intended, since the same addresses serve many
unrelated sites.

Domain rules also need dnsmasq to actually see the query. A client using its own DoH — a browser
with secure DNS on — never asks dnsmasq, so the rule silently does not apply to it. Same if
another resolver (AdGuard Home, say) sits in front of dnsmasq on port 53.

## How it works

When connected, the daemon installs a default route into the tunnel (`0.0.0.0/0` in the tunnel
routing table) and a catch-all policy rule at priority 200 sending all **unmarked** traffic to
that table. It also installs a bypass rule at priority 90:

```
ip rule:  from all fwmark 0x14e lookup main                # pri 90  -> real WAN
          from all lookup main suppress_prefixlength 0     # pri 100
          from all not fwmark 0x14d lookup 333             # pri 200 -> tunnel
```

The tunnel table is 333 — `0x14d`, the same value as the tunnel fwmark.

So the recipe for an exclusion is: **mark the packets you want to bypass with fwmark `0x14e`.**
They hit the priority-90 rule, resolve against the main table, and egress the real WAN, NAT'd by
the normal `wan` zone masquerade. Anything you do not mark stays in the tunnel.

`0x14e` is the daemon's bypass mark — the same one used internally to pin inbound-service replies
to the WAN. The tunnel mark is `0x14d`.

The kill-switch honours `0x14e`: its forward chain accepts marked traffic out the WAN
unconditionally while still rejecting all other non-tunnel egress. Routing and firewall agree —
marked means bypass, unmarked means tunnel-or-blocked. This is safe because `0x14e` is
router-internal netfilter metadata; a LAN client cannot set it on its own packets, so only the
router's own rules ever carry it.

## Works with the kill-switch on

Unlike earlier versions, split tunnelling **does not require turning the kill-switch off**. With
it on, your carve-outs egress the WAN and everything else stays blocked unless it is in the
tunnel — including during reconnects, when the tunnel is briefly down. Non-excluded clients never
leak.

!!! warning
    Carve-out traffic leaves the WAN **in the clear**. That is what an exclusion is for — just be
    clear that those specific devices and destinations are not protected by the tunnel. Everything
    unmarked stays protected.

## Manual: mark the traffic yourself

Without the LuCI panel, the reliable package-free method is an nftables drop-in that marks
matching packets in the `prerouting` (mangle) hook — before the routing decision for forwarded
traffic.

`/etc/nftables.d/30-nymvpn-split.nft`:

```nft
chain nymvpn_split {
    type filter hook prerouting priority mangle - 1; policy accept;

    # keep the ones you need

    # one device straight to the WAN
    ip saddr 192.168.1.100 meta mark set 0x14e

    # a whole LAN subnet
    # ip saddr 192.168.50.0/24 meta mark set 0x14e

    # a destination port, e.g. plain DNS
    # udp dport 53 meta mark set 0x14e

    # a destination network
    # ip daddr 203.0.113.0/24 meta mark set 0x14e
}
```

```bash
/etc/init.d/firewall restart
```

Only the outbound direction needs marking — replies come back via connection tracking, on the WAN
zone's `established,related` accept.

## Using the `pbr` package

The OpenWrt [`pbr`](https://docs.openwrt.melmac.net/pbr/) package can drive this too, but note
the model has inverted. **The base is now all-via-VPN**, so there is no "All via VPN" policy to
add — you only add **exclusions to the WAN**, and those must take effect *before* the daemon's
catch-all rule at priority 200, or rule 200 claims the traffic for the tunnel first.

The way to guarantee that ordering is to have PBR set the bypass mark `0x14e`, which is honoured
at priority 90, rather than relying on a plain `interface 'wan'` policy. If you do point a policy
straight at `wan` without marking, verify with the troubleshooting commands below that it really
egresses the WAN — depending on your `pbr` resolver and priority settings, rule 200 may intercept
it and tunnel it anyway.

```bash
opkg update && opkg install pbr luci-app-pbr
```

## Legacy split tunneling (inclusive / PBR)

Everything above is **exclusion**-based: all traffic is tunnelled, you carve flows back out. Some
setups want the opposite — **inclusive** routing, where nothing is tunnelled by default and you
pick the few clients or destinations that should go through the VPN. That is what legacy mode
restores.

!!! warning "DNS is not tunnelled in this mode"
    Because the default route into the tunnel is withheld, the router's DNS lookups leave via the
    WAN in cleartext from your real address. Your ISP sees every hostname your PBR-selected
    clients visit, even though their traffic is tunnelled. The kill-switch is forced off here, so
    nothing catches it either. [DNS → Caveats](dns.md#caveats) has the measurement and the two
    ways to address it.

Turn it on in LuCI under **NymVPN → Tunnel Settings**, with the **Legacy Split Tunneling (PBR)**
toggle directly above the kill-switch, or:

```bash
nym-vpnc tunnel set --legacy-split-tunnel on
```

What changes:

- The daemon **withholds the default route** into the tunnel (`0.0.0.0/0` and `::/0`). The tunnel
  still comes up; nothing is routed into it until you send it there.
- You select what goes in with [`pbr`](https://docs.openwrt.melmac.net/pbr/) — per device, per
  destination or per port — pointing those policies at the tunnel interface.
- It is **mutually exclusive** with the kill-switch and with the managed exclusion panel. Turning
  it on forces the kill-switch off, regardless of the stored setting, and hides the exclusion
  list. Your exclusion entries are kept and reappear if you turn legacy mode back off.

!!! warning
    Every client you do **not** route into the VPN reaches the internet over the normal WAN in the
    clear, with no kill-switch backstop. That is inherent to inclusive routing. Only use this if
    you deliberately want most traffic on the WAN and a selected subset in the tunnel.

```bash
opkg update && opkg install pbr luci-app-pbr
```

Then add policies routing your chosen sources and destinations to the tunnel device. Confirm with
`ip route get <dest> from <client>` that selected traffic resolves to the tunnel device and
everything else to the WAN.

## Troubleshooting

Confirm a carve-out actually leaves via the WAN:

```bash
ip route get 1.1.1.1 from 192.168.1.100 mark 0x14e   # -> via WAN gateway
ip route get 1.1.1.1 from 192.168.1.100              # -> dev nym1 (tunnel)
```

Check the rules are there:

```bash
ip rule show                       # expect pri 90 fwmark 0x14e, 100 suppress, 200 tunnel
ip route show table all | grep nym
```

Watch the WAN:

```bash
tcpdump -i any -n "host 192.168.1.100 and not host <tunnel-gw>"
```

If marked traffic still goes through the tunnel, the mark is probably not being set in
`prerouting` — forwarded packets are routed *after* that hook, so anywhere later is too late.
Both drop-ins are included into `inet fw4`, so dump whichever you are using:

```bash
nft list chain inet fw4 nym_split        # the managed LuCI panel
nft list chain inet fw4 nymvpn_split     # the manual drop-in above
```

For domain exclusions, also check dnsmasq is actually populating the sets — they start empty and
fill in as names resolve:

```bash
nft list set inet fw4 nym_bypass4
```

An empty set after visiting the domain means dnsmasq never saw the query (client using its own
DoH, or another resolver in front on port 53).
