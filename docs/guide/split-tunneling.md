# Split Tunneling

By default, **all** LAN traffic is routed through the VPN tunnel whenever NymVPN is
connected — this happens regardless of the kill-switch. Split tunnelling is the act of
**carving specific traffic back out to the WAN** so it bypasses the tunnel.

!!! note "This changed in recent versions"
    Earlier builds tied the in-tunnel default route to the kill-switch: turning the
    kill-switch *off* also stopped routing traffic into the tunnel, so you had to add
    traffic back *in* with PBR. That is no longer the case. Routing into the tunnel is
    now always on when connected; the kill-switch **only** controls whether non-tunnel
    WAN egress is blocked. Split tunnelling is now **exclusion**-based, not inclusion-based.

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

## Step 1: Turn the kill-switch off

Carve-out traffic egresses the WAN. With the kill-switch **on**, the firewall blocks all
non-tunnel WAN egress, so your carve-outs would be dropped. Split tunnelling therefore
requires the kill-switch off:

```bash
nym-vpnc tunnel set --killswitch off
```

Or in LuCI: **NymVPN > Tunnel Settings > Kill-Switch** → off. Reconnect after changing it.

!!! warning
    With the kill-switch off, any traffic that bypasses the tunnel — your carve-outs, and
    anything else not routed into the tunnel — goes direct over the WAN in the clear. This
    is the expected trade-off for split tunnelling. If you need a kill-switch *and*
    selective exposure of inbound services, use [Inbound Services](inbound-services.md).

## Step 2: Mark the traffic to exclude

The reliable, package-free method is an nftables drop-in that marks matching packets in
the `prerouting` (mangle) hook, before the routing decision for forwarded traffic.

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
