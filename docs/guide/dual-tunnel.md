# Dual Tunnel

Fast mode for everything, and the mixnet for the devices or domains you choose, at the same time.
A laptop used for a crypto wallet can go through the mixnet while the rest of the house stays on
the faster two-hop tunnel.

## Using it in LuCI

**NymVPN → Split Tunneling → Exclusions.** Add a device or a domain with the route **Mixnet**, or
switch an existing entry's route from **Bypass VPN** to **Mixnet**.

That is the whole setup. While an enabled entry routes via the mixnet and the VPN is connected in
Fast mode, the router runs a second tunnel, through the mixnet, beside the fast one. Removing or
disabling the last mixnet route stops it. Neither change drops the fast tunnel, so the rest of the
network does not notice.

A line above the list says what the mixnet routes have right now: the mixnet tunnel is up (with
its exit), connecting, or the VPN is disconnected.

## What to expect

- **No fallback.** Mixnet-routed traffic only ever leaves through the mixnet. While the mixnet
  tunnel is down (starting, reconnecting, or after a failure) those devices and domains have no
  connection at all; they never fall back to the fast tunnel or the WAN, whether the kill-switch
  is on or off. While the VPN itself is disconnected, the kill-switch decides for them as for
  everything else.
- **It is slow.** The mixnet adds seconds of latency on purpose. Fine for a wallet, a messenger or
  light browsing; not for video calls or downloads.
- **DNS goes through the mixnet too.** A mixnet device's DNS queries to the router are redirected
  through the mixnet to a public resolver: your custom DNS server if it is a public address, Quad9
  (`9.9.9.9`, `2620:fe::fe`) otherwise. A resolver on the router or the LAN (dnscrypt-proxy on
  `127.0.0.1`, a Pi-hole) cannot be reached through the mixnet, so mixnet devices skip it.
  For a mixnet **domain** the lookup still goes through the router's dnsmasq and the fast tunnel;
  only the connections to it use the mixnet.
- **Your address stays hidden from the mixnet entry.** The mixnet tunnel reaches its entry gateway
  through the fast tunnel, so the entry sees the fast tunnel's exit address, not yours. As a
  consequence its traffic, cover traffic included, also counts against the fast tunnel's bandwidth.
- **Gateways are yours to choose.** The mixnet routes use the Mixnet gateways, the same pair
  Mixnet mode uses: in LuCI the **Mixnet gateways** line under the Connect button, or
  `nym-vpnc gateway set --tunnel mixnet …`. **Automatic** (the default) picks a mixnet entry and
  exit that are never one of the fast tunnel's two gateways, with your gateway independence
  criteria applied. A gateway pinned for both tunnels cannot work: the mixnet tunnel then fails
  and says so in the log. Changing the pair reconnects only the mixnet tunnel. After a failure the
  mixnet tunnel retries with backoff, avoiding the failed entry gateway for 20 minutes.
- **Mixnet mode needs none of this.** With the whole VPN in Mixnet mode, mixnet routes simply
  follow the main tunnel.
- **IPv6.** Mixnet devices get IPv6 through the mixnet only when IPv6 is enabled. Otherwise their
  IPv6 is unreachable; it never leaks.

The same limits as for [exclusions](split-tunneling.md#managed-exclusions-luci) apply: OpenWrt 22.03
or newer (fw4), devices on the router's own network segment, and `dnsmasq-full` for domains.

Where routes overlap, the mixnet wins. A mixnet device stays in the mixnet even when it reaches
a bypass domain, and a bypassed device reaching a mixnet domain uses the mixnet.

## Without LuCI

`nym-vpnc tunnel set --dual-tunnel on` starts the mixnet tunnel; marking the traffic is then up to
you. Anything carrying fwmark `0x14f` goes through it, for example:

```
chain nym_mixnet_mark {
    type filter hook prerouting priority mangle - 1; policy accept;
    ether saddr aa:bb:cc:dd:ee:ff meta mark set 0x14f
}
```

`nym-vpnc status` shows the mixnet tunnel's state after the fast tunnel's gateways. Do not mix this
with LuCI's mixnet routes: the LuCI bridge switches the setting to match its list on every edit.

## How it works

The daemon adds two policy rules to the ones described in
[Split Tunneling](split-tunneling.md#how-it-works):

```
ip rule:  from all fwmark 0x14e lookup main                # pri 90  -> real WAN
          from all lookup main suppress_prefixlength 0     # pri 100 -> LAN routes
          from all fwmark 0x14f lookup 335                 # pri 150 -> mixnet tunnel
          from all fwmark 0x14f unreachable                # pri 151
          from all not fwmark 0x14d lookup 333             # pri 200 -> fast tunnel
```

Table 335 (`0x14f`) has a default route into the mixnet tunnel's device, `nym2`, only while that
tunnel is up; in Mixnet mode it points at the main tunnel instead. When it is empty, marked
packets meet the `unreachable` rule. Both rules exist for IPv4 and IPv6 whenever the VPN is
connected, which is what makes the no-fallback guarantee independent of the kill-switch.

LuCI's managed drop-in, `/etc/nftables.d/30-nym-split.nft`, marks mixnet routes with `0x14f` after
the `0x14e` carve-outs (the last mark set wins), and adds a `nym_mixnet_dns` NAT chain that rewrites
mixnet devices' DNS to the router into the public resolver. Mixnet domains fill the `nym_mixnet4`
and `nym_mixnet6` sets through a `dhcp.nym_mixnet_ipset` section.

`nym2` belongs to the `nym` firewall zone (`nym+`), which masquerades and forwards into it. With
the kill-switch on, the connected policy admits it like the fast tunnel's devices while it is up.
The mixnet tunnel's gateway connection carries no fwmark, so it follows the default route into the
fast tunnel and needs no firewall opening of its own.
