# DNS

How name resolution works while the tunnel is up, and how to put an encrypted resolver (DoT/DoH)
in front of it.

## What the VPN does to DNS

LAN clients ask the router, and on OpenWrt that means dnsmasq. dnsmasq answers what it can from
cache and hosts files, and forwards the rest to an **upstream** resolver.

It takes upstreams from two independent places:

1. A **resolv file** — the `resolvfile` option, normally filled in from your WAN connection.
2. A **forwards list** — the `server` entries, LuCI's *Network → DHCP and DNS → Forwards* tab.

On connect the daemon writes the tunnel's DNS servers into a resolv file it owns
(`/tmp/resolv.conf.d/nym-resolv.conf`) and points dnsmasq at it. Your forwards list is untouched,
so domain-specific forwards keep working.

That mechanism was picked because it costs no dnsmasq restart — dnsmasq watches the file and picks
up changes live. Rewriting the forwards list instead would mean restarting dnsmasq on every
connect, and several seconds with no DNS for the whole network each time.

The defaults are Quad9 and Cloudflare:

```
nym-vpnc dns get-default
Default DNS: 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::fe:9
             1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001
```

IPv6 servers are dropped when IPv6 is off. Set your own with `nym-vpnc dns set <ip>...` or in the
web UI.

Whichever servers are in use, the queries travel through the tunnel, so the resolver sees the exit
gateway rather than your ISP connection. That holds in the default split-tunnelling mode, and it
holds for excluded devices too — see [Caveats](#caveats). It does **not** hold under legacy
(inclusive/PBR) split tunnelling.

## These queries are not encrypted

dnsmasq speaks plain DNS on port 53 and nothing else. No DoT, no DoH, no DNSCrypt, no DNS-over-QUIC.

So a custom DNS server changes **which** resolver answers, not **how** the query is carried.
Inside the tunnel it is encrypted along with everything else; from the exit gateway onward it goes
to the resolver in the clear.

If that matters, the resolver has to be something other than dnsmasq.

## Encrypted DNS

The standard OpenWrt approach is a local proxy: a small daemon that speaks DoT or DoH upstream and
listens on loopback, with dnsmasq forwarding plain queries to it over `127.0.0.1` — which never
leaves the router.

Common choices from the packages feed. Check `opkg list` or `apk search` first; vendor firmware
does not always carry all of them.

| Package | Protocol |
|---|---|
| `stubby` | DNS over TLS |
| `https-dns-proxy` | DNS over HTTPS |
| `dnscrypt-proxy2` | DNSCrypt, DoH |

Install and configure per their own docs — `https-dns-proxy` reconfigures dnsmasq for you when its
service starts. NymVPN needs no configuration to work alongside any of them, but two consequences
are worth knowing.

**Your NymVPN custom DNS setting stops applying.** These proxies set dnsmasq's `noresolv` option,
which tells it to ignore the resolv file — and that file is exactly how the daemon injects its
servers. NymVPN detects this, leaves your resolver alone, and says so in `nym-vpnc dns get` and in
the web UI.

That is intended. Your encrypted resolver is a better arrangement than the plaintext one NymVPN
can offer, so overriding it would be wrong. Nothing needs fixing.

**The encrypted queries still go through the tunnel.** The proxy's outbound DoT/DoH connections
follow the same routing as anything else from the router, and the kill-switch permits whatever
leaves via the tunnel interface. Verified with stubby: DoT connections appear on the tunnel
interface sourced from the tunnel address, nothing on the WAN.

So your encrypted resolver sees the exit gateway, not your ISP — the same property as NymVPN's own
DNS, with encryption added. This holds in the default split-tunnelling mode; legacy split
tunnelling changes it, below.

Ad-blocking is unaffected either way. It works through separate dnsmasq directives rather than
upstream servers.

## Caveats

**In the default (exclusion) mode, DNS is tunnelled — including for excluded devices.** An
excluded device's lookup goes to the router, and the router's own upstream query follows the
default route into the tunnel. Two consequences:

- Answers are chosen from the exit gateway's vantage point, while the device then connects from
  your real address. On unicast geo-DNS — Netflix, Akamai, non-anycast Fastly — that can steer an
  excluded streaming box to a distant or wrong-region CDN even though its traffic bypasses the
  VPN. Anything behind Cloudflare or Google anycast is unaffected.
- Excluding a device does not stop its hostnames being resolved through the tunnel. If that was
  the reason for excluding it, DNS is the part that does not follow.

Local `.lan` names and ad-blocking keep working for excluded devices, because dnsmasq answers
those itself with no upstream query involved.

**With legacy (inclusive/PBR) split tunnelling, DNS is not tunnelled and is not private.** That
mode withholds the default route into the tunnel, so only what your PBR rules select goes in — and
DNS is not selected unless you add a rule for it. Measured on a connected router with legacy split
tunnelling on:

```
# ip route get 1.1.1.1
1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.135   ← the WAN, not the tunnel

# tcpdump -i eth0 'udp port 53'
192.168.1.135.37432 > 1.1.1.1.53: A? example.org.    ← cleartext, real WAN IP
```

With legacy split tunnelling off, the same lookup leaves via the tunnel interface from the tunnel
address, and nothing appears on the WAN.

Covering DNS in this mode is not just a matter of adding a PBR rule for port 53. The tunnel
routing table has no default route in legacy mode — that is the whole point of it — so a rule
pointing at that table resolves to nothing and falls through to the WAN. A routing fix has to add
a route to the tunnel device as well. Two things that work today: give the PBR-selected clients
their own resolver by DHCP (option 6), so their queries carry their own source address and your
existing PBR rules route them in with the rest of their traffic; or run an encrypted resolver, so
the query contents are protected even though they leave via the WAN.

**While disconnected with the kill-switch armed**, the kill-switch permits the router's own
lookups to the daemon's DNS server addresses — on port 53, and also 853 (DoT) and 443 (DoH) — so
it can still resolve enough to reconnect. Everything else is dropped, and LAN clients are not
forwarded to those addresses.

For a local proxy that means it keeps working while disconnected **if and only if** its upstream
is one of those addresses. Pointed at Cloudflare or Quad9 — the defaults, and the most common DoT
choices — resolution continues. Pointed anywhere else it stops dead; measured with stubby aimed at
`8.8.8.8`, not one SYN reached the wire. Either way the proxy recovers by itself when the tunnel
returns, no restart needed.

A proxy configured by IP, as DoT usually is, needs no bootstrap resolution. A DoH proxy given a
hostname does, and whether it can get it in the armed-and-disconnected state depends on that
proxy's bootstrap settings — untested here.

**Do not point NymVPN's custom DNS at `127.0.0.1`.** The setting takes bare IPs with no port, so
it would send dnsmasq's queries to port 53 on the router — itself. dnsmasq's loop detection
refuses. Local proxies listen on other ports and are wired up through the forwards list, not here.

See also: [Custom DNS setting has no
effect](../troubleshooting.md#custom-dns-setting-has-no-effect).
