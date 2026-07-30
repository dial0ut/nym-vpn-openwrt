# DNS

How name resolution works while the tunnel is up, and how to combine NymVPN with an encrypted DNS resolver (DoT/DoH).

## What the VPN does to DNS

LAN clients ask the router for name resolution, and on OpenWrt that means dnsmasq. dnsmasq answers what it can from its cache and hosts files, and forwards everything else to an **upstream** resolver.

dnsmasq takes upstream servers from two independent places:

1. A **resolv file**, whose path is the `resolvfile` option and which is normally filled in from your WAN connection.
2. A **forwards list**, the `server` entries — LuCI's *Network → DHCP and DNS → Forwards* tab.

On connect, the daemon writes the tunnel's DNS servers into a resolv file it owns (`/tmp/resolv.conf.d/nym-resolv.conf`) and points dnsmasq at it. Your forwards list is left alone, so domain-specific forwards keep working.

That mechanism is chosen so DNS switching costs no dnsmasq restart: dnsmasq watches the resolv file and picks up changes live. Rewriting the forwards list instead would mean restarting dnsmasq on every connect, and several seconds with no DNS for the whole network.

By default the tunnel DNS servers are Quad9 and Cloudflare:

```
nym-vpnc dns get-default
Default DNS: 9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::fe:9
             1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001
```

IPv6 servers are dropped when IPv6 is disabled. Set your own with `nym-vpnc dns set <ip>...` or in the web UI.

Whichever servers are used, the queries travel through the tunnel, so the resolver sees the exit gateway rather than your ISP connection. That holds in the default split-tunnelling mode too, including for excluded devices — see [Caveats](#caveats). It does **not** hold under legacy (inclusive/PBR) split tunnelling.

## These queries are not encrypted

dnsmasq can only speak plain DNS on port 53. It has no DoT, DoH, DNSCrypt or DNS-over-QUIC support of any kind — there is no such option to enable:

```
dnsmasq --version
Dnsmasq version 2.89 ...
Compile time options: IPv6 GNU-getopt no-RTC no-DBus UBus ... DNSSEC ...
```

So setting a custom DNS server in NymVPN changes **which** resolver answers, not **how** the query is carried. Inside the tunnel the query is encrypted along with everything else, but from the exit gateway onward it goes to the resolver in the clear.

If that matters to you, the resolver has to be something other than dnsmasq.

## Using encrypted DNS

The standard OpenWrt approach is a local proxy. You install a small daemon that speaks DoT or DoH upstream and listens on a loopback address; dnsmasq forwards plain queries to it over `127.0.0.1`, which never leaves the router.

Common choices from the OpenWrt packages feed — check `opkg list` or `apk search`, since vendor firmware does not always carry all of them:

| Package | Protocol |
|---|---|
| `stubby` | DNS over TLS |
| `https-dns-proxy` | DNS over HTTPS |
| `dnscrypt-proxy2` | DNSCrypt, DoH |

Install and configure these per their own documentation — `https-dns-proxy` in particular reconfigures dnsmasq for you when its service starts. NymVPN needs no configuration to work alongside them, but two consequences are worth understanding.

**Your NymVPN custom DNS setting stops applying.** These proxies set dnsmasq's `noresolv` option, which tells it to ignore the resolv file entirely — and that file is exactly how the daemon injects its DNS servers. So NymVPN detects this, deliberately leaves your resolver alone, and says so in `nym-vpnc dns get` and in the web UI.

This is intended. Your encrypted resolver is a better arrangement than the plaintext one NymVPN can offer, so it would be wrong to override it. Nothing needs fixing.

**The encrypted queries still go through the tunnel.** The proxy's outbound DoT or DoH connections follow the same routing as any other traffic from the router, and the kill-switch permits anything leaving via the tunnel interface. Verified with stubby: the DoT connections appear on the tunnel interface sourced from the tunnel address, with nothing on the WAN.

```
# tcpdump -i nym1 'tcp port 853'
10.1.184.141.54372 > 1.0.0.1.853: Flags [S] ...    ← tunnel address
# tcpdump -i eth0 'tcp port 853'
(nothing)
```

So your encrypted resolver sees the exit gateway, not your ISP connection — the same privacy property as NymVPN's own DNS, with encryption added. This holds in the default split-tunnelling mode; legacy split tunnelling changes it, as below.

Ad-blocking is unaffected either way. It works through separate dnsmasq directives rather than upstream servers.

## Caveats

**In the default (exclusion) split-tunnelling mode, DNS is tunnelled — including for excluded devices.** An excluded device's lookup goes to the router, and the router's own upstream query follows the default route into the tunnel. Two consequences worth knowing:

- Answers are chosen from the exit gateway's vantage point, while the excluded device then connects from your real address. For services on unicast geo-DNS — Netflix, Akamai, non-anycast Fastly — that can mean a distant or wrong-region CDN even though the device itself bypasses the VPN. Anything behind Cloudflare or Google anycast is unaffected.
- Excluding a device does not stop its hostnames being resolved through the tunnel. If your reason for excluding it was to keep it away from the VPN entirely, DNS is the part that doesn't follow.

Local `.lan` names and ad-blocking keep working for excluded devices, because dnsmasq answers those itself without an upstream query.

**With legacy (inclusive/PBR) split tunnelling, DNS is not tunnelled and is not private.** That mode deliberately withholds the default route into the tunnel, so only traffic your PBR rules select goes in — and DNS is not selected unless you add a rule for it. Measured on a connected router with legacy split tunnelling on:

```
# ip route get 1.1.1.1
1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.135   ← the WAN, not the tunnel

# tcpdump -i eth0 'udp port 53'
192.168.1.135.37432 > 1.1.1.1.53: A? example.org.    ← cleartext, real WAN IP
```

With legacy split tunnelling off the same lookup goes out the tunnel interface from the tunnel address, and nothing appears on the WAN.

Covering DNS in this mode is not simply a matter of adding a PBR rule for port 53: the tunnel routing table has no default route in legacy mode — that is the whole point of it — so a rule pointing at that table resolves to nothing and falls through to the WAN. A routing fix has to add a route to the tunnel device as well. The two approaches that work today are to give the PBR-selected clients their own resolver by DHCP (option 6), so their queries carry their own source address and your existing PBR rules route them in with the rest of their traffic; or to run an encrypted resolver so that at least the query contents are protected even though they leave via the WAN.

**While disconnected with the kill-switch armed**, the kill-switch allows the router's own lookups to the daemon's DNS server addresses — on port 53, and also on 853 (DoT) and 443 (DoH) — so that it can still resolve enough to reconnect. Everything else is dropped, and LAN clients are not forwarded to those addresses.

The practical consequence for a local proxy is that it keeps working while disconnected **if and only if** its upstream is one of those addresses. Pointed at Cloudflare or Quad9 — the defaults, and the most common DoT choices — resolution continues. Pointed anywhere else it stops dead; measured with stubby aimed at `8.8.8.8`, not one SYN reached the wire. Either way the proxy recovers by itself when the tunnel comes back, with no restart needed.

A proxy configured by IP, as DoT usually is, needs no bootstrap resolution. A DoH proxy given a hostname does, and whether it can obtain it in the armed-and-disconnected state depends on that proxy's bootstrap settings — untested here.

**Do not point NymVPN's custom DNS at `127.0.0.1`.** The setting takes bare IP addresses with no port, so it would send dnsmasq's queries to port 53 on the router — itself. dnsmasq's loop detection will refuse. Local proxies listen on other ports and are configured through the forwards list, not here.

See also: [Custom DNS setting has no effect](../troubleshooting.md#custom-dns-setting-has-no-effect) in Troubleshooting.
