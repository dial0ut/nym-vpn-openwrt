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

Whichever servers are used, the queries travel through the tunnel, so the resolver sees the exit gateway rather than your ISP connection.

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

**The encrypted queries still go through the tunnel.** The proxy's outbound DoT or DoH connections follow the same routing as any other traffic from the router, and the kill-switch permits anything leaving via the tunnel interface. So your encrypted resolver sees the exit gateway, not your ISP connection — the same privacy property as NymVPN's own DNS, with encryption added.

Ad-blocking is unaffected either way. It works through separate dnsmasq directives rather than upstream servers.

## Caveats

**With split tunnelling enabled**, the default route into the tunnel is deliberately withheld, so DNS follows whatever policy routing you have configured rather than automatically using the tunnel. Check your PBR rules if you expect DNS to be tunnelled.

**While disconnected with the kill-switch armed**, outbound traffic that isn't explicitly allowed is blocked — which includes a local proxy's encrypted upstream connections. That is correct no-leak behaviour, but it means name resolution stops until you connect. Whether a given proxy recovers cleanly on reconnect, and whether a DoH proxy can bootstrap its upstream hostname in that state, depends on the proxy and is not something NymVPN controls.

**Do not point NymVPN's custom DNS at `127.0.0.1`.** The setting takes bare IP addresses with no port, so it would send dnsmasq's queries to port 53 on the router — itself. dnsmasq's loop detection will refuse. Local proxies listen on other ports and are configured through the forwards list, not here.

See also: [Custom DNS setting has no effect](../troubleshooting.md#custom-dns-setting-has-no-effect) in Troubleshooting.
