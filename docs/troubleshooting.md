# Troubleshooting

## Firewall stuck after a crash

If `nym-vpnd` is killed or crashes while the kill-switch is on, its fail-closed firewall table
stays loaded and nothing reaches the internet.

The signature is distinctive: DNS names still resolve — the blocked policy permits the configured
public resolvers — but every connection hangs, and the router itself cannot reach the WAN
(`ping: sendto: Operation not permitted`).

**v1.32.0+:**

```
/etc/init.d/nym-vpnd stop      # or restart
```

The init script tears the table down after the daemon is gone, whether or not the daemon was in
any state to disconnect. Since v1.32.0 procd also respawns indefinitely, so a crash-looping daemon
keeps re-owning its firewall instead of being abandoned with the kill-switch up.

**By hand, fw4 (OpenWrt 22.03+):**

```
nft delete table inet nym 2>/dev/null
```

**By hand, older iptables builds:**

```
iptables -F NYM_INPUT 2>/dev/null
iptables -F NYM_OUTPUT 2>/dev/null
iptables -F NYM_FORWARD 2>/dev/null
iptables -t nat -F NYM_NAT 2>/dev/null

iptables -D input_rule -j NYM_INPUT 2>/dev/null
iptables -D output_rule -j NYM_OUTPUT 2>/dev/null
iptables -D forwarding_rule -j NYM_FORWARD 2>/dev/null
iptables -t nat -D postrouting_rule -j NYM_NAT 2>/dev/null

/etc/init.d/firewall restart
```

## "No related RPC reply" on GL.iNet devices

GL.iNet routers serve their admin panel through nginx on port 80, and nginx does not proxy
`/ubus` — the endpoint LuCI uses for RPC. Open the app on port 80 and every RPC call gets an HTML
redirect where JSON was expected. The daemon is fine; only the web transport is broken.

LuCI has its own uhttpd port (default `8080`/`8443`) which serves `/ubus` correctly:

```
http://192.168.8.1:8080
```

If it is not listening there:

```bash
uci set uhttpd.main.listen_http='0.0.0.0:8080'
uci set uhttpd.main.listen_https='0.0.0.0:8443'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

## Upgrade from the LuCI Software page never finishes

Reported against packages up to 1.34.0: *System → Software → Upgrade* sits on "Executing package
manager", and when the dialog finally goes away LuCI wants a new login — while
`opkg upgrade nym-vpn` or `apk upgrade nym-vpn` from a shell works. Those packages restarted rpcd
from their post-install step. LuCI runs opkg and apk *through* rpcd, so the restart cut off the
reply the page was waiting for and dropped every login session. The upgrade itself normally went
through; check with

```bash
opkg list-installed nym-vpn     # or: apk list -I nym-vpn
```

Newer packages refresh rpcd a few seconds *after* the transaction has returned, so the page gets
its result. Being asked to log in again after an upgrade that changed the web UI's permissions is
expected.

Two limits apply to any large package installed from LuCI, not just this one: LuCI stops waiting
for a package operation after 20 seconds and reports *XHR request timed out*, and rpcd kills the
wrapper it launched after 30 seconds by default (`rpcd.@rpcd[0].timeout`). The package manager
itself keeps running in both cases — nym-vpn is a 15–30 MB download written to flash, which can
take longer than that on a slow router or link. Wait a minute, reload the page and check the
installed version as above.

## Not enough disk space

Installed size is roughly 18–36 MB — `nym-vpnd` is 16–33 MB depending on architecture, `nym-vpnc`
another 2–3 MB. Devices with a small RAM-backed `/tmp` may not have room to stage the package.

```bash
df -h
```

Most devices have a writable overlay with more room than tmpfs:

```bash
mkdir -p /overlay/tmp
# stage the package there instead of /tmp
```

Or free some up:

```bash
rm -rf /tmp/opkg-lists          # re-fetch later with opkg update
rm -f /tmp/sf_log.txt /tmp/log/*
```

## Not enough RAM (OOM crash)

NymVPN needs roughly 80–100 MB. At 128 MB total you can hit OOM, most often at the moment both
WireGuard tunnels start.

```text
memory allocation of 26214400 bytes failed
Aborted
```

Fix it with zram — compressed swap in RAM, which roughly doubles what you can use:

```
opkg update
opkg install zram-swap
/etc/init.d/zram start
```

```bash
free -m                         # Swap total should be non-zero
```

zram-swap starts on boot from its own init script once installed:

```bash
/etc/init.d/zram enabled && echo "enabled" || echo "disabled"
```

File-based swap (`swapon /path/to/swapfile`) does **not** work on the UBIFS/JFFS2 filesystems
OpenWrt normally uses. zram is the option.

## Custom DNS setting has no effect

Custom DNS is enabled in the web UI (or `nym-vpnc dns get` says so), but lookups clearly go
elsewhere — a leak test names your ISP's resolver, or one you never configured.

Check whether dnsmasq is ignoring its resolv file:

```
uci get dhcp.@dnsmasq[0].noresolv
```

If that prints `1`, the daemon has deliberately stepped aside. The same setting in LuCI is
**Network → DHCP and DNS → Resolv & Hosts Files → "Ignore resolv file"** (labelled just **DNS** on
some versions).

The reason: the daemon applies VPN DNS servers by writing them into dnsmasq's resolv file, which
is the only way to change upstreams without restarting dnsmasq — and a restart means several
seconds with no DNS for the whole network on every connect. With "Ignore resolv file" ticked,
dnsmasq never reads that file, so nothing written there can take effect. Your entries under
**Forwards** are what resolve instead.

Usually that is correct and intended. AdGuard Home, https-dns-proxy and stubby all tick this box
when installed, because you asked *them* to own DNS. Leave it alone — those queries still ride the
tunnel while connected.

If you did not mean to, untick it:

```
uci delete dhcp.@dnsmasq[0].noresolv
uci commit dhcp
/etc/init.d/dnsmasq restart
```

VPN DNS servers apply from the next connect. Ad-blocking is unaffected either way — it works
through separate dnsmasq directives, not upstream servers.

## No internet after clearing DNS forwards

You emptied **Network → DHCP and DNS → Forwards**, perhaps to force DNS through the VPN, and now
nothing resolves.

This is the previous entry again: with "Ignore resolv file" ticked, the Forwards list is dnsmasq's
*only* source of upstream servers, so emptying it leaves nowhere to forward to.

Put a forward back, or untick "Ignore resolv file" so dnsmasq falls back to the resolv file.
Unticking is the better fix if VPN DNS was the goal, since it also lets the daemon supply the
tunnel's servers.
