# Firewall Integration

## Two backends

OpenWrt moved from iptables to nftables in 22.03. Older firmware runs fw3 (iptables), current
firmware runs fw4 (nftables). Both are still widely deployed.

NymVPN supports both rather than setting a minimum OpenWrt version. Plenty of routers run stable
old firmware their owners have no reason to touch, and requiring a firmware upgrade before you can
install a VPN excludes a lot of them.

The backend is detected by a three-step probe — binary exists, tool works, framework active —
checking fw4 first, then fw3. Both apply rules atomically (`iptables-restore --noflush -w` for
fw3, `nft -f` for fw4), which avoids xtables lock contention with mwan3 and rules out any window
where the ruleset is only half applied.

A definitive result is cached for the process lifetime, but an `Unknown` result is **not** — it
re-probes on the next call. That distinction matters: the daemon can start before the firewall
does, and caching an early `Unknown` would leave the kill-switch silently disabled for the rest of
the process's life.

## Kill-switch

### Rule order, and why DNS breaks if you get it wrong

Every state starts from the same base:

```text
 1. Loopback in/out
 2. ct established — INPUT only (see below)
 3. DHCPv4 and DHCPv6, router as both client and server
 4. IPv6 NDP
 5. mwan3 tracking pings
```

then the state's own rules are appended in this order:

```text
 6. Allow peer endpoints (the gateways)
 7. Allow other allowed endpoints (API, etc.)
 8. Allow DNS to the VPN's DNS servers
 9. Allow traffic to and from the tunnel interface
10. Accept the inbound-exemption mark (INPUT/OUTPUT, only if exemptions exist)
11. Accept the bypass mark 0x14e in FORWARD (always)
12. DNS escape hatch (rate-limited)
13. Block DNS port 53 (reject)
14. NTP escape hatch (rate-limited)
15. Allow LAN traffic (RFC1918), if enabled
16. Final reject (catch-all)
```

**Rule 9 must come before rule 13.** A LAN client's DNS query, once routed into the tunnel,
arrives at the firewall as a packet on the tunnel interface destined for port 53. Put the blanket
port-53 reject first and it catches that query before the tunnel-allow rules get a look at it. DNS
then fails for every client on the LAN, silently, while everything else works — which is a
miserable thing to debug. In the correct order rule 13 only ever fires on DNS that is *not* in the
tunnel, which is the leak it exists to stop.

**Rule 12 must come before rule 13, and rule 14 depends on it.** The NTP hatch exists because a
router with no battery-backed clock boots with the wrong time and cannot validate TLS to the API
or gateway, deadlocking in `DeviceTimeDesynced`. But an NTP server can only be reached after
resolving `*.pool.ntp.org`, and rule 13 would reject that lookup. Both hatches are rate-limited —
sized for a cold-boot resolution round — so neither degrades into a general leak or an exfil
channel.

**Rules 8 and 12 are uid-scoped to root in every state where the tunnel is not up** — Blocked
*and* Connecting (`meta skuid 0` on fw4, `-m owner --uid-owner 0` on fw3). "Router-originated"
is not the same as "daemon-originated": dnsmasq answers LAN clients and re-originates their
queries upstream as its own OUTPUT packets, so an unscoped accept forwards every LAN lookup to
the WAN in plaintext while the kill switch is nominally blocking DNS — confirmed by simultaneous
LAN/WAN packet captures. The daemon resolves in-process (hickory, DoT/DoH to its bootstrap
resolvers) as uid 0, so root-scoping keeps reconnects working while dnsmasq's relayed queries
fall through to rule 13 and fail closed.

The cold-boot pool lookup used to be the exception: it ran `sysntpd → dnsmasq → upstream` under
dnsmasq's uid, which forced the Connecting hatch to stay unscoped — reopening the LAN relay leak
for the duration of every connect attempt. That dependency is gone: the daemon now owns its own
clock bootstrap (`clock_bootstrap` in nym-vpn-lib). When the clock predates the daemon binary's
own mtime, the daemon resolves the pool hostnames itself over plain UDP/53 to the static
resolver set (through the root-scoped rule 12 — deliberately not DoH/DoT, which need the working
clock we don't have yet), makes one SNTP exchange through rule 14, and steps the clock with a
forward-only `clock_settime(2)` floored at the binary mtime. A spoofed SNTP reply can therefore
only push the clock forward, making TLS fail closed. sysntpd keeps running and takes over fine
discipline once the tunnel is up; its own cold-boot lookup now fails closed, which is correct —
it was never entitled to punch through the kill switch.

Known residual limits of the uid scoping, accepted deliberately: a dnsmasq configured to run as
root (non-default) defeats it; any root-owned process on the router can still query the bootstrap
resolvers; and while disconnected, LAN DNS plus the router's own getaddrinfo consumers (opkg/apk,
wget) fail closed instead of resolving — that last one is the fix working as intended. On fw3 the
`owner` match needs `kmod-ipt-extra` plus the `iptables-mod-extra` userspace extension. The
backend probes the extension before applying a uid-scoped policy and, if it is unavailable,
omits the daemon-only exceptions while retaining the kill switch; it never silently falls back
to an unscoped DNS exception. Since Connecting is scoped too, an fw3 router without the
extension cannot resolve anything with the kill switch on — connecting fails closed until the
extension is installed or the kill switch is disabled, and the daemon logs exactly that.

**`ct established` is INPUT-only, deliberately.** That is return traffic *to* the router, so it is
not an egress bypass. Output and forward established accepts are scoped to the tunnel interface
inside the tunnel-allow rules instead. A blanket established accept in those chains let WAN-bound
established flows — IPv6 during reconnects especially — walk straight past the kill-switch.

### Bootstrap stays fail-closed

The first `Connecting` policy is applied even before gateway/API endpoints are known. It permits
only daemon-scoped bootstrap DNS and NTP plus the base DHCP/NDP/mwan3 traffic, so endpoint
resolution can proceed without opening router or LAN egress. As addresses are resolved they are
added to the daemon-scoped allow-list. Disconnected and Error use the same blocked bootstrap
policy when the on-disk endpoint cache is absent or expired.

## Surviving firewall reloads

OpenWrt rebuilds its entire ruleset from scratch on every reload, and reloads are frequent:
network reconfiguration, DHCP changes, dnsmasq restarts, a manual `fw3 reload` or `fw4 reload`.

On fw4 the kill-switch lives in its own `inet nym` table and survives; the reload only wipes the
daemon's masquerade and forward integration inside `inet fw4`. On fw3 all custom iptables chains
are wiped, so the daemon persists the applied restore scripts and tunnel-interface list under
`/tmp`; the fw3 include restores both blocking and forwarding planes.

fw3 policy changes use a fail-closed transition protocol. Before touching live or persisted state,
the daemon creates `/tmp/nym-firewall.transition`. While the marker exists, a firewall reload's
include run installs dedicated emergency OUTPUT/FORWARD drop chains (`NYM_EMERGENCY_OUT/FWD`;
INPUT is untouched and reply-direction packets are accepted, preserving SSH/LuCI management) instead of interpreting absent or
partially-written rules files as kill-switch-off. Once every v4/v6/interface file is complete, the
daemon removes the marker; if fw3's hook jumps are gone (a reload raced the apply) it re-activates
the desired policy from the same persisted scripts and lifts the emergency block last. The daemon
installs the emergency block itself only for a family's first activation (no hook jumps exist yet
for it — on first start, or for IPv6 when it becomes enabled after an IPv4-only policy — so a crash
between creating the chains and hooking them would otherwise leave that traffic open until the
daemon respawns); re-applying a live policy never blackholes traffic, because `*-restore` replaces
chain contents atomically and hook jumps are only (re)inserted when absent or when a foreign rule
has been placed ahead of them — each Nym jump must lead its `*_rule` hook chain, and the LAN
forwarding plane (`NYM_FORWARD_LAN`, which carries the MSS clamp) must be rule 1 ahead of
`NYM_FORWARD`. A
crash leaves the marker behind (reloads stay fail-closed); a later successful apply/reset or an
explicit service stop clears it. In the include, a restore or mandatory-jump failure also falls
back to the emergency block and returns failure rather than claiming success.

Both backends register a `firewall.nym_vpn` UCI include section pointing at a script the firewall
framework runs during its reload cycle:

| | Section | `type` | Extra |
|--|---------|--------|-------|
| fw3 | `include` | `script` | `reload=1` |
| fw4 | `include` | `script` | — |

**fw4 deliberately does not use `fw4_compatible=1`.** That flag makes fw4 capture the script's
stdout and splice it into the ruleset as nft syntax during assembly. What is needed here is the
opposite: the script's `nft add` side effects have to run *after* the table is loaded. Setting the
flag looks like the obvious fix and quietly breaks the integration.

The active backend's include is reconciled at install and upgrade time by
`/etc/uci-defaults/luci-app-nym-vpn` (invoked immediately by package `postinst`), so a fresh install
does not wait for the next reboot to gain reload protection. Backend detection is shared
(`/usr/share/nym-vpn/fw-backend.sh`, used by uci-defaults, `prerm` and the init script): live
state first, then the firewall init script's own backend, then binary presence — so a boot-time
run on a vendor image shipping both stacks still registers the right include. `prerm` leaves the
UCI section alone on upgrades so an interrupted transaction cannot strand the router without it.

## Inbound service exemptions

When connected, the daemon routes all output through the tunnel — including the **reply** to an
inbound connection from the WAN. (That routing is unconditional. The kill-switch only decides
whether non-tunnel egress is additionally *blocked*.)

This breaks port-forwarded services. An external client connects to a public port, the service
replies, and the reply goes out the tunnel. The source IP at egress no longer matches what the
client connected to, so the connection dies.

An inbound exemption adds a per-`{proto, port}` reply path around the tunnel, in three layers:

**1. Mark on inbound, in mangle PREROUTING.** The `mangle_prerouting` chain in table `inet nym`
hooks at priority `mangle - 10` (= -160), ahead of OpenWrt's DNAT at `dstnat` priority -100. It
matches `iifname "<wan>" ct state new <proto> dport <X>` and sets `ct mark = 0x14e`. Running
before DNAT is what makes the mark stick to the connection even when the destination gets
rewritten to a LAN host.

**2. Restore the mark onto reply packets.** Both `mangle_prerouting` (forwarded LAN replies) and
`mangle_output` (router-originated replies) start with `meta mark set ct mark`, copying the
conntrack mark onto the packet mark that routing rule lookup uses. For locally generated packets
the mangle hook triggers a route reevaluation after the mark changes.

**3. Route marked packets around the tunnel.** `ip rule fwmark 0x14e lookup main` at priority 90
sits ahead of the suppress rule (100) and the tunnel rule (200), so marked replies resolve against
the main table — real WAN default — instead of table 333. This rule is installed for the whole
tunnel lifetime, not only when exemptions exist, which is also what makes it the carve-out path
for [split tunnelling](../guide/split-tunneling.md): anything marked `0x14e` bypasses the tunnel,
inbound reply or user-defined outbound exclusion alike.

The filter chains get `meta mark 0x14e accept` after the tunnel-allow rules and before the DNS
block, so the kill-switch reject does not fire on the marked reply.

**This only adds a reply path.** Outbound enforcement is unchanged: a connection the router
initiates has `ct mark = 0`, because the prerouting rule never fired for it — it was not
`iif=wan ct state new` — so it stays in the tunnel. A compromised exempt service cannot exfiltrate
through its own port.

NymVPN does not own port forwards. Those stay in OpenWrt's `firewall.@redirect[]` and are
configured in the native firewall UI. For a LAN-hosted service you set up both: the port forward
there, the exemption here. Operator-facing usage is in
[Inbound Services](../guide/inbound-services.md).

## mwan3

mwan3 does multi-WAN load balancing and failover, and it decides whether a WAN is alive by pinging
tracking IPs. Several supported devices — GL.iNet especially — ship it enabled even on single-WAN
setups.

A kill-switch that blocks all non-tunnel traffic blocks those pings too. mwan3 then concludes the
WAN is down and starts a failover cascade, on a WAN that is working perfectly.

So the firewall reads mwan3's tracking IPs from UCI at rule-build time and adds explicit ICMP
allow rules for them. No mwan3 installed means no tracking IPs found and no extra rules — a no-op
on devices that do not have it.
