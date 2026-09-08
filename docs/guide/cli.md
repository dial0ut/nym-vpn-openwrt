# CLI Usage

`nym-vpnc` is the command-line client. It talks to the `nym-vpnd` daemon over gRPC — everything
LuCI can do goes through the same commands.

## Connection

```bash
nym-vpnc connect-v2
nym-vpnc connect-v2 --relax-independence   # connect even if entry and exit are related (this session only)
nym-vpnc disconnect
nym-vpnc status
```

## Gateways

```bash
nym-vpnc gateway get
nym-vpnc gateway list mixnet-exit          # or mixnet-entry, wg
nym-vpnc gateway set --entry-country DE --exit-country CH
nym-vpnc gateway set --exit-id <base58-gateway-id>
nym-vpnc gateway set --entry-random --exit-random
nym-vpnc gateway tentative                 # the pair a connect would pick right now
```

`gateway list` shows each gateway's operator **family** (node family) when it has declared one,
and `status` names the family of the entry and exit while connected.

### Gateway independence

A two-hop tunnel only hides who talks to whom if the entry and the exit are run by unrelated
parties. The daemon therefore picks the exit first and then only accepts an entry that is
**independent** of it: a different node family (operator group), a different ASN and a
non-overlapping announced prefix. All three criteria are on by default and apply to random and
country selections as well as to explicitly pinned gateways.

When no independent pair matches the current settings — for example both gateways of a small
country belong to one operator, or you pinned two gateways of the same family — the connect stops
in an error state instead of quietly pairing related gateways. `nym-vpnc status` then says:

```
the selected entry and exit are not independent (same operator family/ASN/subnet);
reconnect with --relax-independence or change gateways
```

`nym-vpnc connect-v2 --relax-independence` connects anyway. The relaxation is scoped to that
connect session: it survives the daemon's automatic reconnects but ends at the next disconnect,
and the persisted setting is left untouched. To turn the criteria off permanently use
`nym-vpnc tunnel set --gateway-independence off`.

`nym-vpnc gateway tentative` (or `--json`) previews the outcome without connecting: the probable
entry and exit with id, name, country and family, "needs relaxed independence criteria" when only
a related pair exists, or "no gateways available". The daemon runs the same selection a connect
would, including its temporary blacklist of failing entry gateways, and creates no key material.

### Latency and packet loss

`gateway test` pings gateways from the router and reports RTT and loss, so
you can compare candidate pairs before committing to one. The probes are sent
by the daemon, which means it works while disconnected and while connected
with the kill switch on; while connected the gateways are still probed
directly over the WAN, not through the tunnel.

```bash
nym-vpnc gateway test                          # the configured (or active) entry and exit
nym-vpnc gateway test --exit-country CH        # best 5 exits in CH against the current entry
nym-vpnc gateway test --entry-country DE --exit-country CH --top 3
nym-vpnc gateway test --entry-id <ID> --exit-id <ID> --count 10 --timeout 1
nym-vpnc gateway test --id <ID> --id <ID>      # specific gateways, no role
nym-vpnc gateway test --json
```

Defaults: 5 probes per gateway, 2 s timeout per probe, top 5 gateways per
country (by directory score). When both an entry and an exit were probed, a
second table lists every pair with the summed average RTT, best first — a
rough proxy for the round trip through that pair. Country selectors pick from
the WireGuard gateway list in two-hop mode and from the mixnet entry/exit
lists otherwise; `--top` caps at 20, `--count` at 20 and `--timeout` at 10 s.

A gateway that answers the directory but not ICMP shows 100% loss; some
operators filter echo requests, so treat loss as a hint, not a verdict.

## Account

```bash
nym-vpnc account set "your twenty four word mnemonic phrase here"
nym-vpnc account get
nym-vpnc account forget
nym-vpnc account rotate-keys
```

## Tunnel settings

```bash
nym-vpnc tunnel get
nym-vpnc tunnel set --ipv6 on --two-hop on
nym-vpnc tunnel set --killswitch off       # allows WAN fallback and carve-outs
nym-vpnc tunnel set --killswitch on
nym-vpnc tunnel set --stealth-api on       # API via cover domains on every request
nym-vpnc tunnel set --stealth-api off      # default: cover domains only after a direct request fails
nym-vpnc tunnel set --gateway-independence off   # accept related entry/exit pairs (default: on)
nym-vpnc tunnel set --family-reminders off       # stop reminding about related pairs (default: on)
nym-vpnc tunnel set --always-on on               # connect at daemon start, keep retrying (default: off)
```

**Always On** makes the daemon connect when it starts — once a default route exists — and keep
the tunnel up on its own: reconnects after drops and WAN outages, error states retried with a
growing backoff (5 s doubling to 5 min for firewall/routing/DNS/TUN failures, 60 s then 5 min for
"no performant gateway", clock skew or exhausted bandwidth), and a fresh gateway selection after
ten minutes of Connecting. Errors that need a change from you (account state, a pinned pair that
fails the independence criteria) stop the retries until the configuration or the account changes
or you connect. `nym-vpnc disconnect` pauses it for this session without turning the setting off;
the next connect or daemon start resumes it. `nym-vpnc status` shows an `Always on:` line while
the setting is on: `active`, `retrying in 42 s (attempt 3, last error SetRouting)`, `paused
(disconnected by user)` or `stopped — NeedsRelaxedIndependenceCriteria`. Six consecutive
infrastructure failures make the daemon exit (code 3) for procd to respawn, kill-switch intact;
a service loop that stops answering for three minutes exits the same way (code 2).

**Gateway independence** switches the three independence criteria (family, ASN, subnet) together;
`tunnel get` prints `Gateway independence: on (family, ASN, subnet)` or `off`. Changing it while
connected re-selects the gateways. **Family reminders** only control whether user interfaces
remind you when a pair is not independent; they never affect the tunnel. See
[Gateway independence](#gateway-independence) for what the criteria mean and how to connect
anyway for a single session.

**Stealth API connect** is the same switch as in the NymVPN mobile and desktop apps. The daemon
talks to the Nym API (account, gateway directory, network discovery) over HTTPS; by default it
goes direct and only falls back to *cover domains* — domain fronting through a CDN — when a
direct request fails. With it on, every API request uses the cover domains from the start. Turn
it on where the API hosts are blocked outright; the price is slower API calls (gateway lists,
account sync, the setup phase of a connect). It only affects API traffic, not the tunnel, so it
applies immediately without a reconnect. Shown in `nym-vpnc tunnel get`, which also appends
`(no cover domains available)` when the network environment publishes none — the setting then has
nothing to route through and requests go direct.

## Inbound services

Keeps port-forwarded services reachable from the WAN while the kill-switch is on. The port is the
**WAN-side** one; LAN-hosted services also need a port forward in `Network → Firewall → Port
Forwards`. Full mechanism in [Inbound Services](inbound-services.md).

```bash
nym-vpnc inbound list
nym-vpnc inbound add tcp:443 --label "HTTPS"
nym-vpnc inbound add udp:51820
nym-vpnc inbound del tcp:443
```

## DNS

```bash
nym-vpnc dns get
nym-vpnc dns set 1.1.1.1 9.9.9.9
nym-vpnc dns enable
nym-vpnc dns disable
nym-vpnc dns clear
```

## Ad blocking

```bash
nym-vpnc ad-block get
nym-vpnc ad-block set enabled
nym-vpnc ad-block set disabled
```

## LAN policy

Whether LAN devices can reach each other and local services while the VPN is up. Which zones
reach the tunnel at all is the firewall's: the package declares a `nym` zone and a `lan -> nym`
forwarding, so a guest or IoT zone needs its own forwarding to `nym` (Network → Firewall in LuCI,
or a `config forwarding` section) before its clients can use the VPN.

```bash
nym-vpnc lan get
nym-vpnc lan set allow
nym-vpnc lan set block
```

## Network

```bash
nym-vpnc network get
nym-vpnc network set mainnet                # or canary
```

## Daemon

```bash
nym-vpnc info

/etc/init.d/nym-vpnd start
/etc/init.d/nym-vpnd stop
/etc/init.d/nym-vpnd restart
/etc/init.d/nym-vpnd status

/etc/init.d/nym-vpnd enable                 # start on boot
/etc/init.d/nym-vpnd disable
```

procd respawns the daemon automatically if it dies. On `stop`, the init script disconnects and
tears down the firewall table — including when the daemon is hung and cannot be asked nicely.

## Configuration

Settings live in `/etc/config/nym-vpn` (UCI, preserved across firmware upgrades). Read it if you
like:

```bash
uci show nym-vpn
```

Write it through `nym-vpnc` or LuCI, not by hand — the daemon holds its own copy of most settings
and editing UCI directly will not reach it.

## Logs

```bash
logread -e nym-vpnd
logread -e nym-vpnd -f
```
