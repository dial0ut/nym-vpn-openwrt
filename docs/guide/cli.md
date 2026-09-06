# CLI Usage

`nym-vpnc` is the command-line client. It talks to the `nym-vpnd` daemon over gRPC — everything
LuCI can do goes through the same commands.

## Connection

```bash
nym-vpnc connect-v2
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
```

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
```

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

## Anonymous statistics

Anonymous, aggregated usage statistics for Nym. On by default; reports only leave through the
tunnel while connected unless `--allow-disconnected on` is set. The same switch is in LuCI under
**Privacy**.

```bash
nym-vpnc network-stats get
nym-vpnc network-stats set --enabled off
nym-vpnc network-stats set --enabled on --allow-disconnected off
```

## LAN policy

Whether LAN devices can reach each other and local services while the VPN is up.

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
