# Architecture Overview

## Why this is a fork

Upstream `nymtech/nym-vpn-client` is a monorepo covering macOS, Windows, Linux, iOS and Android:
40+ workspace crates, Swift and Kotlin FFI bindings, per-platform code throughout.

None of that runs on a router. This repo is that monorepo filtered down to the Linux-only paths,
with every other platform stripped — 26 crates, all building against musl for OpenWrt targets. The
LuCI frontend was merged in from its own repo with history intact.

Being a fork means release cycles are ours, OpenWrt-specific subsystems live somewhere they
belong, and the build infrastructure only has to care about embedded Linux.

## Router is not desktop

A desktop client protects one machine. It can split-tunnel per application, because it can see
which process a packet came from, and a human is sitting there to restart it when it dies.

A router sits between a whole LAN and the internet, and neither of those holds.

Per-app split tunnelling is meaningless — the router sees IP packets from downstream clients, not
application identities. So the firewall has to be a kill-switch that covers every device
uniformly, DNS included. See [Firewall Integration](firewall.md).

And nobody is watching. If the daemon dies on a headless router, every device behind it loses
connectivity with no one to notice. So the daemon runs under procd with respawn, and the init
script tears down the kill-switch on stop even when the daemon is too wedged to do it itself.

## One toolchain

Upstream used wireguard-go, which needs a Go toolchain alongside Rust to cross-compile — and Go's
`c-archive` buildmode segfaults on musl. Replacing it with a pure-Rust userspace WireGuard means
the whole tree builds with Rust alone. That is what makes Tier 3 targets feasible at all.
See [WireGuard Backend](wireguard.md).

## OpenWrt-native integration

The point is that the VPN behaves like any other router service — surviving reboots, firewall
reloads, and its own crashes without anyone logging in.

**Process management.** procd service with automatic respawn. On stop the init script runs
`nym-vpnc disconnect` before killing the process, so firewall rules and tunnels get cleaned up
instead of being left dangling.

**Configuration.** UCI holds almost nothing — an `enabled` flag and a `network` selector. Gateway
selection, tunnel mode and credentials are all managed dynamically over RPC and stored in the
daemon's own state.

**LuCI.** The frontend does not speak gRPC. rpcd methods shell out to `nym-vpnc` and parse the
output into JSON. That is a layer of indirection, and it buys not having to ship a gRPC client in
JavaScript.

**DNS.** Handled through dnsmasq rather than a resolver of our own: the daemon writes the tunnel's
servers into a resolv file it owns and points dnsmasq at it, which dnsmasq picks up live. No
restart, so no window with DNS down for the whole LAN on every connect. See [DNS](../guide/dns.md).

**Firewall.** The involved one. OpenWrt rebuilds its entire ruleset from scratch on every reload,
and reloads happen constantly — network reconfiguration, DHCP changes, a manual `fw4 reload`.
NymVPN registers UCI include scripts that the firewall framework calls during that rebuild, so the
kill-switch reinstalls itself. See [Firewall Integration](firewall.md) for the ordering
constraints and the mwan3 interaction.

## Components

```text
┌───────────────────────────────────────────────────────┐
│                    OpenWrt router                     │
│                                                       │
│   ┌──────────┐    gRPC     ┌──────────┐               │
│   │ nym-vpnc │◀───────────▶│ nym-vpnd │               │
│   │  (CLI)   │             │ (daemon) │               │
│   └────▲─────┘             └────┬─────┘               │
│        │                        │                     │
│   ┌────┴─────┐        ┌─────────┴─────┐  ┌──────────┐ │
│   │   LuCI   │        │    gotatun    │  │ firewall │ │
│   │   rpcd   │        │  (WireGuard)  │  │ fw3/fw4  │ │
│   └──────────┘        └─────────┬─────┘  └──────────┘ │
│                                 │                     │
│                        ┌────────┴─────┐               │
│                        │   TUN dev    │               │
│                        │  nym0, nym1  │               │
│                        └──────────────┘               │
└───────────────────────────────────────────────────────┘
```

Everything user-facing goes through `nym-vpnc`, whether you type it or LuCI's rpcd backend runs
it for you. The CLI talks to the daemon over gRPC with protobuf.

Two TUN devices: `nym0` for the entry gateway tunnel, `nym1` for the exit. The firewall component
detects fw3 or fw4 at startup and installs the matching ruleset.

## Two tunnels

Two tunnels rather than one because entry and exit are separate trust boundaries. The entry
gateway sees your real IP but not the destination. The exit gateway sees the destination but not
who you are. Correlating the two takes both gateways cooperating.

`kmod-tun` is the only kernel dependency. WireGuard runs entirely in userspace, so no kernel
WireGuard module is needed.
