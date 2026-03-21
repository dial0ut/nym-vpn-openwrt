# Architecture Overview

## Fork Rationale

The upstream `nymtech/nym-vpn-client` is a monorepo serving desktop clients on macOS, Windows, and Linux, plus mobile apps on iOS and Android. It contains over 40 workspace crates, FFI bindings for Swift and Kotlin, and platform-specific code for each OS.

None of that applies to an OpenWrt router. This repository was created by filtering the monorepo down to Linux-only paths and stripping all non-Linux platform code. The result is 26 workspace crates, all targeting musl-linked static binaries. The LuCI web frontend was merged in from a separate repository with full commit history to keep everything in one place.

The fork allows the project to move independently of upstream release cycles, maintain OpenWrt-specific subsystems that would not belong in the upstream repo, and keep the build infrastructure focused on embedded Linux targets.

## Router vs. Desktop

A desktop VPN client protects a single user running applications on that machine. The client can use fwmark-based split tunneling to route some apps through the VPN and let others bypass it. The user manages their own connection lifecycle.

A router sits between an entire LAN and the internet. Every device behind it sends traffic through the router. This changes two fundamental requirements.

First, the firewall must be a kill-switch that covers all LAN traffic uniformly. Per-app split tunneling does not apply because the router sees IP packets from downstream clients, not application identities. The kill-switch must prevent DNS leaks and block non-tunnel traffic for every device on the network.

Second, the VPN daemon must integrate with the router's process manager for automatic recovery. If the daemon crashes on a desktop, the user notices and restarts it. If it crashes on a headless router, all downstream clients lose connectivity with no one to intervene. See [Firewall Integration](firewall.md) for how the kill-switch is designed.

## Single Toolchain

The upstream project used wireguard-go for its WireGuard backend, which required both a Go and a Rust toolchain for cross-compilation. On musl-based targets like OpenWrt, Go's `c-archive` buildmode has a known segfault issue, making this approach unreliable.

By replacing wireguard-go with a pure Rust userspace WireGuard implementation, the entire project builds with a single Rust toolchain. This simplifies CI, eliminates CGo cross-compilation problems, and makes Tier 3 target support feasible. See [WireGuard Backend Selection](wireguard.md) for the full rationale.

## OpenWrt-Native Integration

Rather than treating OpenWrt as generic Linux, the project hooks into its native subsystems so the VPN behaves like any other router service, surviving reboots, firewall reloads, and daemon crashes without user intervention.

The daemon runs as a procd service with automatic respawn. On stop, the init script calls `nym-vpnc disconnect` before killing the process so that firewall rules and tunnels are cleaned up rather than left dangling. Persistent configuration lives in UCI, though the config is deliberately minimal: just an `enabled` flag and a `network` selector. Everything else (gateway selection, tunnel mode, account credentials) is managed dynamically through RPC.

The LuCI frontend talks to the daemon indirectly: rpcd methods execute `nym-vpnc` commands and parse their output into JSON via `jshn`. This adds a layer of indirection but keeps the frontend aligned with OpenWrt's standard RPC architecture and avoids shipping a gRPC client in JavaScript.

DNS redirection works through dnsmasq rather than a standalone resolver. The daemon sets `noresolv=1` via UCI to stop dnsmasq from querying ISP DNS servers, adds the VPN's DNS servers as upstream, and writes `/etc/resolv.conf` for local programs on the router itself. These UCI changes are staged without committing, so they automatically revert on reboot. A marker file detects unclean shutdowns and triggers rollback on next startup.

The firewall integration is the most involved piece. OpenWrt rebuilds all firewall rules from scratch on every reload event. Network reconfiguration, DHCP changes, and manual reloads all trigger a full rebuild. The VPN installs UCI include scripts that the firewall framework calls during its reload cycle, re-applying the kill-switch rules automatically. See [Firewall Integration](firewall.md) for the rule ordering constraints and mwan3 interaction.

## Component Relationships

```text
┌─────────────────────────────────────────────────────┐
│                    OpenWrt Router                     │
│                                                       │
│  ┌──────────┐    gRPC    ┌──────────┐                │
│  │ nym-vpnc │◀──────────▶│ nym-vpnd │                │
│  │  (CLI)   │            │ (daemon) │                │
│  └──────────┘            └────┬─────┘                │
│       ▲                       │                       │
│       │                       ▼                       │
│  ┌────┴─────┐           ┌──────────┐  ┌──────────┐  │
│  │   LuCI   │           │ gotatun  │  │ firewall │  │
│  │  rpcd    │           │ WireGuard│  │ fw3/fw4  │  │
│  └──────────┘           └────┬─────┘  └──────────┘  │
│                               │                       │
│                          ┌────┴─────┐                │
│                          │ TUN dev  │                │
│                          │ nym0/nym1│                │
│                          └──────────┘                │
└─────────────────────────────────────────────────────┘
```

The daemon and CLI communicate over gRPC using protobuf. All user-facing operations go through `nym-vpnc`, whether invoked directly from the command line or through the LuCI RPC backend.

The LuCI frontend does not speak gRPC. Instead, it calls rpcd methods that execute CLI commands under the hood. This adds a layer of indirection but avoids shipping a gRPC client in JavaScript and keeps the frontend aligned with OpenWrt's standard RPC architecture.

The daemon manages two TUN devices: `nym0` for the entry gateway tunnel and `nym1` for the exit gateway tunnel. The firewall component detects whether the router runs fw3 or fw4 and installs rules accordingly.

## Traffic Flow and Trust Boundaries

1. A LAN client sends traffic to the router
2. Firewall rules redirect outbound traffic into the TUN device
3. The daemon picks up packets from the TUN device
4. Packets enter WireGuard tunnel 1 to the entry gateway
5. The entry gateway routes traffic through the Nym mixnet
6. Traffic exits through WireGuard tunnel 2 at the exit gateway
7. The exit gateway forwards to the public internet

Two separate WireGuard tunnels exist because the entry and exit gateways are different trust boundaries. The entry gateway knows the client's real IP but cannot see the destination. The exit gateway knows the destination but cannot identify the client. Neither gateway alone can correlate who is communicating with whom.

The only kernel dependency is `kmod-tun`, which provides the TUN device interface. No WireGuard kernel module is needed because the WireGuard protocol runs entirely in userspace.
