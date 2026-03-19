# Architecture Overview

## Components

```
┌─────────────────────────────────────────────────────┐
│                    OpenWrt Router                     │
│                                                       │
│  ┌──────────┐    gRPC    ┌──────────┐                │
│  │ nym-vpnc │◀─────────▶│ nym-vpnd │                │
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
│                          └──────────┘                │
└─────────────────────────────────────────────────────┘
```

### nym-vpnd (Daemon)

The core VPN daemon. Manages:

- Mixnet connections to entry and exit gateways
- Two WireGuard tunnels (entry + exit) via gotatun
- Firewall rule installation via `nym-firewall`
- Account credential management

### nym-vpnc (CLI Client)

Communicates with `nym-vpnd` over gRPC (protobuf). All user-facing operations (connect, disconnect, gateway selection) go through the CLI.

### LuCI Frontend

A JavaScript-based web interface that calls `nym-vpnc` indirectly through rpcd shell scripts. The RPC backend (`/usr/libexec/rpcd/nym-vpn`) parses CLI output into JSON for the frontend.

### Gotatun WireGuard

Pure Rust userspace WireGuard implementation. See [Gotatun details](gotatun.md).

### Firewall Integration

Automatic firewall rule management for both iptables (fw3) and nftables (fw4). See [Firewall details](firewall.md).

## Data Flow

1. LAN client sends traffic to the router
2. Firewall rules redirect traffic into the TUN device
3. `nym-vpnd` picks up packets from TUN
4. Packets enter WireGuard tunnel 1 → entry gateway
5. Entry gateway mixes traffic through the Nym mixnet
6. Traffic exits through WireGuard tunnel 2 → exit gateway
7. Exit gateway forwards to the public internet

## Crate Workspace

The Rust workspace (`nym-vpn-core/`) contains ~26 crates. Key crates:

| Crate | Purpose |
|-------|---------|
| `nym-vpn-lib` | Core VPN library |
| `nym-vpnd` | Daemon binary |
| `nym-vpnc` | CLI binary |
| `nym-wg-gotatun` | WireGuard backend |
| `nym-firewall` | Firewall management |
| `nym-routing` | Route table management |
| `nym-dns` | DNS configuration |
| `nym-connection-monitor` | Tunnel health monitoring |
