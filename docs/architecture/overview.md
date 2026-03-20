# Architecture Overview

## Components

```text
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
│                          │ nym0/nym1│                │
│                          └──────────┘                │
└─────────────────────────────────────────────────────┘
```

### nym-vpnd (Daemon)

The core VPN daemon, managed by procd with automatic respawn (5 attempts per hour). It manages:

- Mixnet connections to entry and exit gateways
- Two WireGuard tunnels (entry `nym0` + exit `nym1`) via gotatun
- Firewall rule installation via `nym-firewall`, with auto-detection of fw3 or fw4
- Account credential management
- AmneziaWG obfuscation when enabled

The init script (`/etc/init.d/nym-vpnd`) calls `nym-vpnc disconnect` on stop to ensure firewall rules and tunnels are cleaned up gracefully.

### nym-vpnc (CLI Client)

Communicates with `nym-vpnd` over gRPC (protobuf). All user-facing operations go through the CLI: connection management, gateway selection, tunnel configuration, account handling, DNS, and LAN policy.

### LuCI Frontend

A JavaScript web interface with 21 RPC methods bridging the browser to `nym-vpnc`. The RPC backend (`/usr/libexec/rpcd/nym-vpn`) is a shell script that executes CLI commands, parses their output into JSON via `jshn`, and returns structured responses.

The frontend loads 10 parallel RPC calls on init via a batched `init` method that returns status, gateway config, tunnel config, account state, network, LAN policy, DNS, ad-block, and daemon status in a single response.

Key UI elements:

- Animated connection status ring with uptime timer (persisted to localStorage)
- Visual mixnet hop chain showing entry and exit gateways
- Expandable settings cards for tunnel, gateway, account, DNS, LAN policy, and daemon control
- Toast notifications and confirmation modals

### Gotatun WireGuard

Pure Rust userspace WireGuard implementation. No kernel module dependency beyond `kmod-tun`. See [Gotatun details](gotatun.md).

### Firewall Integration

Automatic firewall rule management for both iptables (fw3) and nftables (fw4), with mwan3 compatibility and IPv6 support. See [Firewall details](firewall.md).

## Data Flow

1. LAN client sends traffic to the router
2. Firewall rules redirect traffic into the TUN device (`nym0` or `nym1`)
3. `nym-vpnd` picks up packets from the TUN device
4. Packets enter WireGuard tunnel 1 to the entry gateway
5. The entry gateway routes traffic through the Nym mixnet
6. Traffic exits through WireGuard tunnel 2 at the exit gateway
7. The exit gateway forwards to the public internet

## Crate Workspace

The Rust workspace (`nym-vpn-core/`) contains ~26 crates. Key crates:

| Crate | Purpose |
|-------|---------|
| `nym-vpn-lib` | Core VPN library, enables gotatun's `amnezia` feature |
| `nym-vpnd` | Daemon binary |
| `nym-vpnc` | CLI binary |
| `nym-wg-gotatun` | WireGuard backend with AmneziaWG obfuscation |
| `nym-firewall` | Firewall management with fw3/fw4 backends |
| `nym-routing` | Route table management |
| `nym-dns` | DNS configuration |
| `nym-connection-monitor` | Tunnel health monitoring |
