# Gotatun WireGuard Backend

## Overview

NymVPN uses [mullvad/gotatun](https://github.com/mullvad/gotatun), a pure Rust userspace WireGuard implementation, for its tunnel backend. This replaces both `wireguard-go` (Go FFI) and kernel WireGuard modules.

**Location:** `nym-vpn-core/crates/nym-wg-gotatun/`

## Why Gotatun?

| Approach | Problem |
|----------|---------|
| Kernel WireGuard (`kmod-wireguard`) | Not available on all devices, requires kernel module management |
| wireguard-go (`nym-wg-go`) | Go cross-compilation with MUSL is painful, especially for MIPS |
| **gotatun** | Pure Rust, single toolchain, works everywhere with `kmod-tun` |

## Modules

- **`lib.rs`** — Public API: `PrivateKey`, `PublicKey`, `PresharedKey`, `PeerConfig`, `PeerEndpointUpdate`
- **`wireguard_go.rs`** — `Tunnel` struct wrapping gotatun; `start()`, `stop()`, `update_peers()`
- **`amnezia.rs`** — `AmneziaConfig` with 9 obfuscation parameters
- **`amnezia_udp.rs`** — UDP transport layer obfuscation (504 lines)

## Key Design Decisions

- `PrivateKey` derives `Zeroize, ZeroizeOnDrop` for secure key handling
- `AmneziaConfig::rand()` returns `Result` instead of panicking
- Feature-gated: `nym-vpn-lib` enables the `amnezia` feature

## AmneziaWG Obfuscation

AmneziaWG defeats deep packet inspection that identifies and blocks standard WireGuard traffic.

**How it works:**

The obfuscation layer wraps gotatun's UDP socket factory:

1. `AmneziaUdpFactory<F>` — wraps the socket factory
2. `AmneziaSend<S>` — remaps WireGuard message headers and prepends junk packets during handshakes
3. `AmneziaRecv<R>` — strips junk and reverses header remapping on receive

When the config is `OFF` or absent, the layer operates in passthrough mode with zero overhead.

### Obfuscation Parameters

| Parameter | Field | Description |
|-----------|-------|-------------|
| Jc | `junk_pkt_count` | Number of junk packets before handshake |
| Jmin | `junk_pkt_min_size` | Minimum junk packet size |
| Jmax | `junk_pkt_max_size` | Maximum junk packet size |
| S1 | `init_pkt_junk_size` | Junk padding on handshake init |
| S2 | `response_pkt_junk_size` | Junk padding on handshake response |
| H1 | `init_pkt_magic_header` | Header remap for init messages |
| H2 | `response_pkt_magic_header` | Header remap for response messages |
| H3 | `under_load_pkt_magic_header` | Header remap for under-load messages |
| H4 | `transport_pkt_magic_header` | Header remap for transport data |
