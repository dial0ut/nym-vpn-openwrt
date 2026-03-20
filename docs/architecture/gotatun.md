# Gotatun WireGuard Backend

## Overview

NymVPN uses [mullvad/gotatun](https://github.com/mullvad/gotatun), a pure Rust userspace WireGuard implementation, for its tunnel backend. This replaces both `wireguard-go` and kernel WireGuard modules.

**Location:** `nym-vpn-core/crates/nym-wg-gotatun/`

## Why Gotatun?

| Approach | Problem |
|----------|---------|
| Kernel WireGuard (`kmod-wireguard`) | Not available on all devices, requires kernel module management |
| wireguard-go (`nym-wg-go`) | Go cross-compilation with MUSL is painful, especially for MIPS |
| **gotatun** | Pure Rust, single toolchain, works everywhere with `kmod-tun` |

## Key Types

```rust
// Secure key types with automatic zeroing
pub struct PrivateKey(x25519_dalek::StaticSecret);  // Zeroize, ZeroizeOnDrop
pub struct PublicKey(x25519_dalek::PublicKey);
pub struct PresharedKey([u8; 32]);                   // Zeroize, ZeroizeOnDrop

pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<PresharedKey>,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
}

pub struct PeerEndpointUpdate {
    pub public_key: PublicKey,
    pub endpoint: SocketAddr,
}
```

`PrivateKey` and `PresharedKey` derive `Zeroize, ZeroizeOnDrop` for secure key material handling. Both hide their values in debug output, printing `(hidden)` instead.

## Tunnel API

```rust
pub struct Tunnel {
    device: device::Device<DeviceTransports>,
}

impl Tunnel {
    pub async fn start(config: Config, tun: tun::AsyncDevice) -> Result<Self>
    pub async fn stop(self)
    pub async fn update_peers(&mut self, peer_updates: &[PeerEndpointUpdate]) -> Result<()>
}
```

The `Tunnel` takes an async TUN device directly. On Linux, it optionally sets `fwmark` on the UDP socket for policy routing. Peer endpoints can be updated at runtime via `update_peers()` without restarting the tunnel.

### Configuration

```rust
pub struct InterfaceConfig {
    pub listen_port: Option<u16>,
    pub private_key: PrivateKey,
    pub mtu: u16,
    pub fwmark: Option<u32>,
    pub azwg_config: Option<AmneziaConfig>,  // when "amnezia" feature enabled
}

pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `gotatun` | Pure Rust WireGuard implementation |
| `x25519-dalek` | X25519 key exchange with `static_secrets` and `zeroize` features |
| `tun` | Async TUN device interface |
| `zeroize` | Secure memory clearing with derive macros |
| `ipnetwork` | IP network/CIDR types |
| `rand` | RNG for Amnezia parameter randomization |

## AmneziaWG Obfuscation

AmneziaWG defeats deep packet inspection that identifies and blocks standard WireGuard traffic. It is implemented at the UDP transport layer in `amnezia_udp.rs` (504 lines) and gated behind the `amnezia` feature flag, which `nym-vpn-lib` enables.

### How It Works

The obfuscation layer wraps gotatun's UDP socket factory:

1. `AmneziaUdpFactory<F>` wraps the socket factory to produce obfuscated sockets
2. `AmneziaSend<S>` remaps WireGuard message headers and prepends junk packets during handshakes
3. `AmneziaRecv<R>` strips junk and reverses header remapping on receive

When the config is `OFF` or absent, the layer operates in passthrough mode with zero overhead.

### Obfuscation Parameters

```rust
pub struct AmneziaConfig {
    pub junk_pkt_count: u8,              // Jc:  junk packets before handshake (3-9 for rand)
    pub junk_pkt_min_size: u16,          // Jmin: minimum junk packet size (0-899)
    pub junk_pkt_max_size: u16,          // Jmax: maximum junk packet size (fixed 1000)
    pub init_pkt_junk_size: u16,         // S1:  init packet junk padding (15-149)
    pub response_pkt_junk_size: u16,     // S2:  response packet junk padding (15-149)
    pub init_pkt_magic_header: i32,      // H1:  header remap for init messages
    pub response_pkt_magic_header: i32,  // H2:  header remap for response messages
    pub under_load_pkt_magic_header: i32,// H3:  header remap for under-load messages
    pub transport_pkt_magic_header: i32, // H4:  header remap for transport data
}
```

### Predefined Configurations

**`OFF`** disables obfuscation. All junk parameters are zero, magic headers are the standard WireGuard values (1, 2, 3, 4).

**`BASE`** adds 4 junk packets (40-70 bytes) before each handshake but does not remap headers or add junk padding to handshake messages.

**`rand()`** generates a randomized config. It tries up to 16 times to produce a valid config, returning an error if all attempts fail validation. Validation rejects configs where:

- `junk_pkt_count` > 128
- `junk_pkt_max_size` > 1280
- `junk_pkt_min_size` > `junk_pkt_max_size`
- `init_pkt_junk_size` or `response_pkt_junk_size` > 1280
- Any two magic headers share the same value
