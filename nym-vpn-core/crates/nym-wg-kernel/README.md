# nym-wg-kernel

Kernel WireGuard via netlink for Linux musl targets.

## Problem

Go's `c-archive` buildmode segfaults on musl libc ([golang/go#13492](https://github.com/golang/go/issues/13492)). This breaks wireguard-go on Alpine Linux, OpenWRT, and other musl systems.

## Solution

Use Linux kernel WireGuard through netlink protocol (same as Mullvad VPN).

## Usage

```rust
use nym_wg_kernel::tunnel::{Tunnel, Config, InterfaceConfig, PeerConfig};

let config = Config {
    interface: InterfaceConfig {
        private_key: [/* 32 bytes */],
        addresses: vec!["10.0.0.2/32".parse()?],
        listen_port: None,
        mtu: 1420,
        fwmark: None,
    },
    peers: vec![PeerConfig {
        public_key: [/* 32 bytes */],
        endpoint: "192.168.1.1:51820".parse()?,
        allowed_ips: vec!["0.0.0.0/0".parse()?],
        persistent_keepalive: Some(25),
    }],
};

let tunnel = Tunnel::start("wg0", config).await?;
// Tunnel active, cleans up on drop
tunnel.stop().await?;
```

## Requirements

- Linux kernel 5.6+ (WireGuard mainlined)
- WireGuard kernel module loaded: `modprobe wireguard`
- Root or `CAP_NET_ADMIN`

## Limitations

- Linux only (musl targets use this, glibc targets use wireguard-go)
- No amnezia obfuscation support (kernel WireGuard is standard protocol)
- Requires kernel module, not embedded

## References

- [Mullvad's implementation](https://github.com/mullvad/mullvadvpn-app/tree/main/talpid-wireguard/src/wireguard_kernel)
- [golang/go#13492](https://github.com/golang/go/issues/13492) - Go musl bug
