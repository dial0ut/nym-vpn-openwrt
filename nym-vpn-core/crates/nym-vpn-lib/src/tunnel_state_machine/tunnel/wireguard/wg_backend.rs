//! Kernel WireGuard backend for musl targets
//!
//! This module is only compiled on Linux musl targets where wireguard-go
//! segfaults due to golang/go#13492 (Go c-archive incompatibility with musl).

#![cfg(all(target_os = "linux", target_env = "musl"))]

use crate::tunnel_state_machine::tunnel::Error;
use crate::wg_config::WgNodeConfig;

const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

/// Kernel WireGuard tunnel wrapper
pub struct WgTunnel {
    tunnel: nym_wg_kernel::tunnel::Tunnel,
}

impl WgTunnel {
    /// Start a kernel WireGuard tunnel
    pub async fn start_kernel(
        interface_name: String,
        wg_config: WgNodeConfig,
    ) -> Result<Self, Error> {
        use nym_wg_kernel::tunnel::{Config, InterfaceConfig, PeerConfig as KernelPeerConfig};

        if !nym_wg_kernel::is_available().await {
            return Err(Error::KernelWireguard(
                "kernel WireGuard unavailable (run: modprobe wireguard or modprobe amneziawg)".into(),
            ));
        }

        tracing::info!("Starting kernel WireGuard tunnel: {}", interface_name);

        // Convert AmneziaConfig from nym-wg-go format to nym-wg-kernel format
        let amnezia_config = wg_config.interface.azwg_config.as_ref().map(|azwg| {
            nym_wg_kernel::AmneziaConfig {
                junk_pkt_count: azwg.junk_pkt_count,
                junk_pkt_min_size: azwg.junk_pkt_min_size,
                junk_pkt_max_size: azwg.junk_pkt_max_size,
                init_pkt_junk_size: azwg.init_pkt_junk_size,
                response_pkt_junk_size: azwg.response_pkt_junk_size,
                init_pkt_magic_header: azwg.init_pkt_magic_header,
                response_pkt_magic_header: azwg.response_pkt_magic_header,
                under_load_pkt_magic_header: azwg.under_load_pkt_magic_header,
                transport_pkt_magic_header: azwg.transport_pkt_magic_header,
            }
        });

        let allowed_ips = wg_config.allowed_ips();
        let kernel_config = Config {
            interface: InterfaceConfig {
                private_key: wg_config.interface.private_key.to_bytes(),
                addresses: wg_config.interface.addresses,
                listen_port: wg_config.interface.listen_port,
                mtu: wg_config.interface.mtu,
                fwmark: wg_config.interface.fwmark,
                amnezia_config,
            },
            peers: vec![KernelPeerConfig {
                public_key: *wg_config.peer.public_key.as_bytes(),
                endpoint: wg_config.peer.endpoint,
                allowed_ips,
                persistent_keepalive: Some(WG_PERSISTENT_KEEPALIVE_SECS),
            }],
        };

        let tunnel = nym_wg_kernel::tunnel::Tunnel::start(interface_name, kernel_config)
            .await
            .map_err(|e| Error::KernelWireguard(e.to_string()))?;

        // Log backend info
        if tunnel.supports_amnezia() {
            tracing::info!("Using Amnezia-WireGuard kernel backend");
        } else {
            tracing::info!("Using standard WireGuard kernel backend");
        }

        Ok(Self { tunnel })
    }

    /// Returns true if Amnezia obfuscation is supported by the kernel backend
    pub fn supports_amnezia(&self) -> bool {
        self.tunnel.supports_amnezia()
    }

    /// Returns the detected WireGuard backend type
    pub fn backend(&self) -> nym_wg_kernel::WgBackend {
        self.tunnel.backend()
    }

    /// Stop the kernel WireGuard tunnel
    pub async fn stop(self) {
        if let Err(e) = self.tunnel.stop().await {
            tracing::error!("Failed to stop kernel WireGuard tunnel: {}", e);
        }
    }
}
