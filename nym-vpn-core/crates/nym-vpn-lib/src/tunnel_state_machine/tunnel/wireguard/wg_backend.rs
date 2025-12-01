//! WireGuard backend abstraction
//!
//! This module provides a unified interface for both kernel and userspace WireGuard implementations.
//! - Linux TunTun mode: uses nym-wg-kernel (kernel netlink)
//! - Other platforms / Netstack mode: uses nym-wg-go (userspace)

use crate::wg_config::WgNodeConfig;

/// Standard WireGuard persistent keepalive interval (seconds)
const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

/// Unified WireGuard tunnel interface
pub enum WgTunnel {
    #[cfg(target_os = "linux")]
    Kernel(nym_wg_kernel::tunnel::Tunnel),

    #[cfg(not(target_env = "musl"))]
    Userspace(nym_wg_go::wireguard_go::Tunnel),
}

impl WgTunnel {
    /// Start a WireGuard tunnel using the best available backend
    ///
    /// On Linux with TunTun mode: uses kernel WireGuard (nym-wg-kernel)
    /// On other platforms or with netstack: uses wireguard-go (nym-wg-go)
    ///
    /// For kernel WireGuard, tun_fd can be None (kernel creates its own interface).
    /// For userspace WireGuard (non-musl only), tun_fd must be Some (uses existing tun device).
    #[cfg(all(target_os = "linux", unix, not(target_env = "musl")))]
    pub async fn start_tun_mode(
        interface_name: String,
        wg_config: WgNodeConfig,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Try kernel WireGuard first if available (always preferred on Linux)
        if nym_wg_kernel::is_available().await {
            tracing::info!("Using kernel WireGuard backend for {}", interface_name);
            match Self::start_kernel(interface_name.clone(), wg_config.clone()).await {
                Ok(tunnel) => {
                    // Drop the tun fd if provided (kernel WG doesn't use it)
                    drop(tun_fd);
                    return Ok(Self::Kernel(tunnel));
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to start kernel WireGuard ({}), falling back to userspace",
                        e
                    );
                }
            }
        } else if tun_fd.is_none() {
            tracing::info!("Kernel WireGuard not available, but no tun device provided");
            return Err("Kernel WireGuard not available and no tun device for userspace fallback".into());
        } else {
            tracing::info!("Kernel WireGuard not available, using userspace backend");
        }

        // Fallback to userspace wireguard-go (requires tun fd)
        let tun_fd = tun_fd.ok_or_else(|| "No tun device provided for userspace WireGuard".to_string())?;
        let tunnel = nym_wg_go::wireguard_go::Tunnel::start(
            wg_config.into_wireguard_config(),
            tun_fd,
        )
        .map_err(|e| format!("Failed to start userspace WireGuard: {}", e))?;

        Ok(Self::Userspace(tunnel))
    }

    /// Start WireGuard tunnel on musl - kernel WireGuard only (no userspace fallback)
    #[cfg(all(target_os = "linux", unix, target_env = "musl"))]
    pub async fn start_tun_mode(
        interface_name: String,
        wg_config: WgNodeConfig,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Drop the tun_fd immediately (kernel WireGuard doesn't need it)
        drop(tun_fd);

        if !nym_wg_kernel::is_available().await {
            return Err("Kernel WireGuard is not available. Please ensure the WireGuard kernel module is loaded (modprobe wireguard)".into());
        }

        tracing::info!("Using kernel WireGuard backend for {} (musl target - userspace not supported)", interface_name);
        let tunnel = Self::start_kernel(interface_name, wg_config).await?;
        Ok(Self::Kernel(tunnel))
    }

    /// Start a WireGuard tunnel using userspace backend (non-Linux or Windows)
    #[cfg(not(all(target_os = "linux", unix)))]
    pub async fn start_tun_mode(
        _interface_name: String,
        wg_config: WgNodeConfig,
        tun_fd: std::os::fd::OwnedFd,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tunnel = nym_wg_go::wireguard_go::Tunnel::start(
            wg_config.into_wireguard_config(),
            tun_fd,
        )
        .map_err(|e| format!("Failed to start WireGuard: {}", e))?;

        Ok(Self::Userspace(tunnel))
    }

    /// Start kernel WireGuard tunnel (Linux only)
    #[cfg(target_os = "linux")]
    async fn start_kernel(
        interface_name: String,
        wg_config: WgNodeConfig,
    ) -> Result<nym_wg_kernel::tunnel::Tunnel, Box<dyn std::error::Error>> {
        use nym_wg_kernel::tunnel::{Config, InterfaceConfig, PeerConfig as KernelPeerConfig};

        // Get allowed IPs before moving wg_config
        let allowed_ips = wg_config.allowed_ips();

        // Convert nym WgNodeConfig to kernel config
        let kernel_config = Config {
            interface: InterfaceConfig {
                private_key: wg_config.interface.private_key.to_bytes(),
                addresses: wg_config.interface.addresses,
                listen_port: wg_config.interface.listen_port,
                mtu: wg_config.interface.mtu,
                fwmark: wg_config.interface.fwmark,
            },
            peers: vec![KernelPeerConfig {
                public_key: *wg_config.peer.public_key.as_bytes(),
                endpoint: wg_config.peer.endpoint,
                allowed_ips,
                persistent_keepalive: Some(WG_PERSISTENT_KEEPALIVE_SECS),
            }],
        };

        nym_wg_kernel::tunnel::Tunnel::start(interface_name, kernel_config)
            .await
            .map_err(|e| e.into())
    }

    /// Stop the tunnel
    pub async fn stop(self) {
        match self {
            #[cfg(target_os = "linux")]
            WgTunnel::Kernel(tunnel) => {
                if let Err(e) = tunnel.stop().await {
                    tracing::error!("Failed to stop kernel WireGuard tunnel: {}", e);
                }
            }
            #[cfg(not(target_env = "musl"))]
            WgTunnel::Userspace(tunnel) => {
                tunnel.stop();
            }
        }
    }

    /// Update peer endpoints (for network changes on iOS)
    #[cfg(target_os = "ios")]
    pub fn bump_sockets(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            WgTunnel::Kernel(_) => {
                // Kernel WireGuard doesn't need socket rebinding
            }
            #[cfg(not(target_env = "musl"))]
            WgTunnel::Userspace(tunnel) => {
                tunnel.bump_sockets();
            }
        }
    }

    /// Rebind tunnel socket to new interface (Windows)
    #[cfg(windows)]
    pub fn rebind_tunnel_socket(
        &mut self,
        address_family: nym_windows::net::AddressFamily,
        interface_index: u32,
    ) {
        match self {
            WgTunnel::Userspace(tunnel) => {
                tunnel.rebind_tunnel_socket(address_family, interface_index);
            }
        }
    }

    /// Get Wintun interface (Windows only)
    #[cfg(windows)]
    pub fn wintun_interface(&self) -> Option<&nym_wg_go::wireguard_go::WintunInterface> {
        match self {
            WgTunnel::Userspace(tunnel) => Some(tunnel.wintun_interface()),
        }
    }
}
