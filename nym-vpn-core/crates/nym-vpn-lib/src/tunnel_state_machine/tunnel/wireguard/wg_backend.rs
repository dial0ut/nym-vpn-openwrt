//! WireGuard backend abstraction
//!
//! - Linux glibc: userspace wireguard-go
//! - Linux musl: kernel WireGuard (wireguard-go segfaults on musl due to golang/go#13492)
//! - Other platforms: userspace wireguard-go

use crate::wg_config::WgNodeConfig;

const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

/// WireGuard backend error
#[derive(Debug, thiserror::Error)]
pub enum WgBackendError {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    #[error("kernel WireGuard error: {0}")]
    Kernel(#[from] nym_wg_kernel::Error),

    #[cfg(not(target_env = "musl"))]
    #[error("userspace WireGuard error: {0}")]
    Userspace(#[from] nym_wg_go::Error),

    #[error("no WireGuard backend available: {0}")]
    NoBackend(String),
}

/// Unified WireGuard tunnel interface
pub enum WgTunnel {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    Kernel(nym_wg_kernel::tunnel::Tunnel),

    #[cfg(not(target_env = "musl"))]
    Userspace(nym_wg_go::wireguard_go::Tunnel),
}

impl WgTunnel {
    // Linux glibc: use userspace wireguard-go
    #[cfg(all(target_os = "linux", unix, not(target_env = "musl")))]
    pub async fn start_tun_mode(
        _interface_name: String,
        wg_config: WgNodeConfig,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self, WgBackendError> {
        let tun_fd = tun_fd.ok_or_else(|| {
            WgBackendError::NoBackend("tun device required for userspace WireGuard".into())
        })?;

        let tunnel = nym_wg_go::wireguard_go::Tunnel::start(
            wg_config.into_wireguard_config(),
            tun_fd,
        )?;

        Ok(Self::Userspace(tunnel))
    }

    // Linux musl: use kernel WireGuard (wireguard-go segfaults)
    #[cfg(all(target_os = "linux", unix, target_env = "musl"))]
    pub async fn start_tun_mode(
        interface_name: String,
        wg_config: WgNodeConfig,
        _tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self, WgBackendError> {
        if !nym_wg_kernel::is_available().await {
            return Err(WgBackendError::NoBackend(
                "kernel WireGuard unavailable (run: modprobe wireguard)".into(),
            ));
        }

        tracing::info!("Using kernel WireGuard for {} (musl)", interface_name);
        Ok(Self::Kernel(Self::start_kernel(interface_name, wg_config).await?))
    }

    // Non-Linux: use userspace wireguard-go
    #[cfg(not(all(target_os = "linux", unix)))]
    pub async fn start_tun_mode(
        _interface_name: String,
        wg_config: WgNodeConfig,
        tun_fd: std::os::fd::OwnedFd,
    ) -> Result<Self, WgBackendError> {
        let tunnel = nym_wg_go::wireguard_go::Tunnel::start(
            wg_config.into_wireguard_config(),
            tun_fd,
        )?;
        Ok(Self::Userspace(tunnel))
    }

    #[cfg(all(target_os = "linux", target_env = "musl"))]
    async fn start_kernel(
        interface_name: String,
        wg_config: WgNodeConfig,
    ) -> Result<nym_wg_kernel::tunnel::Tunnel, nym_wg_kernel::Error> {
        use nym_wg_kernel::tunnel::{Config, InterfaceConfig, PeerConfig as KernelPeerConfig};

        let allowed_ips = wg_config.allowed_ips();
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

        nym_wg_kernel::tunnel::Tunnel::start(interface_name, kernel_config).await
    }

    pub async fn stop(self) {
        match self {
            #[cfg(all(target_os = "linux", target_env = "musl"))]
            WgTunnel::Kernel(tunnel) => {
                if let Err(e) = tunnel.stop().await {
                    tracing::error!("Failed to stop kernel WireGuard: {}", e);
                }
            }
            #[cfg(not(target_env = "musl"))]
            WgTunnel::Userspace(tunnel) => {
                tunnel.stop();
            }
        }
    }

    #[cfg(target_os = "ios")]
    pub fn bump_sockets(&mut self) {
        match self {
            #[cfg(not(target_env = "musl"))]
            WgTunnel::Userspace(tunnel) => tunnel.bump_sockets(),
        }
    }

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

    #[cfg(windows)]
    pub fn wintun_interface(&self) -> Option<&nym_wg_go::wireguard_go::WintunInterface> {
        match self {
            WgTunnel::Userspace(tunnel) => Some(tunnel.wintun_interface()),
        }
    }
}
