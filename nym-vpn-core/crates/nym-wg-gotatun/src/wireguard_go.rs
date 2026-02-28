// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! WireGuard tunnel implementation backed by gotatun (pure Rust).
//!
//! This module provides the same `Tunnel` API as `nym-wg-go::wireguard_go`
//! but uses gotatun instead of wireguard-go + CGo FFI.

use std::fmt;

use gotatun::device::{self, Peer};
use gotatun::tun::tun_async_device::TunDevice;

use super::{Error, PeerConfig, PeerEndpointUpdate, PrivateKey, Result};
#[cfg(feature = "amnezia")]
use crate::amnezia::AmneziaConfig;

/// Classic WireGuard interface configuration.
pub struct InterfaceConfig {
    pub listen_port: Option<u16>,
    pub private_key: PrivateKey,
    pub mtu: u16,
    pub fwmark: Option<u32>,
    #[cfg(feature = "amnezia")]
    pub azwg_config: Option<AmneziaConfig>,
}

impl fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("InterfaceConfig");
        d.field("listen_port", &self.listen_port)
            .field("private_key", &"(hidden)")
            .field("mtu", &self.mtu);
        d.field("fwmark", &self.fwmark);
        #[cfg(feature = "amnezia")]
        d.field("azwg_config", &self.azwg_config);
        d.finish()
    }
}

/// Classic WireGuard configuration.
#[derive(Debug)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

/// Device transport type used by gotatun.
///
/// When the `amnezia` feature is enabled, we wrap the default UDP factory with
/// [`AmneziaUdpFactory`] to apply AmneziaWG obfuscation at the UDP layer.
#[cfg(feature = "amnezia")]
type DeviceTransports = (
    crate::amnezia_udp::AmneziaUdpFactory<gotatun::udp::socket::UdpSocketFactory>,
    TunDevice,
    TunDevice,
);

#[cfg(not(feature = "amnezia"))]
type DeviceTransports = device::DefaultDeviceTransports;

/// WireGuard tunnel backed by gotatun.
pub struct Tunnel {
    device: device::Device<DeviceTransports>,
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Tunnel")
            .field("backend", &"gotatun")
            .finish()
    }
}

impl Tunnel {
    /// Start a new WireGuard tunnel using gotatun.
    ///
    /// Takes a `tun::AsyncDevice` directly instead of an `OwnedFd`.
    pub async fn start(config: Config, tun: tun::AsyncDevice) -> Result<Self> {
        // Wrap the tun::AsyncDevice in gotatun's TunDevice
        let tun_device = TunDevice::from_tun_device(tun)
            .map_err(|e| Error::TunFromFd(e.to_string()))?;

        // Build the gotatun device
        let private_key =
            x25519_dalek::StaticSecret::from(config.interface.private_key.to_bytes());

        // When amnezia feature is enabled, wrap UDP factory with AmneziaUdpFactory.
        // When disabled, use the default UDP factory.
        #[cfg(feature = "amnezia")]
        let udp_factory = crate::amnezia_udp::AmneziaUdpFactory::new(
            gotatun::udp::socket::UdpSocketFactory,
            config.interface.azwg_config.as_ref(),
        );

        #[cfg(feature = "amnezia")]
        let mut builder = device::build()
            .with_udp(udp_factory)
            .with_ip(tun_device)
            .with_private_key(private_key)
            .with_listen_port(config.interface.listen_port.unwrap_or(0));

        #[cfg(not(feature = "amnezia"))]
        let mut builder = device::build()
            .with_default_udp()
            .with_ip(tun_device)
            .with_private_key(private_key)
            .with_listen_port(config.interface.listen_port.unwrap_or(0));

        #[cfg(target_os = "linux")]
        if let Some(fwmark) = config.interface.fwmark {
            builder = builder.with_fwmark(fwmark);
        }

        // Add peers
        for peer_config in &config.peers {
            let gotatun_peer = convert_peer(peer_config);
            builder = builder.with_peer(gotatun_peer);
        }

        let device = builder
            .build()
            .await
            .map_err(|e| Error::DeviceBuild(e.to_string()))?;

        tracing::info!("gotatun WireGuard tunnel started");
        Ok(Self { device })
    }

    /// Stop the tunnel.
    pub async fn stop(self) {
        tracing::info!("Stopping gotatun WireGuard tunnel");
        self.device.stop().await;
    }

    /// Update the endpoints of peers matched by public key.
    pub async fn update_peers(&mut self, peer_updates: &[PeerEndpointUpdate]) -> Result<()> {
        for update in peer_updates {
            let pub_key =
                x25519_dalek::PublicKey::from(*update.public_key.as_bytes());
            let endpoint = update.endpoint;
            self.device.write(async |device| {
                device.modify_peer(&pub_key, |peer_mut| {
                    peer_mut.set_endpoint(Some(endpoint));
                }).await;
            }).await.map_err(|e| Error::UpdatePeers(e.to_string()))?;
        }
        Ok(())
    }
}

/// Convert our PeerConfig to gotatun's Peer type.
fn convert_peer(peer_config: &PeerConfig) -> Peer {
    let pub_key = x25519_dalek::PublicKey::from(*peer_config.public_key.as_bytes());

    let mut peer = Peer::new(pub_key)
        .with_endpoint(peer_config.endpoint)
        .with_allowed_ips(peer_config.allowed_ips.iter().copied());

    if let Some(ref psk) = peer_config.preshared_key {
        peer = peer.with_preshared_key(*psk.as_bytes());
    }

    peer
}
