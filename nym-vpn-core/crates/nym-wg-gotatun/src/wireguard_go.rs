// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! WireGuard tunnel implementation backed by gotatun (pure Rust).
//!
//! This module provides the same `Tunnel` API as `nym-wg-go::wireguard_go`
//! but uses gotatun instead of wireguard-go + CGo FFI.

use std::{fmt, sync::Arc, time::Duration};

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
    device: Arc<tokio::sync::RwLock<Option<device::Device<DeviceTransports>>>>,
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
        let socket_factory = gotatun::udp::socket::UdpSocketFactory::default();

        #[cfg(feature = "amnezia")]
        let udp_factory = crate::amnezia_udp::AmneziaUdpFactory::new(
            socket_factory,
            config.interface.azwg_config.as_ref(),
        );

        #[cfg(not(feature = "amnezia"))]
        let udp_factory = socket_factory;

        let mut builder = device::build()
            .with_udp(udp_factory)
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
        Ok(Self {
            device: Arc::new(tokio::sync::RwLock::new(Some(device))),
        })
    }

    /// Stop the tunnel.
    ///
    /// Always stops the underlying device, no matter how many `StatsReader`
    /// clones are still alive; readers observe the stop and report
    /// "not handshaken" from then on. The `None` arm is defensive and
    /// not reachable via the current API since `stop` consumes `self`.
    pub async fn stop(self) {
        tracing::info!("Stopping gotatun WireGuard tunnel");
        let device = self.device.write().await.take();
        match device {
            Some(device) => device.stop().await,
            None => tracing::debug!("gotatun device already stopped"),
        }
    }

    /// Update the endpoints of peers matched by public key.
    pub async fn update_peers(&mut self, peer_updates: &[PeerEndpointUpdate]) -> Result<()> {
        for update in peer_updates {
            let pub_key =
                x25519_dalek::PublicKey::from(*update.public_key.as_bytes());
            let endpoint = update.endpoint;
            let guard = self.device.read().await;
            let Some(device) = guard.as_ref() else {
                return Err(Error::UpdatePeers("device already stopped".to_string()));
            };
            device.write(async |device| {
                device.modify_peer(&pub_key, |peer_mut| {
                    peer_mut.set_endpoint(Some(endpoint));
                }).await;
            }).await.map_err(|e| Error::UpdatePeers(e.to_string()))?;
        }
        Ok(())
    }

    /// Create a read-only stats handle sharing this tunnel's device.
    pub fn stats_reader(&self) -> StatsReader {
        StatsReader {
            device: Arc::clone(&self.device),
        }
    }
}

/// Read-only handle for querying live peer stats off a running tunnel.
///
/// Holds a clone of the `Arc` around the same shared, take-able device slot
/// as the `Tunnel`, so it stays usable after the `Tunnel` itself has moved
/// into the tunnel event-handler task. Once `Tunnel::stop` takes the device
/// out of the slot, every `StatsReader` clone reports "not handshaken" from
/// then on rather than keeping the device alive.
#[derive(Clone)]
pub struct StatsReader {
    device: Arc<tokio::sync::RwLock<Option<device::Device<DeviceTransports>>>>,
}

impl StatsReader {
    /// Returns true once every peer on the device has completed a handshake.
    ///
    /// An empty peer list or an already-stopped device counts as not
    /// handshaken — callers treat "unknown" as "not yet".
    pub async fn all_peers_have_handshake(&self) -> bool {
        let guard = self.device.read().await;
        let Some(device) = guard.as_ref() else {
            return false;
        };
        let last_handshakes = device
            .read(async |device| {
                device
                    .peers()
                    .await
                    .into_iter()
                    .map(|peer_stats| peer_stats.stats.last_handshake)
                    .collect::<Vec<_>>()
            })
            .await;
        all_peers_handshaken(last_handshakes)
    }
}

/// True iff the list is non-empty and every entry has a handshake timestamp.
fn all_peers_handshaken(last_handshakes: impl IntoIterator<Item = Option<Duration>>) -> bool {
    let mut any = false;
    for last_handshake in last_handshakes {
        if last_handshake.is_none() {
            return false;
        }
        any = true;
    }
    any
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::all_peers_handshaken;

    #[test]
    fn no_peers_is_not_handshaken() {
        assert!(!all_peers_handshaken(Vec::<Option<Duration>>::new()));
    }

    #[test]
    fn peer_without_handshake_is_not_handshaken() {
        assert!(!all_peers_handshaken([None::<Duration>]));
    }

    #[test]
    fn all_peers_with_handshake_is_handshaken() {
        assert!(all_peers_handshaken([
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(2)),
        ]));
    }

    #[test]
    fn mixed_peers_are_not_handshaken() {
        assert!(!all_peers_handshaken([Some(Duration::from_secs(1)), None]));
    }

    #[tokio::test]
    async fn stopped_device_reports_not_handshaken() {
        let reader = super::StatsReader {
            device: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };
        assert!(!reader.all_peers_have_handshake().await);
    }
}
