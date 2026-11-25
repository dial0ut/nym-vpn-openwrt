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
pub use crate::two_hop::TwoHopLink;
use crate::two_hop::{EntryIpRx, EntryIpTx, ExitUdpFactory};
#[cfg(feature = "amnezia")]
use crate::amnezia::AmneziaConfig;

/// `SO_RCVBUF`/`SO_SNDBUF` forced on the WireGuard UDP sockets.
///
/// Gotatun < 0.7.0 unconditionally set 7 MB; 0.7.0+ leaves the OS defaults,
/// which are far too small on OpenWrt (`net.core.{r,w}mem_default`). The
/// kernel clamps to `{r,w}mem_max`, as it did before.
const UDP_SOCKET_BUFFER_SIZE: usize = 7 * 1024 * 1024;

/// Handshake-initiation retransmit range forced on every peer, replacing the
/// stock `REKEY_TIMEOUT` (5s) + jitter.
///
/// A lost initiation is only retried after this timeout, and a gateway slow
/// to install our peer after registration drops the first one. With stock
/// timing every such loss is a flat 5-second stall on the connect path.
/// Retransmitting after ~1s caps it at ~1s. This also applies to rekey
/// initiations, where retrying loss sooner only speeds recovery;
/// `REKEY_ATTEMPT_TIME` still bounds the total retry window, and duplicate
/// initiations are handled by the protocol.
const REKEY_TIMEOUT_FAST: std::ops::RangeInclusive<Duration> =
    Duration::from_millis(1000)..=Duration::from_millis(1333);

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

/// UDP side of a device that talks to its peer over the network.
///
/// With the `amnezia` feature the default UDP factory is wrapped in
/// [`AmneziaUdpFactory`], which applies AmneziaWG obfuscation at the UDP layer.
#[cfg(feature = "amnezia")]
type SocketUdp = crate::amnezia_udp::AmneziaUdpFactory<gotatun::udp::socket::UdpSocketFactory>;

#[cfg(not(feature = "amnezia"))]
type SocketUdp = gotatun::udp::socket::UdpSocketFactory;

/// A gotatun device over one of the transport sets a tunnel can run on.
enum AnyDevice {
    /// UDP socket and TUN interface.
    Socket(device::Device<(SocketUdp, TunDevice, TunDevice)>),
    /// Entry hop of a two-hop tunnel: also carries the exit device's datagrams.
    Entry(device::Device<(SocketUdp, EntryIpTx, EntryIpRx)>),
    /// Exit hop of a two-hop tunnel: its datagrams go to the entry device.
    Exit(device::Device<(ExitUdpFactory, TunDevice, TunDevice)>),
}

/// Runs `$body` with `$device` bound to the device of whichever variant.
macro_rules! with_device {
    ($any:expr, $device:ident => $body:expr) => {
        match $any {
            AnyDevice::Socket($device) => $body,
            AnyDevice::Entry($device) => $body,
            AnyDevice::Exit($device) => $body,
        }
    };
}

impl AnyDevice {
    async fn stop(self) {
        with_device!(self, device => device.stop().await)
    }

    async fn set_endpoint(
        &self,
        public_key: &x25519_dalek::PublicKey,
        endpoint: std::net::SocketAddr,
    ) -> Result<()> {
        with_device!(self, device => {
            device
                .write(async |device| {
                    device
                        .modify_peer(public_key, |peer_mut| {
                            peer_mut.set_endpoint(Some(endpoint));
                        })
                        .await;
                })
                .await
                .map_err(|e| Error::UpdatePeers(e.to_string()))
        })
    }

    async fn last_handshakes(&self) -> Vec<Option<Duration>> {
        with_device!(self, device => {
            device
                .read(async |device| {
                    device
                        .peers()
                        .await
                        .into_iter()
                        .map(|peer_stats| peer_stats.stats.last_handshake)
                        .collect::<Vec<_>>()
                })
                .await
        })
    }
}

type SharedDevice = Arc<tokio::sync::RwLock<Option<AnyDevice>>>;

/// WireGuard tunnel backed by gotatun.
pub struct Tunnel {
    device: SharedDevice,
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
        let tun_device = tun_device(tun)?;
        let builder = device::build()
            .with_udp(socket_udp(&config.interface))
            .with_ip(tun_device);
        let device = configure(builder, &config)
            .build()
            .await
            .map_err(|e| Error::DeviceBuild(e.to_string()))?;

        tracing::info!("gotatun WireGuard tunnel started");
        Ok(Self::new(AnyDevice::Socket(device)))
    }

    /// Start the two tunnels of a two-hop connection, linked in-process.
    ///
    /// The exit tunnel's WireGuard datagrams never touch the entry
    /// interface: they are handed to the entry tunnel directly. `entry_tun`
    /// keeps carrying everything else the entry tunnel allows.
    ///
    /// Returns the entry and the exit tunnel.
    pub async fn start_two_hop(
        entry_config: Config,
        entry_tun: tun::AsyncDevice,
        exit_config: Config,
        exit_tun: tun::AsyncDevice,
        link: TwoHopLink,
    ) -> Result<(Self, Self)> {
        let (entry_ip_tx, entry_ip_rx, exit_udp) =
            crate::two_hop::split(link, tun_device(entry_tun)?).await;

        let entry_builder = device::build()
            .with_udp(socket_udp(&entry_config.interface))
            .with_ip_pair(entry_ip_tx, entry_ip_rx);
        let entry_device = configure(entry_builder, &entry_config)
            .build()
            .await
            .map_err(|e| Error::DeviceBuild(e.to_string()))?;
        let entry = Self::new(AnyDevice::Entry(entry_device));

        let exit_builder = device::build()
            .with_udp(exit_udp)
            .with_ip(tun_device(exit_tun)?);
        let exit_device = match configure(exit_builder, &exit_config).build().await {
            Ok(device) => device,
            Err(e) => {
                entry.stop().await;
                return Err(Error::DeviceBuild(e.to_string()));
            }
        };

        tracing::info!("gotatun two-hop WireGuard tunnels started, linked in-process");
        Ok((entry, Self::new(AnyDevice::Exit(exit_device))))
    }

    fn new(device: AnyDevice) -> Self {
        Self {
            device: Arc::new(tokio::sync::RwLock::new(Some(device))),
        }
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
            device.set_endpoint(&pub_key, endpoint).await?;
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
    device: SharedDevice,
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
        all_peers_handshaken(device.last_handshakes().await)
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

fn tun_device(tun: tun::AsyncDevice) -> Result<TunDevice> {
    TunDevice::from_tun_device(tun).map_err(|e| Error::TunFromFd(e.to_string()))
}

/// The UDP socket factory of a device that reaches its peer over the network.
fn socket_udp(interface: &InterfaceConfig) -> SocketUdp {
    let socket_factory = gotatun::udp::socket::UdpSocketFactory {
        recv_buffer_size: Some(UDP_SOCKET_BUFFER_SIZE),
        send_buffer_size: Some(UDP_SOCKET_BUFFER_SIZE),
    };

    #[cfg(feature = "amnezia")]
    return crate::amnezia_udp::AmneziaUdpFactory::new(socket_factory, interface.azwg_config.as_ref());

    #[cfg(not(feature = "amnezia"))]
    {
        let _ = interface;
        socket_factory
    }
}

/// Applies the key, port, fwmark and peers of `config` to a device builder.
fn configure<Udp, IpTx, IpRx>(
    builder: device::DeviceBuilder<Udp, IpTx, IpRx>,
    config: &Config,
) -> device::DeviceBuilder<Udp, IpTx, IpRx> {
    let private_key = x25519_dalek::StaticSecret::from(config.interface.private_key.to_bytes());
    let mut builder = builder
        .with_private_key(private_key)
        .with_listen_port(config.interface.listen_port.unwrap_or(0));

    #[cfg(target_os = "linux")]
    if let Some(fwmark) = config.interface.fwmark {
        builder = builder.with_fwmark(fwmark);
    }

    for peer_config in &config.peers {
        builder = builder.with_peer(convert_peer(peer_config));
    }
    builder
}

/// Convert our PeerConfig to gotatun's Peer type.
fn convert_peer(peer_config: &PeerConfig) -> Peer {
    let pub_key = x25519_dalek::PublicKey::from(*peer_config.public_key.as_bytes());

    let mut peer = Peer::new(pub_key)
        .with_endpoint(peer_config.endpoint)
        .with_allowed_ips(peer_config.allowed_ips.iter().copied())
        .dangerously_with_timer_params(gotatun::noise::TimerParams {
            rekey_timeout: REKEY_TIMEOUT_FAST,
            ..Default::default()
        });

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
