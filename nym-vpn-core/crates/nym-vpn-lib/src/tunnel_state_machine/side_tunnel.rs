// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! The dual tunnel's mixnet side: a mixnet tunnel beside the two-hop tunnel
//! for the traffic carrying [`nym_routing::SIDE_TUNNEL_FWMARK`].
//!
//! The Connected state owns it, so a reconnect of the two-hop tunnel restarts
//! it, while its own failures never touch the two-hop tunnel: it retries on
//! its own. Its gateway connection carries no fwmark and rides the two-hop
//! tunnel, so the mixnet entry never sees the home address and the
//! kill-switch admits no endpoint for it. While it is down the marked traffic
//! is unreachable; the routing rules guarantee that, not this task.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use nym_common::trace_err_chain;
use nym_connection_monitor::{ConnectionStatusEvent, TimingConfig};
use nym_gateway_directory::{BlacklistedGateways, GatewayCacheHandle, NodeIdentity};
use nym_registration_client::{
    MixnetRegistrationResult, RegistrationClientBuilder, RegistrationClientBuilderConfig,
    RegistrationMode, RegistrationResult,
};
use nym_vpn_lib_types::{
    GatewayIndependence, GatewayLightInfo, MixnetConnectionData, NymAddress,
    SideTunnelConnectionData, TunnelType,
};
use nym_vpn_store::keys::wireguard::WireguardKeysDb;
use time::OffsetDateTime;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    Error, NymConfig, Result, RouteHandler, TunnelMetadata, TunnelSettings,
    tunnel::{self, SelectedGateways, mixnet},
    tunnel_monitor::{
        DEFAULT_TUN_MTU, REGISTRATION_CLIENT_STARTUP_TIMEOUT, TunnelMonitor, registration_node,
        spawn_connection_monitor,
    },
};
use crate::{GatewayDirectoryError, UserAgent, mixnet::VpnTopologyServiceHandle};

/// Device of the side tunnel; inside the `nym+` firewall zone.
pub const SIDE_TUNNEL_INTERFACE: &str = "nym2";

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A session that lasted this long starts the backoff over. A mixnet tunnel
/// that dies right after its first probe is declared failed up to two
/// minutes later.
const STABLE_SESSION: Duration = Duration::from_secs(180);

/// How long the Connected state may take to admit the device.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long stopping may take: the mixnet client's shutdown is not bounded.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum SideTunnelEvent {
    /// Down, and an attempt pending or running. `retry_attempt` counts the
    /// sessions in a row that did not last.
    Connecting { retry_attempt: u32 },

    /// The device exists and the side-tunnel table routes into it. The
    /// firewall must admit it before the reply: the tunnel starts then.
    InterfaceUp {
        metadata: TunnelMetadata,
        reply_tx: oneshot::Sender<()>,
    },

    /// The tunnel passes its probes.
    Up(Box<SideTunnelConnectionData>),

    /// The device and its routes are gone.
    Down,
}

pub struct SideTunnelHandle {
    shutdown_token: CancellationToken,
    join_handle: JoinHandle<()>,
}

impl SideTunnelHandle {
    /// Returns once the routes and the device are gone, or after
    /// [`STOP_TIMEOUT`].
    pub async fn stop(self) {
        self.shutdown_token.cancel();
        if tokio::time::timeout(STOP_TIMEOUT, self.join_handle)
            .await
            .is_err()
        {
            tracing::warn!("Side tunnel did not stop within {STOP_TIMEOUT:?}");
        }
    }
}

pub struct SideTunnel {
    nym_config: NymConfig,
    /// The two-hop tunnel's settings; see [`side_selection_settings`].
    tunnel_settings: TunnelSettings,
    /// The two-hop tunnel's gateways, which take no role here: one operator
    /// must not see both the home address and the mixnet traffic.
    primary_gateways: [NodeIdentity; 2],
    user_agent: UserAgent,
    route_handler: RouteHandler,
    gateway_cache_handle: GatewayCacheHandle,
    topology_service: VpnTopologyServiceHandle,
    wg_keys_db: WireguardKeysDb,
    /// Entry gateways that failed here; the two-hop blacklist is not touched.
    blacklisted_entry_gateways: BlacklistedGateways,
    event_tx: mpsc::UnboundedSender<SideTunnelEvent>,
    shutdown_token: CancellationToken,
}

impl SideTunnel {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        nym_config: NymConfig,
        tunnel_settings: TunnelSettings,
        primary_gateways: &SelectedGateways,
        user_agent: UserAgent,
        route_handler: RouteHandler,
        gateway_cache_handle: GatewayCacheHandle,
        topology_service: VpnTopologyServiceHandle,
        wg_keys_db: WireguardKeysDb,
    ) -> (SideTunnelHandle, mpsc::UnboundedReceiver<SideTunnelEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let shutdown_token = CancellationToken::new();
        let side_tunnel = Self {
            nym_config,
            tunnel_settings,
            primary_gateways: [
                primary_gateways.entry_gateway().identity,
                primary_gateways.exit_gateway().identity,
            ],
            user_agent,
            route_handler,
            gateway_cache_handle,
            topology_service,
            wg_keys_db,
            blacklisted_entry_gateways: BlacklistedGateways::new(),
            event_tx,
            shutdown_token: shutdown_token.clone(),
        };
        let join_handle = tokio::spawn(side_tunnel.run());

        (
            SideTunnelHandle {
                shutdown_token,
                join_handle,
            },
            event_rx,
        )
    }

    async fn run(mut self) {
        // Sessions in a row that did not last; zero after a stable one.
        let mut retry_attempt = 0;
        self.send_event(SideTunnelEvent::Connecting { retry_attempt });
        loop {
            let session_token = self.shutdown_token.child_token();
            let outcome = Box::pin(self.run_session(&session_token)).await;
            session_token.cancel();

            let stable = match outcome {
                Ok(lifetime) => lifetime >= STABLE_SESSION,
                Err(_) if self.shutdown_token.is_cancelled() => false,
                Err(e) => {
                    trace_err_chain!(e, "Side tunnel attempt failed");
                    false
                }
            };
            if self.shutdown_token.is_cancelled() {
                break;
            }

            retry_attempt = if stable {
                0
            } else {
                retry_attempt.saturating_add(1)
            };
            // Sent before the wait, so that the state reads "connecting"
            // from the moment the tunnel is down.
            self.send_event(SideTunnelEvent::Connecting { retry_attempt });
            let delay = retry_delay(retry_attempt);
            tracing::info!("Side tunnel down; retrying in {delay:?}");
            if self
                .shutdown_token
                .run_until_cancelled(tokio::time::sleep(delay))
                .await
                .is_none()
            {
                break;
            }
        }
        tracing::info!("Side tunnel stopped");
    }

    /// One attempt. Returns how long the tunnel passed its probes; zero when
    /// it came up but never did.
    async fn run_session(&mut self, session_token: &CancellationToken) -> Result<Duration> {
        let selected_gateways = self.select_gateways(session_token).await?;
        let entry = selected_gateways.entry_gateway().identity;

        let registration = session_token
            .run_until_cancelled(Box::pin(self.register(&selected_gateways, session_token)))
            .await
            .ok_or(tunnel::Error::Cancelled)?
            .inspect_err(|_| self.blacklist_entry_gateway(entry, "registration failure"))?;

        let lifetime =
            Box::pin(self.run_tunnel(&selected_gateways, registration, session_token)).await?;
        if lifetime.is_zero() && !session_token.is_cancelled() {
            self.blacklist_entry_gateway(entry, "tunnel that never passed its probes");
        }
        Ok(lifetime)
    }

    async fn select_gateways(&self, session_token: &CancellationToken) -> Result<SelectedGateways> {
        let settings = side_selection_settings(&self.tunnel_settings);
        // Only a gateway pinned for both tunnels gets here: a two-hop
        // selection leaves the side tunnel's pins alone.
        for pinned in [
            settings.entry_point.pinned_gateway(),
            settings.exit_point.pinned_gateway(),
        ]
        .into_iter()
        .flatten()
        {
            if self.primary_gateways.contains(pinned.inner()) {
                tracing::warn!(
                    "Mixnet gateway {pinned} is pinned for the two-hop tunnel too; the side \
                     tunnel cannot use it"
                );
            }
        }
        let select = |criteria| {
            tunnel::select_gateways(
                self.gateway_cache_handle.clone(),
                &self.blacklisted_entry_gateways,
                &settings,
                criteria,
                self.wg_keys_db.clone(),
                &self.primary_gateways,
                session_token.child_token(),
            )
        };
        match select(settings.independence_criteria(false)).await {
            Err(tunnel::Error::SelectGateways(err))
                if matches!(
                    *err,
                    GatewayDirectoryError::NeedsRelaxedIndependenceCriteria { .. }
                ) =>
            {
                // Nobody is there to ask, as there is for the two-hop pair.
                tracing::warn!(
                    "No independent mixnet gateway pair; the side tunnel connects without the \
                     independence criteria"
                );
                Ok(select(GatewayIndependence::disabled()).await?)
            }
            result => Ok(result?),
        }
    }

    async fn register(
        &self,
        selected_gateways: &SelectedGateways,
        session_token: &CancellationToken,
    ) -> Result<MixnetRegistrationResult> {
        let entry_node = registration_node(
            "Side tunnel entry",
            selected_gateways.entry_gateway(),
            selected_gateways.entry_keypair().clone(),
        )?;
        let exit_node = registration_node(
            "Side tunnel exit",
            selected_gateways.exit_gateway(),
            selected_gateways.exit_keypair().clone(),
        )?;
        let nym_network = self
            .nym_config
            .network_rx
            .borrow()
            .nym_network
            .network
            .clone();

        let config = RegistrationClientBuilderConfig::builder()
            .entry_node(entry_node)
            .exit_node(exit_node)
            // The two-hop tunnel's identity and, with it, its credentials.
            // Its gateways are excluded above, so the identity never meets
            // a gateway a kept-alive authenticator client is connected to.
            .data_path(self.nym_config.data_path.clone())
            .mixnet_client_config(
                self.tunnel_settings
                    .mixnet_client_config
                    .clone()
                    .unwrap_or_default(),
            )
            .mixnet_client_startup_timeout(REGISTRATION_CLIENT_STARTUP_TIMEOUT)
            .mode(RegistrationMode::Mixnet)
            .user_agent(self.user_agent.clone())
            .custom_topology_provider(Box::new(self.topology_service.make_topology_provider()))
            .network_env(nym_network)
            .cancel_token(session_token.child_token())
            // No fwmark: the gateway connection rides the two-hop tunnel.
            .connection_fd_callback(Arc::new(|_fd| {}))
            .build();

        let registration_client = Box::pin(RegistrationClientBuilder::new(config).build()).await?;
        match Box::pin(registration_client.register()).await? {
            RegistrationResult::Mixnet(result) => Ok(*result),
            RegistrationResult::Wireguard(_) => Err(Error::UnexpectedRegistrationResult),
        }
    }

    /// Brings the device up, carries the traffic until the tunnel fails or
    /// the session is cancelled, and takes routes and device down again.
    async fn run_tunnel(
        &mut self,
        selected_gateways: &SelectedGateways,
        registration: MixnetRegistrationResult,
        session_token: &CancellationToken,
    ) -> Result<Duration> {
        let enable_ipv6 = self.tunnel_settings.enable_ipv6;
        let assigned_addresses = registration.assigned_addresses;
        let interface_ipv6 = enable_ipv6.then_some(assigned_addresses.interface_addresses.ipv6);
        let connection_data = SideTunnelConnectionData {
            entry_gateway: GatewayLightInfo::from(selected_gateways.entry_gateway().clone()),
            exit_gateway: GatewayLightInfo::from(selected_gateways.exit_gateway().clone()),
            connected_at: OffsetDateTime::now_utc(),
            tunnel: MixnetConnectionData {
                nym_address: NymAddress::from(assigned_addresses.mixnet_client_address),
                exit_ipr: NymAddress::from(assigned_addresses.exit_mix_address),
                entry_ip: assigned_addresses.entry_mixnet_gateway_ip,
                exit_ip: assigned_addresses.exit_mixnet_gateway_ip,
                ipv4: assigned_addresses.interface_addresses.ipv4,
                ipv6: interface_ipv6,
            },
        };

        let mtu = self
            .tun_mtu(assigned_addresses.entry_mixnet_gateway_ip)
            .await;
        TunnelMonitor::cleanup_stale_tun_devices(&[SIDE_TUNNEL_INTERFACE]).await;
        let tun_device = match TunnelMonitor::create_mixnet_device(
            SIDE_TUNNEL_INTERFACE,
            assigned_addresses.interface_addresses.ipv4,
            interface_ipv6,
            mtu,
        )
        .await
        {
            Ok(tun_device) => tun_device,
            Err(e) => {
                registration.mixnet_client.disconnect().await;
                return Err(e);
            }
        };

        let mut ips = vec![IpAddr::V4(assigned_addresses.interface_addresses.ipv4)];
        ips.extend(interface_ipv6.map(IpAddr::V6));
        let metadata = TunnelMetadata {
            interface: SIDE_TUNNEL_INTERFACE.to_owned(),
            ips,
            ipv4_gateway: None,
            ipv6_gateway: None,
        };

        if let Err(e) = self
            .route_handler
            .add_side_tunnel_routes(SIDE_TUNNEL_INTERFACE.to_owned(), mtu, enable_ipv6)
            .await
        {
            // A partial add leaves routes behind.
            self.route_handler.remove_side_tunnel_routes().await;
            registration.mixnet_client.disconnect().await;
            return Err(Error::AddRoutes(e));
        }
        tracing::info!("Side tunnel device {SIDE_TUNNEL_INTERFACE} is up");
        self.announce_interface_up(metadata).await;

        let mixnet_client_token = registration.mixnet_client.cancellation_token();
        let tunnel_token = session_token.child_token();
        let tunnel_handle = mixnet::connected_tunnel::start_mixnet_tunnel(
            registration.mixnet_client,
            assigned_addresses,
            tun_device,
            tunnel_token.child_token(),
            registration.event_rx,
        )
        .await
        .map_err(|e| Error::Tunnel(Box::new(e)));

        let lifetime = match tunnel_handle {
            Ok(_) => {
                Box::pin(self.monitor(connection_data, mixnet_client_token, &tunnel_token)).await
            }
            Err(_) => Ok(Duration::ZERO),
        };

        // Routes first: the marked traffic turns unreachable before the
        // device goes, never towards anything else.
        self.route_handler.remove_side_tunnel_routes().await;
        self.send_event(SideTunnelEvent::Down);
        tunnel_token.cancel();
        match tunnel_handle {
            Ok(tunnel_handle) => {
                // The device closes with the tombstone.
                if let Err(e) = tunnel_handle.wait().await {
                    tracing::error!("Failed to join the side tunnel: {e}");
                }
            }
            Err(e) => return Err(e),
        }
        tracing::info!("Side tunnel device {SIDE_TUNNEL_INTERFACE} is down");
        lifetime
    }

    /// Until the probes fail, the mixnet client stops or `tunnel_token` is
    /// cancelled. Returns how long the probes passed.
    async fn monitor(
        &mut self,
        connection_data: SideTunnelConnectionData,
        mixnet_client_token: CancellationToken,
        tunnel_token: &CancellationToken,
    ) -> Result<Duration> {
        let (monitor_tx, mut monitor_rx) = mpsc::unbounded_channel();
        let monitor_handle = spawn_connection_monitor(
            SIDE_TUNNEL_INTERFACE,
            TimingConfig::mixnet(),
            monitor_tx,
            tunnel_token.child_token(),
        )?;

        let mut viable_since = None;
        let mut last_status = None;
        loop {
            tokio::select! {
                event = monitor_rx.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    if last_status == Some(event.status) {
                        continue;
                    }
                    last_status = Some(event.status);
                    match event.status {
                        ConnectionStatusEvent::Viable => {
                            tracing::info!("Side tunnel connection is viable");
                            if viable_since.is_none() {
                                viable_since = Some(Instant::now());
                                self.send_event(SideTunnelEvent::Up(Box::new(SideTunnelConnectionData {
                                    connected_at: OffsetDateTime::now_utc(),
                                    ..connection_data.clone()
                                })));
                            }
                        }
                        ConnectionStatusEvent::IntermittentFailure { retry } => {
                            tracing::info!("Side tunnel connection is failing (retry: {retry})");
                        }
                        ConnectionStatusEvent::Failed => {
                            tracing::info!("Side tunnel connection is down");
                            break;
                        }
                    }
                }
                _ = mixnet_client_token.cancelled() => {
                    tracing::error!("Side tunnel mixnet client exited unexpectedly");
                    break;
                }
                _ = tunnel_token.cancelled() => break,
            }
        }

        tunnel_token.cancel();
        if let Err(e) = monitor_handle.await {
            tracing::error!("Side tunnel connection monitor exited with error: {e}");
        }
        Ok(viable_since.map_or(Duration::ZERO, |since| since.elapsed()))
    }

    async fn tun_mtu(&mut self, entry_ip: IpAddr) -> u16 {
        if let Some(mtu) = self.tunnel_settings.mixnet_tunnel_options.mtu {
            return mtu;
        }
        self.route_handler
            .get_mtu_for_route(entry_ip)
            .await
            .inspect_err(|e| trace_err_chain!(e, "Failed to detect mtu for route"))
            .unwrap_or(DEFAULT_TUN_MTU)
    }

    async fn announce_interface_up(&mut self, metadata: TunnelMetadata) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_event(SideTunnelEvent::InterfaceUp { metadata, reply_tx });
        if tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await.is_err() {
            tracing::warn!("Side tunnel interface up reply timeout");
        }
    }

    fn blacklist_entry_gateway(&self, entry: NodeIdentity, failure_kind: &str) {
        if let Err(e) = self.blacklisted_entry_gateways.add(entry) {
            tracing::error!("Failed to blacklist side tunnel entry gateway {entry}: {e}");
        } else {
            tracing::warn!("Side tunnel avoids entry gateway {entry} after a {failure_kind}");
        }
    }

    fn send_event(&self, event: SideTunnelEvent) {
        // The Connected state stops listening before it stops the tunnel.
        let _ = self.event_tx.send(event);
    }
}

/// Automatic gateways: random mixnet entry and exit, the independence
/// criteria and the performance thresholds of the two-hop settings.
fn side_selection_settings(primary: &TunnelSettings) -> TunnelSettings {
    TunnelSettings {
        tunnel_type: TunnelType::Mixnet,
        entry_point: primary.side_entry_point.clone(),
        exit_point: primary.side_exit_point.clone(),
        ..primary.clone()
    }
}

fn retry_delay(retry_attempt: u32) -> Duration {
    INITIAL_RETRY_DELAY
        .saturating_mul(2u32.saturating_pow(retry_attempt))
        .min(MAX_RETRY_DELAY)
}

/// Pends forever without a side tunnel, so it can sit in a `select!`.
pub async fn next_event(
    event_rx: Option<&mut mpsc::UnboundedReceiver<SideTunnelEvent>>,
) -> Option<SideTunnelEvent> {
    match event_rx {
        Some(event_rx) => event_rx.recv().await,
        None => futures::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_doubles_up_to_the_cap() {
        assert_eq!(retry_delay(0), INITIAL_RETRY_DELAY);
        assert_eq!(retry_delay(1), INITIAL_RETRY_DELAY * 2);
        assert_eq!(retry_delay(4), INITIAL_RETRY_DELAY * 16);
        assert_eq!(retry_delay(5), MAX_RETRY_DELAY);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }
}
