// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use std::ops::Deref;

use std::os::fd::BorrowedFd;
use std::{net::IpAddr, time::Duration};
use std::{os::fd::RawFd, sync::Arc};

use futures::{FutureExt, future::Fuse, pin_mut};
use nix::sys::socket::{SetSockOpt, sockopt::Mark};
use nym_gateway_directory::{
    BlacklistedGateways, GatewayCacheHandle, GatewayClient, GatewayMinPerformance, ResolvedConfig,
};
use time::OffsetDateTime;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tun::AbstractDevice;
use tun::AsyncDevice;

use nym_authenticator_client::AuthClientMixnetListenerHandle;
use nym_common::{ErrorExt, trace_err_chain};
use nym_connection_monitor::{
    ConnectionEvent, ConnectionMonitor, ConnectionStatusEvent, IcmpProbe, IcmpProbeConfig,
    TcpProbe, TcpProbeConfig, TimingConfig,
};
use nym_registration_client::{
    MixnetRegistrationResult, RegistrationClientBuilder, RegistrationClientBuilderConfig,
    RegistrationMode, RegistrationNymNode, RegistrationResult, WireguardRegistrationResult,
};
use nym_registration_common::{NymNodeInformation, NymNodeLPInformation};
use nym_vpn_account_controller::{AccountCommandSender, AccountStateReceiver};
use nym_vpn_lib_types::{
    AccountControllerError, BridgeAddress, ConnectionData, ErrorStateReason,
    EstablishConnectionData, GatewayLightInfo, MixnetConnectionData, NymAddress,
    TunnelConnectionData, TunnelType, WireguardConnectionData, WireguardNode,
};
use nym_vpn_store::keys::wireguard::WireguardKeysDb;

use super::route_handler::{RouteHandler, RoutingConfig};
use super::tun_ipv6;
use super::tunnel::wireguard::connected_tunnel::TunTunTunnelOptions;
use super::{
    Error, NymConfig, Result, TunnelInterface, TunnelMetadata, TunnelSettings,
    tunnel::{
        self, AnyTunnelHandle, SelectedGateways, Tombstone,
    },
};
use crate::{
    DEFAULT_MIN_GATEWAY_PERFORMANCE, DEFAULT_MIN_MIXNODE_PERFORMANCE, UserAgent,
    bandwidth_controller::BandwidthController,
    mixnet::VpnTopologyServiceHandle,
    tunnel_state_machine::{
        TunnelConstants, account, ipv6_availability,
        tunnel::{
            mixnet,
            transports::{self, TransportError},
            wireguard::{
                ConnectionData as WgConnectionData, MetadataEvent, MetadataReceiver,
                connected_tunnel::ConnectedTunnel,
            },
        },
    },
};
/// Default MTU for mixnet tun device.
const DEFAULT_TUN_MTU: u16 = 1500;

pub type TunnelMonitorEventSender = mpsc::UnboundedSender<TunnelMonitorEvent>;
pub type TunnelMonitorEventReceiver = mpsc::UnboundedReceiver<TunnelMonitorEvent>;

/// Timeout when waiting for reply from the event handler.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for starting the registration client.
/// On embedded devices (MIPS routers etc.), BLS12-381 ecash credential
/// operations can take much longer than on desktop CPUs, so we use a
/// generous timeout to avoid a connect/timeout/reconnect loop.
const REGISTRATION_CLIENT_STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TunnelMonitorEvent {
    /// Checking account
    AwaitingAccountReadiness,

    /// Refreshing gateways
    RefreshingGateways,

    /// Selecting gateways
    SelectingGateways,

    /// Selected gateways
    SelectedGateways {
        gateways: Box<SelectedGateways>,
        /// Back channel to acknowledge that the event has been processed
        reply_tx: tokio::sync::oneshot::Sender<()>,
    },

    /// Registering with gateways
    RegisteringWithGateways,

    /// Finished gateway registration
    RegisteredWithGateways {
        /// Connection data
        connection_data: Box<EstablishConnectionData>,
        /// Back channel to acknowledge that the event has been processed
        reply_tx: tokio::sync::oneshot::Sender<()>,
    },

    /// Tunnel interface is up.
    InterfaceUp {
        /// Tunnel interface
        tunnel_interface: TunnelInterface,
        /// Connection data
        connection_data: Box<EstablishConnectionData>,
        /// Back channel to acknowledge that the event has been processed
        reply_tx: tokio::sync::oneshot::Sender<()>,
    },

    /// Tunnel is up and functional.
    Up {
        /// Tunnel interface
        tunnel_interface: TunnelInterface,
        /// Connection data
        connection_data: Box<ConnectionData>,
    },

    /// Tunnel went down
    Down {
        /// Error state reason.
        /// When set indicates that the state machine should transition to error state.
        error_state_reason: Option<ErrorStateReason>,
        /// Back channel to acknowledge that the event has been processed
        reply_tx: tokio::sync::oneshot::Sender<()>,
    },

    /// Connection has failed
    ConnectionFailed,

    /// Registration with the entry gateway failed (e.g. the gateway accepted the
    /// connection but rejected WireGuard registration). Handled like a
    /// connection failure: the entry gateway is blacklisted and re-selected so
    /// we don't retry a gateway that registers-but-fails indefinitely.
    RegistrationFailed,
}

pub struct TunnelMonitorHandle {
    shutdown_token: CancellationToken,
    join_handle: JoinHandle<Tombstone>,
}

impl TunnelMonitorHandle {
    pub fn cancel(&self) {
        tracing::info!("Cancelling tunnel monitor handle");
        self.shutdown_token.cancel();
    }

    pub async fn wait(self) -> Tombstone {
        self.join_handle
            .await
            .inspect_err(|e| {
                tracing::error!("Failed to join on tunnel monitor handle: {}", e);
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct TunnelParameters {
    pub nym_config: NymConfig,
    pub resolved_gateway_config: Option<ResolvedConfig>,
    pub tunnel_settings: TunnelSettings,
    pub tunnel_constants: TunnelConstants,
    pub selected_gateways: Option<SelectedGateways>,
    pub user_agent: UserAgent,
    pub blacklisted_entry_gateways: BlacklistedGateways,
}

pub struct TunnelMonitor {
    tunnel_parameters: TunnelParameters,
    monitor_event_sender: mpsc::UnboundedSender<TunnelMonitorEvent>,
    route_handler: RouteHandler,
    account_controller_state: AccountStateReceiver,
    account_command_tx: AccountCommandSender,
    gateway_cache_handle: GatewayCacheHandle,
    custom_topology_provider: VpnTopologyServiceHandle,
    wg_keys_db: WireguardKeysDb,
    shutdown_token: CancellationToken,
}

impl TunnelMonitor {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        tunnel_parameters: TunnelParameters,
        account_controller_state: AccountStateReceiver,
        account_command_tx: AccountCommandSender,
        gateway_cache_handle: GatewayCacheHandle,
        custom_topology_provider: VpnTopologyServiceHandle,
        monitor_event_sender: mpsc::UnboundedSender<TunnelMonitorEvent>,
        wg_keys_db: WireguardKeysDb,
        route_handler: RouteHandler,
    ) -> TunnelMonitorHandle {
        let shutdown_token = CancellationToken::new();
        let tunnel_monitor = Self {
            tunnel_parameters,
            monitor_event_sender,
            route_handler,
            account_controller_state,
            account_command_tx,
            gateway_cache_handle,
            custom_topology_provider,
            wg_keys_db,
            shutdown_token: shutdown_token.clone(),
        };
        let join_handle = tokio::spawn(tunnel_monitor.run());

        TunnelMonitorHandle {
            shutdown_token,
            join_handle,
        }
    }

    async fn run(mut self) -> Tombstone {
        let (tombstone, reason) = match Box::pin(self.run_inner()).await {
            Ok(tombstone) => (tombstone, None),
            Err(e) => {
                trace_err_chain!(e, "Tunnel monitor exited with error");
                (Tombstone::default(), e.error_state_reason())
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send_event(TunnelMonitorEvent::Down {
            error_state_reason: reason,
            reply_tx,
        });
        if tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await.is_err() {
            tracing::warn!("Tunnel down reply timeout.");
        }

        tombstone
    }

    async fn run_inner(&mut self) -> Result<Tombstone> {
        if self.enable_ipv6() && !ipv6_availability::is_ipv6_enabled_in_os().await {
            return Err(Error::Ipv6Unavailable);
        }

        self.send_event(TunnelMonitorEvent::AwaitingAccountReadiness);

        self.shutdown_token
            .clone()
            .run_until_cancelled(self.await_account_readiness_with_retry())
            .await
            .ok_or(tunnel::Error::Cancelled)??;

        self.send_event(TunnelMonitorEvent::RefreshingGateways);

        let gateway_performance_options = self
            .tunnel_parameters
            .tunnel_settings
            .gateway_performance_options;
        let gateway_min_performance = GatewayMinPerformance::from_percentage_values(
            gateway_performance_options
                .mixnet_min_performance
                .map(u64::from),
            gateway_performance_options
                .vpn_min_performance
                .map(u64::from),
        );

        let mut gateway_config = self.tunnel_parameters.nym_config.gateway_config.clone();
        match gateway_min_performance {
            Ok(gateway_min_performance) => {
                gateway_config =
                    gateway_config.with_min_gateway_performance(gateway_min_performance);
            }
            Err(e) => {
                tracing::error!(
                    "Invalid gateway performance values. Will carry on with initial values. Error: {}",
                    e
                );
            }
        }

        let user_agent = self.tunnel_parameters.user_agent.clone();
        let resolver_overrides = self
            .tunnel_parameters
            .resolved_gateway_config
            .as_ref()
            .map(|v| &v.nym_api_resolver_overrides);

        let vpn_resolver_overrides = self
            .tunnel_parameters
            .resolved_gateway_config
            .as_ref()
            .map(|v| &v.nym_vpn_api_resolver_overrides);

        let gateway_directory_client = GatewayClient::new_with_resolver_overrides(
            gateway_config.clone(),
            user_agent.clone(),
            resolver_overrides,
            vpn_resolver_overrides,
        )
        .await
        .map_err(Error::GatewayDirectoryClient)?;

        self.gateway_cache_handle
            .replace_gateway_client(gateway_directory_client)
            .ok();
        self.gateway_cache_handle.refresh_all().await.ok();

        let selected_gateways =
            if let Some(ref selected_gateways) = self.tunnel_parameters.selected_gateways {
                selected_gateways.clone()
            } else {
                self.send_event(TunnelMonitorEvent::SelectingGateways);

                let new_gateways = tunnel::select_gateways(
                    self.gateway_cache_handle.clone(),
                    &self.tunnel_parameters.blacklisted_entry_gateways,
                    &self.tunnel_parameters.tunnel_settings,
                    self.wg_keys_db.clone(),
                    self.shutdown_token.child_token(),
                )
                .await?;

                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                self.send_event(TunnelMonitorEvent::SelectedGateways {
                    gateways: Box::new(new_gateways.clone()),
                    reply_tx,
                });

                // Wait for reply before proceeding to connect to let state machine configure firewall.
                if tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await.is_err() {
                    tracing::warn!("Failed to receive selected gateways reply in time");
                }

                new_gateways
            };

        self.send_event(TunnelMonitorEvent::RegisteringWithGateways);

        let fwmark = self.tunnel_parameters.tunnel_constants.fwmark;
        let connection_fd_callback = move |fd: RawFd| {
            tracing::debug!("Bypass websocket");
            let borrowed_fd = unsafe { &BorrowedFd::borrow_raw(fd) };
            if let Err(err) = Mark.set(borrowed_fd, &fwmark) {
                tracing::error!("Could not set fwmark for websocket fd: {err}");
            }
        };

        let mixnet_client_config = self
            .tunnel_parameters
            .tunnel_settings
            .mixnet_client_config
            .clone()
            .unwrap_or_default();

        tracing::debug!(
            "Mixnet client performance thresholds: min_mixnode={:?}, min_gateway={:?}",
            mixnet_client_config.min_mixnode_performance,
            mixnet_client_config.min_gateway_performance
        );

        let custom_topology_provider = self.custom_topology_provider.clone();
        custom_topology_provider
            .update_config(
                mixnet_client_config
                    .min_mixnode_performance
                    .unwrap_or(DEFAULT_MIN_MIXNODE_PERFORMANCE),
                mixnet_client_config
                    .min_gateway_performance
                    .unwrap_or(DEFAULT_MIN_GATEWAY_PERFORMANCE),
                self.tunnel_parameters
                    .resolved_gateway_config
                    .as_ref()
                    .map(|v| v.nym_api_resolver_overrides.clone()),
            )
            .await;

        tracing::debug!(
            "Connecting to entry gateway: {}",
            selected_gateways
                .entry_gateway()
                .identity()
                .to_base58_string()
        );
        tracing::debug!(
            "Connecting to exit gateway: {}",
            selected_gateways
                .exit_gateway()
                .identity()
                .to_base58_string()
        );

        let entry_ip = selected_gateways
            .entry_gateway()
            .lookup_ip()
            .ok_or(tunnel::Error::NoIpAddressAnnounced {
                gateway_id: selected_gateways
                    .entry_gateway()
                    .identity()
                    .to_base58_string(),
            })
            .map_err(Box::new)?;

        let exit_ip = selected_gateways
            .exit_gateway()
            .lookup_ip()
            .ok_or(tunnel::Error::NoIpAddressAnnounced {
                gateway_id: selected_gateways
                    .exit_gateway()
                    .identity()
                    .to_base58_string(),
            })
            .map_err(Box::new)?;

        // Build per-gateway Lewes Protocol registration data from each gateway's
        // advertised LP details (ports upstream gateway_provider/selector.rs inline,
        // since this fork has no gateway_provider module). The registration builder
        // requests LP unconditionally (enable_lp_registration(true)); it only takes
        // effect when a gateway advertises valid LP details and use_lp() is satisfied,
        // otherwise the legacy WireGuard registration path runs unchanged.
        let entry_gateway = selected_gateways.entry_gateway();
        if let Some(data) = entry_gateway.lewes_protocol_details.as_ref()
            && !data.verify(&entry_gateway.identity)
        {
            tracing::warn!(
                "Entry gateway {} has malformed LP information, something fishy is going on",
                entry_gateway.identity()
            );
            return Err(tunnel::Error::SelectGateways(Box::new(
                crate::GatewayDirectoryError::MalformedLewesProtocolInfo {
                    identity: entry_gateway.identity().to_base58_string(),
                },
            ))
            .into());
        }
        let entry_lp_data = entry_gateway
            .lewes_protocol_details
            .clone()
            .and_then(|data| {
                let kem_keys = data.content.kem_keys().ok()?;
                let ciphersuite = nym_lp::Ciphersuite::from_node_version(
                    semver::Version::parse(entry_gateway.version.as_ref()?).ok()?,
                )?;
                Some(NymNodeLPInformation {
                    address: SocketAddr::new(entry_ip, data.content.control_port),
                    expected_kem_key_hashes: kem_keys,
                    x25519: data.content.x25519,
                    ciphersuite,
                    // TODO: proper derivation from build version; upstream hardcodes 1.
                    lp_protocol_version: 1,
                })
            });

        let exit_gateway = selected_gateways.exit_gateway();
        if let Some(data) = exit_gateway.lewes_protocol_details.as_ref()
            && !data.verify(&exit_gateway.identity)
        {
            tracing::warn!(
                "Exit gateway {} has malformed LP information, something fishy is going on",
                exit_gateway.identity()
            );
            return Err(tunnel::Error::SelectGateways(Box::new(
                crate::GatewayDirectoryError::MalformedLewesProtocolInfo {
                    identity: exit_gateway.identity().to_base58_string(),
                },
            ))
            .into());
        }
        let exit_lp_data = exit_gateway
            .lewes_protocol_details
            .clone()
            .and_then(|data| {
                let kem_keys = data.content.kem_keys().ok()?;
                let ciphersuite = nym_lp::Ciphersuite::from_node_version(
                    semver::Version::parse(exit_gateway.version.as_ref()?).ok()?,
                )?;
                Some(NymNodeLPInformation {
                    address: SocketAddr::new(exit_ip, data.content.control_port),
                    expected_kem_key_hashes: kem_keys,
                    x25519: data.content.x25519,
                    ciphersuite,
                    lp_protocol_version: 1,
                })
            });

        let entry_node = RegistrationNymNode {
            node: NymNodeInformation {
                identity: selected_gateways.entry_gateway().identity,
                ipr_address: selected_gateways
                    .entry_gateway()
                    .ipr_address
                    .map(Into::into),
                authenticator_address: selected_gateways
                    .entry_gateway()
                    .authenticator_address
                    .map(Into::into),
                ip_address: entry_ip,
                version: selected_gateways.entry_gateway().version.clone().into(),
                lp_data: entry_lp_data,
            },
            keys: selected_gateways.entry_keypair().clone(),
        };

        let exit_node = RegistrationNymNode {
            node: NymNodeInformation {
                identity: selected_gateways.exit_gateway().identity,
                ipr_address: selected_gateways.exit_gateway().ipr_address.map(Into::into),
                authenticator_address: selected_gateways
                    .exit_gateway()
                    .authenticator_address
                    .map(Into::into),
                ip_address: exit_ip,
                version: selected_gateways.exit_gateway().version.clone().into(),
                lp_data: exit_lp_data,
            },
            keys: selected_gateways.exit_keypair().clone(),
        };

        let network_env = self
            .tunnel_parameters
            .nym_config
            .network_rx
            .borrow()
            .clone();
        let nym_network = network_env.nym_network.network.clone();
        let mode = match self.tunnel_parameters.tunnel_settings.tunnel_type {
            TunnelType::Mixnet => RegistrationMode::Mixnet,
            TunnelType::Wireguard => RegistrationMode::Wireguard,
        };
        let rcb_config_builder = RegistrationClientBuilderConfig::builder()
            .entry_node(entry_node)
            .exit_node(exit_node)
            .enable_lp_registration(true)
            .data_path(self.tunnel_parameters.nym_config.data_path.clone())
            .mixnet_client_config(mixnet_client_config)
            .mixnet_client_startup_timeout(REGISTRATION_CLIENT_STARTUP_TIMEOUT)
            .mode(mode)
            .user_agent(user_agent)
            .custom_topology_provider(Box::new(
                self.custom_topology_provider.make_topology_provider(),
            ))
            .network_env(nym_network)
            .cancel_token(self.shutdown_token.child_token());

        let rcb_config_builder =
            rcb_config_builder.connection_fd_callback(Arc::new(connection_fd_callback));

        let rc_builder_config = rcb_config_builder.build();

        // Setup shutdown guard to cancel pending tasks that otherwise may continue running upon return
        let shutdown_guard = self.shutdown_token.clone().drop_guard();

        let rc_builder = RegistrationClientBuilder::new(rc_builder_config);

        let registration_client = Box::pin(rc_builder.build()).await?;
        let registration_result = Box::pin(registration_client.register())
            .await
            // A gateway that accepts the connection but fails registration must
            // be dropped from the entry pool, otherwise we keep retrying it
            // indefinitely (upstream nym-vpn-client #5379).
            .inspect_err(|_| self.send_event(TunnelMonitorEvent::RegistrationFailed))?;

        // Send event upon successful gateway registration
        // The receiver should handle the event and add firewall exceptions for entry gateway
        let tunnel_connection_data = match &registration_result {
            RegistrationResult::Mixnet(result) => {
                TunnelConnectionData::Mixnet(MixnetConnectionData {
                    nym_address: NymAddress::from(result.assigned_addresses.mixnet_client_address),
                    exit_ipr: NymAddress::from(result.assigned_addresses.exit_mix_address),
                    entry_ip: result.assigned_addresses.entry_mixnet_gateway_ip,
                    exit_ip: result.assigned_addresses.exit_mixnet_gateway_ip,
                    ipv4: result.assigned_addresses.interface_addresses.ipv4,
                    ipv6: self
                        .tunnel_parameters
                        .tunnel_settings
                        .enable_ipv6
                        .then_some(result.assigned_addresses.interface_addresses.ipv6),
                })
            }
            RegistrationResult::Wireguard(result) => {
                TunnelConnectionData::Wireguard(WireguardConnectionData {
                    entry_bridge_addr: None, // not known yet
                    entry: WireguardNode::from(result.entry_gateway_data()),
                    exit: WireguardNode::from(result.exit_gateway_data()),
                })
            }
        };
        let connection_data = Box::new(EstablishConnectionData {
            entry_gateway: GatewayLightInfo::from(selected_gateways.entry_gateway().clone()),
            exit_gateway: GatewayLightInfo::from(selected_gateways.exit_gateway().clone()),
            tunnel: Some(tunnel_connection_data),
        });
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send_event(TunnelMonitorEvent::RegisteredWithGateways {
            connection_data,
            reply_tx,
        });
        if tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await.is_err() {
            tracing::warn!("Registered with gateways reply timeout");
        }

        let (entry_metadata_tx, entry_metadata_rx) =
            tokio::sync::oneshot::channel::<MetadataEvent>();
        let (exit_metadata_tx, exit_metadata_rx) = tokio::sync::oneshot::channel::<MetadataEvent>();

        let (entry_metadata_addr_tx, entry_metadata_addr_rx) = tokio::sync::oneshot::channel();
        let (bridge_close_tx, mut bridge_close_rx) = mpsc::unbounded_channel();

        // todo: refactor
        let (
            StartTunnelResult {
                tunnel_interface,
                tunnel_conn_data,
                mut tunnel_handle,
            },
            wg_tunnel_runtime,
            mixnet_client_token,
            _bridge_close_tx,
        ) = match registration_result {
            RegistrationResult::Mixnet(inner_result) => {
                let mixnet_client_token = inner_result.mixnet_client.cancellation_token();

                (
                    self.start_mixnet_tunnel(*inner_result).await?,
                    None,
                    Some(mixnet_client_token),
                    // Return sender back to avoid it being dropped
                    Some(bridge_close_tx),
                )
            }
            RegistrationResult::Wireguard(inner_result) => {
                let (mut connection_data, mut wg_tunnel_runtime) = self
                    .setup_wireguard_tunnel(
                        *inner_result,
                        entry_metadata_rx,
                        exit_metadata_rx,
                        &selected_gateways,
                    )
                    .await?;

                let bridge_close_tx = if self.tunnel_parameters.tunnel_settings.bridges_enabled() {
                    let (entry_bridge_addr, transport_fwd_handle) = self
                        .start_bridges(&selected_gateways, bridge_close_tx)
                        .await?;

                    wg_tunnel_runtime.transport_fwd_handle = Some(transport_fwd_handle);
                    connection_data.entry_bridge_addr = Some(entry_bridge_addr);

                    None
                } else {
                    // Return bridge_close_tx back to avoid it being dropped
                    Some(bridge_close_tx)
                };

                let connected_tunnel = ConnectedTunnel::new(
                    selected_gateways.entry_keypair().clone(),
                    selected_gateways.exit_keypair().clone(),
                    connection_data,
                );

                let _ = entry_metadata_addr_tx;
                let start_tunnel_result =
                    self.start_wireguard_tunnel(connected_tunnel).await?;

                let mixnet_client_token = wg_tunnel_runtime.mixnet_client_token();

                (
                    start_tunnel_result,
                    Some(wg_tunnel_runtime),
                    mixnet_client_token,
                    bridge_close_tx,
                )
            }
        };

        let establishing_connection_data = EstablishConnectionData {
            entry_gateway: GatewayLightInfo::from(selected_gateways.entry_gateway().clone()),
            exit_gateway: GatewayLightInfo::from(selected_gateways.exit_gateway().clone()),
            tunnel: Some(tunnel_conn_data.clone()),
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send_event(TunnelMonitorEvent::InterfaceUp {
            tunnel_interface: tunnel_interface.clone(),
            connection_data: Box::new(establishing_connection_data),
            reply_tx,
        });

        if tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await.is_err() {
            tracing::warn!("Interface up reply timeout");
        }

        // Send metadata endpoint data to the bandwidth controller
        match &tunnel_interface {
            TunnelInterface::One(exit) => {
                let _metadata_event_handler = tokio::spawn(async move {
                    if let Ok(entry_metadata_endpoint) = entry_metadata_addr_rx.await {
                        tracing::info!(
                            "Received entry metadata endpoint: {entry_metadata_endpoint}"
                        );
                        entry_metadata_tx
                            .send(MetadataEvent::MetadataProxy(entry_metadata_endpoint))
                            .ok();
                    }
                });
                exit_metadata_tx
                    .send(MetadataEvent::TunnelMetadata(exit.clone()))
                    .ok();
            }
            TunnelInterface::Two { entry, exit } => {
                entry_metadata_tx
                    .send(MetadataEvent::TunnelMetadata(entry.clone()))
                    .ok();
                exit_metadata_tx
                    .send(MetadataEvent::TunnelMetadata(exit.clone()))
                    .ok();
            }
        }

        let mixnet_monitoring_token = mixnet_client_token
            .map(|token| token.cancelled_owned().fuse())
            .unwrap_or(Fuse::terminated());
        pin_mut!(mixnet_monitoring_token);

        let (tunnel_connection_monitor_tx, mut tunnel_connection_monitor_rx) =
            mpsc::unbounded_channel();
        let tunnel_connection_monitor_handle = self.create_tunnel_connection_monitor(
            tunnel_interface.exit_tunnel_metadata(),
            tunnel_connection_monitor_tx,
        )?;

        let mut last_connection_status = None;
        let mut has_sent_up_event = false;
        let connection_data = Box::new(ConnectionData {
            entry_gateway: GatewayLightInfo::from(selected_gateways.entry_gateway().clone()),
            exit_gateway: GatewayLightInfo::from(selected_gateways.exit_gateway().clone()),
            connected_at: OffsetDateTime::now_utc(),
            tunnel: tunnel_conn_data,
        });

        loop {
            tokio::select! {
                event = tunnel_connection_monitor_rx.recv() => {
                    let Some(event) = event else {
                        tracing::info!("Event channel with connection monitor is closed");
                        break;
                    };
                    // Prevent repeated messages
                    if last_connection_status != Some(event.status) {
                        last_connection_status = Some(event.status);

                        match event.status {
                            ConnectionStatusEvent::Viable => {
                                tracing::info!("Tunnel connection is viable");
                                if !has_sent_up_event {
                                    has_sent_up_event = true;

                                    self.send_event(TunnelMonitorEvent::Up {
                                        tunnel_interface: tunnel_interface.clone(),
                                        connection_data: connection_data.clone(),
                                    });
                                }
                            }
                            ConnectionStatusEvent::IntermittentFailure { retry } => {
                                tracing::info!("Tunnel connection is failing (retry: {retry})");
                            }
                            ConnectionStatusEvent::Failed => {
                                tracing::info!("Tunnel connection is down. Exiting");
                                self.send_event(TunnelMonitorEvent::ConnectionFailed);
                                break;
                            }
                        }
                    }
                }
                close_event = bridge_close_rx.recv() => {
                    if close_event.is_some() {
                        tracing::info!("Bridge close signal received. Exiting");
                    } else {
                        tracing::info!("Bridge channel is closed. Exiting");
                    }
                    break;
                }
                _  = &mut mixnet_monitoring_token => {
                    tracing::error!("MixnetClient exited unexpectedly");
                    break;
                }
                _ = self.shutdown_token.cancelled() => {
                    break;
                }
            }
        }

        // Trigger cancellation since many other tasks depend on shutdown token
        drop(shutdown_guard);

        // Shutdown WireGuard tunnel runtime
        if let Some(wg_tunnel_runtime) = wg_tunnel_runtime {
            if let Err(err) = wg_tunnel_runtime.bandwidth_controller_handle.await {
                tracing::error!("Failed to await bandwidth controller handle: {}", err);
            }

            if let Some(transport_fwd_handle) = wg_tunnel_runtime.transport_fwd_handle
                && let Err(err) = transport_fwd_handle.await
            {
                tracing::error!("Failed to await transport forward handle: {}", err);
            }

            if let Some(authenticator_listener_handle) =
                wg_tunnel_runtime.authenticator_listener_handle
            {
                authenticator_listener_handle.stop().await;
            }
        }

        if let Err(e) = tunnel_connection_monitor_handle.await {
            tracing::error!("Tunnel connection monitor exited with error: {}", e);
        }

        tracing::info!("Waiting for tunnel to exit");
        tunnel_handle.cancel();

        let tun_devices = tunnel_handle
            .wait()
            .await
            .inspect_err(|e| {
                trace_err_chain!(e, "Failed to gracefully shutdown the tunnel");
            })
            .unwrap_or_default();

        tracing::info!("Tunnel monitor finished");

        Ok(tun_devices)
    }

    async fn await_account_readiness_with_retry(&mut self) -> Result<(), Error> {
        match self
            .account_controller_state
            .wait_for_account_ready_to_connect()
            .await
        {
            Ok(()) => Ok(()),
            Err(AccountControllerError::ErrorState(reason)) if reason.is_retryable() => {
                tracing::debug!(
                    "Account controller is in a retryable error state : {reason}. Forcing a refresh"
                );
                self.account_command_tx
                    .background_refresh_account_state()
                    .await
                    .map_err(|e| Error::Account(account::Error::Command(e)))?;
                self.account_controller_state
                    .wait_for_account_ready_to_connect()
                    .await
            }
            Err(e) => Err(e),
        }
        .map_err(|e| Error::Account(account::Error::ControllerState(e)))
    }

    fn send_event(&mut self, event: TunnelMonitorEvent) {
        if let Err(e) = self.monitor_event_sender.send(event)
            && !self.shutdown_token.is_cancelled()
        {
            tracing::error!("Failed to send monitor event: {}", e);
        }
    }

    async fn start_mixnet_tunnel(
        &mut self,
        registration_result: MixnetRegistrationResult,
    ) -> Result<StartTunnelResult> {
        let assigned_addresses = registration_result.assigned_addresses;
        let mtu = if let Some(mtu) = self
            .tunnel_parameters
            .tunnel_settings
            .mixnet_tunnel_options
            .mtu
        {
            mtu
        } else {
            use nym_common::ErrorExt;
            self.route_handler
                .get_mtu_for_route(assigned_addresses.entry_mixnet_gateway_ip)
                .await
                .inspect_err(|e| {
                    tracing::warn!(
                        "{}",
                        e.display_chain_with_msg("Failed to detect mtu for route")
                    );
                })
                .unwrap_or(DEFAULT_TUN_MTU)
        };

        let tun_device = Self::create_mixnet_device(
            assigned_addresses.interface_addresses.ipv4,
            self.enable_ipv6()
                .then_some(assigned_addresses.interface_addresses.ipv6),
            mtu,
        )
        .await?;

        let tun_name = tun_device
            .deref()
            .tun_name()
            .map_err(Error::GetTunDeviceName)?;

        tracing::info!("Created tun device: {}", tun_name);

        let routing_config = RoutingConfig::Mixnet {
            tun_name: tun_name.clone(),
            tun_mtu: mtu,
        };

        self.set_routes(routing_config, self.enable_ipv6()).await?;

        let tunnel_conn_data = TunnelConnectionData::Mixnet(MixnetConnectionData {
            nym_address: NymAddress::from(assigned_addresses.mixnet_client_address),
            exit_ipr: NymAddress::from(assigned_addresses.exit_mix_address),
            entry_ip: assigned_addresses.entry_mixnet_gateway_ip,
            exit_ip: assigned_addresses.exit_mixnet_gateway_ip,
            ipv4: assigned_addresses.interface_addresses.ipv4,
            ipv6: self
                .tunnel_parameters
                .tunnel_settings
                .enable_ipv6
                .then_some(assigned_addresses.interface_addresses.ipv6),
        });

        let mut ips = vec![IpAddr::V4(assigned_addresses.interface_addresses.ipv4)];
        if self.enable_ipv6() {
            ips.push(IpAddr::V6(assigned_addresses.interface_addresses.ipv6));
        }
        let tunnel_metadata = TunnelMetadata {
            interface: tun_name,
            ips,
            ipv4_gateway: None,
            ipv6_gateway: None,
        };

        let tunnel_handle = mixnet::connected_tunnel::start_mixnet_tunnel(
            registration_result.mixnet_client,
            assigned_addresses,
            tun_device,
            self.shutdown_token.child_token(),
            registration_result.event_rx,
        )
        .await
        .map_err(|e| Error::Tunnel(Box::new(e)))?;

        Ok(StartTunnelResult {
            tunnel_interface: TunnelInterface::One(tunnel_metadata),
            tunnel_conn_data,
            tunnel_handle: AnyTunnelHandle::from(tunnel_handle),
        })
    }

    async fn setup_wireguard_tunnel(
        &self,
        registration_result: WireguardRegistrationResult,
        entry_metadata_rx: MetadataReceiver,
        exit_metadata_rx: MetadataReceiver,
        selected_gateways: &SelectedGateways,
    ) -> Result<(WgConnectionData, WgTunnelRuntime)> {
        let (entry_signal_tx, entry_signal_rx) = tokio::sync::oneshot::channel();
        let (exit_signal_tx, exit_signal_rx) = tokio::sync::oneshot::channel();

        let _metadata_event_handler = tokio::spawn(async move {
            if let Ok(entry) = entry_metadata_rx.await {
                entry_signal_tx.send(entry.into()).ok();
            }
            if let Ok(exit) = exit_metadata_rx.await {
                exit_signal_tx.send(exit.into()).ok();
            }
        });

        let (
            entry_gateway_client,
            exit_gateway_client,
            entry_gateway_data,
            exit_gateway_data,
            authenticator_listener_handle,
            bw_controller,
        ) = match registration_result {
            WireguardRegistrationResult::Legacy(res) => (
                Some(res.entry_gateway_client),
                Some(res.exit_gateway_client),
                res.entry_gateway_data,
                res.exit_gateway_data,
                Some(res.authenticator_listener_handle),
                res.bw_controller,
            ),
            WireguardRegistrationResult::LewesProtocol(res) => (
                None,
                None,
                res.entry_gateway_data,
                res.exit_gateway_data,
                None,
                res.bw_controller,
            ),
        };

        let gw_update_version = self
            .tunnel_parameters
            .nym_config
            .network_rx
            .borrow()
            .gw_update_version();

        let bw = BandwidthController::create(
            bw_controller,
            self.account_command_tx.clone(),
            selected_gateways,
            entry_gateway_client,
            exit_gateway_client,
            &entry_gateway_data,
            &exit_gateway_data,
            entry_signal_rx,
            exit_signal_rx,
            gw_update_version,
            self.shutdown_token.child_token(),
        );

        let authenticator_listener_handle = match authenticator_listener_handle {
            Some(handle) if bw.is_using_latest_client() => {
                // We don't need the mixnet client anymore
                tracing::info!(
                    "Disconnecting mixnet client as we are using the latest bandwidth controller"
                );
                handle.stop().await;
                None
            }
            Some(handle) => Some(handle),
            None => None,
        };
        let bandwidth_controller_handle = tokio::spawn(bw.run());

        let rt = WgTunnelRuntime {
            bandwidth_controller_handle,
            transport_fwd_handle: None,
            authenticator_listener_handle,
        };

        let connection_data = WgConnectionData {
            entry_bridge_addr: None,
            entry: entry_gateway_data,
            exit: exit_gateway_data,
        };

        Ok((connection_data, rt))
    }

    async fn start_bridges(
        &self,
        selected_gateways: &SelectedGateways,
        bridge_close_tx: mpsc::UnboundedSender<()>,
    ) -> Result<(BridgeAddress, JoinHandle<()>)> {
        let entry_bridge_params = selected_gateways
            .entry_gateway()
            .get_bridge_params()
            .ok_or(TransportError::config_err(
                "attempted to open transport connection without bridge params",
            ))?;

        // Attempt transport Connection. If successful a listening UDP connection is created
        // and the bind address of that UDP listener is provided to the entry wireguard tunnel
        // as the endpoint address.
        tracing::info!("Establishing DVPN QUIC transport tunnel");

        let fwmark = self.tunnel_parameters.tunnel_constants.fwmark;
        let on_quic_socket_open = move |fd| {
            tracing::debug!("Bypass quic socket");
            let borrowed_fd = unsafe { &BorrowedFd::borrow_raw(fd) };
            if let Err(err) = Mark.set(borrowed_fd, &fwmark) {
                tracing::error!("Could not set fwmark for quic socket fd: {err}");
            }
        };
        let bridge_conn = transports::BridgeConn::try_connect(
            entry_bridge_params,
            self.shutdown_token.child_token(),
            on_quic_socket_open,
        )
        .await?;
        let remote_addr = bridge_conn.endpoint;
        let (listen_addr, join_handle) = transports::UdpForwarder::launch(
            bridge_conn,
            None,
            bridge_close_tx,
            self.shutdown_token.child_token(),
        )
        .await?;

        tracing::info!("quic transport connected, udp forwarder open on {listen_addr}");

        let bridge_addr = BridgeAddress {
            listen_addr,
            remote_addr,
        };

        Ok((bridge_addr, join_handle))
    }

    /// Start WireGuard tunnel using userspace gotatun
    async fn start_wireguard_tunnel(
        &mut self,
        connected_tunnel: ConnectedTunnel,
    ) -> Result<StartTunnelResult> {
        let conn_data = connected_tunnel.connection_data();
        let use_bridges = self.tunnel_parameters.tunnel_settings.bridges_enabled();

        // Clean up any stale TUN devices from a previous crash/interrupted session.
        // If they exist, the kernel auto-assigned names (tun0, tun1) would shift and
        // the route manager's interface map would reference stale indices.
        Self::cleanup_stale_tun_devices().await;

        // Prepare network environment for the wireguard connection to the entry gateway
        let entry_mtu = connected_tunnel.entry_mtu();
        let entry_tun = Self::create_wireguard_device(
            conn_data.entry.private_ipv4,
            self.enable_ipv6().then_some(conn_data.entry.private_ipv6),
            None,
            entry_mtu,
            "nym0",
        )?;
        let entry_tun_name = entry_tun
            .deref()
            .tun_name()
            .map_err(Error::GetTunDeviceName)?;
        tracing::info!("Created entry tun device: {}", entry_tun_name);

        let mut ips = vec![IpAddr::V4(conn_data.entry.private_ipv4)];
        if self.enable_ipv6() {
            ips.push(IpAddr::V6(conn_data.entry.private_ipv6));
        }
        let entry_tunnel_metadata = TunnelMetadata {
            interface: entry_tun_name.clone(),
            ips,
            ipv4_gateway: None,
            ipv6_gateway: None,
        };

        let exit_mtu = connected_tunnel.exit_mtu();
        let exit_tun = Self::create_wireguard_device(
            conn_data.exit.private_ipv4,
            self.enable_ipv6().then_some(conn_data.exit.private_ipv6),
            // todo: this needs to be able to set both destinations?
            Some(conn_data.entry.private_ipv4.into()),
            exit_mtu,
            "nym1",
        )?;
        let exit_tun_name = exit_tun
            .deref()
            .tun_name()
            .map_err(Error::GetTunDeviceName)?;
        tracing::info!("Created exit tun device: {}", exit_tun_name);

        let mut ips = vec![IpAddr::V4(conn_data.exit.private_ipv4)];
        if self.enable_ipv6() {
            ips.push(IpAddr::V6(conn_data.exit.private_ipv6));
        }

        let exit_tunnel_metadata = TunnelMetadata {
            interface: exit_tun_name.clone(),
            ips,
            ipv4_gateway: Some(conn_data.entry.private_ipv4),
            ipv6_gateway: self
                .tunnel_parameters
                .tunnel_settings
                .enable_ipv6
                .then_some(conn_data.entry.private_ipv6),
        };

        let routing_config = RoutingConfig::Wireguard {
            entry_tun_name: entry_tunnel_metadata.interface.clone(),
            exit_tun_name: exit_tunnel_metadata.interface.clone(),
            entry_tun_mtu: entry_mtu,
            exit_tun_mtu: exit_mtu,
            private_entry_gateway_address: self
                .tunnel_parameters
                .tunnel_constants
                .private_entry_gateway_address,
            exit_gateway_address: conn_data.exit.endpoint.ip(),
        };
        self.set_routes(routing_config, self.enable_ipv6()).await?;

        let tunnel_conn_data = TunnelConnectionData::Wireguard(WireguardConnectionData {
            entry_bridge_addr: conn_data.entry_bridge_addr.clone(),
            entry: WireguardNode::from(&conn_data.entry),
            exit: WireguardNode::from(&conn_data.exit),
        });

        let dns_config = self.tunnel_parameters.tunnel_settings.resolved_dns_config();
        let tunnel_options = TunTunTunnelOptions {
            entry_tun,
            exit_tun,
            dns: dns_config.tunnel_config().to_vec(),
        };

        let tunnel_handle = connected_tunnel
            .run(
                tunnel_options,
                self.tunnel_parameters.tunnel_constants,
                !use_bridges,
            )
            .await?;
        let tunnel_handle = AnyTunnelHandle::from(tunnel_handle);

        Ok(StartTunnelResult {
            tunnel_interface: TunnelInterface::Two {
                entry: entry_tunnel_metadata,
                exit: exit_tunnel_metadata,
            },
            tunnel_conn_data,
            tunnel_handle,
        })
    }

    async fn set_routes(&mut self, routing_config: RoutingConfig, enable_ipv6: bool) -> Result<()> {
        self.route_handler
            .add_routes(routing_config, enable_ipv6)
            .await
            .map_err(Error::AddRoutes)?;

        Ok(())
    }

    async fn create_mixnet_device(
        interface_ipv4: Ipv4Addr,
        interface_ipv6: Option<Ipv6Addr>,
        mtu: u16,
    ) -> Result<AsyncDevice> {
        let tun_device = {
            let mut tun_config = tun::Configuration::default();

            tun_config
                .name("nym0")
                .address(interface_ipv4)
                // Newer `tun` crate versions skip configuring the IPv4 address
                // when no netmask is set, which silently drops IPv4 on the
                // mixnet (5-hop) adapter. Mirror create_wireguard_device and set
                // it explicitly (upstream nym-vpn-client #5207).
                .netmask(Ipv4Addr::BROADCAST)
                .mtu(mtu)
                .up();

            tun::create_as_async(&tun_config).map_err(Error::CreateTunDevice)?
        };

        let tun_name = tun_device
            .deref()
            .tun_name()
            .map_err(Error::GetTunDeviceName)?;

        if let Some(interface_ipv6) = interface_ipv6 {
            tun_ipv6::set_ipv6_addr(&tun_name, interface_ipv6)
                .map_err(Error::SetTunDeviceIpv6Addr)?;
        }

        Ok(tun_device)
    }

    fn create_wireguard_device(
        interface_ipv4: Ipv4Addr,
        interface_ipv6: Option<Ipv6Addr>,
        destination: Option<IpAddr>,
        mtu: u16,
        name: &str,
    ) -> Result<AsyncDevice> {
        let mut tun_config = tun::Configuration::default();

        tun_config
            .name(name)
            .address(interface_ipv4)
            .netmask(Ipv4Addr::BROADCAST)
            .mtu(mtu)
            .up();

        if let Some(destination) = destination {
            tun_config.destination(destination);
        }

        let tun_device = tun::create_as_async(&tun_config).map_err(Error::CreateTunDevice)?;

        let tun_name = tun_device
            .deref()
            .tun_name()
            .map_err(Error::GetTunDeviceName)?;

        if let Some(interface_ipv6) = interface_ipv6 {
            tun_ipv6::set_ipv6_addr(&tun_name, interface_ipv6)
                .map_err(Error::SetTunDeviceIpv6Addr)?;
        }

        Ok(tun_device)
    }

    /// Remove stale TUN devices left behind by a previous crash or
    /// interrupted shutdown. Silently succeeds if they don't exist.
    async fn cleanup_stale_tun_devices() {
        for name in &["nym0", "nym1", "tun0", "tun1"] {
            let path = format!("/sys/class/net/{name}");
            if tokio::fs::metadata(&path).await.is_ok() {
                tracing::warn!("Found stale TUN device {name}, removing");
                let result = tokio::process::Command::new("ip")
                    .args(["link", "delete", name])
                    .output()
                    .await;
                match result {
                    Ok(output) if output.status.success() => {
                        tracing::info!("Removed stale TUN device {name}");
                    }
                    Ok(output) => {
                        tracing::warn!(
                            "Failed to remove {name}: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to run ip link delete {name}: {e}");
                    }
                }
            }
        }
    }

    fn enable_ipv6(&self) -> bool {
        self.tunnel_parameters.tunnel_settings.enable_ipv6
    }

    fn create_icmp_probe(&self, exit_tunnel_metadata: &TunnelMetadata) -> Result<IcmpProbe> {
        let icmp_probe_config = IcmpProbeConfig::default_v4()
            .with_interface(exit_tunnel_metadata.interface.clone());

        IcmpProbe::new(icmp_probe_config).map_err(Error::CreateIcmpProbe)
    }

    fn create_tcp_probe(&self, exit_tunnel_metadata: &TunnelMetadata) -> Result<TcpProbe> {
        let tcp_probe_config = TcpProbeConfig::default_v4()
            .with_interface(exit_tunnel_metadata.interface.clone());

        TcpProbe::new(tcp_probe_config).map_err(Error::CreateTcpProbe)
    }

    fn create_tunnel_connection_monitor(
        &self,
        exit_tunnel_metadata: &TunnelMetadata,
        event_tx: mpsc::UnboundedSender<ConnectionEvent>,
    ) -> Result<JoinHandle<Result<(), nym_connection_monitor::Error>>> {
        let timing_config = match self.tunnel_parameters.tunnel_settings.tunnel_type {
            TunnelType::Mixnet => TimingConfig::mixnet(),
            TunnelType::Wireguard => TimingConfig::two_hop(),
        };

        // Create ICMP probe first, fallback to TCP probe on failure
        match self.create_icmp_probe(exit_tunnel_metadata) {
            Ok(icmp_probe) => Ok(ConnectionMonitor::spawn(
                icmp_probe,
                timing_config,
                event_tx,
                self.shutdown_token.child_token(),
            )),
            Err(err) => {
                tracing::warn!("{}", err.display_chain());
                tracing::info!("Fallback to TCP probe");
                let tcp_probe = self.create_tcp_probe(exit_tunnel_metadata)?;

                Ok(ConnectionMonitor::spawn(
                    tcp_probe,
                    timing_config,
                    event_tx,
                    self.shutdown_token.child_token(),
                ))
            }
        }
    }
}

struct StartTunnelResult {
    tunnel_interface: TunnelInterface,
    tunnel_conn_data: TunnelConnectionData,
    tunnel_handle: AnyTunnelHandle,
}

struct WgTunnelRuntime {
    bandwidth_controller_handle: JoinHandle<()>,
    transport_fwd_handle: Option<JoinHandle<()>>,
    authenticator_listener_handle: Option<AuthClientMixnetListenerHandle>,
}

impl WgTunnelRuntime {
    // Returns the mixnet cancellation token, to monitor mixnet client unexpected stop.
    // Returns None if we already stopped it (in new Wireguard mode) and we don't need to monitor it.
    fn mixnet_client_token(&self) -> Option<CancellationToken> {
        self.authenticator_listener_handle
            .as_ref()
            .map(|handle| handle.mixnet_cancel_token())
    }
}
