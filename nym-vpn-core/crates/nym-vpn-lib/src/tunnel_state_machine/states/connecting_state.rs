// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use futures::{
    FutureExt,
    future::{BoxFuture, Fuse},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::Error;
use crate::tunnel_state_machine::gateway_ext::GatewayExt;
use crate::tunnel_state_machine::{
    ErrorStateReason, NextTunnelState, PrivateActionAfterDisconnect, PrivateTunnelState, Result,
    SharedState, TunnelCommand, TunnelInterface, TunnelStateHandler,
    states::{ConnectedState, DisconnectedState, DisconnectingState, ErrorState, OfflineState},
    tunnel::{SelectedGateways, Tombstone},
    tunnel_monitor::{
        TunnelMonitor, TunnelMonitorEvent, TunnelMonitorEventReceiver, TunnelMonitorEventSender,
        TunnelMonitorHandle, TunnelParameters,
    },
};

use nym_common::trace_err_chain;
use nym_dns::DnsConfig;
use nym_firewall::{
    AllowedClients, AllowedEndpoint, AllowedTunnelTraffic, Endpoint, FirewallPolicy,
    TransportProtocol,
};
use nym_gateway_directory::ResolvedConfig;
use nym_vpn_lib_types::TunnelConnectionData;
use nym_vpn_lib_types::{
    AccountControllerErrorStateReason, AccountControllerState, EstablishConnectionData,
    EstablishConnectionState, GatewayLightInfo, TunnelType,
};

/// Initial delay between retry attempts.
const INITIAL_WAIT_DELAY: Duration = Duration::from_secs(2);

/// Wait delay multiplier used for each subsequent retry attempt.
const DELAY_MULTIPLIER: u32 = 2;

/// Max wait delay between retry attempts.
const MAX_WAIT_DELAY: Duration = Duration::from_secs(15);

/// Number of fast retry attempts before switching to exponential backoff.
const FAST_RETRY_ATTEMPTS: u32 = 2;

/// Fast retry delay for network recovery scenarios (first FAST_RETRY_ATTEMPTS).
const NETWORK_RECOVERY_DELAY: Duration = Duration::from_millis(500);

/// Overall deadline for the VPN API reachability probe that distinguishes a
/// local outage from a broken gateway inside the post-drop grace window.
const API_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

type ResolveApiAddrsFuture = BoxFuture<'static, Result<ResolvedConfig>>;
type ReconnectDelayFuture = BoxFuture<'static, ()>;

pub struct ConnectingState {
    retry_attempt: u32,
    tunnel_monitor_handle: Option<TunnelMonitorHandle>,
    tunnel_monitor_event_sender: Option<TunnelMonitorEventSender>,
    tunnel_monitor_event_receiver: TunnelMonitorEventReceiver,
    selected_gateways: Option<SelectedGateways>,
    connection_data: Option<EstablishConnectionData>,
    firewall_policy_params: ConnectingPolicyParameters,
    resolve_api_addrs_fut: Fuse<ResolveApiAddrsFuture>,
    reconnect_delay_fut: Fuse<ReconnectDelayFuture>,
}

impl ConnectingState {
    pub async fn enter(
        retry_attempt: u32,
        selected_gateways: Option<SelectedGateways>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // Disallow networking until firewall exceptions and resolver overrides are configured
        shared_state.disallow_networking().await;

        if shared_state
            .connectivity_handle
            .connectivity()
            .await
            .is_offline()
        {
            return OfflineState::enter(true, selected_gateways, shared_state).await;
        }

        let firewall_policy_params = {
            let mut bridge_endpoints = Vec::new();
            if shared_state.tunnel_settings.bridges_enabled()
                && let Some(gateways) = &selected_gateways
                && let Some(params) = &gateways.entry_gateway().bridge_params
            {
                bridge_endpoints = params.get_addrs();
            }

            let firewall_policy_params = ConnectingPolicyParameters {
                enable_ipv6: shared_state.tunnel_settings.enable_ipv6,
                allow_lan: shared_state.tunnel_settings.allow_lan,
                wg_entry_endpoint: None,
                bridge_endpoints,
                ws_entry_endpoints: selected_gateways
                    .as_ref()
                    .map(|v| v.entry_gateway().endpoints())
                    .unwrap_or_default(),
                lp_entry_endpoints: selected_gateways
                    .as_ref()
                    .map(|v| v.entry_gateway().lp_endpoints())
                    .unwrap_or_default(),
                api_endpoints: Vec::new(),
                // Allow default DNS servers since hickory does not rely on custom DNS
                dns_servers: shared_state.tunnel_settings.default_dns_ips(),
                tunnel_interface: None,
                inbound_exemptions: shared_state.tunnel_settings.inbound_exemptions.clone(),
            };

            if let Err(err) = Self::set_firewall_policy(shared_state, &firewall_policy_params) {
                trace_err_chain!(err, "failed to set firewall policy");
                return ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await;
            }
            firewall_policy_params
        };

        let reconnect_delay_fut = if retry_attempt > 0 {
            let wait_delay = wait_delay(retry_attempt);
            tracing::info!("Waiting {}ms before reconnect", wait_delay.as_millis());
            tokio::time::sleep(wait_delay).boxed().fuse()
        } else {
            std::future::ready(()).boxed().fuse()
        };

        let (monitor_event_sender, monitor_event_receiver) = mpsc::unbounded_channel();

        let initial_connection_data =
            selected_gateways
                .as_ref()
                .map(|gateways| EstablishConnectionData {
                    entry_gateway: GatewayLightInfo::from(gateways.entry_gateway().clone()),
                    exit_gateway: GatewayLightInfo::from(gateways.exit_gateway().clone()),
                    tunnel: None,
                });

        let connecting_state = Self {
            tunnel_monitor_handle: None,
            tunnel_monitor_event_sender: Some(monitor_event_sender),
            tunnel_monitor_event_receiver: monitor_event_receiver,
            retry_attempt,
            selected_gateways,
            connection_data: initial_connection_data.clone(),
            resolve_api_addrs_fut: Fuse::terminated(),
            reconnect_delay_fut,
            firewall_policy_params,
        };

        let tunnel_state = connecting_state.make_connecting_tunnel_state(
            shared_state,
            EstablishConnectionState::ResolvingApiAddresses,
        );

        (Box::new(connecting_state), tunnel_state)
    }

    fn set_firewall_policy(
        shared_state: &mut SharedState,
        params: &ConnectingPolicyParameters,
    ) -> Result<()> {
        let policy = params.as_policy();

        // Apply even before peer/API endpoints are known. Base rules retain
        // mwan3 tracking traffic, while daemon-scoped DNS/NTP bootstrap
        // exceptions let endpoint resolution proceed. Skipping this apply
        // left a fresh install fully open because there was no prior cached
        // Blocked policy to inherit.

        // The firewall caches the kill-switch flag; sync it from live settings
        // so a runtime toggle (LuCI / `tunnel set`) takes effect without a
        // daemon restart.
        shared_state
            .firewall
            .set_killswitch(shared_state.tunnel_settings.killswitch);
        shared_state
            .firewall
            .apply_policy(policy)
            .map_err(Error::SetFirewallPolicy)
    }

    async fn reset_routes(shared_state: &mut SharedState) {
        shared_state.route_handler.remove_routes().await
    }

    /// Whether the currently selected entry gateway is inside its post-drop
    /// grace window and must be retried rather than blamed and re-selected.
    fn grace_retry_pending(&self, shared_state: &SharedState) -> bool {
        match (&self.selected_gateways, shared_state.entry_gateway_grace) {
            (Some(gateways), Some((identity, deadline))) => {
                gateways.entry_gateway().identity == identity
                    && std::time::Instant::now() < deadline
            }
            _ => false,
        }
    }

    async fn reconnect(self, shared_state: &mut SharedState) -> NextTunnelState {
        let next_attempt = self.retry_attempt.saturating_add(1);
        // Refresh the selection every other attempt — unless the current
        // gateway is owed a grace retry, which must run against the same
        // gateway to mean anything.
        let next_gateways =
            if next_attempt.is_multiple_of(2) && !self.grace_retry_pending(shared_state) {
                None
            } else {
                self.selected_gateways
            };

        tracing::info!("Reconnecting, attempt {next_attempt}");

        NextTunnelState::NewState(
            ConnectingState::enter(next_attempt, next_gateways, shared_state).await,
        )
    }

    async fn disconnect(
        after_disconnect: PrivateActionAfterDisconnect,
        tunnel_monitor_handle: TunnelMonitorHandle,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        Self::reset_routes(shared_state).await;

        NextTunnelState::NewState(
            DisconnectingState::enter(after_disconnect, tunnel_monitor_handle, shared_state).await,
        )
    }

    async fn handle_tunnel_close(tombstone: Tombstone, shared_state: &mut SharedState) {
        shared_state.route_handler.remove_routes().await;

        // drop tombstone to close tunnel devices
        let _ = tombstone;
    }

    async fn handle_reconnect_delay(
        mut self: Box<Self>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        // Same resolver the idle states use; what the kill-switch admits is
        // decided in one place.
        self.resolve_api_addrs_fut = crate::tunnel_state_machine::resolve_api_endpoints(
            shared_state.nym_config.gateway_config.clone(),
        )
        .fuse();

        NextTunnelState::SameState(self)
    }

    async fn handle_resolved_gateway_config(
        mut self: Box<Self>,
        resolver_result: Result<ResolvedConfig>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        let resolved_gateway_config = match resolver_result {
            Ok(resolved_gateway_config) => {
                tracing::info!("Resolved gateway config: {:?}", resolved_gateway_config);
                resolved_gateway_config
            }
            Err(e) => {
                trace_err_chain!(e, "Failed to resolve gateway config");
                return self.reconnect(shared_state).await;
            }
        };

        shared_state.adopt_resolved_api_endpoints(&resolved_gateway_config);
        self.firewall_policy_params.api_endpoints = shared_state.api_endpoints.clone();
        if let Err(err) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
            trace_err_chain!(err, "failed to set firewall policy");
            return NextTunnelState::NewState(
                ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
            );
        }

        if resolved_gateway_config.has_resolver_overrides() {
            let resolver_overrides = resolved_gateway_config
                .nym_vpn_api_resolver_overrides
                .clone();

            // Set DNS resolver overrides to ensure that HTTP clients use IP addresses specified in firewall exceptions.
            if !shared_state
                .set_resolver_overrides(resolver_overrides)
                .await
            {
                return NextTunnelState::NewState(
                    ErrorState::enter(
                        ErrorStateReason::Internal("Failed to set resolver overrides".to_owned()),
                        shared_state,
                    )
                    .await,
                );
            }
        } else {
            tracing::warn!(
                "There are no resolver overrides, which may result in the firewall blocking API requests"
            );
        }

        // Allow networking now when firewall and resolver overrides are configured.
        shared_state.allow_networking().await;

        Self::force_account_refresh_if_time_desynced(self.retry_attempt, shared_state).await;

        self.start_tunnel_monitor(Some(resolved_gateway_config), shared_state)
            .await
    }

    /// Requests account summary refresh on the very first connection attempt if the
    /// account controller is stuck in the device-time-desynced error state. This is
    /// an escape hatch so a disconnect/reconnect can leave the error state instead
    /// of failing indefinitely.
    async fn force_account_refresh_if_time_desynced(
        retry_attempt: u32,
        shared_state: &SharedState,
    ) {
        if retry_attempt == 0
            && let AccountControllerState::Error(
                AccountControllerErrorStateReason::DeviceTimeDesynced,
            ) = shared_state.account_controller_state.get_state()
        {
            tracing::info!("Forcing account state refresh due to device time being desynced");
            if let Err(err) = shared_state
                .account_command_tx
                .background_refresh_account_state()
                .await
            {
                trace_err_chain!(
                    err,
                    "failed to request background refresh for account state"
                );
            }
        }
    }

    async fn start_tunnel_monitor(
        mut self: Box<Self>,
        resolved_gateway_config: Option<ResolvedConfig>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        let Some(tunnel_monitor_event_sender) = self.tunnel_monitor_event_sender.take() else {
            return NextTunnelState::NewState(
                ErrorState::enter(
                    ErrorStateReason::Internal(
                        "Monitor event sender is not set. This is a logical error.".to_owned(),
                    ),
                    shared_state,
                )
                .await,
            );
        };

        let tunnel_parameters = TunnelParameters {
            nym_config: shared_state.nym_config.clone(),
            resolved_gateway_config,
            tunnel_settings: shared_state.tunnel_settings.clone(),
            tunnel_constants: shared_state.tunnel_constants,
            selected_gateways: self.selected_gateways.clone(),
            user_agent: shared_state.user_agent.clone(),
            blacklisted_entry_gateways: shared_state.blacklisted_entry_gateways.clone(),
        };
        let tunnel_monitor_handle = TunnelMonitor::start(
            tunnel_parameters,
            shared_state.account_controller_state.clone(),
            shared_state.account_command_tx.clone(),
            shared_state.gateway_cache_handle.clone(),
            shared_state.topology_service.clone(),
            tunnel_monitor_event_sender,
            shared_state.wg_keys_db.clone(),
            shared_state.route_handler.clone(),
        );

        self.tunnel_monitor_handle = Some(tunnel_monitor_handle);

        NextTunnelState::SameState(self)
    }

    async fn handle_registered_with_gateways(
        &mut self,
        connection_data: Box<EstablishConnectionData>,
        shared_state: &mut SharedState,
    ) -> Result<()> {
        // Only allow entry wg endpoint in firewall when bridges are not enabled.
        // Because all bridges are already added to firewall exceptions.
        let wg_entry_endpoint = if let Some(TunnelConnectionData::Wireguard(ref wg)) =
            connection_data.tunnel
            && !shared_state.tunnel_settings.bridges_enabled()
        {
            Some(wg.entry.endpoint)
        } else {
            None
        };
        self.firewall_policy_params.wg_entry_endpoint = wg_entry_endpoint;
        Self::set_firewall_policy(shared_state, &self.firewall_policy_params)?;

        self.connection_data = Some(*connection_data);

        Ok(())
    }

    async fn handle_interface_up(
        &mut self,
        tunnel_interface: TunnelInterface,
        connection_data: Box<EstablishConnectionData>,
        shared_state: &mut SharedState,
    ) -> Result<()> {
        self.connection_data = Some(*connection_data);

        self.firewall_policy_params.tunnel_interface = Some(tunnel_interface);
        Self::set_firewall_policy(shared_state, &self.firewall_policy_params)?;

        Ok(())
    }

    async fn handle_selected_gateways(
        &mut self,
        gateways: Box<SelectedGateways>,
        shared_state: &mut SharedState,
    ) -> Result<()> {
        let set_policy_result = {
            if shared_state.tunnel_settings.bridges_enabled()
                && let Some(params) = &gateways.entry_gateway().bridge_params
            {
                self.firewall_policy_params.bridge_endpoints = params.get_addrs()
            }

            self.firewall_policy_params.ws_entry_endpoints = gateways.entry_gateway().endpoints();
            self.firewall_policy_params.lp_entry_endpoints =
                gateways.entry_gateway().lp_endpoints();
            Self::set_firewall_policy(shared_state, &self.firewall_policy_params)
        };
        self.selected_gateways = Some(*gateways);

        set_policy_result
    }

    /// Quick reachability probe against the known VPN API endpoints, used to
    /// tell a local outage from a broken gateway when a reconnect fails inside
    /// the post-drop grace window. Reaching any endpoint proves the local
    /// network is up. Probes run concurrently under a single deadline so the
    /// event loop is never held up for more than API_PROBE_TIMEOUT. No known
    /// endpoints counts as unreachable (indeterminate, so the grace stands).
    async fn any_api_endpoint_reachable(shared_state: &SharedState) -> bool {
        let probes: Vec<_> = shared_state
            .api_endpoints
            .iter()
            .take(2)
            .map(|addr| Box::pin(tokio::net::TcpStream::connect(*addr)))
            .collect();
        if probes.is_empty() {
            return false;
        }
        matches!(
            tokio::time::timeout(API_PROBE_TIMEOUT, futures::future::select_ok(probes)).await,
            Ok(Ok(_))
        )
    }

    /// Handle a failed connection/registration attempt against the selected
    /// gateways. While the entry gateway of a recently dropped (previously
    /// viable) session is inside its grace window AND the local network is
    /// down (the VPN API is unreachable too), the failure is forgiven and the
    /// same selection retried: blaming the gateway for a WAN blip switches
    /// the user's server for no reason. Once the API answers, the network is
    /// up and the gateway looks genuinely at fault — but this failed attempt
    /// may have started while the network was still down (recovery edge), so
    /// the grace is expired and the same gateway retried one final time; the
    /// next failure comes from an attempt made with the network provenly up
    /// and blacklists it (when culpable), forcing re-selection.
    async fn handle_gateway_failure(
        &mut self,
        entry_culpable: bool,
        failure_kind: &str,
        shared_state: &mut SharedState,
    ) {
        let Some(ref selected_gateways) = self.selected_gateways else {
            return;
        };
        let entry_gateway_identifier = selected_gateways.entry_gateway().identity;

        if self.grace_retry_pending(shared_state) {
            if !Self::any_api_endpoint_reachable(shared_state).await {
                tracing::warn!(
                    "Tunnel {failure_kind} via entry gateway {entry_gateway_identifier} \
                     shortly after a working session dropped, and the VPN API is \
                     unreachable too — this is a local network outage; retrying the \
                     same gateway instead of re-selecting"
                );
                return;
            }
            shared_state.entry_gateway_grace = None;
            tracing::warn!(
                "Tunnel {failure_kind} via entry gateway {entry_gateway_identifier} \
                 while the VPN API is reachable — the network is up, but this \
                 attempt may predate its recovery; giving the gateway one final \
                 retry before blaming it"
            );
            return;
        }

        shared_state.entry_gateway_grace = None;
        if entry_culpable {
            if let Err(e) = shared_state
                .blacklisted_entry_gateways
                .add(entry_gateway_identifier)
            {
                tracing::error!(
                    "Failed to add gateway {entry_gateway_identifier} to blacklisted entry gateway list: {e}"
                );
            } else {
                tracing::warn!(
                    "Blacklisted entry gateway {entry_gateway_identifier} due to repeated {failure_kind}"
                );
            }
        } else {
            tracing::warn!(
                "Repeated {failure_kind} at the exit gateway; re-selecting without blacklisting the entry gateway"
            );
        }
        self.selected_gateways = None;
    }

    fn make_connecting_tunnel_state(
        &self,
        shared_state: &SharedState,
        state: EstablishConnectionState,
    ) -> PrivateTunnelState {
        PrivateTunnelState::Connecting {
            retry_attempt: self.retry_attempt,
            state,
            tunnel_type: shared_state.tunnel_settings.tunnel_type,
            connection_data: self.connection_data.clone(),
        }
    }
}

#[async_trait::async_trait]
impl TunnelStateHandler for ConnectingState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState {
        tokio::select! {
            _ = &mut self.reconnect_delay_fut => {
                self.handle_reconnect_delay(shared_state).await
            },
            resolved_gateway_config = &mut self.resolve_api_addrs_fut => {
                self.handle_resolved_gateway_config(resolved_gateway_config, shared_state).await
            }
            Some(monitor_event) = self.tunnel_monitor_event_receiver.recv() => {
                match monitor_event {
                    TunnelMonitorEvent::AwaitingAccountReadiness => {
                        let new_state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::AwaitingAccountReadiness);
                        NextTunnelState::NewState((self, new_state))
                    }
                    TunnelMonitorEvent::RefreshingGateways => {
                        let new_state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::RefreshingGateways);
                        NextTunnelState::NewState((self, new_state))
                    }
                    TunnelMonitorEvent::RegisteringWithGateways => {
                        let new_state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::RegisteringWithGateways);
                        NextTunnelState::NewState((self, new_state))
                    }
                    TunnelMonitorEvent::SelectingGateways => {
                        let new_state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::SelectingGateways);
                        NextTunnelState::NewState((self, new_state))
                    }
                    TunnelMonitorEvent::SelectedGateways {
                        gateways, reply_tx
                    } => {
                    let next_state = match self.handle_selected_gateways(gateways, shared_state).await {
                            Ok(()) => {
                                NextTunnelState::SameState(self)
                            }
                            Err(e) => {
                                trace_err_chain!(e, "Failed to set firewall policy");
                                if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                                    NextTunnelState::NewState(DisconnectingState::enter(
                                        PrivateActionAfterDisconnect::Error(ErrorStateReason::SetFirewallPolicy),
                                        tunnel_monitor_handle,
                                        shared_state
                                    ).await)
                                } else {
                                    NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await)
                                }
                            }
                        };
                        _ = reply_tx.send(());
                        next_state
                    }
                    TunnelMonitorEvent::RegisteredWithGateways { connection_data, reply_tx } => {
                        let next_state = match self.handle_registered_with_gateways(connection_data, shared_state).await {
                            Ok(()) => {
                                let new_state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::ConnectingTunnel);
                                NextTunnelState::NewState((self, new_state))
                            }
                            Err(e) => {
                                trace_err_chain!(e, "Failed to set firewall policy");
                                if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                                    NextTunnelState::NewState(DisconnectingState::enter(
                                        PrivateActionAfterDisconnect::Error(ErrorStateReason::SetFirewallPolicy),
                                        tunnel_monitor_handle,
                                        shared_state
                                    ).await)
                                } else {
                                    NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await)
                                }
                            }
                        };
                        _ = reply_tx.send(());
                        next_state
                    }
                    TunnelMonitorEvent::InterfaceUp {
                        tunnel_interface, connection_data, reply_tx
                    }  => {
                        let next_state = match self.handle_interface_up(tunnel_interface, connection_data, shared_state).await {
                            Ok(()) => {
                                let state = self.make_connecting_tunnel_state(shared_state, EstablishConnectionState::ConnectingTunnel);
                                NextTunnelState::NewState((self, state))
                            },
                            Err(e) => {
                                trace_err_chain!(e, "Failed to set firewall policy");
                                if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                                    NextTunnelState::NewState(DisconnectingState::enter(
                                        PrivateActionAfterDisconnect::Error(ErrorStateReason::SetFirewallPolicy),
                                        tunnel_monitor_handle,
                                        shared_state
                                    ).await)
                                } else {
                                    NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await)
                                }
                            }
                        };
                        _ = reply_tx.send(());
                        next_state
                    }
                    TunnelMonitorEvent::Up { tunnel_interface, connection_data } => {
                        // We have successfully connected, clear any blacklisted entry gateways
                        shared_state.entry_gateway_grace = None;
                        match shared_state.blacklisted_entry_gateways.is_empty() {
                            Ok(is_empty) => if !is_empty {
                                tracing::info!("Clearing blacklisted entry gateways");
                                if let Err(e) = shared_state.blacklisted_entry_gateways.clear() {
                                    tracing::error!("Failed to clear blacklisted entry gateway list: {e}");
                                }
                            }
                            Err(e) => tracing::error!("Failed to read blacklisted entry gateway list: {e}")
                        }

                        NextTunnelState::NewState(ConnectedState::enter(
                            tunnel_interface,
                            *connection_data,
                            self.selected_gateways.expect("selected gateways must be set"),
                            self.tunnel_monitor_handle.expect("monitor handle must be set!"),
                            self.tunnel_monitor_event_receiver,
                            shared_state,
                        ).await)
                    }
                    TunnelMonitorEvent::Down { error_state_reason, reply_tx } => {
                        // Signal that the message was received first.
                        _ = reply_tx.send(());

                        if let Some(error_state_reason) = error_state_reason {
                            NextTunnelState::NewState(DisconnectingState::enter(
                                PrivateActionAfterDisconnect::Error(error_state_reason),
                                self.tunnel_monitor_handle.expect("monitor handle must be set!"),
                                shared_state
                            ).await)
                        } else {
                            if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle.take() {
                                let tombstone = tunnel_monitor_handle.wait().await;
                                Self::handle_tunnel_close(tombstone, shared_state).await;
                            }

                            tracing::info!("Tunnel closed");

                            self.reconnect(shared_state).await
                        }
                    }
                    TunnelMonitorEvent::ConnectionFailed => {
                        // Failed to connect via the entry gateway. Inside the post-drop
                        // grace window with the API also unreachable this is forgiven
                        // (local outage); otherwise blacklist and force gateway
                        // re-selection.
                        self.handle_gateway_failure(true, "connection failure", shared_state).await;
                        NextTunnelState::SameState(self)
                    }
                    TunnelMonitorEvent::RegistrationFailed { entry_culpable } => {
                        // Registration failed. Only blacklist the entry gateway when it is
                        // the culpable party — an exit-gateway registration rejection must
                        // not poison the (innocent) entry gateway. Either way force
                        // re-selection (once past the post-drop grace window) so a
                        // Random exit can land on a different node next attempt (a
                        // pinned, broken exit will simply keep retrying).
                        self.handle_gateway_failure(entry_culpable, "registration failure", shared_state).await;
                        NextTunnelState::SameState(self)
                    }
                }
           }
            Some(command) = command_rx.recv() => {
                tracing::debug!("ConnectingState received command: {command:?}");
                match command {
                    TunnelCommand::Connect => {
                        if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                            Self::disconnect(PrivateActionAfterDisconnect::Reconnect { gateways: None }, tunnel_monitor_handle, shared_state).await
                        } else {
                            NextTunnelState::NewState(ConnectingState::enter(self.retry_attempt, None, shared_state).await)
                        }
                    },
                    TunnelCommand::Disconnect => {
                        if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                            Self::disconnect(PrivateActionAfterDisconnect::Nothing, tunnel_monitor_handle, shared_state).await
                        } else {
                            Self::reset_routes(shared_state).await;
                            NextTunnelState::NewState(DisconnectedState::enter(None, shared_state).await)
                        }
                    },
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        let Some(diff) = shared_state.tunnel_settings.diff(&tunnel_settings) else {
                            return NextTunnelState::SameState(self);
                        };

                        // Assign before re-applying so the firewall sync inside
                        // set_firewall_policy picks up the new killswitch/
                        // allow_lan/inbound_exemptions values, not stale ones.
                        shared_state.tunnel_settings = tunnel_settings;

                        // Hot-apply path — mirrors connected_state. The exempt
                        // routing rule is permanent for the tunnel lifetime, so only
                        // the firewall mark-set rules are re-applied here.
                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = shared_state.tunnel_settings.allow_lan;
                        }
                        if diff.inbound_exemptions_changed() {
                            self.firewall_policy_params.inbound_exemptions =
                                shared_state.tunnel_settings.inbound_exemptions.clone();
                        }

                        if diff.allow_lan_changed() || diff.inbound_exemptions_changed() || diff.killswitch_changed() {
                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                                return NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await);
                            }
                        }

                        // Not all changes require the tunnel to be reconnected
                        if diff.only_hot_appliable_changed() || (diff.only_mixnet_performance_options_changed() && shared_state.tunnel_settings.tunnel_type == TunnelType::Wireguard) {
                            return NextTunnelState::SameState(self);
                        }

                        // Same rule as connected_state: a settings-driven
                        // reconnect keeps the pair it had unless the change is
                        // an input to gateway selection.
                        let next_gateways = if diff.affects_gateway_selection() {
                            None
                        } else {
                            self.selected_gateways
                        };

                        if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                           Self::disconnect(PrivateActionAfterDisconnect::Reconnect { gateways: next_gateways }, tunnel_monitor_handle, shared_state).await
                        } else {
                            NextTunnelState::NewState(ConnectingState::enter(self.retry_attempt, next_gateways, shared_state).await)
                        }
                    }
                }
            }
            Some(connectivity) = shared_state.connectivity_handle.next() => {
                if connectivity.is_offline() {
                    if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                        Self::disconnect(PrivateActionAfterDisconnect::Offline {
                            reconnect: true,
                            gateways: self.selected_gateways
                        }, tunnel_monitor_handle, shared_state).await
                    } else {
                        NextTunnelState::NewState(OfflineState::enter(true, self.selected_gateways, shared_state).await)
                    }
                } else {
                    NextTunnelState::SameState(self)
                }
            }
            _ = shutdown_token.cancelled() => {
                if let Some(tunnel_monitor_handle) = self.tunnel_monitor_handle {
                    Self::disconnect(PrivateActionAfterDisconnect::Nothing, tunnel_monitor_handle, shared_state).await
                } else {
                    Self::reset_routes(shared_state).await;
                    NextTunnelState::NewState(DisconnectedState::enter(None, shared_state).await)
                }
            }
        }
    }
}

/// Firewall policy configuration when connecting
#[derive(Debug, Clone)]
struct ConnectingPolicyParameters {
    /// Whether IPv6 is enabled
    enable_ipv6: bool,

    /// Whether to allow LAN traffic
    allow_lan: bool,

    /// WireGuard entry endpoint
    wg_entry_endpoint: Option<SocketAddr>,

    /// Bridge endpoints
    bridge_endpoints: Vec<SocketAddr>,

    /// Entry gateway websocket endpoints
    ws_entry_endpoints: Vec<SocketAddr>,

    /// Entry gateway Lewes Protocol control endpoints
    lp_entry_endpoints: Vec<SocketAddr>,

    /// API endpoints
    api_endpoints: Vec<SocketAddr>,

    /// DNS servers
    dns_servers: Vec<IpAddr>,

    /// Tunnel interface
    tunnel_interface: Option<TunnelInterface>,

    /// Inbound services exempted from the tunnel.
    inbound_exemptions: Vec<nym_firewall::InboundExemption>,
}

impl ConnectingPolicyParameters {
    pub fn as_policy(&self) -> FirewallPolicy {
        // Allow websocket entry endpoints
        let mut peer_endpoints = self
            .ws_entry_endpoints
            .iter()
            .filter(|addr| addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()))
            .map(|addr| {
                AllowedEndpoint::new(
                    Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                    AllowedClients::Root,
                )
            })
            .collect::<Vec<_>>();

        // Allow WireGuard and entry endpoint
        if let Some(addr) = self.wg_entry_endpoint {
            if addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()) {
                let allow_wg_endpoint = AllowedEndpoint::new(
                    Endpoint::from_socket_address(addr, TransportProtocol::Udp),
                    AllowedClients::Root,
                );

                peer_endpoints.push(allow_wg_endpoint);
            } else {
                tracing::warn!("WireGuard endpoint contains IPv6 address, but IPv6 is disabled!");
            }
        }

        // Allow endpoints from bridge connections to the entry gateway.
        self.bridge_endpoints
            .iter()
            .filter(|addr| addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()))
            .for_each(|addr| {
                let allow_bridge_endpoint = AllowedEndpoint::new(
                    Endpoint::from_socket_address(*addr, TransportProtocol::Udp),
                    AllowedClients::Root,
                );
                peer_endpoints.push(allow_bridge_endpoint);
            });

        // Allow API endpoints
        let mut allowed_endpoints = self
            .api_endpoints
            .iter()
            .filter(|ip| ip.is_ipv4() || (self.enable_ipv6 && ip.is_ipv6()))
            .map(|addr| {
                AllowedEndpoint::new(
                    Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                    AllowedClients::Root,
                )
            })
            .collect::<Vec<_>>();

        // Allow LP control endpoints for LP-based registration. These must be in
        // allowed_endpoints (non-tunnel), not peer_endpoints, since LP registration
        // connects to the entry gateway's control port before the tunnel is up
        // (upstream nym-vpn-client #5516).
        allowed_endpoints.extend(
            self.lp_entry_endpoints
                .iter()
                .filter(|addr| addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()))
                .map(|addr| {
                    AllowedEndpoint::new(
                        Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                        AllowedClients::Root,
                    )
                }),
        );

        let tunnel = self
            .tunnel_interface
            .clone()
            .map(nym_firewall::TunnelInterface::from);

        // Set non-tunnel DNS to allow api client to use those DNS servers.
        let dns_config = DnsConfig::from_addresses(&[], &self.dns_servers).resolve(
            // pass empty because we already override the config with non-tunnel addresses.
            &[],
        );

        FirewallPolicy::Connecting {
            peer_endpoints,
            tunnel,
            allow_lan: self.allow_lan,
            dns_config,
            allowed_endpoints,
            // todo: only allow connection towards entry endpoint?
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
            inbound_exemptions: self.inbound_exemptions.clone(),
        }
    }
}

fn wait_delay(retry_attempt: u32) -> Duration {
    // Use fast retries for the first FAST_RETRY_ATTEMPTS to handle network recovery
    // where the network reports as "online" before DNS/routing are ready.
    if retry_attempt <= FAST_RETRY_ATTEMPTS {
        NETWORK_RECOVERY_DELAY
    } else {
        // After fast retries, use exponential backoff for persistent failures
        let multiplier = retry_attempt
            .saturating_sub(FAST_RETRY_ATTEMPTS)
            .saturating_mul(DELAY_MULTIPLIER);
        let delay = INITIAL_WAIT_DELAY.saturating_mul(multiplier);
        std::cmp::min(delay, MAX_WAIT_DELAY)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wait_delay_sequence() {
        let retry_attempt_values: Vec<u32> = (0..10).collect();
        let expected_delays: [Duration; 10] = [
            NETWORK_RECOVERY_DELAY,
            NETWORK_RECOVERY_DELAY,
            NETWORK_RECOVERY_DELAY,
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(12),
            MAX_WAIT_DELAY,
            MAX_WAIT_DELAY,
            MAX_WAIT_DELAY,
            MAX_WAIT_DELAY,
        ];

        let delay_values: Vec<Duration> = retry_attempt_values
            .iter()
            .map(|i| wait_delay(*i))
            .collect();
        assert_eq!(delay_values, expected_delays);
    }
}
