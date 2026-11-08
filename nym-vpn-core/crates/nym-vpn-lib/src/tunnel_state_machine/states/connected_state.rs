// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;

use nym_dns::ResolvedDnsConfig;
use nym_vpn_lib_types::{ErrorStateReason, TunnelType};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    ConnectionData, NextTunnelState, PrivateActionAfterDisconnect, PrivateTunnelState,
    SessionStart, SharedState, TunnelCommand, TunnelInterface, TunnelMetadata,
    TunnelStateHandler,
    side_tunnel::{self, SideTunnel, SideTunnelEvent, SideTunnelHandle},
    states::{ConnectingState, DisconnectingState},
    tunnel::SelectedGateways,
    tunnel_monitor::{TunnelMonitorEvent, TunnelMonitorEventReceiver, TunnelMonitorHandle},
};
use crate::tunnel_state_machine::{Error, Result, gateway_ext::GatewayExt};
use nym_common::trace_err_chain;
use nym_firewall::{AllowedClients, AllowedEndpoint, Endpoint, FirewallPolicy, TransportProtocol};
use nym_vpn_lib_types::{SideTunnelState, TunnelConnectionData};

use super::ErrorState;

pub struct ConnectedState {
    tunnel_monitor_handle: TunnelMonitorHandle,
    tunnel_monitor_event_receiver: TunnelMonitorEventReceiver,
    selected_gateways: SelectedGateways,
    tunnel_interface: TunnelInterface,
    firewall_policy_params: ConnectedPolicyParameters,
    /// Set when the bandwidth controller ended the session, to the gateway
    /// to blame as in `TunnelMonitorEvent::BandwidthChecks`.
    bandwidth_failure: Option<Option<bool>>,
    /// Whether the session's bandwidth checks worked.
    bandwidth_checks_worked: bool,
    connected_at: SessionStart,
    /// What the Connected events carry; the side tunnel's state changes it.
    connection_data: ConnectionData,
    side_tunnel: Option<RunningSideTunnel>,
}

struct RunningSideTunnel {
    handle: SideTunnelHandle,
    event_rx: mpsc::UnboundedReceiver<SideTunnelEvent>,
}

impl ConnectedState {
    pub async fn enter(
        tunnel_interface: TunnelInterface,
        connection_data: ConnectionData,
        selected_gateways: SelectedGateways,
        tunnel_monitor_handle: TunnelMonitorHandle,
        tunnel_monitor_event_receiver: TunnelMonitorEventReceiver,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        let wg_entry_endpoint =
            if let TunnelConnectionData::Wireguard(ref wg) = connection_data.tunnel {
                if shared_state.tunnel_settings.bridges_enabled() {
                    // this will be `Some` if we get to the connected state with bridges enabled.
                    wg.entry_bridge_addr.as_ref().map(|addr| addr.remote_addr)
                } else {
                    Some(wg.entry.endpoint)
                }
            } else {
                None
            };

        let firewall_policy_params = {
            // Include entry gateway WebSocket endpoints
            let mut ws_endpoints = selected_gateways.entry_gateway().endpoints();
            // Also include exit gateway WebSocket endpoints for SOCKS5 support in 2-hop mode.
            // These endpoints are whitelisted in firewall rules (peer_endpoints), allowing SOCKS5
            // to establish direct connections to the exit gateway
            ws_endpoints.extend(selected_gateways.exit_gateway().endpoints());

            ConnectedPolicyParameters {
                enable_ipv6: shared_state.tunnel_settings.enable_ipv6,
                allow_lan: shared_state.tunnel_settings.allow_lan,
                wg_entry_endpoint,
                ws_entry_endpoints: ws_endpoints,
                dns_config: shared_state.tunnel_settings.resolved_dns_config(),
                tunnel_interface: tunnel_interface.clone(),
                side_tunnel: None,
                allowed_endpoints: Vec::new(),
                inbound_exemptions: shared_state.tunnel_settings.inbound_exemptions.clone(),
            }
        };

        let mut connected_state = Self {
            tunnel_monitor_handle,
            tunnel_monitor_event_receiver,
            selected_gateways,
            tunnel_interface,
            firewall_policy_params,
            bandwidth_failure: None,
            bandwidth_checks_worked: false,
            connected_at: SessionStart::now(),
            connection_data,
            side_tunnel: None,
        };

        if let Err(e) =
            Self::set_firewall_policy(shared_state, &connected_state.firewall_policy_params)
        {
            trace_err_chain!(e, "failed to apply firewall policy");
            return DisconnectingState::enter(
                PrivateActionAfterDisconnect::Error(ErrorStateReason::SetFirewallPolicy),
                connected_state.tunnel_monitor_handle,
                shared_state,
            )
            .await;
        } else if let Err(e) = connected_state.set_dns(shared_state).await {
            trace_err_chain!(e, "failed to set dns");
            return DisconnectingState::enter(
                PrivateActionAfterDisconnect::Error(ErrorStateReason::SetDns),
                connected_state.tunnel_monitor_handle,
                shared_state,
            )
            .await;
        }

        // Reset DNS resolver overrides since connections can be established over the tunnel
        shared_state.reset_resolver_overrides().await;

        if shared_state.tunnel_settings.side_tunnel_enabled() {
            connected_state.start_side_tunnel(shared_state);
        }

        let state = connected_state.private_state();
        (Box::new(connected_state), state)
    }

    fn private_state(&self) -> PrivateTunnelState {
        PrivateTunnelState::Connected {
            connection_data: self.connection_data.clone(),
        }
    }

    /// A new Connected event when the side tunnel's state changed since
    /// `previous`, so that clients see it.
    fn same_or_updated(self: Box<Self>, previous: &Option<SideTunnelState>) -> NextTunnelState {
        if self.connection_data.side_tunnel == *previous {
            NextTunnelState::SameState(self)
        } else {
            let state = self.private_state();
            NextTunnelState::NewState((self, state))
        }
    }

    fn start_side_tunnel(&mut self, shared_state: &SharedState) {
        tracing::info!("Starting the mixnet side tunnel");
        let (handle, event_rx) = SideTunnel::start(
            shared_state.nym_config.clone(),
            shared_state.tunnel_settings.clone(),
            &self.selected_gateways,
            shared_state.user_agent.clone(),
            shared_state.route_handler.clone(),
            shared_state.gateway_cache_handle.clone(),
            shared_state.topology_service.clone(),
            shared_state.wg_keys_db.clone(),
        );
        self.side_tunnel = Some(RunningSideTunnel { handle, event_rx });
        self.connection_data.side_tunnel = Some(SideTunnelState::Connecting { retry_attempt: 0 });
    }

    /// Takes the side tunnel down and out of the firewall policy; the
    /// two-hop tunnel stays.
    async fn stop_side_tunnel(&mut self, shared_state: &mut SharedState) -> Result<()> {
        if let Some(side_tunnel) = self.side_tunnel.take() {
            tracing::info!("Stopping the mixnet side tunnel");
            side_tunnel.handle.stop().await;
        }
        // Already done by the side tunnel, unless it did not stop in time.
        shared_state.route_handler.remove_side_tunnel_routes().await;
        self.connection_data.side_tunnel = None;
        if self.firewall_policy_params.side_tunnel.take().is_some() {
            Self::set_firewall_policy(shared_state, &self.firewall_policy_params)?;
        }
        Ok(())
    }

    /// Before leaving the state; the next state's policy and routes replace
    /// this one's.
    async fn stop_side_tunnel_on_exit(&mut self) {
        if let Some(side_tunnel) = self.side_tunnel.take() {
            side_tunnel.handle.stop().await;
        }
    }

    async fn handle_side_tunnel_event(
        mut self: Box<Self>,
        event: SideTunnelEvent,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        let previous = self.connection_data.side_tunnel.clone();
        match event {
            SideTunnelEvent::Connecting { retry_attempt } => {
                self.connection_data.side_tunnel =
                    Some(SideTunnelState::Connecting { retry_attempt });
            }
            SideTunnelEvent::InterfaceUp { metadata, reply_tx } => {
                self.firewall_policy_params.side_tunnel = Some(metadata);
                let result = Self::set_firewall_policy(shared_state, &self.firewall_policy_params);
                _ = reply_tx.send(());
                if let Err(e) = result {
                    trace_err_chain!(e, "failed to admit the side tunnel in the firewall");
                    return self
                        .disconnect(
                            PrivateActionAfterDisconnect::Error(
                                ErrorStateReason::SetFirewallPolicy,
                            ),
                            shared_state,
                        )
                        .await;
                }
            }
            SideTunnelEvent::Up(connection_data) => {
                self.connection_data.side_tunnel = Some(SideTunnelState::Up(*connection_data));
            }
            SideTunnelEvent::Down => {
                if self.firewall_policy_params.side_tunnel.take().is_some()
                    && let Err(e) =
                        Self::set_firewall_policy(shared_state, &self.firewall_policy_params)
                {
                    trace_err_chain!(e, "failed to drop the side tunnel from the firewall");
                    return self
                        .disconnect(
                            PrivateActionAfterDisconnect::Error(
                                ErrorStateReason::SetFirewallPolicy,
                            ),
                            shared_state,
                        )
                        .await;
                }
            }
        }
        self.same_or_updated(&previous)
    }

    fn set_firewall_policy(
        shared_state: &mut SharedState,
        params: &ConnectedPolicyParameters,
    ) -> Result<()> {
        let policy = params.as_policy();

        shared_state
            .firewall
            .set_killswitch(shared_state.tunnel_settings.killswitch);
        shared_state
            .firewall
            .apply_policy(policy)
            .map_err(Error::SetFirewallPolicy)
    }

    async fn set_dns(&self, shared_state: &mut SharedState) -> Result<()> {
        let dns_config = shared_state.tunnel_settings.resolved_dns_config();
        let tunnel_metadata = self.tunnel_interface.exit_tunnel_metadata();

        shared_state
            .dns_handler
            .set(tunnel_metadata.interface.clone(), dns_config)
            .await
            .map_err(Error::SetDns)?;

        Ok(())
    }

    async fn reset_dns(shared_state: &mut SharedState) {
        if let Err(error) = shared_state
            .dns_handler
            .reset_before_interface_removal()
            .await
        {
            trace_err_chain!(error, "Failed to reset DNS");
        }
    }

    async fn reset_routes(shared_state: &mut SharedState) {
        shared_state.route_handler.remove_routes().await
    }

    async fn disconnect(
        mut self,
        after_disconnect: PrivateActionAfterDisconnect,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        self.stop_side_tunnel_on_exit().await;
        Self::reset_dns(shared_state).await;
        Self::reset_routes(shared_state).await;

        NextTunnelState::NewState(
            DisconnectingState::enter(after_disconnect, self.tunnel_monitor_handle, shared_state)
                .await,
        )
    }

    async fn handle_tunnel_down(
        mut self,
        error_state_reason: Option<ErrorStateReason>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        if error_state_reason.is_none() {
            tracing::info!("Tunnel closed. Reconnecting.");
        }

        self.stop_side_tunnel_on_exit().await;
        Self::reset_dns(shared_state).await;
        Self::reset_routes(shared_state).await;

        let lifetime = self.connected_at.lifetime();
        let tunnel_type = shared_state.tunnel_settings.tunnel_type;
        let worked = self.bandwidth_checks_worked;

        match (error_state_reason, self.bandwidth_failure) {
            (Some(block_reason), _) => {
                NextTunnelState::NewState(ErrorState::enter(block_reason, shared_state).await)
            }
            (None, Some(entry_culpable)) => {
                // The tunnel carried traffic until the bandwidth checks
                // failed, so the local network is not the cause: no grace,
                // and a backoff that grows with the streak.
                shared_state.entry_gateway_grace = None;
                let retry_attempt = shared_state.bandwidth_failure_streak.record_failure(worked);
                if !shared_state.bandwidth_failure_streak.ends_sessions() {
                    tracing::warn!(
                        "Bandwidth failures ended {retry_attempt} sessions in a row; \
                         later sessions run on without top-ups until the gateway ends them"
                    );
                }
                let gateways = match entry_culpable {
                    Some(true) => {
                        shared_state.blacklist_entry_gateway(
                            self.selected_gateways.entry_gateway().identity,
                            "bandwidth failure",
                        );
                        None
                    }
                    Some(false) => {
                        tracing::warn!(
                            "Bandwidth failure at the exit gateway; re-selecting without blacklisting the entry gateway"
                        );
                        None
                    }
                    None => Some(self.selected_gateways),
                };
                NextTunnelState::NewState(
                    ConnectingState::enter(retry_attempt, gateways, shared_state).await,
                )
            }
            (None, None) => {
                shared_state
                    .bandwidth_failure_streak
                    .record_other_end(worked);

                // This session was viable moments ago, so reconnect failures in
                // the near future are far more likely a local outage than the
                // gateway's fault. Grant the entry gateway a grace window during
                // which failures are retried against it instead of blacklisting
                // it and switching the user to a different server.
                let entry = self.selected_gateways.entry_gateway().identity;
                shared_state.entry_gateway_grace = Some((
                    entry,
                    tokio::time::Instant::now() + crate::tunnel_state_machine::GATEWAY_BLAME_GRACE,
                ));

                // Unless the grace keeps forgiving a gateway whose sessions
                // never last: Connecting then probes the API to decide.
                let retry_attempt = if shared_state.short_session_strikes.record(
                    entry,
                    lifetime,
                    tunnel_type,
                ) {
                    tracing::warn!(
                        "Session via entry gateway {entry} lasted only {}s, again; checking whether the gateway is to blame",
                        lifetime.as_secs()
                    );
                    shared_state.entry_gateway_suspect = Some(entry);
                    1
                } else {
                    0
                };

                NextTunnelState::NewState(
                    ConnectingState::enter(
                        retry_attempt,
                        Some(self.selected_gateways),
                        shared_state,
                    )
                    .await,
                )
            }
        }
    }
}

#[async_trait::async_trait]
impl TunnelStateHandler for ConnectedState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                tracing::debug!("ConnectedState received command: {command:?}");
                match command {
                    TunnelCommand::Connect { relax_independence } => {
                        shared_state.relax_independence = relax_independence;
                        self.disconnect(PrivateActionAfterDisconnect::Reconnect { gateways: None }, shared_state).await
                    },
                    TunnelCommand::Disconnect => {
                        self.disconnect(PrivateActionAfterDisconnect::Nothing, shared_state).await
                    },
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        let Some(diff) = shared_state.tunnel_settings.diff(&tunnel_settings) else {
                            return NextTunnelState::SameState(self);
                        };

                        // Hot-apply path: mutate firewall_policy_params for every
                        // field we can re-apply in place, then call set_firewall_policy
                        // exactly once. The exempt routing rule (fwmark 0x14e -> main,
                        // pri 90) is a permanent fixture of the connected tunnel — it is
                        // installed once in create_routing_rules and torn down at
                        // disconnect — so toggling inbound exemptions here only re-applies
                        // the firewall mark-set rules; the routing rule needs no change.
                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = tunnel_settings.allow_lan;
                        }
                        if diff.inbound_exemptions_changed() {
                            self.firewall_policy_params.inbound_exemptions =
                                tunnel_settings.inbound_exemptions.clone();
                        }

                        if diff.allow_lan_changed() || diff.inbound_exemptions_changed() {
                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                                return NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await);
                            }
                        }

                        shared_state.tunnel_settings = tunnel_settings;

                        // A gateway newly pinned for the side tunnel that the
                        // two-hop pair already sits on: re-select the pair,
                        // which then leaves it to the side tunnel.
                        let side_pin_taken = diff.side_gateways_changed()
                            && shared_state.tunnel_settings.side_tunnel_pins_taken_by(&self.selected_gateways);

                        // Not all changes require the tunnel to be reconnected
                        let mixnet_only = diff.only_mixnet_performance_options_changed() && shared_state.tunnel_settings.tunnel_type == TunnelType::Wireguard;
                        if (diff.only_hot_appliable_changed() || mixnet_only) && !side_pin_taken {
                            // The side tunnel is the mixnet here: restart it
                            // with the new options or gateways, or start or
                            // stop it.
                            let previous = self.connection_data.side_tunnel.clone();
                            let wanted = shared_state.tunnel_settings.side_tunnel_enabled();
                            let running = self.side_tunnel.is_some();
                            let restart = mixnet_only || diff.side_gateways_changed();
                            if running && (!wanted || restart)
                                && let Err(e) = self.stop_side_tunnel(shared_state).await
                            {
                                trace_err_chain!(e, "failed to set firewall policy");
                                return self.disconnect(PrivateActionAfterDisconnect::Error(ErrorStateReason::SetFirewallPolicy), shared_state).await;
                            }
                            if wanted && self.side_tunnel.is_none() {
                                self.start_side_tunnel(shared_state);
                            }
                            self.same_or_updated(&previous)
                        } else {
                            // Toggling a setting must not move the user to a
                            // different server: carry the running pair through
                            // the reconnect unless the change is one gateway
                            // selection actually depends on.
                            let gateways = (!diff.affects_gateway_selection() && !side_pin_taken)
                                .then(|| self.selected_gateways.clone());
                            self.disconnect(PrivateActionAfterDisconnect::Reconnect { gateways }, shared_state).await
                        }
                    }
                }
            }
            Some(monitor_event) = self.tunnel_monitor_event_receiver.recv() => {
                match monitor_event {
                    TunnelMonitorEvent::Down { error_state_reason, reply_tx } => {
                        _ = reply_tx.send(());
                        self.handle_tunnel_down(error_state_reason, shared_state).await
                    }
                    TunnelMonitorEvent::BandwidthChecks { failure, worked } => {
                        self.bandwidth_failure = failure;
                        self.bandwidth_checks_worked = worked;
                        NextTunnelState::SameState(self)
                    }
                    _ => {
                        NextTunnelState::SameState(self)
                    }
                }
            }
            Some(event) = side_tunnel::next_event(self.side_tunnel.as_mut().map(|side_tunnel| &mut side_tunnel.event_rx)) => {
                self.handle_side_tunnel_event(event, shared_state).await
            }
            Some(connectivity) = shared_state.connectivity_handle.next() => {
                if connectivity.is_offline() {
                    let after_disconnect = PrivateActionAfterDisconnect::Offline {
                        reconnect: true,
                        gateways: Some(self.selected_gateways.clone())
                    };
                    self.disconnect(after_disconnect, shared_state).await
                } else {
                    NextTunnelState::SameState(self)
                }
            }
            _ = shutdown_token.cancelled() => {
                self.disconnect(PrivateActionAfterDisconnect::Nothing, shared_state).await
            }
        }
    }
}

/// Firewall policy configuration when connected
#[derive(Debug, Clone)]
struct ConnectedPolicyParameters {
    /// Whether IPv6 is enabled
    enable_ipv6: bool,

    /// Whether to allow LAN traffic
    allow_lan: bool,

    /// WireGuard entry endpoint
    wg_entry_endpoint: Option<SocketAddr>,

    /// Entry gateway websocket endpoints
    ws_entry_endpoints: Vec<SocketAddr>,

    /// Resolved DNS configuration including in-tunnel and out-of-tunnel DNS servers
    dns_config: ResolvedDnsConfig,

    /// Tunnel interface
    tunnel_interface: TunnelInterface,

    /// The side tunnel's device while it is up.
    side_tunnel: Option<TunnelMetadata>,

    /// Outbound endpoints reachable while connected (cloudflared, frp, etc.).
    allowed_endpoints: Vec<nym_firewall::AllowedEndpoint>,

    /// Inbound services exempted from the tunnel.
    inbound_exemptions: Vec<nym_firewall::InboundExemption>,
}

impl ConnectedPolicyParameters {
    pub fn as_policy(&self) -> FirewallPolicy {
        // Allow websocket entry endpoints
        let mut peer_endpoints = self
            .ws_entry_endpoints
            .iter()
            .filter(|addr| addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()))
            .map(|addr| {
                AllowedEndpoint::new(
                    Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                    // On Linux, All is needed so the mangle chain rule sets fwmark for outbound traffic
                    AllowedClients::All,
                )
            })
            .collect::<Vec<_>>();

        // Allow WireGuard / Quic entry endpoint
        if let Some(addr) = self.wg_entry_endpoint {
            if addr.is_ipv4() || (self.enable_ipv6 && addr.is_ipv6()) {
                let allow_wg_endpoint = AllowedEndpoint::new(
                    Endpoint::from_socket_address(addr, TransportProtocol::Udp),
                    // On Linux, All is needed so the mangle chain rule sets fwmark for outbound traffic
                    AllowedClients::All,
                );

                peer_endpoints.push(allow_wg_endpoint);
            } else {
                tracing::warn!("WireGuard endpoint contains IPv6 address, but IPv6 is disabled!");
            }
        }

        let tunnel = nym_firewall::TunnelInterface::from(self.tunnel_interface.clone());

        FirewallPolicy::Connected {
            peer_endpoints,
            tunnel,
            side_tunnel: self
                .side_tunnel
                .clone()
                .map(nym_firewall::TunnelMetadata::from),
            allow_lan: self.allow_lan,
            dns_config: self.dns_config.clone(),
            allowed_endpoints: self.allowed_endpoints.clone(),
            inbound_exemptions: self.inbound_exemptions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_firewall::TransportProtocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_mock_gateway_with_websocket_endpoints(
        ip: Ipv4Addr,
        ws_port: u16,
        wss_port: u16,
    ) -> nym_gateway_directory::Gateway {
        use nym_gateway_directory::Gateway;
        use nym_sdk::mixnet::NodeIdentity;

        // Create a dummy identity for testing
        let dummy_identity =
            NodeIdentity::from_base58_string("7CWjY3QFoA9dgE535u9bQiXCfzgMZvSpJu842GA1Wn42")
                .expect("Valid test identity");

        Gateway::builder()
            .identity(dummy_identity)
            .ips(vec![IpAddr::V4(ip)])
            .clients_ws_port(Some(ws_port))
            .clients_wss_port(Some(wss_port))
            .build()
    }

    #[test]
    fn test_firewall_policy_includes_exit_gateway_endpoints() {
        // Create mock entry gateway with WebSocket on port 9000 (WS) and 9001 (WSS)
        let entry_gateway =
            create_mock_gateway_with_websocket_endpoints(Ipv4Addr::new(192, 168, 1, 1), 9000, 9001);
        let entry_endpoints = entry_gateway.endpoints();

        // Create mock exit gateway with WebSocket on port 9000 (WS) and 9001 (WSS)
        let exit_gateway =
            create_mock_gateway_with_websocket_endpoints(Ipv4Addr::new(192, 168, 1, 2), 9000, 9001);
        let exit_endpoints = exit_gateway.endpoints();

        // Create ConnectedPolicyParameters (simulating what happens in enter())
        // We'll directly test with the endpoints without needing SelectedGateways
        let mut ws_endpoints = entry_endpoints.clone();
        ws_endpoints.extend(exit_endpoints.clone());

        // Create a minimal TunnelInterface for testing
        use crate::tunnel_state_machine::TunnelMetadata;
        use ipnetwork::IpNetwork;
        let tunnel_metadata = TunnelMetadata {
            interface: "test0".to_string(),
            ips: vec![
                IpNetwork::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24)
                    .unwrap()
                    .network(),
            ],
            ipv4_gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ipv6_gateway: None,
        };
        let tunnel_interface = TunnelInterface::One(tunnel_metadata);

        // Create ResolvedDnsConfig using DnsConfig::default().resolve()
        use nym_dns::DnsConfig;
        let dns_config = DnsConfig::default().resolve(
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        );

        let params = ConnectedPolicyParameters {
            enable_ipv6: false,
            allow_lan: false,
            wg_entry_endpoint: None,
            ws_entry_endpoints: ws_endpoints,
            dns_config,
            tunnel_interface,
            side_tunnel: None,
            allowed_endpoints: Vec::new(),
            inbound_exemptions: Vec::new(),
        };

        // Build firewall policy
        let policy = params.as_policy();

        // Extract peer endpoints
        let peer_endpoints = policy.peer_endpoints();

        // Verify entry gateway endpoints are included
        assert!(
            entry_endpoints.iter().any(|entry_ep| {
                peer_endpoints.iter().any(|allowed_ep| {
                    allowed_ep.endpoint.address == *entry_ep
                        && allowed_ep.endpoint.protocol == TransportProtocol::Tcp
                })
            }),
            "Entry gateway endpoints should be in peer_endpoints"
        );

        // Verify exit gateway endpoints are included
        assert!(
            exit_endpoints.iter().any(|exit_ep| {
                peer_endpoints.iter().any(|allowed_ep| {
                    allowed_ep.endpoint.address == *exit_ep
                        && allowed_ep.endpoint.protocol == TransportProtocol::Tcp
                })
            }),
            "Exit gateway endpoints should be in peer_endpoints for SOCKS5 support"
        );

        // Verify we have endpoints from both gateways
        assert!(
            peer_endpoints.len() >= entry_endpoints.len() + exit_endpoints.len(),
            "peer_endpoints should contain endpoints from both entry and exit gateways"
        );
    }
}
