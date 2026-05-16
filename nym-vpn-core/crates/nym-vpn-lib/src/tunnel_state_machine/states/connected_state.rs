// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;

use nym_dns::ResolvedDnsConfig;
use nym_vpn_lib_types::{ErrorStateReason, TunnelType};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    ConnectionData, NextTunnelState, PrivateActionAfterDisconnect, PrivateTunnelState, SharedState,
    TunnelCommand, TunnelInterface, TunnelStateHandler,
    states::{ConnectingState, DisconnectingState},
    tunnel::SelectedGateways,
    tunnel_monitor::{TunnelMonitorEvent, TunnelMonitorEventReceiver, TunnelMonitorHandle},
};
use crate::tunnel_state_machine::{Error, Result, gateway_ext::GatewayExt};
use nym_common::trace_err_chain;
use nym_firewall::{AllowedClients, AllowedEndpoint, Endpoint, FirewallPolicy, TransportProtocol};
use nym_vpn_lib_types::TunnelConnectionData;

use super::ErrorState;

pub struct ConnectedState {
    tunnel_monitor_handle: TunnelMonitorHandle,
    tunnel_monitor_event_receiver: TunnelMonitorEventReceiver,
    selected_gateways: SelectedGateways,
    tunnel_interface: TunnelInterface,
    firewall_policy_params: ConnectedPolicyParameters,
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
                allowed_endpoints: Vec::new(),
                inbound_exemptions: shared_state.tunnel_settings.inbound_exemptions.clone(),
            }
        };

        let connected_state = Self {
            tunnel_monitor_handle,
            tunnel_monitor_event_receiver,
            selected_gateways,
            tunnel_interface,
            firewall_policy_params,
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

        (
            Box::new(connected_state),
            PrivateTunnelState::Connected { connection_data },
        )
    }

    fn set_firewall_policy(
        shared_state: &mut SharedState,
        params: &ConnectedPolicyParameters,
    ) -> Result<()> {
        let policy = params.as_policy();

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
        self,
        after_disconnect: PrivateActionAfterDisconnect,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        Self::reset_dns(shared_state).await;
        Self::reset_routes(shared_state).await;

        NextTunnelState::NewState(
            DisconnectingState::enter(after_disconnect, self.tunnel_monitor_handle, shared_state)
                .await,
        )
    }

    async fn handle_tunnel_down(
        self,
        error_state_reason: Option<ErrorStateReason>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        if error_state_reason.is_none() {
            tracing::info!("Tunnel closed. Reconnecting.");
        }

        Self::reset_dns(shared_state).await;
        Self::reset_routes(shared_state).await;

        match error_state_reason {
            Some(block_reason) => {
                NextTunnelState::NewState(ErrorState::enter(block_reason, shared_state).await)
            }
            None => NextTunnelState::NewState(
                ConnectingState::enter(0, Some(self.selected_gateways), shared_state).await,
            ),
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
                    TunnelCommand::Connect => {
                        self.disconnect(PrivateActionAfterDisconnect::Reconnect, shared_state).await
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
                        // exactly once. After that, surgically update the exempt
                        // routing rule when the inbound-exemption set transitions
                        // between empty and non-empty.
                        let had_exemptions = !shared_state.tunnel_settings.inbound_exemptions.is_empty();
                        let has_exemptions = !tunnel_settings.inbound_exemptions.is_empty();
                        let exempt_rule_transition = match (had_exemptions, has_exemptions) {
                            (false, true) => Some(true),    // 0 -> N: install rule
                            (true, false) => Some(false),   // N -> 0: remove rule
                            _ => None,                       // no transition
                        };

                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = tunnel_settings.allow_lan;
                        }
                        if diff.inbound_exemptions_changed() {
                            self.firewall_policy_params.inbound_exemptions =
                                tunnel_settings.inbound_exemptions.clone();
                        }

                        // Order is load-bearing:
                        // - 0 -> N: install rule first, then re-apply firewall.
                        //   If rule install fails, no mark-set rules exist yet and we
                        //   leave clean.
                        // - N -> 0 or N -> M: re-apply firewall first (drops the
                        //   mangle/mark rules in the 0-case), then remove the routing
                        //   rule. Removing the routing rule before the firewall would
                        //   leave a brief window where marked replies have no route
                        //   to main and would fall into the tunnel rule (functional
                        //   bug, not a leak).
                        if exempt_rule_transition == Some(true) {
                            if let Err(e) = shared_state.route_handler
                                .set_exempt_rule(true, shared_state.tunnel_settings.enable_ipv6)
                                .await
                            {
                                trace_err_chain!(e, "failed to install exempt routing rule");
                                return NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await);
                            }
                        }

                        if diff.allow_lan_changed() || diff.inbound_exemptions_changed() {
                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                                return NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await);
                            }
                        }

                        if exempt_rule_transition == Some(false) {
                            if let Err(e) = shared_state.route_handler
                                .set_exempt_rule(false, shared_state.tunnel_settings.enable_ipv6)
                                .await
                            {
                                trace_err_chain!(e, "failed to remove exempt routing rule");
                                return NextTunnelState::NewState(ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await);
                            }
                        }

                        shared_state.tunnel_settings = tunnel_settings;

                        // Not all changes require the tunnel to be reconnected
                        if diff.only_hot_appliable_changed() || (diff.only_mixnet_performance_options_changed() && shared_state.tunnel_settings.tunnel_type == TunnelType::Wireguard) {
                            NextTunnelState::SameState(self)
                        } else {
                            self.disconnect(PrivateActionAfterDisconnect::Reconnect, shared_state).await
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
                    _ => {
                        NextTunnelState::SameState(self)
                    }
                }
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
