// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    NextTunnelState, PrivateTunnelState, SharedState, TunnelCommand, TunnelStateHandler,
    states::{ConnectingState, OfflineState},
    tunnel::Tombstone,
};
use nym_common::trace_err_chain;
use nym_firewall::{
    AllowedClients, AllowedEndpoint, Endpoint, FirewallPolicy, TransportProtocol,
};

pub struct DisconnectedState;

impl DisconnectedState {
    pub async fn enter(
        tombstone: Option<Tombstone>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // Kill-switch between sessions: once a prior Connecting has populated
        // the cached API endpoints, keep a Blocked policy in place while the
        // tunnel is down so traffic only reaches the Nym VPN API. On cold boot
        // the cache is empty and we fall back to an open firewall so the
        // account controller can sync.
        if shared_state.tunnel_settings.killswitch && !shared_state.api_endpoints.is_empty() {
            Self::apply_blocked_policy(shared_state);
        } else {
            Self::reset_firewall_policy(shared_state);
        }

        // Drop tombstone to close tunnel devices.
        drop(tombstone);

        // Reset resolver overrides and allow all networking since firewall is no longer active
        shared_state.reset_resolver_overrides().await;
        shared_state.allow_networking().await;

        (Box::new(Self), PrivateTunnelState::Disconnected)
    }

    fn apply_blocked_policy(shared_state: &mut SharedState) {
        let enable_ipv6 = shared_state.tunnel_settings.enable_ipv6;
        let allowed_endpoints = shared_state
            .api_endpoints
            .iter()
            .filter(|addr| addr.is_ipv4() || (enable_ipv6 && addr.is_ipv6()))
            .map(|addr| {
                AllowedEndpoint::new(
                    Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                    AllowedClients::Root,
                )
            })
            .collect();
        // DNS must stay open to resolve API hostnames; resolver overrides are
        // cleared on DisconnectedState entry so the account controller falls
        // back to system DNS.
        let dns_servers = shared_state.tunnel_settings.default_dns_ips();
        let policy = FirewallPolicy::Blocked {
            allow_lan: shared_state.tunnel_settings.allow_lan,
            allowed_endpoints,
            dns_servers,
        };
        if let Err(e) = shared_state.firewall.apply_policy(policy) {
            trace_err_chain!(e, "Failed to apply disconnected kill-switch policy");
        }
    }

    fn reset_firewall_policy(shared_state: &mut SharedState) {
        if let Err(e) = shared_state.firewall.reset_policy() {
            trace_err_chain!(e, "Failed to reset firewall policy");
        }
    }

    async fn reset_dns(shared_state: &mut SharedState) {
        if let Err(error) = shared_state.dns_handler.reset().await {
            trace_err_chain!(error, "Failed to reset DNS");
        }
    }
}

#[async_trait::async_trait]
impl TunnelStateHandler for DisconnectedState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                tracing::debug!("DisconnectedState received command: {command:?}");
                match command {
                    TunnelCommand::Connect => {
                        NextTunnelState::NewState(ConnectingState::enter(0, None, shared_state).await)
                    },
                    TunnelCommand::Disconnect => NextTunnelState::SameState(self),
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        shared_state.tunnel_settings = tunnel_settings;
                        NextTunnelState::SameState(self)
                    }
                }
            }
            Some(connectivity) = shared_state.connectivity_handle.next() => {
                if connectivity.is_offline() {
                    NextTunnelState::NewState(OfflineState::enter(false, None, shared_state).await)
                } else {
                    NextTunnelState::SameState(self)
                }
            }
            _ = shutdown_token.cancelled() => {
                Self::reset_dns(shared_state).await;
                NextTunnelState::Finished
            }
        }
    }
}
