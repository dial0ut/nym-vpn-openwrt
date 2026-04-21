// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use nym_common::trace_err_chain;
use nym_firewall::FirewallPolicy;

use crate::tunnel_state_machine::{Error, Result};
use crate::tunnel_state_machine::{
    ErrorStateReason, NextTunnelState, PrivateTunnelState, SharedState, TunnelCommand,
    TunnelStateHandler,
    states::{ConnectingState, DisconnectedState, OfflineState},
};

pub struct ErrorState {
    firewall_policy_params: BlockedPolicyParameters,
}

impl ErrorState {
    pub async fn enter(
        reason: ErrorStateReason,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // Disallow networking in error state since there are no configured firewall exceptions
        shared_state.disallow_networking().await;

        let firewall_policy_params = BlockedPolicyParameters {
            allow_lan: shared_state.tunnel_settings.allow_lan,
        };

        if let Err(err) = Self::set_firewall_policy(shared_state, &firewall_policy_params) {
            trace_err_chain!(err, "failed to set firewall policy");
        }

        let blocked_state = Self {
            firewall_policy_params,
        };

        (Box::new(blocked_state), PrivateTunnelState::Error(reason))
    }

    fn set_firewall_policy(
        shared_state: &mut SharedState,
        params: &BlockedPolicyParameters,
    ) -> Result<()> {
        let policy = params.as_policy();

        shared_state
            .firewall
            .apply_policy(policy)
            .map_err(Error::SetFirewallPolicy)
    }

    fn reset_firewall_policy(shared_state: &mut SharedState) {
        if let Err(e) = shared_state.firewall.reset_policy() {
            trace_err_chain!(e, "Failed to reset firewall policy");
        }
    }

    async fn reset_dns(shared_state: &mut SharedState) {
        if let Err(error) = shared_state.dns_handler.reset().await {
            trace_err_chain!(error, "Unable to disable filtering resolver");
        }
    }
}

#[async_trait::async_trait]
impl TunnelStateHandler for ErrorState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                tracing::debug!("ErrorState received command: {command:?}");
                match command {
                    TunnelCommand::Connect => {
                        Self::reset_dns(shared_state).await;

                        if shared_state.connectivity_handle.connectivity().await.is_offline() {
                            NextTunnelState::NewState(OfflineState::enter(true, None, shared_state).await)
                        } else {
                            NextTunnelState::NewState(ConnectingState::enter(0, None, shared_state).await)
                        }
                    },
                    TunnelCommand::Disconnect => {
                        Self::reset_dns(shared_state).await;

                        if shared_state.connectivity_handle.connectivity().await.is_offline() {
                            NextTunnelState::NewState(OfflineState::enter(false, None, shared_state).await)
                        } else {
                            NextTunnelState::NewState(DisconnectedState::enter(None, shared_state).await)
                        }
                    },
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        let Some(diff) = shared_state.tunnel_settings.diff(&tunnel_settings) else {
                            return NextTunnelState::SameState(self);
                        };

                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = tunnel_settings.allow_lan;

                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                            }
                        }

                        shared_state.tunnel_settings = tunnel_settings;
                        NextTunnelState::SameState(self)
                    }
                }
            }
            _ = shutdown_token.cancelled() => {
                Self::reset_dns(shared_state).await;
                Self::reset_firewall_policy(shared_state);
                NextTunnelState::Finished
            }
        }
    }
}

// Firewall policy configuration when blocked
#[derive(Debug, Clone)]
pub struct BlockedPolicyParameters {
    /// Whether to allow LAN traffic
    pub allow_lan: bool,
}

impl BlockedPolicyParameters {
    pub fn as_policy(&self) -> FirewallPolicy {
        FirewallPolicy::Blocked {
            allow_lan: self.allow_lan,
            allowed_endpoints: Vec::new(),
            dns_servers: Vec::new(),
        }
    }
}
