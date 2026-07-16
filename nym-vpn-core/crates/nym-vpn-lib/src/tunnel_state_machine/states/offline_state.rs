// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use nym_common::trace_err_chain;
use nym_firewall::FirewallPolicy;

use crate::tunnel_state_machine::{
    Error, NextTunnelState, PrivateTunnelState, Result, SharedState, TunnelCommand,
    TunnelStateHandler,
    states::{ConnectingState, DisconnectedState},
    tunnel::SelectedGateways,
};

/// Firewall policy parameters used by [`OfflineState`]. While the device has
/// no network connectivity there is nothing useful to whitelist, so this
/// applies a fully-locked `Blocked` policy.
#[derive(Debug, Clone)]
struct BlockedPolicyParameters {
    allow_lan: bool,
}

impl BlockedPolicyParameters {
    fn as_policy(&self) -> FirewallPolicy {
        FirewallPolicy::Blocked {
            allow_lan: self.allow_lan,
            allowed_endpoints: Vec::new(),
            dns_servers: Vec::new(),
        }
    }
}

pub struct OfflineState {
    /// Whether to connect the tunnel once online
    reconnect: bool,

    /// Gateways to which the tunnel will reconnect to once online
    selected_gateways: Option<SelectedGateways>,

    firewall_policy_params: BlockedPolicyParameters,
}

impl OfflineState {
    pub async fn enter(
        reconnect: bool,
        selected_gateways: Option<SelectedGateways>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        shared_state.disallow_networking().await;

        let firewall_policy_params = BlockedPolicyParameters {
            allow_lan: shared_state.tunnel_settings.allow_lan,
        };

        if let Err(e) = Self::set_firewall_policy(shared_state, &firewall_policy_params) {
            trace_err_chain!(e, "Failed to apply firewall policy for blocked state");
        }

        (
            Box::new(Self {
                reconnect,
                selected_gateways,
                firewall_policy_params,
            }),
            PrivateTunnelState::Offline { reconnect },
        )
    }

    fn set_firewall_policy(
        shared_state: &mut SharedState,
        params: &BlockedPolicyParameters,
    ) -> Result<()> {
        let policy = params.as_policy();

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

    fn reset_firewall_policy(shared_state: &mut SharedState) {
        if let Err(e) = shared_state.firewall.reset_policy() {
            trace_err_chain!(e, "Failed to reset firewall policy");
        }
    }

    async fn reset_dns(shared_state: &mut SharedState) {
        if let Err(error) = shared_state.dns_handler.reset().await {
            trace_err_chain!(error, "Unable to reset DNS");
        }
    }
}

#[async_trait::async_trait]
impl TunnelStateHandler for OfflineState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                tracing::debug!("OfflineState received command: {command:?}");
                match command {
                    TunnelCommand::Connect => {
                        if self.reconnect {
                            NextTunnelState::SameState(self)
                        } else {
                            self.reconnect = true;
                            let new_state = PrivateTunnelState::Offline { reconnect: self.reconnect };
                            NextTunnelState::NewState((self, new_state))
                        }
                    },
                    TunnelCommand::Disconnect => {
                        if self.reconnect {
                            self.reconnect = false;
                            let new_state = PrivateTunnelState::Offline { reconnect: self.reconnect };
                            NextTunnelState::NewState((self, new_state))
                        } else {
                            NextTunnelState::SameState(self)
                        }
                    },
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        let Some(diff) = shared_state.tunnel_settings.diff(&tunnel_settings) else {
                            return NextTunnelState::SameState(self);
                        };

                        if diff.entry_point_changed() || diff.exit_point_changed() || diff.quic_changed() {
                            self.selected_gateways = None;
                        };

                        // Assign before re-applying so the firewall sync below
                        // (inside set_firewall_policy) picks up the new
                        // killswitch/allow_lan values, not the stale ones.
                        shared_state.tunnel_settings = tunnel_settings;

                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = shared_state.tunnel_settings.allow_lan;
                        }

                        if diff.allow_lan_changed() || diff.killswitch_changed() {
                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                            }
                        }

                        NextTunnelState::SameState(self)
                    }
                }
            }
            Some(connectivity) = shared_state.connectivity_handle.next() => {
                if connectivity.is_offline() {
                    NextTunnelState::SameState(self)
                } else {
                    Self::reset_dns(shared_state).await;

                    if self.reconnect {
                        NextTunnelState::NewState(ConnectingState::enter(0, self.selected_gateways, shared_state).await)
                    } else {
                        NextTunnelState::NewState(DisconnectedState::enter(None, shared_state).await)
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
