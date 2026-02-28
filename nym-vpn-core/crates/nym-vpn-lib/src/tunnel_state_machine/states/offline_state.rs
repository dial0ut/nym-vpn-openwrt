// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{Error, Result, states::error_state::BlockedPolicyParameters};
use crate::tunnel_state_machine::{
    NextTunnelState, PrivateTunnelState, SharedState, TunnelCommand, TunnelStateHandler,
    states::{ConnectingState, DisconnectedState},
    tunnel::SelectedGateways,
};
use nym_common::trace_err_chain;

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

                        if diff.allow_lan_changed() {
                            self.firewall_policy_params.allow_lan = tunnel_settings.allow_lan;

                            if let Err(e) = Self::set_firewall_policy(shared_state, &self.firewall_policy_params) {
                                trace_err_chain!(e, "failed to set firewall policy");
                            }
                        }

                        if diff.entry_point_changed() || diff.exit_point_changed() || diff.quic_changed() {
                            self.selected_gateways = None;
                        };

                        shared_state.tunnel_settings = tunnel_settings;
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
