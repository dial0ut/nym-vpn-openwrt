// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    ErrorStateReason, IdleApiAccess, NextTunnelState, PrivateTunnelState, SharedState,
    TunnelCommand, TunnelStateHandler,
    states::{ConnectingState, ErrorState, OfflineState},
    tunnel::Tombstone,
};
use nym_common::trace_err_chain;

pub struct DisconnectedState {
    api_access: IdleApiAccess,
}

impl DisconnectedState {
    pub async fn enter(
        tombstone: Option<Tombstone>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // The post-drop gateway grace window and the "connect anyway" relaxation
        // of the independence criteria are scoped to a connect session.
        shared_state.entry_gateway_grace = None;
        shared_state.relax_independence = false;

        drop(tombstone);

        // A failed apply must surface as an error state, not as Disconnected
        // with the kill-switch supposedly on.
        if let Err(e) = shared_state.enter_idle_firewall().await {
            trace_err_chain!(e, "Failed to apply kill-switch policy on disconnect");
            return ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await;
        }

        shared_state.allow_networking().await;
        Self::reset_dns(shared_state).await;

        let state = Self {
            api_access: IdleApiAccess::start(shared_state),
        };
        (Box::new(state), PrivateTunnelState::Disconnected)
    }

    async fn reset_dns(shared_state: &mut SharedState) {
        let idle = shared_state.tunnel_settings.idle_dns();
        if let Err(error) = shared_state.dns_handler.reset_idle(idle).await {
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
                    TunnelCommand::Connect { relax_independence } => {
                        shared_state.relax_independence = relax_independence;
                        NextTunnelState::NewState(ConnectingState::enter(0, None, shared_state).await)
                    },
                    TunnelCommand::Disconnect => NextTunnelState::SameState(self),
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        let idle_dns_changed =
                            shared_state.tunnel_settings.idle_dns() != tunnel_settings.idle_dns();
                        shared_state.tunnel_settings = tunnel_settings;
                        if idle_dns_changed {
                            Self::reset_dns(shared_state).await;
                        }
                        if let Err(e) = shared_state.enter_idle_firewall().await {
                            trace_err_chain!(e, "Failed to apply kill-switch policy on settings change");
                            NextTunnelState::NewState(
                                ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                            )
                        } else {
                            self.api_access.schedule(shared_state);
                            NextTunnelState::SameState(self)
                        }
                    }
                }
            }
            result = &mut self.api_access.resolve_fut => {
                match self.api_access.handle_resolved(result, shared_state).await {
                    Ok(()) => NextTunnelState::SameState(self),
                    Err(e) => {
                        trace_err_chain!(e, "Failed to re-apply kill-switch policy with API endpoints");
                        NextTunnelState::NewState(
                            ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                        )
                    }
                }
            }
            _ = &mut self.api_access.timer_fut => {
                self.api_access.schedule(shared_state);
                NextTunnelState::SameState(self)
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
