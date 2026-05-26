// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use nym_common::trace_err_chain;

use crate::tunnel_state_machine::{
    ErrorStateReason, NextTunnelState, PrivateTunnelState, SharedState, TunnelCommand,
    TunnelSettingsDiffFields, TunnelStateHandler,
    states::{ConnectingState, DisconnectedState, OfflineState},
};

pub struct ErrorState;

impl ErrorState {
    pub async fn enter(
        reason: ErrorStateReason,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // Mirror DisconnectedState: only lock the firewall when the user
        // opted into the kill-switch AND we have API endpoints to whitelist.
        // Otherwise reset so the daemon can reach the API and self-recover
        // from transient connect errors. The previous behavior — Blocked
        // with empty exemptions — was a one-way deadlock.
        shared_state.apply_killswitch_policy();

        shared_state.reset_resolver_overrides().await;
        shared_state.allow_networking().await;

        (Box::new(Self), PrivateTunnelState::Error(reason))
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

                        shared_state.tunnel_settings = tunnel_settings;

                        if diff.is_field_changed(&TunnelSettingsDiffFields::AllowLan)
                            || diff.is_field_changed(&TunnelSettingsDiffFields::Killswitch)
                            || diff.is_field_changed(&TunnelSettingsDiffFields::EnableIpv6)
                            || diff.is_field_changed(&TunnelSettingsDiffFields::Dns)
                        {
                            shared_state.apply_killswitch_policy();
                        }

                        NextTunnelState::SameState(self)
                    }
                }
            }
            _ = shutdown_token.cancelled() => {
                Self::reset_dns(shared_state).await;
                if let Err(e) = shared_state.firewall.reset_policy() {
                    trace_err_chain!(e, "Failed to reset firewall policy");
                }
                NextTunnelState::Finished
            }
        }
    }
}
