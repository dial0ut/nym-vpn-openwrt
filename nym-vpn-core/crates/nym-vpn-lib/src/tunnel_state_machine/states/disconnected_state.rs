// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    ErrorStateReason, NextTunnelState, PrivateTunnelState, SharedState, TunnelCommand,
    TunnelStateHandler,
    states::{ConnectingState, ErrorState, OfflineState},
    tunnel::Tombstone,
};
use nym_common::trace_err_chain;

pub struct DisconnectedState;

impl DisconnectedState {
    pub async fn enter(
        tombstone: Option<Tombstone>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // The post-drop gateway grace window and the "connect anyway" relaxation
        // of the independence criteria are scoped to a connect session.
        shared_state.entry_gateway_grace = None;
        shared_state.relax_independence = false;

        // Drop tombstone to close tunnel devices.
        drop(tombstone);

        // A failed apply must not be shrugged off into a state that
        // announces unrestricted networking: with the kill-switch enabled
        // the user believes traffic is fenced while nothing enforces it.
        // Surface it as an error state instead so the UI shows the problem.
        if let Err(e) = shared_state.apply_killswitch_policy() {
            trace_err_chain!(e, "Failed to apply kill-switch policy on disconnect");
            return ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await;
        }

        // Reset resolver overrides and allow all networking since firewall is no longer active
        shared_state.reset_resolver_overrides().await;
        shared_state.allow_networking().await;

        (Box::new(Self), PrivateTunnelState::Disconnected)
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
                    TunnelCommand::Connect { relax_independence } => {
                        shared_state.relax_independence = relax_independence;
                        NextTunnelState::NewState(ConnectingState::enter(0, None, shared_state).await)
                    },
                    TunnelCommand::Disconnect => NextTunnelState::SameState(self),
                    TunnelCommand::SetTunnelSettings(tunnel_settings) => {
                        shared_state.tunnel_settings = tunnel_settings;
                        // Re-apply so enabling/disabling the kill-switch while
                        // disconnected installs/removes the Blocked table now,
                        // instead of silently waiting for the next connect.
                        if let Err(e) = shared_state.apply_killswitch_policy() {
                            trace_err_chain!(e, "Failed to apply kill-switch policy on settings change");
                            NextTunnelState::NewState(
                                ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                            )
                        } else {
                            NextTunnelState::SameState(self)
                        }
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
