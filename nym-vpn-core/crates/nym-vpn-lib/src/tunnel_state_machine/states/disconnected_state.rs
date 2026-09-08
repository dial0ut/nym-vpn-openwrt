// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Instant;

use futures::{
    FutureExt,
    future::{BoxFuture, Fuse},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel_state_machine::{
    API_ENDPOINT_RETRY_DELAY, ErrorStateReason, NextTunnelState, PrivateTunnelState, Result,
    SharedState, TunnelCommand, TunnelStateHandler, resolve_api_endpoints,
    states::{ConnectingState, ErrorState, OfflineState},
    tunnel::Tombstone,
};
use nym_common::trace_err_chain;
use nym_gateway_directory::ResolvedConfig;

type ResolveApiAddrsFuture = BoxFuture<'static, Result<ResolvedConfig>>;
type RefreshTimerFuture = BoxFuture<'static, ()>;

/// Idle between tunnel sessions. With the kill-switch on it keeps the
/// firewall Blocked and refreshes the API allow-list every
/// [`crate::tunnel_state_machine::API_ENDPOINT_REFRESH_INTERVAL`]; until a
/// resolution succeeds it stays Blocked with whatever the cache offered.
pub struct DisconnectedState {
    resolve_api_addrs_fut: Fuse<ResolveApiAddrsFuture>,
    refresh_timer_fut: Fuse<RefreshTimerFuture>,
}

impl DisconnectedState {
    pub async fn enter(
        tombstone: Option<Tombstone>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // The gateway grace window is scoped to a connect session.
        shared_state.entry_gateway_grace = None;

        drop(tombstone);

        // A failed apply must surface as an error state, not as Disconnected
        // with the kill-switch supposedly on.
        if let Err(e) = shared_state.apply_killswitch_policy() {
            trace_err_chain!(e, "Failed to apply kill-switch policy on disconnect");
            return ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await;
        }

        // Overrides are cleared here and only come back with the next live
        // resolution: at once after a cold start, otherwise when the current
        // allow-list ages out.
        shared_state.reset_resolver_overrides().await;
        shared_state.allow_networking().await;
        Self::reset_dns(shared_state).await;

        let mut state = Self {
            resolve_api_addrs_fut: Fuse::terminated(),
            refresh_timer_fut: Fuse::terminated(),
        };
        state.schedule_api_endpoint_refresh(shared_state);

        (Box::new(state), PrivateTunnelState::Disconnected)
    }

    fn schedule_api_endpoint_refresh(&mut self, shared_state: &SharedState) {
        if !shared_state.tunnel_settings.killswitch {
            self.resolve_api_addrs_fut = Fuse::terminated();
            self.refresh_timer_fut = Fuse::terminated();
            return;
        }
        if shared_state.api_endpoints_need_refresh() {
            tracing::info!(
                "Kill-switch on while idle: resolving the API endpoints through the DNS hatch"
            );
            self.resolve_api_addrs_fut =
                resolve_api_endpoints(shared_state.nym_config.gateway_config.clone()).fuse();
            self.refresh_timer_fut = Fuse::terminated();
        } else {
            self.arm_refresh_timer(shared_state.api_endpoints_refresh_due());
        }
    }

    fn arm_refresh_timer(&mut self, due: Instant) {
        self.refresh_timer_fut = tokio::time::sleep_until(due.into()).boxed().fuse();
    }

    async fn handle_resolved_api_endpoints(
        mut self: Box<Self>,
        result: Result<ResolvedConfig>,
        shared_state: &mut SharedState,
    ) -> NextTunnelState {
        match result {
            Ok(resolved) => {
                if let Err(e) = shared_state.install_idle_api_access(&resolved).await {
                    trace_err_chain!(
                        e,
                        "Failed to re-apply kill-switch policy with API endpoints"
                    );
                    return NextTunnelState::NewState(
                        ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                    );
                }
                self.arm_refresh_timer(shared_state.api_endpoints_refresh_due());
            }
            Err(e) => {
                trace_err_chain!(
                    e,
                    "Failed to resolve the API endpoints while idle; API access stays blocked, retrying in {:?}",
                    API_ENDPOINT_RETRY_DELAY
                );
                self.arm_refresh_timer(Instant::now() + API_ENDPOINT_RETRY_DELAY);
            }
        }
        NextTunnelState::SameState(self)
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
                    TunnelCommand::Connect => {
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
                        if let Err(e) = shared_state.apply_killswitch_policy() {
                            trace_err_chain!(e, "Failed to apply kill-switch policy on settings change");
                            NextTunnelState::NewState(
                                ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                            )
                        } else {
                            self.schedule_api_endpoint_refresh(shared_state);
                            NextTunnelState::SameState(self)
                        }
                    }
                }
            }
            result = &mut self.resolve_api_addrs_fut => {
                self.handle_resolved_api_endpoints(result, shared_state).await
            }
            _ = &mut self.refresh_timer_fut => {
                self.schedule_api_endpoint_refresh(shared_state);
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
