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

/// Idle between tunnel sessions.
///
/// With the kill-switch on this state keeps the firewall Blocked and owns the
/// API allow-list while idle: on entry, and every
/// [`crate::tunnel_state_machine::API_ENDPOINT_REFRESH_INTERVAL`] after
/// that, it resolves the API hostnames through the daemon's DNS hatch with
/// the same resolver Connecting uses, re-applies Blocked with those endpoints
/// admitted (daemon only) and pins the HTTP clients to them. Until a
/// resolution succeeds the firewall stays Blocked with whatever the on-disk
/// cache offered, which on a fresh install is nothing: fail closed, never
/// open. The resolution runs as a future inside the event loop, so commands
/// keep being served while it is in flight.
pub struct DisconnectedState {
    resolve_api_addrs_fut: Fuse<ResolveApiAddrsFuture>,
    refresh_timer_fut: Fuse<RefreshTimerFuture>,
}

impl DisconnectedState {
    pub async fn enter(
        tombstone: Option<Tombstone>,
        shared_state: &mut SharedState,
    ) -> (Box<dyn TunnelStateHandler>, PrivateTunnelState) {
        // The post-drop gateway grace window is scoped to a connect session.
        shared_state.entry_gateway_grace = None;

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

        // Cached addresses come without the resolver overrides the HTTP
        // clients need to hit exactly the admitted IPs, so they are cleared
        // here and re-installed by the first live resolution below.
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

    /// Start a resolution now if the allow-list is missing, cache-only or
    /// aged out; otherwise arm the timer for when it will be.
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

    /// Point dnsmasq at what is usable while idle: the LAN custom resolvers
    /// the kill-switch admits, plus the WAN resolvers only when the
    /// kill-switch is off. Re-run whenever the DNS or kill-switch settings
    /// change while disconnected so the change takes effect at once.
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
                        // Re-apply so enabling/disabling the kill-switch while
                        // disconnected installs/removes the Blocked table now,
                        // instead of silently waiting for the next connect.
                        if let Err(e) = shared_state.apply_killswitch_policy() {
                            trace_err_chain!(e, "Failed to apply kill-switch policy on settings change");
                            NextTunnelState::NewState(
                                ErrorState::enter(ErrorStateReason::SetFirewallPolicy, shared_state).await,
                            )
                        } else {
                            // Turning the kill-switch on needs the allow-list;
                            // turning it off cancels any pending resolution.
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
