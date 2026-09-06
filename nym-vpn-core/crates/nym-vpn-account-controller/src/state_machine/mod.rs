// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{pin::Pin, time::Duration};

use nym_offline_monitor::ConnectivityMonitor;
use nym_vpn_lib_types::{AccountControllerErrorStateReason, AccountControllerState};
use tokio::{
    sync::mpsc,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;

use crate::{SharedAccountState, commands::AccountCommand};

mod decentralised_state;
mod error_state;
mod logged_out_state;
mod offline_state;
mod ready_state;
mod syncing_state;
mod upgrade_mode_state;
// Account Controller state machine available states

/// Account stored, online, can't proceed without user action and/or temporary failure somewhere
pub(crate) use error_state::ErrorState;

/// No account stored, online
pub use logged_out_state::LoggedOutState;

/// Maybe account stored, offline,
pub use offline_state::OfflineState;

/// Account stored, online, ready to connect
pub(crate) use ready_state::ReadyState;

/// Account stored, online, determining if we can't connect or not
pub(crate) use syncing_state::SyncingState;

/// We're in the process of attempting to acquire a zk-nym
pub(crate) use syncing_state::requesting_zknym_state::RequestingZkNymsState;

/// Account is operating independently of VPN API
pub(crate) use decentralised_state::DecentralisedState;

/// The system is undergoing an upgrade mode, where zk-nyms can't be issued
pub(crate) use upgrade_mode_state::UpgradeModeState;

// The interval at which we update the account state while the tunnel is up or a connect has
// been requested
const ACCOUNT_UPDATE_INTERVAL: Duration = Duration::from_secs(2 * 60);

// The interval at which we update the account state while the tunnel is idle: Disconnected and
// nobody has asked to connect. A connect request switches back to ACCOUNT_UPDATE_INTERVAL and
// syncs right away if the last sync is older than that, so a long idle cadence costs nothing at
// connect time.
const ACCOUNT_IDLE_UPDATE_INTERVAL: Duration = Duration::from_secs(30 * 60);

// The interval at which we attempt to exit the upgrade mode by trying to get a new zk-nym instead
// (note: this does not prevent bandwidth controller from notifying us directly about the UM being over)
const UPGRADE_MODE_DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);

#[async_trait::async_trait]
pub(crate) trait AccountControllerStateHandler<C: ConnectivityMonitor>: Send {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<AccountCommand>,
        shared_state: &'async_trait mut SharedAccountState<C>,
    ) -> NextAccountControllerState<C>;
}

pub(crate) enum NextAccountControllerState<C: ConnectivityMonitor> {
    NewState(
        (
            Box<dyn AccountControllerStateHandler<C>>,
            PrivateAccountControllerState,
        ),
    ),
    SameState(Box<dyn AccountControllerStateHandler<C>>),
    Finished,
}

impl<C: ConnectivityMonitor>
    From<(
        Box<dyn AccountControllerStateHandler<C>>,
        PrivateAccountControllerState,
    )> for NextAccountControllerState<C>
{
    fn from(
        new_state: (
            Box<dyn AccountControllerStateHandler<C>>,
            PrivateAccountControllerState,
        ),
    ) -> Self {
        NextAccountControllerState::NewState(new_state)
    }
}

impl<C: ConnectivityMonitor> From<Box<dyn AccountControllerStateHandler<C>>>
    for NextAccountControllerState<C>
{
    fn from(state: Box<dyn AccountControllerStateHandler<C>>) -> Self {
        NextAccountControllerState::SameState(state)
    }
}

impl From<PrivateAccountControllerState> for AccountControllerState {
    fn from(value: PrivateAccountControllerState) -> Self {
        match value {
            PrivateAccountControllerState::Offline => Self::Offline,
            PrivateAccountControllerState::Syncing => Self::Syncing,
            PrivateAccountControllerState::LoggedOut => Self::LoggedOut,
            PrivateAccountControllerState::ReadyToConnect => Self::ReadyToConnect,
            PrivateAccountControllerState::Decentralised => Self::Decentralised,
            PrivateAccountControllerState::UpgradeMode => Self::UpgradeMode,
            PrivateAccountControllerState::Error(reason) => Self::Error(reason),
            PrivateAccountControllerState::RequestingZkNyms => Self::RequestingZkNyms,
        }
    }
}

/// How often the account controller re-syncs with the VPN API on its own while it is
/// `ReadyState`. Set by the daemon from the tunnel state. `ErrorState` ignores it and keeps
/// retrying on the normal cadence, so idle backoff never slows error recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccountRefreshMode {
    /// Tunnel is up or a connect has been requested: keep the account state fresh.
    #[default]
    Active,
    /// Tunnel is Disconnected and nothing is pending: slow heartbeat only.
    Idle,
}

impl AccountRefreshMode {
    fn interval(self) -> Duration {
        match self {
            AccountRefreshMode::Active => ACCOUNT_UPDATE_INTERVAL,
            AccountRefreshMode::Idle => ACCOUNT_IDLE_UPDATE_INTERVAL,
        }
    }
}

/// Timer driving the periodic re-sync of `ReadyState` (mode-dependent) and `ErrorState` (always
/// `Active`).
///
/// The deadline is always `entered_at + interval(mode)`, where `entered_at` is when the state was
/// entered, i.e. when the last sync attempt concluded. Changing the mode re-targets that deadline
/// rather than restarting the wait, so switching to `Active` after a long idle period reports the
/// account state as stale (and the caller syncs immediately) instead of waiting another interval.
pub(crate) struct RefreshTimer {
    entered_at: Instant,
    sleep: Pin<Box<Sleep>>,
}

impl RefreshTimer {
    pub(crate) fn start(mode: AccountRefreshMode) -> Self {
        let entered_at = Instant::now();
        Self {
            entered_at,
            sleep: Box::pin(tokio::time::sleep_until(entered_at + mode.interval())),
        }
    }

    /// Resolves when the next timed sync is due.
    pub(crate) async fn tick(&mut self) {
        self.sleep.as_mut().await
    }

    /// Re-arms the timer for `mode`. Returns `true` when the state was entered longer ago than
    /// `mode` tolerates: the timer is then due immediately and the caller should sync now.
    pub(crate) fn set_mode(&mut self, mode: AccountRefreshMode) -> bool {
        let deadline = self.entered_at + mode.interval();
        self.sleep.as_mut().reset(deadline);
        deadline <= Instant::now()
    }

    /// Records a `SetRefreshMode` command. Returns `true` when the caller should sync right away:
    /// the mode changed, the account state is stale for the new mode, and the VPN API is
    /// reachable.
    pub(crate) fn apply_mode<C: ConnectivityMonitor>(
        &mut self,
        shared_state: &mut SharedAccountState<C>,
        mode: AccountRefreshMode,
    ) -> bool {
        if shared_state.refresh_mode == mode {
            return false;
        }
        tracing::debug!("Account refresh mode: {mode:?}");
        shared_state.refresh_mode = mode;
        self.set_mode(mode) && !shared_state.firewall_active
    }
}

/// Private enum describing the account controller state
#[derive(Debug, Clone)]
pub(super) enum PrivateAccountControllerState {
    Offline,
    Syncing,
    LoggedOut,
    ReadyToConnect,
    Decentralised,
    UpgradeMode,
    Error(AccountControllerErrorStateReason),
    RequestingZkNyms,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fires_within(timer: &mut RefreshTimer, duration: Duration) -> bool {
        tokio::time::timeout(duration, timer.tick()).await.is_ok()
    }

    #[test]
    fn idle_interval_is_longer_than_active() {
        assert!(AccountRefreshMode::Idle.interval() > AccountRefreshMode::Active.interval());
        assert_eq!(AccountRefreshMode::default(), AccountRefreshMode::Active);
    }

    #[tokio::test(start_paused = true)]
    async fn active_timer_fires_after_the_update_interval() {
        let mut timer = RefreshTimer::start(AccountRefreshMode::Active);
        assert!(!fires_within(&mut timer, ACCOUNT_UPDATE_INTERVAL / 2).await);
        assert!(fires_within(&mut timer, ACCOUNT_UPDATE_INTERVAL).await);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timer_outlasts_the_active_interval() {
        let mut timer = RefreshTimer::start(AccountRefreshMode::Idle);
        assert!(!fires_within(&mut timer, ACCOUNT_UPDATE_INTERVAL * 2).await);
        assert!(fires_within(&mut timer, ACCOUNT_IDLE_UPDATE_INTERVAL).await);
    }

    #[tokio::test(start_paused = true)]
    async fn going_active_after_a_stale_idle_wait_is_due_immediately() {
        let mut timer = RefreshTimer::start(AccountRefreshMode::Idle);
        tokio::time::advance(ACCOUNT_UPDATE_INTERVAL).await;
        assert!(timer.set_mode(AccountRefreshMode::Active));
        assert!(fires_within(&mut timer, Duration::ZERO).await);
    }

    #[tokio::test(start_paused = true)]
    async fn going_active_before_the_active_interval_keeps_the_original_deadline() {
        let mut timer = RefreshTimer::start(AccountRefreshMode::Idle);
        let elapsed = ACCOUNT_UPDATE_INTERVAL / 2;
        tokio::time::advance(elapsed).await;
        assert!(!timer.set_mode(AccountRefreshMode::Active));
        // Due at entered_at + ACTIVE, not at now + ACTIVE.
        assert!(fires_within(&mut timer, ACCOUNT_UPDATE_INTERVAL - elapsed).await);
    }

    #[tokio::test(start_paused = true)]
    async fn going_idle_extends_the_deadline() {
        let mut timer = RefreshTimer::start(AccountRefreshMode::Active);
        tokio::time::advance(ACCOUNT_UPDATE_INTERVAL / 2).await;
        assert!(!timer.set_mode(AccountRefreshMode::Idle));
        assert!(!fires_within(&mut timer, ACCOUNT_UPDATE_INTERVAL).await);
        assert!(fires_within(&mut timer, ACCOUNT_IDLE_UPDATE_INTERVAL).await);
    }
}
