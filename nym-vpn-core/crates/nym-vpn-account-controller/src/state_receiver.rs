// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_vpn_lib_types::{AccountControllerError, AccountControllerState};
use tokio::{sync::watch, time::Instant};

use crate::state_machine::ACCOUNT_VALIDATION_FRESHNESS;

// Channel to keep track of the account controller state
#[derive(Clone)]
pub struct AccountStateReceiver {
    inner: watch::Receiver<AccountControllerState>,
    last_validated: watch::Receiver<Option<Instant>>,
}

impl AccountStateReceiver {
    pub fn new(
        inner: watch::Receiver<AccountControllerState>,
        last_validated: watch::Receiver<Option<Instant>>,
    ) -> Self {
        Self {
            inner,
            last_validated,
        }
    }

    /// Returns Ok() when the AC is ready to connect, returns an Error if it can't reach that state
    ///
    /// A re-check of an account validated within `ACCOUNT_VALIDATION_FRESHNESS`
    /// doesn't hold the connect up: proceeding is the same as the connect having
    /// arrived just before the refresh started. Tickets are local and the
    /// gateway enforces their validity.
    pub async fn wait_for_account_ready_to_connect(
        &mut self,
    ) -> Result<(), AccountControllerError> {
        loop {
            let state = self.get_state();
            match state {
                AccountControllerState::Offline => {
                    return Err(AccountControllerError::Offline);
                }
                AccountControllerState::LoggedOut => {
                    return Err(AccountControllerError::NoAccountStored);
                }
                AccountControllerState::Error(reason) => {
                    return Err(AccountControllerError::ErrorState(reason));
                }
                AccountControllerState::Syncing | AccountControllerState::RequestingZkNyms
                    if self.recently_validated() =>
                {
                    tracing::debug!(
                        "Account controller is {state}, but the account was validated recently"
                    );
                    return Ok(());
                }
                AccountControllerState::Syncing | AccountControllerState::RequestingZkNyms => {
                    tracing::debug!("Account controller is {state}, waiting for the next state");

                    self.inner.changed().await.map_err(|_| {
                        AccountControllerError::Internal(
                            "Account controller state receiver has closed".into(),
                        )
                    })?;
                }
                AccountControllerState::ReadyToConnect
                | AccountControllerState::Decentralised
                | AccountControllerState::UpgradeMode => {
                    return Ok(());
                }
            }
        }
    }

    pub fn get_state(&self) -> AccountControllerState {
        self.inner.borrow().to_owned()
    }

    pub fn subscribe(&self) -> watch::Receiver<AccountControllerState> {
        self.inner.clone()
    }

    fn recently_validated(&self) -> bool {
        self.last_validated
            .borrow()
            .is_some_and(|validated| validated.elapsed() < ACCOUNT_VALIDATION_FRESHNESS)
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use nym_vpn_lib_types::AccountControllerErrorStateReason;

    use super::*;

    struct Channels {
        state: watch::Sender<AccountControllerState>,
        receiver: AccountStateReceiver,
    }

    fn channels(state: AccountControllerState, last_validated: Option<Instant>) -> Channels {
        let (state, state_rx) = watch::channel(state);
        let (_, last_validated_rx) = watch::channel(last_validated);
        Channels {
            state,
            receiver: AccountStateReceiver::new(state_rx, last_validated_rx),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recheck_of_a_fresh_validation_does_not_wait() {
        for state in [
            AccountControllerState::Syncing,
            AccountControllerState::RequestingZkNyms,
        ] {
            let mut channels = channels(state, Some(Instant::now()));
            tokio::time::advance(ACCOUNT_VALIDATION_FRESHNESS / 2).await;
            assert_eq!(
                channels
                    .receiver
                    .wait_for_account_ready_to_connect()
                    .now_or_never(),
                Some(Ok(()))
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn syncing_waits_without_a_validation() {
        let channels = channels(AccountControllerState::Syncing, None);
        let mut receiver = channels.receiver.clone();
        let wait = tokio::spawn(async move { receiver.wait_for_account_ready_to_connect().await });

        tokio::task::yield_now().await;
        assert!(!wait.is_finished());

        channels
            .state
            .send_replace(AccountControllerState::ReadyToConnect);
        assert_eq!(wait.await.unwrap(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn syncing_waits_once_the_validation_is_stale() {
        let mut channels = channels(AccountControllerState::Syncing, Some(Instant::now()));
        tokio::time::advance(ACCOUNT_VALIDATION_FRESHNESS).await;
        assert!(
            channels
                .receiver
                .wait_for_account_ready_to_connect()
                .now_or_never()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_validation_does_not_mask_an_error() {
        let reason = AccountControllerErrorStateReason::DeviceTimeDesynced;
        let mut channels = channels(
            AccountControllerState::Error(reason.clone()),
            Some(Instant::now()),
        );
        assert_eq!(
            channels
                .receiver
                .wait_for_account_ready_to_connect()
                .now_or_never(),
            Some(Err(AccountControllerError::ErrorState(reason)))
        );
    }
}
