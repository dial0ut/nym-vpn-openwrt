// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    SharedAccountState,
    commands::{AccountCommand, UpgradeModeCommand, common_handler, handler},
    state_machine::{
        AccountControllerStateHandler, AccountRefreshMode, LoggedOutState,
        NextAccountControllerState, OfflineState, PrivateAccountControllerState, RefreshTimer,
        SyncingState,
    },
};
use nym_offline_monitor::ConnectivityMonitor;
use nym_vpn_lib_types::{AccountCommandError, AccountControllerErrorStateReason};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// ErrorState
/// We encountered something that doesn't allow us to make any progress.
/// This can range from internal issue, storage failure, API failure or unregistered account, expired subsciprions etc.
/// The full list of reason is available in the AccountControllerErrorStateReason enum
///
/// Crucially, we are online and an account is stored.
///
/// Possible next state :
/// - SyncingState : We go into that state on a timer, to see if the problem persists. The refresh account commands allows for manually go there.
///   The timer always runs on the normal cadence, whatever refresh mode the daemon set: idle backoff must not slow error recovery
///   (an API outage or a boot-time clock skew fixed later by NTP should clear within minutes, not half an hour).
/// - OfflineState : the connectivity monitor is telling we're not connected
/// - LoggedOutState : We successfully handled a forget_account command
pub struct ErrorState {
    refresh_timer: RefreshTimer,
    reason: AccountControllerErrorStateReason,
}

impl ErrorState {
    pub fn enter<C: ConnectivityMonitor>(
        reason: AccountControllerErrorStateReason,
    ) -> (
        Box<dyn AccountControllerStateHandler<C>>,
        PrivateAccountControllerState,
    ) {
        tracing::error!("Account Controller entering error state : {reason:#?}");
        let state = PrivateAccountControllerState::Error(reason.clone());
        (Box::new(Self::new(reason)), state)
    }

    fn new(reason: AccountControllerErrorStateReason) -> Self {
        Self {
            refresh_timer: RefreshTimer::start(AccountRefreshMode::Active),
            reason,
        }
    }
}

#[async_trait::async_trait]
impl<C: ConnectivityMonitor> AccountControllerStateHandler<C> for ErrorState {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<AccountCommand>,
        shared_state: &'async_trait mut SharedAccountState<C>,
    ) -> NextAccountControllerState<C> {
        tokio::select! {
            _ = self.refresh_timer.tick() => {
                if shared_state.firewall_active {
                    tracing::debug!("VPN API is firewalled, timed account syncing skipped");
                    return NextAccountControllerState::NewState(ErrorState::enter(self.reason));
                } else {
                    return NextAccountControllerState::NewState(SyncingState::enter(shared_state, 0));
                }
            },
            Some(command) = command_rx.recv() => {
                match command {
                    AccountCommand::CreateAccount(return_sender) => return_sender.send(Err(AccountCommandError::ExistingAccount)),
                    AccountCommand::StoreAccount(return_sender, _) => return_sender.send(Err(AccountCommandError::ExistingAccount)),
                    AccountCommand::RegisterAccount(return_sender, account, platform) => {
                        let res = handler::handle_register_account(shared_state, account, platform).await;
                        return_sender.send(res);
                    }
                    AccountCommand::ForgetAccount(return_sender) => {
                        let res = handler::handle_forget_account(shared_state).await;
                        let error = res.is_err();
                        return_sender.send(res);
                        if error {
                            return NextAccountControllerState::NewState(SyncingState::enter(shared_state, 0));
                        } else {
                            return NextAccountControllerState::NewState(LoggedOutState::enter());
                        }
                    },
                    AccountCommand::RotateKeys(return_sender) => {
                        let res = handler::handle_rotate_keys(shared_state).await;
                        return_sender.send(res);
                    },
                    AccountCommand::AccountBalance(return_sender) => return_sender.send(Err(AccountCommandError::AccountNotDecentralised)),
                    AccountCommand::ObtainTicketbooks(return_sender, _) => return_sender.send(Err(AccountCommandError::AccountNotDecentralised)),
                    AccountCommand::ResetDeviceIdentity(return_sender, seed) => {
                        let res = handler::handle_reset_device_identity(shared_state, seed).await;
                        let error = res.is_err();
                        return_sender.send(res);
                        if error {
                            return NextAccountControllerState::SameState(self);
                        } else {
                            return NextAccountControllerState::NewState(SyncingState::enter(shared_state, 0));
                        }
                    },
                    AccountCommand::RefreshAccountState(return_sender) => {
                        return_sender.send(Ok(()));
                        if shared_state.firewall_active {
                            return NextAccountControllerState::SameState(self);
                        } else {
                            return NextAccountControllerState::NewState(SyncingState::enter(shared_state, 0));
                        }
                    },

                    AccountCommand::VpnApiFirewallDown(return_sender) =>  {
                        shared_state.firewall_active = false;
                        return_sender.send(Ok(()));
                    },
                    AccountCommand::VpnApiFirewallUp(return_sender) => {
                        shared_state.firewall_active = true;
                        return_sender.send(Ok(()));
                    },
                    // Recorded for the ReadyState we hope to reach; the error retry timer itself
                    // stays on the normal cadence.
                    AccountCommand::SetRefreshMode(mode) => {
                        shared_state.refresh_mode = mode;
                    },

                    AccountCommand::Common(common_command) => {
                        common_handler::handle_common_command(common_command, shared_state).await
                    },
                    AccountCommand::UpgradeMode(upgrade_mode_command) => match upgrade_mode_command {
                        UpgradeModeCommand::GetUpgradeModeEnabled(return_sender) => {
                            return_sender.send(Ok(false))
                        }
                        UpgradeModeCommand::DisableUpgradeMode(return_sender) => {
                            warn!(
                                "received unexpected command to disable upgrade mode while in 'ErrorState' state"
                            );
                            return_sender.send(Ok(()))
                        }
                    },
                }
                NextAccountControllerState::SameState(self)
            }
            Some(connectivity) = shared_state.connectivity_handle.next() => {
                if connectivity.is_offline() {
                    NextAccountControllerState::NewState(OfflineState::enter())
                } else {
                    NextAccountControllerState::SameState(self)
                }
            }
            _ = shutdown_token.cancelled() => {
                NextAccountControllerState::Finished
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{ACCOUNT_IDLE_UPDATE_INTERVAL, ACCOUNT_UPDATE_INTERVAL};

    /// Idle backoff applies to `ReadyState` only: an error retry is never further away than the
    /// normal cadence, so a boot-time clock skew or API outage clears within minutes even when
    /// the daemon has declared itself idle.
    #[tokio::test(start_paused = true)]
    async fn error_retry_stays_on_the_normal_cadence() {
        assert!(ACCOUNT_IDLE_UPDATE_INTERVAL > ACCOUNT_UPDATE_INTERVAL);
        let mut state = ErrorState::new(AccountControllerErrorStateReason::DeviceTimeDesynced);
        assert!(
            tokio::time::timeout(ACCOUNT_UPDATE_INTERVAL / 2, state.refresh_timer.tick())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(ACCOUNT_UPDATE_INTERVAL, state.refresh_timer.tick())
                .await
                .is_ok()
        );
    }
}
