// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    SharedAccountState,
    commands::{AccountCommand, UpgradeModeCommand, common_handler, handler},
    state_machine::{
        AccountControllerStateHandler, LoggedOutState, NextAccountControllerState, OfflineState,
        PrivateAccountControllerState, RefreshTimer, SyncingState,
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
///   The timer's interval follows the refresh mode set by the daemon: slow while the tunnel is idle, normal otherwise.
/// - OfflineState : the connectivity monitor is telling we're not connected
/// - LoggedOutState : We successfully handled a forget_account command
pub struct ErrorState {
    refresh_timer: RefreshTimer,
    reason: AccountControllerErrorStateReason,
}

impl ErrorState {
    pub fn enter<C: ConnectivityMonitor>(
        shared_state: &SharedAccountState<C>,
        reason: AccountControllerErrorStateReason,
    ) -> (
        Box<dyn AccountControllerStateHandler<C>>,
        PrivateAccountControllerState,
    ) {
        let refresh_timer = RefreshTimer::start(shared_state.refresh_mode);
        tracing::error!("Account Controller entering error state : {reason:#?}");
        (
            Box::new(Self {
                refresh_timer,
                reason: reason.clone(),
            }),
            PrivateAccountControllerState::Error(reason),
        )
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
                    return NextAccountControllerState::NewState(ErrorState::enter(shared_state, self.reason));
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
                    AccountCommand::SetRefreshMode(mode) => {
                        if self.refresh_timer.apply_mode(shared_state, mode) {
                            return NextAccountControllerState::NewState(SyncingState::enter(shared_state, 0));
                        }
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
