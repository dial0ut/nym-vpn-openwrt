// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Service commands that only read and can be slow. Each runs in a task of
//! its own, so the service loop, and the liveness probe it answers, never
//! waits on one. A run is bounded by a deadline and abandoned when its caller
//! goes away: tonic drops a gRPC handler's future on client disconnect, and
//! the reply receiver with it.
//!
//! Account mutations stay on the loop, in order with Connect.

use std::{future::Future, sync::Arc, time::Duration};

use nym_diagnostic::DiagnosticHandler;
use nym_vpn_account_controller::{AccountCommandSender, AvailableTicketbooks};
use nym_vpn_lib_types::{
    AccountBalanceResponse, AccountCommandError, Coin, DeeplinkClient, DeeplinkKind,
    DiagnosticReport, DiagnosticResult, DiagnosticRunParams, GetDeeplinkParams, NymVpnDevice,
    NymVpnUsage, ParsedAccountLinks, VpnAccountSummary,
};
use nym_vpn_network_config::Network;
use tokio::sync::{Semaphore, oneshot, watch};
use url::Url;

use super::error::AccountLinksError;

/// DNS, HTTP, gateway and hybrid transport checks, each bounded by its own
/// timeouts of a few seconds per step.
const RUN_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(90);

/// Most reads are API round trips. The account controller answers one
/// command at a time, so even a local read can queue behind a slow one.
const ACCOUNT_READ_TIMEOUT: Duration = Duration::from_secs(30);

type AccountReply<T> = oneshot::Sender<Result<T, AccountCommandError>>;

pub(super) struct OffLoop {
    account_command_tx: AccountCommandSender,
    network_rx: watch::Receiver<Box<Network>>,
    /// One diagnostic run at a time.
    diagnostic_slot: Arc<Semaphore>,
}

impl OffLoop {
    pub(super) fn new(
        account_command_tx: AccountCommandSender,
        network_rx: watch::Receiver<Box<Network>>,
    ) -> Self {
        Self {
            account_command_tx,
            network_rx,
            diagnostic_slot: Arc::new(Semaphore::new(1)),
        }
    }

    pub(super) fn is_account_stored(&self, reply_tx: oneshot::Sender<bool>) {
        let account = self.account_command_tx.clone();
        spawn_reply(
            "Account lookup",
            reply_tx,
            ACCOUNT_READ_TIMEOUT,
            || false,
            async move {
                account
                    .get_account_id()
                    .await
                    .map(|id| id.is_some())
                    .unwrap_or(false)
            },
        );
    }

    pub(super) fn account_identity(&self, reply_tx: AccountReply<Option<String>>) {
        self.account_read("Account identity read", reply_tx, |account| async move {
            account.get_account_id().await
        });
    }

    pub(super) fn account_links(
        &self,
        reply_tx: oneshot::Sender<Result<ParsedAccountLinks, AccountLinksError>>,
        locale: String,
    ) {
        let account = self.account_command_tx.clone();
        let network_rx = self.network_rx.clone();
        spawn_reply(
            "Account links read",
            reply_tx,
            ACCOUNT_READ_TIMEOUT,
            || Err(AccountLinksError::FailedToParseAccountLinks),
            async move {
                let account_id = account
                    .get_account_id()
                    .await
                    .map_err(|_| AccountLinksError::FailedToParseAccountLinks)?;
                let account_management = network_rx
                    .borrow()
                    .nym_vpn_network
                    .account_management
                    .clone()
                    .ok_or(AccountLinksError::AccountManagementNotConfigured)?;
                account_management
                    .try_into_parsed_links(&locale, account_id.as_deref())
                    .map(ParsedAccountLinks::from)
                    .map_err(|err| {
                        tracing::error!("Failed to parse account links: {:?}", err);
                        AccountLinksError::FailedToParseAccountLinks
                    })
            },
        );
    }

    pub(super) fn account_usage(&self, reply_tx: AccountReply<Vec<NymVpnUsage>>) {
        self.account_read("Account usage read", reply_tx, |account| async move {
            account
                .get_usage()
                .await
                .map(|usage| usage.into_iter().map(NymVpnUsage::from).collect())
        });
    }

    pub(super) fn device_identity(&self, reply_tx: AccountReply<Option<String>>) {
        self.account_read("Device identity read", reply_tx, |account| async move {
            account.get_device_identity().await
        });
    }

    pub(super) fn devices(&self, reply_tx: AccountReply<Vec<NymVpnDevice>>) {
        self.account_read("Device list read", reply_tx, |account| async move {
            let devices = account.get_devices().await?;
            Ok(devices.into_iter().map(NymVpnDevice::from).collect())
        });
    }

    pub(super) fn active_devices(&self, reply_tx: AccountReply<Vec<NymVpnDevice>>) {
        self.account_read("Active device list read", reply_tx, |account| async move {
            let devices = account.get_active_devices().await?;
            Ok(devices.into_iter().map(NymVpnDevice::from).collect())
        });
    }

    pub(super) fn available_tickets(&self, reply_tx: AccountReply<AvailableTicketbooks>) {
        self.account_read("Ticket read", reply_tx, |account| async move {
            account.get_available_tickets().await
        });
    }

    pub(super) fn account_summary(&self, reply_tx: AccountReply<Option<VpnAccountSummary>>) {
        self.account_read("Account summary read", reply_tx, |account| async move {
            account.get_account_summary().await
        });
    }

    /// Creates a deeplink in the account controller; nothing else depends on
    /// it before the client has the link.
    pub(super) fn deeplink(&self, reply_tx: AccountReply<String>, params: GetDeeplinkParams) {
        let base_url = match self.deeplink_base_url(&params) {
            Ok(base_url) => base_url,
            Err(err) => {
                reply_tx.send(Err(err)).ok();
                return;
            }
        };
        self.account_read("Deeplink request", reply_tx, move |account| async move {
            account
                .get_deeplink(params.kind, params.name, base_url)
                .await
        });
    }

    fn deeplink_base_url(&self, params: &GetDeeplinkParams) -> Result<Url, AccountCommandError> {
        match params.kind {
            DeeplinkKind::Privy => {
                let network = self.network_rx.borrow();
                let Some(account_management) = &network.nym_vpn_network.account_management else {
                    return Err(AccountCommandError::DeeplinkError(
                        "No account management data is available at this time".to_string(),
                    ));
                };

                let opt_url = match params.client {
                    DeeplinkClient::Mobile => account_management.privy_mobile_url(&params.locale),
                    DeeplinkClient::Desktop => account_management.privy_desktop_url(&params.locale),
                    DeeplinkClient::Web => account_management.privy_web_url(&params.locale),
                };

                opt_url.ok_or(AccountCommandError::DeeplinkError(
                    "The privy path could not be determined".to_string(),
                ))
            }
        }
    }

    pub(super) fn decentralised_balance(&self, reply_tx: oneshot::Sender<AccountBalanceResponse>) {
        let account = self.account_command_tx.clone();
        spawn_reply(
            "Balance query",
            reply_tx,
            ACCOUNT_READ_TIMEOUT,
            || AccountBalanceResponse {
                result: Err(account_read_timed_out("Balance query")),
            },
            async move {
                AccountBalanceResponse {
                    result: account
                        .decentralised_balance()
                        .await
                        .map(|coins| coins.into_iter().map(Coin::from).collect()),
                }
            },
        );
    }

    fn account_read<T, F, R>(&self, what: &'static str, reply_tx: AccountReply<T>, read: F)
    where
        T: Send + 'static,
        F: FnOnce(AccountCommandSender) -> R,
        R: Future<Output = Result<T, AccountCommandError>> + Send + 'static,
    {
        spawn_reply(
            what,
            reply_tx,
            ACCOUNT_READ_TIMEOUT,
            move || Err(account_read_timed_out(what)),
            read(self.account_command_tx.clone()),
        );
    }

    pub(super) fn run_diagnostic(
        &self,
        reply_tx: oneshot::Sender<DiagnosticReport>,
        params: DiagnosticRunParams,
    ) {
        let Ok(permit) = self.diagnostic_slot.clone().try_acquire_owned() else {
            reply_tx
                .send(diagnostic_failure("another diagnostic run is in progress"))
                .ok();
            return;
        };
        let network = *self.network_rx.borrow().clone();
        spawn_reply(
            "Diagnostic run",
            reply_tx,
            RUN_DIAGNOSTIC_TIMEOUT,
            || diagnostic_failure("the diagnostic run timed out"),
            async move {
                let _permit = permit;
                let report = DiagnosticHandler::run(network, params).await;
                match serde_json::to_string_pretty(&report) {
                    Ok(report_log) => tracing::info!("{report_log}"),
                    Err(e) => tracing::error!("Error serializing report :{e}"),
                }
                report
            },
        );
    }
}

fn account_read_timed_out(what: &str) -> AccountCommandError {
    AccountCommandError::internal(format!(
        "{what} timed out after {}s",
        ACCOUNT_READ_TIMEOUT.as_secs()
    ))
}

/// A report carrying nothing but `error`, in its HTTP section.
fn diagnostic_failure(error: &str) -> DiagnosticReport {
    DiagnosticReport {
        dns: None,
        http: Some(DiagnosticResult::from_err(error)),
        gateway: None,
        hybrid_transport: None,
    }
}

/// Run `work` in a task of its own and reply with its result, or with
/// `on_timeout()` once `deadline` passes. The work is dropped unfinished when
/// the caller goes away.
pub(super) fn spawn_reply<T, W>(
    what: &'static str,
    reply_tx: oneshot::Sender<T>,
    deadline: Duration,
    on_timeout: impl FnOnce() -> T + Send + 'static,
    work: W,
) where
    T: Send + 'static,
    W: Future<Output = T> + Send + 'static,
{
    tokio::spawn(async move {
        // `closed()` needs `&mut`; the sender is ours alone from here.
        let mut reply_tx = reply_tx;
        tokio::select! {
            _ = reply_tx.closed() => {
                tracing::debug!("{what} abandoned: the caller went away");
            }
            result = tokio::time::timeout(deadline, work) => {
                let reply = result.unwrap_or_else(|_elapsed| {
                    tracing::warn!("{what} did not finish within {}s", deadline.as_secs());
                    on_timeout()
                });
                reply_tx.send(reply).ok();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_slow_reply_times_out_with_the_fallback() {
        let (tx, rx) = oneshot::channel();
        spawn_reply("Test", tx, Duration::from_secs(30), || "timed out", async {
            tokio::time::sleep(Duration::from_secs(600)).await;
            "done"
        });
        let start = tokio::time::Instant::now();
        assert_eq!(rx.await.unwrap(), "timed out");
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn the_work_is_dropped_when_the_caller_goes_away() {
        struct Dropped(Option<oneshot::Sender<()>>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.take().unwrap().send(()).ok();
            }
        }
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let (tx, rx) = oneshot::channel::<()>();
        spawn_reply("Test", tx, Duration::from_secs(600), || (), async move {
            let _dropped = Dropped(Some(dropped_tx));
            std::future::pending::<()>().await
        });
        tokio::task::yield_now().await;
        drop(rx);
        let start = tokio::time::Instant::now();
        dropped_rx.await.unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_answers_the_probe_while_an_account_read_hangs() {
        use crate::service::VpnServiceCommand;
        use nym_vpn_lib_types::TunnelState;
        use tokio::sync::mpsc;

        // An account controller that takes commands and never answers them.
        let (account_tx, mut account_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(command) = account_rx.recv().await {
                held.push(command);
            }
        });
        let network = Network::mainnet_default().unwrap();
        let (_network_tx, network_rx) = watch::channel(Box::new(network));
        let off_loop = OffLoop::new(AccountCommandSender::new(account_tx), network_rx);

        // The service loop in miniature, dispatching as it does.
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    VpnServiceCommand::GetAccountUsage(tx, ()) => off_loop.account_usage(tx),
                    VpnServiceCommand::GetTunnelState(tx, ()) => {
                        tx.send(TunnelState::Disconnected).ok();
                    }
                    other => panic!("unexpected {other}"),
                }
            }
        });

        let (usage_tx, usage_rx) = oneshot::channel();
        command_tx
            .send(VpnServiceCommand::GetAccountUsage(usage_tx, ()))
            .unwrap();
        let start = tokio::time::Instant::now();
        assert_eq!(
            crate::liveness::probe_service(&command_tx).await,
            Some(true)
        );
        assert!(start.elapsed() < Duration::from_secs(1));

        let usage = usage_rx.await.unwrap();
        assert!(
            matches!(usage, Err(AccountCommandError::Internal(_))),
            "{usage:?}"
        );
        assert_eq!(start.elapsed(), ACCOUNT_READ_TIMEOUT);
    }
}
