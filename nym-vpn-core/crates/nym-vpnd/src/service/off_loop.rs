// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Service commands that only read and can be slow. Each runs in a task of
//! its own, so the service loop, and the liveness probe it answers, never
//! waits on one. A run is bounded by a deadline and abandoned when its caller
//! goes away: tonic drops a gRPC handler's future on client disconnect, and
//! the reply receiver with it.

use std::{future::Future, sync::Arc, time::Duration};

use nym_diagnostic::DiagnosticHandler;
use nym_vpn_lib_types::{DiagnosticReport, DiagnosticResult, DiagnosticRunParams};
use nym_vpn_network_config::Network;
use tokio::sync::{Semaphore, oneshot, watch};

/// DNS, HTTP, gateway and hybrid transport checks, each bounded by its own
/// timeouts of a few seconds per step.
const RUN_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(90);

pub(super) struct OffLoop {
    network_rx: watch::Receiver<Box<Network>>,
    /// One diagnostic run at a time.
    diagnostic_slot: Arc<Semaphore>,
}

impl OffLoop {
    pub(super) fn new(network_rx: watch::Receiver<Box<Network>>) -> Self {
        Self {
            network_rx,
            diagnostic_slot: Arc::new(Semaphore::new(1)),
        }
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
}
