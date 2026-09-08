// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! In-process liveness check for the service loop.
//!
//! procd restarts a daemon that dies, and the Always On supervisor handles a
//! daemon that keeps failing; neither notices a daemon that is merely stuck,
//! accepting gRPC connections but never answering. That was the one thing the
//! external shell watchdog could catch. This task asks the service loop for
//! the tunnel state through the same channel the gRPC layer uses and, after
//! [`STRIKES`] consecutive unanswered probes, has the process exit abruptly so
//! procd respawns it. Abrupt on purpose: the shutdown path would tear the
//! kill-switch table down for the respawn window.
//!
//! Inline service commands are all bounded well under a minute (diagnostics:
//! 2–10 s per step; account calls carry API timeouts), so a single slow
//! command can cost at most one strike before the next probe answers.

use std::{future::Future, time::Duration};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::service::VpnServiceCommand;

/// How often the service loop is probed.
pub const INTERVAL: Duration = Duration::from_secs(60);
/// How long one probe may go unanswered before it counts as a strike.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Consecutive strikes before the daemon is judged hung.
pub const STRIKES: u32 = 3;
/// Exit code for a hung service loop; procd respawns.
pub const EXIT_CODE_HUNG: i32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The daemon is shutting down normally.
    Shutdown,
    /// The service loop missed `STRIKES` probes in a row.
    Hung,
}

/// Probe outcome: `Some(true)` answered, `Some(false)` timed out, `None` the
/// loop is gone (channel closed), which is a shutdown, not a hang.
type Probe = Option<bool>;

/// Drive `probe` every `interval` until it fails `strikes` times in a row or
/// `shutdown` fires. Generic over the probe so a test can plug in one that
/// never answers.
pub async fn watch<P, Fut>(
    mut probe: P,
    interval: Duration,
    strikes: u32,
    shutdown: CancellationToken,
) -> Verdict
where
    P: FnMut() -> Fut,
    Fut: Future<Output = Probe>,
{
    let mut missed = 0u32;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Verdict::Shutdown,
            _ = tokio::time::sleep(interval) => {}
        }
        let outcome = tokio::select! {
            _ = shutdown.cancelled() => return Verdict::Shutdown,
            outcome = probe() => outcome,
        };
        match outcome {
            None => return Verdict::Shutdown,
            Some(true) => missed = 0,
            Some(false) => {
                missed += 1;
                tracing::warn!("liveness: service loop did not answer ({missed}/{strikes})");
                if missed >= strikes {
                    return Verdict::Hung;
                }
            }
        }
    }
}

/// One production probe: `GetTunnelState` with a `TIMEOUT`.
async fn probe_service(tx: &mpsc::UnboundedSender<VpnServiceCommand>) -> Probe {
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(VpnServiceCommand::GetTunnelState(reply_tx, ()))
        .is_err()
    {
        return None;
    }
    match tokio::time::timeout(TIMEOUT, reply_rx).await {
        Ok(Ok(_)) => Some(true),
        // The loop dropped our sender without answering: it is going away.
        Ok(Err(_)) => None,
        Err(_) => Some(false),
    }
}

/// Spawn the production watcher; exits the process on a hang.
pub fn spawn(tx: mpsc::UnboundedSender<VpnServiceCommand>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let verdict = watch(|| probe_service(&tx), INTERVAL, STRIKES, shutdown).await;
        if verdict == Verdict::Hung {
            tracing::error!(
                "liveness: service loop unresponsive for {} probes, exiting for procd",
                STRIKES
            );
            // Give the non-blocking log writer a moment; exit() skips destructors.
            std::thread::sleep(Duration::from_millis(200));
            std::process::exit(EXIT_CODE_HUNG);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    #[tokio::test]
    async fn answered_probes_never_strike() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let shutdown = CancellationToken::new();
        let s = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            s.cancel();
        });
        let verdict = watch(
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                async { Some(true) }
            },
            Duration::from_millis(5),
            3,
            shutdown,
        )
        .await;
        assert_eq!(verdict, Verdict::Shutdown);
        assert!(calls.load(Ordering::SeqCst) >= 3, "probes kept running");
    }

    #[tokio::test]
    async fn three_consecutive_misses_are_a_hang() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let verdict = watch(
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                async { Some(false) }
            },
            Duration::from_millis(1),
            3,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(verdict, Verdict::Hung);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn one_answer_resets_the_count() {
        // miss, miss, answer, miss, miss, answer, ... never three in a row.
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let shutdown = CancellationToken::new();
        let s = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            s.cancel();
        });
        let verdict = watch(
            move || {
                let n = c.fetch_add(1, Ordering::SeqCst);
                async move { Some(n % 3 == 2) }
            },
            Duration::from_millis(1),
            3,
            shutdown,
        )
        .await;
        assert_eq!(verdict, Verdict::Shutdown);
        assert!(calls.load(Ordering::SeqCst) > 6);
    }

    #[tokio::test]
    async fn blocked_service_channel_is_a_hang_and_closed_channel_is_not() {
        // A receiver that never reads: every probe times out.
        let (tx, _rx) = mpsc::unbounded_channel::<VpnServiceCommand>();
        let probe = |tx: mpsc::UnboundedSender<VpnServiceCommand>| async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(VpnServiceCommand::GetTunnelState(reply_tx, ()))
                .ok()?;
            match tokio::time::timeout(Duration::from_millis(2), reply_rx).await {
                Ok(Ok(_)) => Some(true),
                Ok(Err(_)) => None,
                Err(_) => Some(false),
            }
        };
        let t = tx.clone();
        let verdict = watch(
            move || probe(t.clone()),
            Duration::from_millis(1),
            3,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(verdict, Verdict::Hung);

        // The loop is gone: sending fails, which is a shutdown.
        drop(_rx);
        let verdict = watch(
            move || probe(tx.clone()),
            Duration::from_millis(1),
            3,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(verdict, Verdict::Shutdown);
    }
}
