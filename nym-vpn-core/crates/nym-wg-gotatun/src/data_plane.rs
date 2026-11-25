// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! A thread of its own for the packet path of a WireGuard device.
//!
//! A gotatun device is a chain of tasks joined by queues: receive, decrypt,
//! buffer, write, and the same the other way. On the daemon's multi-threaded
//! runtime every packet entering an idle stage wakes a parked worker thread
//! to run it, a system call per stage per packet, and the stages take
//! packets off their queues one at a time.
//!
//! Run by one thread, a stage hands over without waking anybody, and it has
//! finished a whole burst before the next stage starts on it. Bursts
//! therefore stay bursts all the way to the interface, which is what lets
//! segments be merged there.

use std::{future::Future, io};

use tokio::{runtime::Handle, sync::oneshot};

/// A single-threaded runtime on a dedicated thread. Stops, with everything
/// still running on it, when dropped.
pub(crate) struct DataPlane {
    handle: Handle,
    _stop: oneshot::Sender<()>,
}

impl DataPlane {
    pub(crate) fn start(thread_name: &str) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel::<()>();

        std::thread::Builder::new()
            .name(thread_name.to_owned())
            .spawn(move || {
                // Ends when the sender is dropped.
                let _ = runtime.block_on(stopped);
                runtime.shutdown_background();
            })?;

        Ok(Self {
            handle,
            _stop: stop,
        })
    }

    /// Runs `future` on the thread and returns its output.
    ///
    /// Everything `future` spawns, and every socket or device it opens,
    /// belongs to this thread too.
    pub(crate) async fn run<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.handle.spawn(future).await {
            Ok(output) => output,
            Err(err) => std::panic::resume_unwind(err.into_panic()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DataPlane;

    #[tokio::test]
    async fn runs_on_its_own_thread() {
        let plane = DataPlane::start("test-plane").unwrap();

        let name = plane
            .run(async { std::thread::current().name().map(str::to_owned) })
            .await;
        assert_eq!(name.as_deref(), Some("test-plane"));

        let spawned = plane
            .run(async {
                tokio::spawn(async { std::thread::current().name().map(str::to_owned) })
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(spawned.as_deref(), Some("test-plane"));
    }

    #[tokio::test]
    async fn dropping_it_stops_what_runs_on_it() {
        let plane = DataPlane::start("test-plane").unwrap();
        let (held, mut dropped) = tokio::sync::mpsc::channel::<()>(1);

        plane
            .run(async move {
                tokio::spawn(async move {
                    let _held = held;
                    std::future::pending::<()>().await;
                });
            })
            .await;
        drop(plane);

        // The task and what it held are gone with the runtime.
        assert!(dropped.recv().await.is_none());
    }
}
