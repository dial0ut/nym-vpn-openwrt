// Copyright 2016-2025 Mullvad VPN AB. All Rights Reserved.
// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    sync::{Arc, LazyLock},
};

use tokio::sync::watch;
use tokio_util::sync::{CancellationToken, DropGuard};

use nym_common::ErrorExt;
use nym_routing::RouteManagerHandle;

#[path = "linux.rs"]
mod imp;

/// Disables offline monitor
static FORCE_DISABLE_OFFLINE_MONITOR: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("NYM_DISABLE_OFFLINE_MONITOR")
        .map(|v| v != "0")
        .unwrap_or(false)
});

#[derive(Clone)]
pub struct ConnectivityHandle {
    inner: Arc<Option<imp::ConnectivityHandle>>,
    rx: watch::Receiver<Connectivity>,
    _shutdown_drop_guard: Arc<DropGuard>,
}

impl fmt::Debug for ConnectivityHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectivityHandle")
            .field("rx", &self.rx)
            .finish_non_exhaustive()
    }
}

impl ConnectivityHandle {
    fn new(
        inner: Option<imp::ConnectivityHandle>,
        rx: watch::Receiver<Connectivity>,
        shutdown_drop_guard: DropGuard,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            rx,
            _shutdown_drop_guard: Arc::new(shutdown_drop_guard),
        }
    }

    /// Returns current connectivity status.
    pub async fn connectivity(&self) -> Connectivity {
        match self.inner.as_ref() {
            Some(monitor) => monitor.connectivity().await,
            None => Connectivity::PresumeOnline,
        }
    }

    /// Returns next connectivity status once changed.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe as it uses the channel internally.
    pub async fn next(&mut self) -> Option<Connectivity> {
        if self.inner.is_some() {
            self.rx.changed().await.ok()?;
            Some(*self.rx.borrow_and_update())
        } else {
            None
        }
    }
}

#[async_trait::async_trait]
impl ConnectivityMonitor for ConnectivityHandle {
    /// Returns current connectivity status.
    async fn connectivity(&'async_trait self) -> Connectivity {
        self.connectivity().await
    }

    /// Returns next connectivity status once changed.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe as it uses the channel internally.
    async fn next(&'async_trait mut self) -> Option<Connectivity> {
        self.next().await
    }
}

/// Spawn offline monitor.
pub async fn spawn_monitor(
    route_manager: RouteManagerHandle,
    fwmark: Option<u32>,
) -> ConnectivityHandle {
    let (tx, rx) = watch::channel(Connectivity::PresumeOnline);
    let shutdown_token = CancellationToken::new();
    let child_token = shutdown_token.child_token();

    let monitor = if *FORCE_DISABLE_OFFLINE_MONITOR {
        tracing::info!("Offline monitor is disabled.");
        None
    } else {
        imp::spawn_monitor(tx, route_manager, fwmark, child_token)
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    "{}",
                    error.display_chain_with_msg("Failed to spawn offline monitor")
                );
            })
            .ok()
    };

    ConnectivityHandle::new(monitor, rx, shutdown_token.drop_guard())
}

/// Details about the hosts's connectivity.
///
/// Information about the host's connectivity, such as the presence of
/// configured IPv4 and/or IPv6.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Connectivity {
    Status {
        /// Whether IPv4 connectivity seems to be available on the host.
        ipv4: bool,
        /// Whether IPv6 connectivity seems to be available on the host.
        ipv6: bool,
    },
    /// On/offline status could not be verified, but we have no particular
    /// reason to believe that the host is offline.
    PresumeOnline,
}

impl Connectivity {
    /// Create a new `Connectivity` instance that presumes the host is offline until
    /// proven otherwise.
    pub fn new_presume_offline() -> Self {
        Connectivity::Status {
            ipv4: false,
            ipv6: false,
        }
    }

    /// Inverse of [`Connectivity::is_offline`].
    pub fn is_online(&self) -> bool {
        !self.is_offline()
    }

    /// If no IPv4 nor IPv6 routes exist, we have no way of reaching the internet
    /// so we consider ourselves offline.
    pub fn is_offline(&self) -> bool {
        matches!(
            self,
            Connectivity::Status {
                ipv4: false,
                ipv6: false
            }
        )
    }

    /// Whether IPv6 connectivity seems to be available on the host.
    ///
    /// If IPv6 status is unknown, `false` is returned.
    pub fn has_ipv6(&self) -> bool {
        matches!(self, Connectivity::Status { ipv6: true, .. })
    }
}

/// This is a trait to allow mocking in integration tests
#[async_trait::async_trait]
pub trait ConnectivityMonitor: Send + Sync {
    /// Returns current connectivity status.
    async fn connectivity(&'async_trait self) -> Connectivity;

    /// Returns next connectivity status once changed.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe as it uses the channel internally.
    async fn next(&'async_trait mut self) -> Option<Connectivity>;
}
