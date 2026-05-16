// Copyright 2016-2024 Mullvad VPN AB. All Rights Reserved.
// Copyright 2024 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::Route;

use super::RequiredRoute;

use std::{collections::HashSet, net::IpAddr, sync::Arc};
use tokio::sync::{mpsc, oneshot};

#[path = "linux.rs"]
mod imp;

pub use imp::Error as PlatformError;

/// Errors that can be encountered whilst initializing route manager
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Route manager thread may have panicked
    #[error("the channel sender was dropped")]
    ManagerChannelDown,
    /// Platform specific error occurred
    #[error("internal route manager error")]
    PlatformError(#[from] imp::Error),
    /// Attempt to use route manager that has been dropped
    #[error("cannot send message to route manager since it is down")]
    RouteManagerDown,
}

impl Error {
    /// Return whether retrying the operation that caused this error is likely to succeed.
    pub fn is_recoverable(&self) -> bool {
        false
    }
}

/// Represents a firewall mark.
type Fwmark = u32;

/// Commands for the underlying route manager object.
#[derive(Debug)]
pub(crate) enum RouteManagerCommand {
    AddRoutes(
        HashSet<RequiredRoute>,
        oneshot::Sender<Result<(), PlatformError>>,
    ),
    ClearRoutes,
    Shutdown(oneshot::Sender<()>),
    /// `(enable_ipv6, enable_exempt, sender)` — `enable_exempt` installs the
    /// fwmark→main routing rule used by the inbound-service exemption feature.
    CreateRoutingRules(bool, bool, oneshot::Sender<Result<(), PlatformError>>),
    ClearRoutingRules(oneshot::Sender<Result<(), PlatformError>>),
    NewChangeListener(oneshot::Sender<mpsc::UnboundedReceiver<CallbackMessage>>),
    GetMtuForRoute(IpAddr, oneshot::Sender<Result<u16, PlatformError>>),
    /// Attempt to fetch a route for the given destination with an optional firewall mark.
    GetDestinationRoute(
        IpAddr,
        Option<Fwmark>,
        oneshot::Sender<Result<Option<Route>, PlatformError>>,
    ),
}

#[derive(Debug, Clone)]
pub enum CallbackMessage {
    NewRoute(Route),
    DelRoute(Route),
}

/// Route manager applies a set of routes to the route table.
/// If a destination has to be routed through the default node,
/// the route will be adjusted dynamically when the default route changes.
#[derive(Debug, Clone)]
pub struct RouteManagerHandle {
    tx: Arc<mpsc::UnboundedSender<RouteManagerCommand>>,
}

impl RouteManagerHandle {
    /// Construct a route manager.
    pub async fn spawn(fwmark: u32, table_id: u32) -> Result<Self, Error> {
        let (manage_tx, manage_rx) = tokio::sync::mpsc::unbounded_channel();
        let manage_tx = Arc::new(manage_tx);
        let manager = imp::RouteManagerImpl::new(fwmark, table_id).await?;
        tokio::spawn(manager.run(manage_rx));

        Ok(Self { tx: manage_tx })
    }

    /// Stop route manager and revert all changes to routing
    pub async fn stop(&self) {
        let (wait_tx, wait_rx) = oneshot::channel();
        let _ = self.tx.send(RouteManagerCommand::Shutdown(wait_tx));
        let _ = wait_rx.await;
    }

    /// Applies the given routes until they are cleared
    pub async fn add_routes(&self, routes: HashSet<RequiredRoute>) -> Result<(), Error> {
        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::AddRoutes(routes, result_tx))
            .map_err(|_| Error::RouteManagerDown)?;

        result_rx
            .await
            .map_err(|_| Error::ManagerChannelDown)?
            .map_err(Error::PlatformError)
    }

    /// Removes all routes previously applied in [`RouteManagerHandle::add_routes`].
    pub fn clear_routes(&self) -> Result<(), Error> {
        self.tx
            .send(RouteManagerCommand::ClearRoutes)
            .map_err(|_| Error::RouteManagerDown)
    }

    /// Ensure that packets are routed using the correct tables.
    ///
    /// `enable_exempt` adds an extra `ip rule fwmark 0x14e lookup main pref 90`
    /// so traffic marked by the inbound-service-exemption firewall path exits
    /// via the real WAN instead of the tunnel.
    pub async fn create_routing_rules(
        &self,
        enable_ipv6: bool,
        enable_exempt: bool,
    ) -> Result<(), Error> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::CreateRoutingRules(
                enable_ipv6,
                enable_exempt,
                response_tx,
            ))
            .map_err(|_| Error::RouteManagerDown)?;
        response_rx
            .await
            .map_err(|_| Error::ManagerChannelDown)?
            .map_err(Error::PlatformError)
    }

    /// Remove any routing rules created by [Self::create_routing_rules].
    pub async fn clear_routing_rules(&self) -> Result<(), Error> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::ClearRoutingRules(response_tx))
            .map_err(|_| Error::RouteManagerDown)?;
        response_rx
            .await
            .map_err(|_| Error::ManagerChannelDown)?
            .map_err(Error::PlatformError)
    }

    /// Listen for route changes.
    pub async fn change_listener(&self) -> Result<mpsc::UnboundedReceiver<CallbackMessage>, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::NewChangeListener(response_tx))
            .map_err(|_| Error::RouteManagerDown)?;
        response_rx.await.map_err(|_| Error::ManagerChannelDown)
    }

    /// Get a route for the given destination.
    pub async fn get_destination_route(
        &self,
        destination: IpAddr,
        mark: Option<Fwmark>,
    ) -> Result<Option<Route>, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::GetDestinationRoute(
                destination,
                mark,
                response_tx,
            ))
            .map_err(|_| Error::RouteManagerDown)?;
        response_rx
            .await
            .map_err(|_| Error::ManagerChannelDown)?
            .map_err(Error::PlatformError)
    }

    /// Get MTU for the route to the given IP.
    pub async fn get_mtu_for_route(&self, ip: IpAddr) -> Result<u16, Error> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(RouteManagerCommand::GetMtuForRoute(ip, response_tx))
            .map_err(|_| Error::RouteManagerDown)?;
        response_rx
            .await
            .map_err(|_| Error::ManagerChannelDown)?
            .map_err(Error::PlatformError)
    }
}
