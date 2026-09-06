// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

mod any_tunnel_handle;
mod gateway_selector;
mod independence;
pub mod mixnet;
mod tombstone;
pub mod transports;
pub mod wireguard;

pub use gateway_selector::{SelectedGateways, select_gateway_pair};
use nym_gateway_directory::{BlacklistedGateways, GatewayCacheHandle};
use nym_vpn_lib_types::GatewayIndependence;
use nym_vpn_store::keys::wireguard::WireguardKeysDb;
use tokio_util::sync::CancellationToken;

use crate::{GatewayDirectoryError, MixnetError, tunnel_state_machine::TunnelSettings};
pub use any_tunnel_handle::AnyTunnelHandle;
pub use tombstone::Tombstone;

pub async fn select_gateways(
    gateway_cache_handle: GatewayCacheHandle,
    blacklisted_entry_gateways: &BlacklistedGateways,
    tunnel_settings: &TunnelSettings,
    independence_criteria: GatewayIndependence,
    wg_keys_db: WireguardKeysDb,
    cancel_token: CancellationToken,
) -> Result<SelectedGateways> {
    let select_gateways_fut = gateway_selector::select_gateways(
        gateway_cache_handle,
        blacklisted_entry_gateways,
        tunnel_settings,
        independence_criteria,
        wg_keys_db,
    );

    cancel_token
        .run_until_cancelled(select_gateways_fut)
        .await
        .ok_or(Error::Cancelled)?
        .map_err(|err| Error::SelectGateways(Box::new(err)))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to select gateways")]
    SelectGateways(#[source] Box<GatewayDirectoryError>),

    #[error("mixnet tunnel has failed")]
    MixnetClient(#[from] MixnetError),

    #[error("{} has no ip addresses announced", gateway_id)]
    NoIpAddressAnnounced { gateway_id: String },

    #[error("bandwidth controller error")]
    BandwidthController(#[from] crate::bandwidth_controller::Error),

    #[error("registration client error")]
    RegistrationClient(#[source] Box<nym_registration_client::RegistrationClientError>),

    #[error("WireGuard error")]
    Wireguard(#[from] nym_wg_gotatun::Error),

    #[error("failed to dup tunnel file descriptor")]
    DupFd(#[source] std::io::Error),

    #[error("transport error")]
    Transport(#[from] transports::TransportError),

    #[error("connection cancelled")]
    Cancelled,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
