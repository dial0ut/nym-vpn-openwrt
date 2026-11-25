// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! The nym bandwidth controller of one tunnel session.
//!
//! The registration clients no longer open the credential storage
//! themselves: they are handed a request sender to a running controller.
//! One is started per session over the account's credential storage and
//! stops with the session, which closes the storage again, so an account
//! reset between sessions never meets an open database.
//!
//! The account controller stays the one that acquires ticketbooks. This
//! controller only spends them, so it gets no credential fetcher and
//! restocks nothing by itself.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use nym_bandwidth_controller::{
    BandwidthController, config::BandwidthControllerConfig,
    requests::BandwidthControllerRequestSender,
};
use nym_bandwidth_fetcher::NyxdGlobalDataFetcher;
use nym_credential_storage::{ephemeral_storage::EphemeralCredentialStorage, storage::Storage};
use nym_registration_client::RegistrationClientError;
use nym_sdk::{NymNetworkDetails, mixnet::StoragePaths};
use nym_validator_client::{
    QueryHttpRpcNyxdClient,
    nyxd::{Config as NyxdClientConfig, NyxdClient},
};
use tokio_util::sync::CancellationToken;

/// Starts the session's controller and returns the sender to it. The
/// controller runs until `session_token` is cancelled.
pub(crate) async fn spawn(
    data_path: Option<&Path>,
    network: &NymNetworkDetails,
    session_token: &CancellationToken,
) -> Result<BandwidthControllerRequestSender, RegistrationClientError> {
    match data_path {
        Some(data_path) => {
            let storage = StoragePaths::new_from_dir(data_path)
                .map_err(|err| RegistrationClientError::StorageInitialization(Box::new(err)))?
                .persistent_credential_storage()
                .await
                .map_err(|err| RegistrationClientError::StorageInitialization(Box::new(err)))?;
            Ok(start(storage, network, session_token))
        }
        None => Ok(start(
            EphemeralCredentialStorage::default(),
            network,
            session_token,
        )),
    }
}

/// Where the registration client keeps the mixnet identity. Without a data
/// directory the session is throwaway, so a temporary one will do.
pub(crate) fn registration_data_path(data_path: Option<&Path>) -> PathBuf {
    data_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::temp_dir().join("nym-vpn-ephemeral"))
}

fn start<St>(
    storage: St,
    network: &NymNetworkDetails,
    session_token: &CancellationToken,
) -> BandwidthControllerRequestSender
where
    St: Storage + Send + Sync + 'static,
    <St as Storage>::StorageError: Send + Sync + 'static,
{
    let config = BandwidthControllerConfig {
        managed_ticket_types: Vec::new(),
        ..Default::default()
    };
    let mut controller = BandwidthController::new(storage).with_config(config);

    // Signing material missing from the storage is fetched from the chain,
    // as the controller did before it took fetchers.
    match nyxd_client(network) {
        Ok(client) => {
            controller = controller
                .with_credential_public_data_fetcher(NyxdGlobalDataFetcher::new(Arc::new(client)));
        }
        Err(err) => {
            tracing::warn!("No nyxd client for the bandwidth controller: {err}");
        }
    }

    let sender = controller.get_request_sender();
    tokio::spawn(controller.run(session_token.child_token().into()));
    sender
}

fn nyxd_client(network: &NymNetworkDetails) -> Result<QueryHttpRpcNyxdClient, String> {
    let config =
        NyxdClientConfig::try_from_nym_network_details(network).map_err(|err| err.to_string())?;
    let nyxd_url = network
        .endpoints
        .first()
        .map(|endpoint| endpoint.nyxd_url())
        .ok_or_else(|| "no nyxd endpoint in the network details".to_owned())?;

    NyxdClient::connect(config, nyxd_url.as_str()).map_err(|err| err.to_string())
}
