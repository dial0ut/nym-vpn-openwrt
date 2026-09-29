// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Lewes Protocol registration with both gateways at once.
//!
//! Upstream's `LpBasedRegistrationClient` (nym-registration-client,
//! `clients/lp.rs`) runs one outer session to the entry gateway: it registers
//! with the exit through it, then with the entry on the same session. Every
//! step waits on the one before, and the entry legs cost about two entry
//! round trips after the exit is done. Here the entry registration gets its
//! own session and runs while the exit registration is forwarded, so the
//! connect waits for the longer leg only. The protocol exchange per gateway
//! is upstream's, unchanged.

use std::sync::Arc;

use nym_bandwidth_controller::{BandwidthController, BandwidthTicketProvider};
use nym_credential_storage::ephemeral_storage::EphemeralCredentialStorage;
use nym_credentials_interface::TicketType;
use nym_lp::peer::{DHKeyPair, LpRemotePeer};
use nym_registration_client::{
    LpClientError, LpRegistrationClient, NestedLpSession, RegistrationClientBuilderConfig,
    RegistrationClientError, RegistrationNymNode, RegistrationResult,
};
use nym_registration_common::NymNodeLPInformation;
use nym_sdk::NymNetworkDetails;
use nym_validator_client::{
    QueryHttpRpcNyxdClient,
    nyxd::{Config as NyxdClientConfig, NyxdClient},
};
use rand09::SeedableRng;
use tokio::net::TcpStream;

/// Built before any gateway is contacted, so its errors are local ones.
pub(crate) struct ParallelLpRegistration {
    config: RegistrationClientBuilderConfig,
    bandwidth_controller: Box<dyn BandwidthTicketProvider>,
}

impl ParallelLpRegistration {
    pub(crate) async fn new(
        config: RegistrationClientBuilderConfig,
    ) -> Result<Self, RegistrationClientError> {
        let nyxd_client = nyxd_client(&config.network_env)?;
        let bandwidth_controller: Box<dyn BandwidthTicketProvider> =
            match config.setup_credential_storage().await? {
                Some(storage) => Box::new(BandwidthController::new(storage, nyxd_client)),
                None => Box::new(BandwidthController::new(
                    EphemeralCredentialStorage::default(),
                    nyxd_client,
                )),
            };

        Ok(Self {
            config,
            bandwidth_controller,
        })
    }

    pub(crate) async fn register(self) -> Result<RegistrationResult, RegistrationClientError> {
        let timeout = self.config.lp_registration_config.exchange_timeout;
        let cancel_token = self.config.cancel_token.clone();
        match tokio::time::timeout(
            timeout,
            cancel_token.run_until_cancelled(Box::pin(self.register_wg())),
        )
        .await
        {
            Ok(Some(result)) => {
                result.inspect_err(|e| tracing::error!("LP registration failed : {e}"))
            }
            Ok(None) => Err(RegistrationClientError::Cancelled),
            Err(elapsed) => {
                tracing::warn!("timed out while attempting to complete LP registration");
                Err(RegistrationClientError::Timeout(elapsed))
            }
        }
    }

    async fn register_wg(self) -> Result<RegistrationResult, RegistrationClientError> {
        let entry = &self.config.entry_node;
        let exit = &self.config.exit_node;
        let entry_lp = lp_data(entry)?;
        let exit_lp = lp_data(exit)?;
        let lp_config = self.config.lp_registration_config;
        let bandwidth_controller = &*self.bandwidth_controller;

        let entry_lp_keypair = Arc::new(DHKeyPair::new(&mut rand09::rng()));
        let exit_lp_keypair = Arc::new(DHKeyPair::new(&mut rand09::rng()));
        // Two sessions to the entry at once, so each gets its own key.
        let forwarding_lp_keypair = Arc::new(DHKeyPair::new(&mut rand09::rng()));

        let entry_error = |source: LpClientError| RegistrationClientError::EntryGatewayRegisterLp {
            gateway_id: entry.node.identity.to_base58_string(),
            lp_address: entry_lp.address,
            source: Box::new(source),
        };
        let exit_error = |source: LpClientError| RegistrationClientError::ExitGatewayRegisterLp {
            gateway_id: exit.node.identity.to_base58_string(),
            lp_address: exit_lp.address,
            source: Box::new(source),
        };

        let exit_leg = async {
            let mut forwarding_client = LpRegistrationClient::<TcpStream>::new(
                forwarding_lp_keypair,
                remote_peer(entry_lp),
                entry_lp.address,
                entry_lp.ciphersuite,
                entry_lp.lp_protocol_version,
                lp_config,
            );
            forwarding_client
                .perform_handshake()
                .await
                .map_err(entry_error)?;

            let mut nested_session = NestedLpSession::new(
                exit_lp.address,
                exit_lp_keypair.clone(),
                remote_peer(exit_lp),
                exit_lp.ciphersuite,
                exit_lp.lp_protocol_version,
            );
            let mut rng = rand09::rngs::StdRng::from_os_rng();
            let exit_gateway_data = nested_session
                .handshake_and_register_dvpn(
                    &mut forwarding_client,
                    &mut rng,
                    &exit.keys,
                    &exit.node.identity,
                    bandwidth_controller,
                    TicketType::V1WireguardExit,
                )
                .await
                .map_err(exit_error)?;
            tracing::info!("Exit gateway registration completed via forwarding");
            Ok::<_, RegistrationClientError>(exit_gateway_data)
        };

        let entry_leg = async {
            let mut entry_client = LpRegistrationClient::<TcpStream>::new(
                entry_lp_keypair.clone(),
                remote_peer(entry_lp),
                entry_lp.address,
                entry_lp.ciphersuite,
                entry_lp.lp_protocol_version,
                lp_config,
            );
            entry_client
                .perform_handshake()
                .await
                .map_err(entry_error)?;

            let mut rng = rand09::rngs::StdRng::from_os_rng();
            let entry_gateway_data = entry_client
                .register_dvpn(
                    &mut rng,
                    &entry.keys,
                    &entry.node.identity,
                    bandwidth_controller,
                    TicketType::V1WireguardEntry,
                )
                .await
                .map_err(entry_error)?;
            tracing::info!("Entry gateway registration successful");
            Ok::<_, RegistrationClientError>(entry_gateway_data)
        };

        tracing::info!("Registering with entry and exit gateways in parallel");
        let (exit_gateway_data, entry_gateway_data) = tokio::try_join!(exit_leg, entry_leg)?;
        tracing::info!("LP registration successful for both gateways");

        Ok(RegistrationResult::wireguard_lp(
            entry_gateway_data,
            exit_gateway_data,
            entry_lp_keypair,
            exit_lp_keypair,
            self.bandwidth_controller,
        ))
    }
}

fn lp_data(node: &RegistrationNymNode) -> Result<&NymNodeLPInformation, RegistrationClientError> {
    node.node
        .lp_data
        .as_ref()
        .ok_or_else(|| RegistrationClientError::LpRegistrationNotPossible {
            node_id: node.node.identity.to_base58_string(),
        })
}

fn remote_peer(data: &NymNodeLPInformation) -> LpRemotePeer {
    LpRemotePeer::new(data.x25519).with_key_digests(data.expected_kem_key_hashes.clone())
}

/// Same client upstream's builder makes for the bandwidth controller.
fn nyxd_client(
    network: &NymNetworkDetails,
) -> Result<QueryHttpRpcNyxdClient, RegistrationClientError> {
    let config = NyxdClientConfig::try_from_nym_network_details(network)
        .map_err(RegistrationClientError::FailedToCreateNyxdClientConfig)?;
    let nyxd_url = network
        .endpoints
        .first()
        .map(|ep| ep.nyxd_url())
        .ok_or(RegistrationClientError::InvalidNyxdUrl)?;

    NyxdClient::connect(config, nyxd_url.as_str())
        .map_err(RegistrationClientError::FailedToConnectUsingNyxdClient)
}
