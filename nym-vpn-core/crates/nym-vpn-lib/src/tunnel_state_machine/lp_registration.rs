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

use nym_credentials_interface::TicketType;
use nym_lp::peer::{DHKeyPair, LpRemotePeer};
use nym_registration_client::{
    LpClientError, LpDvpnRegistrationClient, LpGatewayClient, NestedLpDvpnRegistrationClient,
    NestedLpSession, RegistrationClientBuilderConfig, RegistrationClientError,
    RegistrationNymNode, RegistrationResult,
};
use nym_registration_common::NymNodeLPInformation;
use rand010::{SeedableRng, rngs::SysRng};
use tokio::net::TcpStream;

/// Built before any gateway is contacted, so its errors are local ones.
pub(crate) struct ParallelLpRegistration {
    config: RegistrationClientBuilderConfig,
}

impl ParallelLpRegistration {
    pub(crate) fn new(config: RegistrationClientBuilderConfig) -> Self {
        Self { config }
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
        let bandwidth_controller = &self.config.bandwidth_request_sender;
        let spend_time_skew = self.config.spend_time_skew;

        let entry_lp_keypair = lp_keypair()?;
        let exit_lp_keypair = lp_keypair()?;
        // Two sessions to the entry at once, so each gets its own key.
        let forwarding_lp_keypair = lp_keypair()?;

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
            let mut forwarding_client = LpGatewayClient::<TcpStream>::new(
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
            nested_session
                .perform_handshake(&mut forwarding_client)
                .await
                .map_err(exit_error)?;
            let mut rng = rand010::rngs::StdRng::try_from_rng(&mut SysRng)?;
            let exit_gateway_data =
                NestedLpDvpnRegistrationClient::new(&mut nested_session, &mut forwarding_client)
                    .register(
                        &mut rng,
                        &exit.keys,
                        &exit.node.identity,
                        bandwidth_controller,
                        spend_time_skew,
                        TicketType::V1WireguardExit,
                    )
                    .await
                    .map_err(exit_error)?;
            tracing::info!("Exit gateway registration completed via forwarding");
            Ok::<_, RegistrationClientError>(exit_gateway_data)
        };

        let entry_leg = async {
            let mut entry_client = LpGatewayClient::<TcpStream>::new(
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

            let mut rng = rand010::rngs::StdRng::try_from_rng(&mut SysRng)?;
            let entry_gateway_data = LpDvpnRegistrationClient::new(&mut entry_client)
                .register(
                    &mut rng,
                    &entry.keys,
                    &entry.node.identity,
                    bandwidth_controller,
                    spend_time_skew,
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

fn lp_keypair() -> Result<Arc<DHKeyPair>, RegistrationClientError> {
    DHKeyPair::new(&mut rand010::rng())
        .map(Arc::new)
        .map_err(|_| RegistrationClientError::KeyGenerationFailure)
}
