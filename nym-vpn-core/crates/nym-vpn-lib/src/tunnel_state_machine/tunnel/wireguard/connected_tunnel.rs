// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{net::IpAddr, sync::Arc};

use ipnetwork::IpNetwork;
use nym_crypto::asymmetric::x25519;
use nym_wg_gotatun::{amnezia::AmneziaConfig, wireguard_go};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;
use tun::AsyncDevice;

use crate::{
    tunnel_state_machine::{
        TunnelConstants,
        tunnel::{
            Error, Result, Tombstone,
            wireguard::{
                ConnectionData,
                two_hop_config::{ENTRY_MTU, EXIT_MTU},
            },
        },
    },
    wg_config::{AllowedIps, WgNodeConfig},
};

pub struct ConnectedTunnel {
    entry_wg_keypair: Arc<x25519::KeyPair>,
    exit_wg_keypair: Arc<x25519::KeyPair>,
    connection_data: ConnectionData,
}

impl ConnectedTunnel {
    pub fn new(
        entry_wg_keypair: Arc<x25519::KeyPair>,
        exit_wg_keypair: Arc<x25519::KeyPair>,
        connection_data: ConnectionData,
    ) -> Self {
        Self {
            entry_wg_keypair,
            exit_wg_keypair,
            connection_data,
        }
    }

    pub fn connection_data(&self) -> &ConnectionData {
        &self.connection_data
    }

    pub fn connection_data_mut(&mut self) -> &mut ConnectionData {
        &mut self.connection_data
    }

    pub fn entry_mtu(&self) -> u16 {
        ENTRY_MTU
    }

    pub fn exit_mtu(&self) -> u16 {
        EXIT_MTU
    }

    pub async fn run(
        self,
        options: TunTunTunnelOptions,
        tunnel_constants: TunnelConstants,
        entry_amnezia: bool,
    ) -> Result<TunnelHandle> {
        let mut wg_entry_config = WgNodeConfig::with_gateway_data(
            self.connection_data.effective_entry_gateway_data(),
            self.entry_wg_keypair.private_key(),
            AllowedIps::Specific(vec![
                IpNetwork::from(self.connection_data.exit.endpoint.ip()),
                IpNetwork::from(tunnel_constants.in_tunnel_bandwidth_metadata_endpoint.ip()),
            ]),
            options.dns.clone(),
            self.entry_mtu(),
            true, // gotatun handles IPv6 fine
            Some(tunnel_constants.fwmark),
        );
        if entry_amnezia {
            wg_entry_config = wg_entry_config.with_amnezia_config(AmneziaConfig::BASE);
        }

        let wg_exit_config = WgNodeConfig::with_gateway_data(
            self.connection_data.exit.clone(),
            self.exit_wg_keypair.private_key(),
            AllowedIps::All,
            options.dns,
            self.exit_mtu(),
            true, // gotatun handles IPv6 fine
            None,
        );

        let entry_tunnel = wireguard_go::Tunnel::start(
            wg_entry_config.into_wireguard_config(),
            options.entry_tun,
        )
        .await
        .map_err(Error::Wireguard)?;

        let exit_tunnel = wireguard_go::Tunnel::start(
            wg_exit_config.into_wireguard_config(),
            options.exit_tun,
        )
        .await
        .map_err(Error::Wireguard)?;

        let shutdown_token = CancellationToken::new();
        let child_shutdown_token = shutdown_token.child_token();

        let event_handler_task = tokio::spawn(async move {
            child_shutdown_token.cancelled().await;
            tracing::debug!("Received tunnel shutdown event. Exiting event loop.");

            entry_tunnel.stop().await;
            exit_tunnel.stop().await;

            Tombstone::default()
        });

        Ok(TunnelHandle {
            shutdown_token,
            event_handler_task,
        })
    }
}

/// TunTun tunnel options — two separate TUN devices for entry and exit.
pub struct TunTunTunnelOptions {
    /// Entry tunnel device.
    pub entry_tun: AsyncDevice,

    /// Exit tunnel device.
    pub exit_tun: AsyncDevice,

    /// In-tunnel DNS addresses
    pub dns: Vec<IpAddr>,
}

pub struct TunnelHandle {
    shutdown_token: CancellationToken,
    event_handler_task: JoinHandle<Tombstone>,
}

impl TunnelHandle {
    /// Close entry and exit WireGuard tunnels and signal mixnet facilities shutdown.
    pub fn cancel(&mut self) {
        self.shutdown_token.cancel();
    }

    /// Wait until the tunnel finished execution.
    ///
    /// Returns a tombstone containing the no longer used tunnel devices.
    pub async fn wait(self) -> Result<Tombstone, JoinError> {
        self.event_handler_task.await
    }
}
