// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;

use crate::tunnel_state_machine::TunnelMetadata;
use nym_registration_common::WireguardConfiguration;

use nym_vpn_lib_types::BridgeAddress;

pub mod connected_tunnel;
pub mod fd;
pub mod two_hop_config;

#[derive(Debug)]
pub struct ConnectionData {
    pub entry_bridge_addr: Option<BridgeAddress>,
    pub entry: WireguardConfiguration,
    pub exit: WireguardConfiguration,
}

impl ConnectionData {
    /// Returns effective entry endpoint set to bridge listen endpoint when entry bridge address is available. Otherwise, returns the wireguard entry endpoint.
    pub fn effective_entry_endpoint(&self) -> SocketAddr {
        self.entry_bridge_addr
            .as_ref()
            .map(|addr| addr.listen_addr)
            .unwrap_or(self.entry.endpoint)
    }

    /// Returns effective *remote* entry endpoint set to bridge remote endpoint when entry bridge address is available. Otherwise, returns the wireguard entry endpoint.
    pub fn effective_remote_entry_endpoint(&self) -> SocketAddr {
        self.entry_bridge_addr
            .as_ref()
            .map(|addr| addr.remote_addr)
            .unwrap_or(self.entry.endpoint)
    }
}

pub enum MetadataEvent {
    MetadataProxy(SocketAddr),
    TunnelMetadata(TunnelMetadata),
}

impl From<MetadataEvent> for nym_wg_metadata_client::TunUpSendData {
    fn from(event: MetadataEvent) -> Self {
        match event {
            MetadataEvent::MetadataProxy(proxy_addr) => {
                nym_wg_metadata_client::TunUpSendData::TcpProxy(proxy_addr)
            }
            MetadataEvent::TunnelMetadata(metadata) => {
                nym_wg_metadata_client::TunUpSendData::InterfaceName(metadata.interface)
            }
        }
    }
}

pub type MetadataSender = tokio::sync::oneshot::Sender<MetadataEvent>;
pub type MetadataReceiver = tokio::sync::oneshot::Receiver<MetadataEvent>;
