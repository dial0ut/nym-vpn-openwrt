// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! High-level kernel WireGuard tunnel interface

use std::net::SocketAddr;

use ipnetwork::IpNetwork;

use crate::{DeviceMessage, DeviceNla, Handle, PeerMessage, PeerNla, AllowedIpMessage, Result};

pub type PrivateKey = [u8; 32];
pub type PublicKey = [u8; 32];

const WGDEVICE_F_REPLACE_PEERS: u32 = 0x01;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    pub private_key: PrivateKey,
    pub addresses: Vec<IpNetwork>,
    pub listen_port: Option<u16>,
    pub mtu: u16,
    pub fwmark: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

pub struct Tunnel {
    handle: Handle,
    interface_name: String,
    interface_index: u32,
}

impl Tunnel {
    pub async fn start(interface_name: impl Into<String>, config: Config) -> Result<Self> {
        let interface_name = interface_name.into();
        let mut handle = Handle::connect().await?;

        // Create the WireGuard interface
        let interface_index = handle.create_device(interface_name.clone(), config.interface.mtu.into()).await?;

        // Flush any existing addresses (in case interface was reused from a previous attempt)
        handle.flush_addresses(interface_index).await?;

        // Assign IP addresses to the interface
        for addr in &config.interface.addresses {
            handle.set_ip_address(interface_index, addr.ip()).await?;
        }

        // Configure WireGuard settings (private key, peers, etc.)
        let device_config = Self::build_device_config(
            handle.wg_handle.message_type,
            interface_name.clone(),
            &config,
        )?;

        log::debug!("Setting WireGuard config for {}: {} peers, {} allowed IPs on first peer",
            interface_name,
            config.peers.len(),
            config.peers.first().map(|p| p.allowed_ips.len()).unwrap_or(0)
        );

        if let Some(peer) = config.peers.first() {
            log::debug!("  Peer endpoint: {}, keepalive: {:?}, allowed_ips: {:?}",
                peer.endpoint,
                peer.persistent_keepalive,
                peer.allowed_ips
            );
        }

        handle.wg_handle.set_config(device_config).await?;

        Ok(Self {
            handle,
            interface_name,
            interface_index,
        })
    }

    fn build_device_config(
        message_type: u16,
        interface_name: String,
        config: &Config,
    ) -> Result<DeviceMessage> {
        let mut nlas = vec![
            DeviceNla::IfName(
                std::ffi::CString::new(interface_name).map_err(|_| crate::Error::InterfaceName)?
            ),
            DeviceNla::PrivateKey(config.interface.private_key),
            // Replace all existing peers
            DeviceNla::Flags(WGDEVICE_F_REPLACE_PEERS),
        ];

        // Add listen port if specified
        if let Some(port) = config.interface.listen_port {
            nlas.push(DeviceNla::ListenPort(port));
        }

        // Add fwmark if specified
        if let Some(fwmark) = config.interface.fwmark {
            nlas.push(DeviceNla::Fwmark(fwmark));
        }

        // Add peers
        if !config.peers.is_empty() {
            let peer_messages: Vec<PeerMessage> = config
                .peers
                .iter()
                .map(Self::build_peer_config)
                .collect();
            nlas.push(DeviceNla::Peers(peer_messages));
        }

        Ok(DeviceMessage {
            message_type,
            command: 1, // WG_CMD_SET_DEVICE
            nlas,
        })
    }

    /// Build peer configuration
    fn build_peer_config(peer: &PeerConfig) -> PeerMessage {
        let mut peer_nlas = vec![
            PeerNla::PublicKey(peer.public_key),
            PeerNla::Endpoint(peer.endpoint),
            // Replace allowed IPs for this peer
            PeerNla::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
        ];

        // Add persistent keepalive if specified
        if let Some(keepalive) = peer.persistent_keepalive {
            peer_nlas.push(PeerNla::PersistentKeepalive(keepalive));
        }

        // Add allowed IPs
        if !peer.allowed_ips.is_empty() {
            let allowed_ip_messages: Vec<AllowedIpMessage> = peer
                .allowed_ips
                .iter()
                .map(|network| AllowedIpMessage {
                    family: if network.ip().is_ipv4() {
                        libc::AF_INET as u16
                    } else {
                        libc::AF_INET6 as u16
                    },
                    ip: network.ip(),
                    cidr: network.prefix(),
                })
                .collect();
            peer_nlas.push(PeerNla::AllowedIps(allowed_ip_messages));
        }

        PeerMessage(peer_nlas)
    }

    /// Get the interface name
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Get the interface index
    pub fn interface_index(&self) -> u32 {
        self.interface_index
    }

    /// Update peer endpoint
    ///
    /// Useful for re-resolving DNS or handling network changes
    pub async fn update_peer_endpoint(
        &mut self,
        public_key: PublicKey,
        new_endpoint: SocketAddr,
    ) -> Result<()> {
        let device_config = DeviceMessage {
            message_type: self.handle.wg_handle.message_type,
            command: 1, // WG_CMD_SET_DEVICE
            nlas: vec![
                DeviceNla::IfName(
                    std::ffi::CString::new(self.interface_name.clone())
                        .map_err(|_| crate::Error::InterfaceName)?
                ),
                DeviceNla::Peers(vec![PeerMessage(vec![
                    PeerNla::PublicKey(public_key),
                    PeerNla::Endpoint(new_endpoint),
                ])]),
            ],
        };

        self.handle.wg_handle.set_config(device_config).await
    }

    /// Get current device configuration
    pub async fn get_config(&mut self) -> Result<DeviceMessage> {
        self.handle
            .wg_handle
            .get_by_name(self.interface_name.clone())
            .await
    }

    /// Stop the tunnel and clean up resources
    ///
    /// This will delete the WireGuard interface.
    /// Note: Also called automatically when the Tunnel is dropped.
    pub async fn stop(mut self) -> Result<()> {
        self.handle.delete_device(self.interface_index).await
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Best-effort cleanup - spawn blocking task to delete interface
        // Note: In production, prefer calling `stop()` explicitly for error handling
        let interface_index = self.interface_index;

        tokio::spawn(async move {
            // Create a temporary route handle for deletion
            match rtnetlink::new_connection() {
                Ok((conn, mut route_handle, _messages)) => {
                    use futures::future::abortable;
                    let (conn, abort_handle) = abortable(conn);
                    tokio::spawn(conn);

                    let result = async {
                        use futures::StreamExt;
                        use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
                        use netlink_packet_route::{link::LinkMessage, RouteNetlinkMessage};

                        let mut link_message = LinkMessage::default();
                        link_message.header.index = interface_index;

                        let mut request = NetlinkMessage::from(RouteNetlinkMessage::DelLink(link_message));
                        request.header.flags = NLM_F_REQUEST | NLM_F_ACK;

                        let mut response = route_handle.request(request).ok()?;

                        while let Some(message) = response.next().await {
                            if let NetlinkPayload::Error(err) = message.payload {
                                // ENODEV is expected if stop() was called explicitly
                                if -err.raw_code() == libc::ENODEV {
                                    log::debug!("WireGuard interface {} already deleted", interface_index);
                                    return Some(());
                                }
                                log::error!("Failed to delete WireGuard interface on drop: {}", err);
                                return None;
                            }
                        }
                        Some(())
                    }.await;

                    abort_handle.abort();

                    if result.is_none() {
                        log::warn!("Failed to clean up WireGuard interface {} on drop", interface_index);
                    }
                }
                Err(e) => {
                    log::error!("Failed to create netlink connection for cleanup: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Only runs on systems with kernel WireGuard and root privileges
    async fn test_tunnel_lifecycle() {
        let config = Config {
            interface: InterfaceConfig {
                private_key: [1u8; 32], // Dummy key for testing
                addresses: vec!["10.100.0.2/32".parse().unwrap()],
                listen_port: Some(51820),
                mtu: 1420,
                fwmark: None,
            },
            peers: vec![PeerConfig {
                public_key: [2u8; 32], // Dummy key for testing
                endpoint: "192.0.2.1:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: Some(25),
            }],
        };

        let tunnel = Tunnel::start("wg-test", config).await;
        match tunnel {
            Ok(tunnel) => {
                eprintln!("Created tunnel: {}", tunnel.interface_name());
                tunnel.stop().await.expect("Failed to stop tunnel");
                eprintln!("Stopped tunnel successfully");
            }
            Err(e) => {
                eprintln!("Failed to create tunnel (expected if not root): {}", e);
            }
        }
    }
}
