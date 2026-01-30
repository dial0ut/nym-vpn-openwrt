// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Kernel WireGuard implementation using netlink
//!
//! This crate provides a native Linux kernel WireGuard interface using netlink protocol,
//! eliminating the need for Go's wireguard-go FFI and fixing musl libc compatibility issues.
//!
//! Based on Mullvad VPN's implementation:
//! https://github.com/mullvad/mullvadvpn-app/tree/main/talpid-wireguard/src/wireguard_kernel

use netlink_packet_core::DecodeError;
use thiserror::Error;

pub mod amnezia;
mod nl_message;
mod wg_message;
pub mod tunnel;

pub use amnezia::AmneziaConfig;
pub use nl_message::{ControlNla, NetlinkControlMessage};
pub use wg_message::{AllowedIpMessage, DeviceMessage, DeviceNla, PeerMessage, PeerNla};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to decode netlink message")]
    Decode(#[source] DecodeError),

    #[error("Failed to execute netlink control request")]
    NetlinkControlMessage(#[source] nl_message::Error),

    #[error("Failed to open netlink socket")]
    NetlinkSocket(#[source] std::io::Error),

    #[error("Failed to send netlink control request")]
    NetlinkRequest(#[source] netlink_proto::Error<NetlinkControlMessage>),

    #[error("WireGuard netlink interface unavailable. Is the kernel module loaded?")]
    WireguardNetlinkInterfaceUnavailable,

    #[error("Unknown WireGuard command: {0}")]
    UnknownWireguardCommand(u8),

    #[error("Received no response")]
    NoResponse,

    #[error("Received truncated message")]
    Truncated,

    #[error("WireGuard device does not exist")]
    NoDevice,

    #[error("Failed to get config: {0}")]
    WgGetConf(netlink_packet_core::ErrorMessage),

    #[error("Failed to apply config: {0}")]
    WgSetConf(netlink_packet_core::ErrorMessage),

    #[error("Interface name too long")]
    InterfaceName,

    #[error("Send request error")]
    SendRequest(#[source] netlink_proto::Error<DeviceMessage>),

    #[error("Create device error")]
    NetlinkCreateDevice(#[source] rtnetlink::Error),

    #[error("Add IP to device error")]
    NetlinkSetIp(#[source] rtnetlink::Error),

    #[error("Failed to delete device")]
    DeleteDevice(#[source] rtnetlink::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Detected WireGuard kernel backend
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgBackend {
    /// Standard WireGuard kernel module (kmod-wireguard)
    Standard,
    /// Amnezia-WireGuard kernel module with obfuscation support (kmod-amneziawg)
    Amnezia,
}

impl WgBackend {
    /// Returns true if this backend supports Amnezia obfuscation
    pub fn supports_amnezia(&self) -> bool {
        matches!(self, WgBackend::Amnezia)
    }
}

/// Check if kernel WireGuard is available on this system
pub async fn is_available() -> bool {
    Handle::connect().await.is_ok()
}

/// Main handle for kernel WireGuard operations
#[derive(Debug)]
pub struct Handle {
    pub wg_handle: WireguardConnection,
    route_handle: rtnetlink::Handle,
    wg_abort_handle: futures::future::AbortHandle,
    route_abort_handle: futures::future::AbortHandle,
}

/// Result of WireGuard family detection
struct WgFamilyDetection {
    message_type: u16,
    backend: WgBackend,
}

impl Handle {
    /// Connect to netlink and detect WireGuard kernel module
    ///
    /// Automatically detects whether Amnezia-WireGuard or standard WireGuard
    /// kernel module is available, preferring Amnezia when present.
    pub async fn connect() -> Result<Self> {
        use futures::future::abortable;
        use netlink_proto::sys::protocols::NETLINK_GENERIC;

        let detection = Self::detect_wireguard_family().await?;
        let (conn, wireguard_connection, _messages) =
            netlink_proto::new_connection(NETLINK_GENERIC).map_err(Error::NetlinkSocket)?;
        let wg_handle = WireguardConnection {
            message_type: detection.message_type,
            connection: wireguard_connection,
            backend: detection.backend,
        };
        let (abortable_connection, wg_abort_handle) = abortable(conn);
        tokio::spawn(abortable_connection);

        let (conn, route_handle, _messages) =
            rtnetlink::new_connection().map_err(Error::NetlinkSocket)?;
        let (abortable_connection, route_abort_handle) = abortable(conn);
        tokio::spawn(abortable_connection);

        Ok(Self {
            wg_handle,
            route_handle,
            wg_abort_handle,
            route_abort_handle,
        })
    }

    /// Returns the detected WireGuard backend type
    pub fn backend(&self) -> WgBackend {
        self.wg_handle.backend
    }

    /// Detect available WireGuard kernel module
    ///
    /// Tries Amnezia-WireGuard first (available on OpenWrt 23.05+), falls back to
    /// standard WireGuard if not available.
    async fn detect_wireguard_family() -> Result<WgFamilyDetection> {
        use futures::future::abortable;
        use futures::StreamExt;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
        use netlink_proto::sys::{protocols::NETLINK_GENERIC, SocketAddr};

        let (conn, handle, _messages) =
            netlink_proto::new_connection(NETLINK_GENERIC).map_err(Error::NetlinkSocket)?;
        let (conn, abort_handle) = abortable(conn);
        tokio::spawn(conn);

        let result = async {
            // Helper to try resolving a family ID
            async fn try_get_family_id(
                handle: &netlink_proto::ConnectionHandle<NetlinkControlMessage>,
                family_name: &std::ffi::CStr,
            ) -> Option<u16> {
                let mut message: NetlinkMessage<NetlinkControlMessage> =
                    NetlinkControlMessage::get_netlink_family_id(Box::from(family_name))
                        .ok()?
                        .into();
                message.header.flags = NLM_F_REQUEST | NLM_F_ACK;

                let mut req = handle.request(message, SocketAddr::new(0, 0)).ok()?;
                let response = req.next().await?;

                if let NetlinkPayload::InnerMessage(msg) = response.payload {
                    for nla in msg.nlas.into_iter() {
                        if let ControlNla::FamilyId(id) = nla {
                            return Some(id);
                        }
                    }
                }
                None
            }

            // Try Amnezia-WireGuard first (available on OpenWrt 23.05+)
            if let Some(id) = try_get_family_id(&handle, c"amneziawg").await {
                log::info!("Detected Amnezia-WireGuard kernel module (family_id={})", id);
                return Ok(WgFamilyDetection {
                    message_type: id,
                    backend: WgBackend::Amnezia,
                });
            }

            // Fall back to standard WireGuard
            if let Some(id) = try_get_family_id(&handle, c"wireguard").await {
                log::info!("Detected standard WireGuard kernel module (family_id={})", id);
                return Ok(WgFamilyDetection {
                    message_type: id,
                    backend: WgBackend::Standard,
                });
            }

            Err(Error::WireguardNetlinkInterfaceUnavailable)
        }
        .await;

        abort_handle.abort();
        result
    }

    /// Create a WireGuard device with the given name and MTU
    pub async fn create_device(&mut self, name: String, mtu: u32) -> Result<u32> {
        use netlink_packet_core::{
            NLM_F_ACK, NLM_F_CREATE, NLM_F_MATCH, NLM_F_REPLACE,
            NLM_F_REQUEST,
        };
        use netlink_packet_route::link::InfoKind;
        use rtnetlink::{LinkMessageBuilder, LinkUnspec};

        // Choose the correct link kind based on detected backend
        let info_kind = match self.wg_handle.backend {
            WgBackend::Amnezia => {
                log::debug!("Creating device '{}' with link kind 'amneziawg'", name);
                InfoKind::Other("amneziawg".to_string())
            }
            WgBackend::Standard => {
                log::debug!("Creating device '{}' with link kind 'wireguard'", name);
                InfoKind::Wireguard
            }
        };

        // Create the WireGuard link using rtnetlink with the appropriate kind
        let message = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(info_kind)
            .name(name.clone())
            .up() // Set link to UP (IFF_UP)
            .mtu(mtu)
            .build();

        let reply = self
            .route_handle
            .link()
            .add(message)
            .set_flags(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE | NLM_F_MATCH)
            .execute()
            .await;

        // EEXIST is OK - device already exists
        if let Err(rtnetlink::Error::NetlinkError(err)) = reply {
            if -err.raw_code() != libc::EEXIST {
                return Err(Error::NetlinkCreateDevice(rtnetlink::Error::NetlinkError(
                    err,
                )));
            }
        }

        // Fetch interface index of the device
        self.wg_handle
            .get_by_name(name)
            .await?
            .nlas
            .into_iter()
            .find_map(|nla| match nla {
                DeviceNla::IfIndex(index) => Some(index),
                _ => None,
            })
            .ok_or(Error::NoDevice)
    }

    /// Set IP address on the WireGuard interface
    pub async fn set_ip_address(&mut self, index: u32, addr: std::net::IpAddr) -> Result<()> {
        use futures::StreamExt;
        use netlink_packet_core::{
            NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
        };
        use netlink_packet_route::RouteNetlinkMessage;
        use rtnetlink::AddressMessageBuilder;

        let address_message = match addr {
            std::net::IpAddr::V4(ipv4_addr) => AddressMessageBuilder::<std::net::Ipv4Addr>::new()
                .address(ipv4_addr, 32)
                .index(index)
                .build(),
            std::net::IpAddr::V6(ipv6_addr) => AddressMessageBuilder::<std::net::Ipv6Addr>::new()
                .address(ipv6_addr, 128)
                .index(index)
                .build(),
        };

        let mut request =
            NetlinkMessage::from(RouteNetlinkMessage::NewAddress(address_message));
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

        let mut response = self
            .route_handle
            .request(request)
            .map_err(Error::NetlinkSetIp)?;

        while let Some(response_message) = response.next().await {
            if let NetlinkPayload::Error(err) = response_message.payload {
                log::error!(
                    "Netlink error adding IP {} to interface index {}: code={:?} ({:?})",
                    addr,
                    index,
                    err.code,
                    err
                );
                return Err(Error::NetlinkSetIp(rtnetlink::Error::NetlinkError(err)));
            }
        }

        Ok(())
    }

    /// Remove all IP addresses from an interface
    ///
    /// This is used to clean up stale addresses when reusing an existing interface,
    /// preventing IP address accumulation across reconnection attempts.
    pub async fn flush_addresses(&mut self, index: u32) -> Result<()> {
        use futures::TryStreamExt;

        // Get all addresses on this interface
        let addresses: Vec<_> = self
            .route_handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute()
            .try_collect()
            .await
            .map_err(Error::NetlinkSetIp)?;

        log::debug!("Flushing {} addresses from interface index {}", addresses.len(), index);

        // Delete each address
        for addr_msg in addresses {
            if let Err(e) = self
                .route_handle
                .address()
                .del(addr_msg)
                .execute()
                .await
            {
                log::warn!("Failed to delete address during flush: {}", e);
                // Continue flushing other addresses
            }
        }

        Ok(())
    }

    /// Delete a WireGuard device by interface index
    pub async fn delete_device(&mut self, index: u32) -> Result<()> {
        use futures::StreamExt;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
        use netlink_packet_route::{link::LinkMessage, RouteNetlinkMessage};

        let mut link_message = LinkMessage::default();
        link_message.header.index = index;

        let mut request = NetlinkMessage::from(RouteNetlinkMessage::DelLink(link_message));
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self
            .route_handle
            .request(request)
            .map_err(Error::DeleteDevice)?;

        while let Some(message) = response.next().await {
            if let NetlinkPayload::Error(err) = message.payload {
                return Err(Error::DeleteDevice(rtnetlink::Error::NetlinkError(err)));
            }
        }

        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.wg_abort_handle.abort();
        self.route_abort_handle.abort();
    }
}

/// WireGuard netlink connection
#[derive(Debug, Clone)]
pub struct WireguardConnection {
    connection: netlink_proto::ConnectionHandle<DeviceMessage>,
    message_type: u16,
    /// The detected backend type (standard WireGuard or Amnezia)
    pub backend: WgBackend,
}

impl WireguardConnection {
    /// Get WireGuard device by interface name
    pub async fn get_by_name(&mut self, name: String) -> Result<DeviceMessage> {
        self.fetch_device(DeviceMessage::get_by_name(self.message_type, name)?)
            .await
    }

    /// Get WireGuard device by interface index
    pub async fn get_by_index(&mut self, index: u32) -> Result<DeviceMessage> {
        self.fetch_device(DeviceMessage::get_by_index(self.message_type, index))
            .await
    }

    async fn fetch_device(&mut self, device_message: DeviceMessage) -> Result<DeviceMessage> {
        use futures::StreamExt;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
        use netlink_proto::sys::SocketAddr;

        let mut netlink_message = NetlinkMessage::new(
            netlink_packet_core::NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(device_message),
        );
        netlink_message.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;

        let mut response = self
            .connection
            .request(netlink_message, SocketAddr::new(0, 0))
            .map_err(Error::SendRequest)?;

        match response.next().await {
            Some(received_message) => match received_message.payload {
                NetlinkPayload::InnerMessage(inner) => Ok(inner),
                NetlinkPayload::Error(err) => {
                    if err.raw_code() == -libc::ENODEV {
                        Err(Error::NoDevice)
                    } else {
                        Err(Error::WgGetConf(err))
                    }
                }
                _ => {
                    log::error!("Received unexpected response");
                    Err(Error::NoResponse)
                }
            },
            None => Err(Error::NoResponse),
        }
    }

    /// Configure WireGuard device (set private key, peers, etc.)
    pub async fn set_config(&mut self, device_message: DeviceMessage) -> Result<()> {
        use futures::StreamExt;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
        use netlink_proto::sys::SocketAddr;

        log::debug!("Sending WireGuard config: command={}, nlas={:?}",
            device_message.command,
            device_message.nlas.iter().map(|nla| format!("{:?}", nla)).collect::<Vec<_>>()
        );

        let mut netlink_message = NetlinkMessage::new(
            netlink_packet_core::NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(device_message),
        );
        netlink_message.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut request = self
            .connection
            .request(netlink_message, SocketAddr::new(0, 0))
            .map_err(Error::SendRequest)?;

        while let Some(response) = request.next().await {
            if let NetlinkPayload::Error(err) = response.payload {
                log::error!("WireGuard set_config netlink error: {:?}", err);
                return Err(Error::WgSetConf(err));
            }
        }
        log::debug!("WireGuard config set successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Only runs on systems with kernel WireGuard
    async fn test_wireguard_detection() {
        let available = is_available().await;
        eprintln!("Kernel WireGuard available: {}", available);
    }

    #[tokio::test]
    #[ignore]
    async fn test_connect() {
        let handle = Handle::connect().await;
        match handle {
            Ok(_) => eprintln!("Successfully connected to kernel WireGuard"),
            Err(e) => eprintln!("Failed to connect: {}", e),
        }
    }
}
