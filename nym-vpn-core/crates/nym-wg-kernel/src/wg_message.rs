// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! WireGuard-specific netlink messages
//!
//! Based on Mullvad's implementation:
//! https://github.com/mullvad/mullvadvpn-app/blob/main/talpid-wireguard/src/wireguard_kernel/wg_message.rs

use byteorder::{ByteOrder, NativeEndian};
use ipnetwork::IpNetwork;
use netlink_packet_core::{
    DecodeError, Emitable, NetlinkDeserializable, NetlinkHeader, NetlinkPayload,
    NetlinkSerializable, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};
use std::{
    ffi::CString,
    io::Write,
    mem,
    net::{IpAddr, SocketAddr},
};

/// WireGuard netlink constants
mod constants {
    #![allow(dead_code)]
    pub const WG_GENL_VERSION: u8 = 1;

    /// Command constants
    pub const WG_CMD_GET_DEVICE: u8 = 0;
    pub const WG_CMD_SET_DEVICE: u8 = 1;

    // wgdevice_flag
    pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

    // wgdevice_attribute
    pub const WGDEVICE_A_UNSPEC: u16 = 0;
    pub const WGDEVICE_A_IFINDEX: u16 = 1;
    pub const WGDEVICE_A_IFNAME: u16 = 2;
    pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
    pub const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
    pub const WGDEVICE_A_FLAGS: u16 = 5;
    pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
    pub const WGDEVICE_A_FWMARK: u16 = 7;
    pub const WGDEVICE_A_PEERS: u16 = 8;

    // wgpeer_flag
    pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
    pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
    pub const WGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

    // wgpeer_attribute
    pub const WGPEER_A_UNSPEC: u16 = 0;
    pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
    pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
    pub const WGPEER_A_FLAGS: u16 = 3;
    pub const WGPEER_A_ENDPOINT: u16 = 4;
    pub const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
    pub const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
    pub const WGPEER_A_RX_BYTES: u16 = 7;
    pub const WGPEER_A_TX_BYTES: u16 = 8;
    pub const WGPEER_A_ALLOWEDIPS: u16 = 9;
    pub const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

    // wgallowedip_attribute
    pub const WGALLOWEDIP_A_UNSPEC: u16 = 0;
    pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
    pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
    pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
}

use constants::*;

type PrivateKey = [u8; 32];
type PublicKey = [u8; 32];
type PresharedKey = [u8; 32];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DeviceMessage {
    pub nlas: Vec<DeviceNla>,
    pub message_type: u16,
    pub command: u8,
}

impl DeviceMessage {
    pub fn get_by_name(message_type: u16, name: String) -> Result<Self, crate::Error> {
        let c_name = CString::new(name).map_err(|_| crate::Error::InterfaceName)?;
        if c_name.as_bytes_with_nul().len() > libc::IFNAMSIZ {
            return Err(crate::Error::InterfaceName);
        }

        Ok(Self {
            message_type,
            nlas: vec![DeviceNla::IfName(c_name)],
            command: WG_CMD_GET_DEVICE,
        })
    }

    pub fn get_by_index(message_type: u16, index: u32) -> Self {
        Self {
            message_type,
            nlas: vec![DeviceNla::IfIndex(index)],
            command: WG_CMD_GET_DEVICE,
        }
    }

    fn read_genlmsghdr(buff: &[u8]) -> Result<u8, crate::Error> {
        if buff.len() < mem::size_of::<libc::genlmsghdr>() {
            return Err(crate::Error::Truncated);
        }

        let cmd = buff[0];
        if cmd == WG_CMD_GET_DEVICE || cmd == WG_CMD_SET_DEVICE {
            Ok(cmd)
        } else {
            Err(crate::Error::UnknownWireguardCommand(cmd))
        }
    }
}

impl NetlinkSerializable for DeviceMessage {
    fn message_type(&self) -> u16 {
        self.message_type
    }

    fn buffer_len(&self) -> usize {
        mem::size_of::<libc::genlmsghdr>() + self.nlas.as_slice().buffer_len()
    }

    fn serialize(&self, mut buffer: &mut [u8]) {
        let command_buf = [self.command, WG_GENL_VERSION, 0u8, 0u8];
        let _ = buffer.write(&command_buf).unwrap();
        self.nlas.as_slice().emit(buffer)
    }
}

impl From<DeviceMessage> for NetlinkPayload<DeviceMessage> {
    fn from(msg: DeviceMessage) -> Self {
        NetlinkPayload::InnerMessage(msg)
    }
}

impl NetlinkDeserializable for DeviceMessage {
    type Error = crate::Error;

    fn deserialize(_header: &NetlinkHeader, payload: &[u8]) -> Result<DeviceMessage, Self::Error> {
        let command = Self::read_genlmsghdr(payload)?;
        let new_payload = &payload[mem::size_of::<libc::genlmsghdr>()..];
        let mut nlas = vec![];
        for buf in NlasIterator::new(new_payload) {
            nlas.push(DeviceNla::parse(&buf.map_err(crate::Error::Decode)?).map_err(crate::Error::Decode)?);
        }

        Ok(DeviceMessage {
            nlas,
            command,
            message_type: _header.message_type,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DeviceNla {
    IfIndex(u32),
    IfName(CString),
    Flags(u32),
    PrivateKey(PrivateKey),
    PublicKey(PublicKey),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<PeerMessage>),
    Unspec(Vec<u8>),
}

impl Nla for DeviceNla {
    fn value_len(&self) -> usize {
        use DeviceNla::*;
        match self {
            IfIndex(_) | Fwmark(_) | Flags(_) => 4,
            IfName(name) => name.as_bytes_with_nul().len(),
            PrivateKey(key) | PublicKey(key) => key.len(),
            ListenPort(_) => 2,
            Peers(peers) => peers.as_slice().buffer_len(),
            Unspec(payload) => payload.len(),
        }
    }

    fn kind(&self) -> u16 {
        use DeviceNla::*;
        match self {
            IfIndex(_) => WGDEVICE_A_IFINDEX,
            IfName(_) => WGDEVICE_A_IFNAME,
            PrivateKey(_) => WGDEVICE_A_PRIVATE_KEY,
            PublicKey(_) => WGDEVICE_A_PUBLIC_KEY,
            Flags(_) => WGDEVICE_A_FLAGS,
            ListenPort(_) => WGDEVICE_A_LISTEN_PORT,
            Fwmark(_) => WGDEVICE_A_FWMARK,
            Peers(_) => WGDEVICE_A_PEERS | NLA_F_NESTED,
            Unspec(_) => WGDEVICE_A_UNSPEC,
        }
    }

    fn emit_value(&self, mut buffer: &mut [u8]) {
        use DeviceNla::*;
        match self {
            IfIndex(value) | Fwmark(value) | Flags(value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            IfName(interface_name) => {
                let _ = buffer
                    .write(interface_name.as_bytes_with_nul())
                    .expect("Failed to write interface name");
            }
            PrivateKey(key) | PublicKey(key) => {
                buffer[..32].copy_from_slice(key);
            }
            ListenPort(value) => NativeEndian::write_u16(buffer, *value),
            Peers(peers) => peers.as_slice().emit(buffer),
            Unspec(payload) => {
                buffer[..payload.len()].copy_from_slice(payload);
            }
        }
    }
}

impl<'a> Parseable<NlaBuffer<&'a [u8]>> for DeviceNla {
    fn parse(buf: &NlaBuffer<&'a [u8]>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() & !NLA_F_NESTED {
            WGDEVICE_A_IFINDEX => {
                DeviceNla::IfIndex(netlink_packet_core::parse_u32(payload).map_err(|_| DecodeError::from("Invalid IFINDEX"))?)
            }
            WGDEVICE_A_IFNAME => {
                let name = CString::new(&payload[..payload.len() - 1])
                    .map_err(|_| DecodeError::from("Invalid IFNAME"))?;
                DeviceNla::IfName(name)
            }
            WGDEVICE_A_FLAGS => {
                DeviceNla::Flags(netlink_packet_core::parse_u32(payload).map_err(|_| DecodeError::from("Invalid FLAGS"))?)
            }
            WGDEVICE_A_PRIVATE_KEY => {
                if payload.len() != 32 {
                    return Err(DecodeError::from("Invalid PRIVATE_KEY length"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(payload);
                DeviceNla::PrivateKey(key)
            }
            WGDEVICE_A_PUBLIC_KEY => {
                if payload.len() != 32 {
                    return Err(DecodeError::from("Invalid PUBLIC_KEY length"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(payload);
                DeviceNla::PublicKey(key)
            }
            WGDEVICE_A_LISTEN_PORT => {
                DeviceNla::ListenPort(netlink_packet_core::parse_u16(payload).map_err(|_| DecodeError::from("Invalid LISTEN_PORT"))?)
            }
            WGDEVICE_A_FWMARK => {
                DeviceNla::Fwmark(netlink_packet_core::parse_u32(payload).map_err(|_| DecodeError::from("Invalid FWMARK"))?)
            }
            WGDEVICE_A_PEERS => {
                let mut peers = vec![];
                for nla_buf in NlasIterator::new(payload) {
                    let peer_buf = nla_buf?;
                    peers.push(PeerMessage::parse(&peer_buf)?);
                }
                DeviceNla::Peers(peers)
            }
            _ => DeviceNla::Unspec(payload.to_vec()),
        })
    }
}

/// WireGuard peer configuration
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerMessage(pub Vec<PeerNla>);

impl Nla for PeerMessage {
    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        0 | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }
}

impl<'a> Parseable<NlaBuffer<&'a [u8]>> for PeerMessage {
    fn parse(buf: &NlaBuffer<&'a [u8]>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in NlasIterator::new(buf.value()) {
            nlas.push(PeerNla::parse(&nla_buf?)?);
        }
        Ok(PeerMessage(nlas))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PeerNla {
    PublicKey(PublicKey),
    PresharedKey(PresharedKey),
    Flags(u32),
    Endpoint(SocketAddr),
    PersistentKeepalive(u16),
    LastHandshakeTime(u64, u64),
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<AllowedIpMessage>),
    ProtocolVersion(u32),
    Unspec(Vec<u8>),
}

impl Nla for PeerNla {
    fn value_len(&self) -> usize {
        use PeerNla::*;
        match self {
            PublicKey(_) | PresharedKey(_) => 32,
            Flags(_) | ProtocolVersion(_) => 4,
            Endpoint(addr) => match addr {
                SocketAddr::V4(_) => mem::size_of::<libc::sockaddr_in>(),
                SocketAddr::V6(_) => mem::size_of::<libc::sockaddr_in6>(),
            },
            PersistentKeepalive(_) => 2,
            LastHandshakeTime(_, _) => 16,
            RxBytes(_) | TxBytes(_) => 8,
            AllowedIps(ips) => ips.as_slice().buffer_len(),
            Unspec(payload) => payload.len(),
        }
    }

    fn kind(&self) -> u16 {
        use PeerNla::*;
        match self {
            PublicKey(_) => WGPEER_A_PUBLIC_KEY,
            PresharedKey(_) => WGPEER_A_PRESHARED_KEY,
            Flags(_) => WGPEER_A_FLAGS,
            Endpoint(_) => WGPEER_A_ENDPOINT,
            PersistentKeepalive(_) => WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
            LastHandshakeTime(_, _) => WGPEER_A_LAST_HANDSHAKE_TIME,
            RxBytes(_) => WGPEER_A_RX_BYTES,
            TxBytes(_) => WGPEER_A_TX_BYTES,
            AllowedIps(_) => WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
            ProtocolVersion(_) => WGPEER_A_PROTOCOL_VERSION,
            Unspec(_) => WGPEER_A_UNSPEC,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use PeerNla::*;
        match self {
            PublicKey(key) | PresharedKey(key) => {
                buffer[..32].copy_from_slice(key);
            }
            Flags(value) | ProtocolVersion(value) => {
                NativeEndian::write_u32(buffer, *value);
            }
            Endpoint(addr) => {
                write_sockaddr(addr, buffer);
            }
            PersistentKeepalive(value) => {
                NativeEndian::write_u16(buffer, *value);
            }
            LastHandshakeTime(tv_sec, tv_nsec) => {
                NativeEndian::write_u64(&mut buffer[0..8], *tv_sec);
                NativeEndian::write_u64(&mut buffer[8..16], *tv_nsec);
            }
            RxBytes(value) | TxBytes(value) => {
                NativeEndian::write_u64(buffer, *value);
            }
            AllowedIps(ips) => {
                ips.as_slice().emit(buffer);
            }
            Unspec(payload) => {
                buffer[..payload.len()].copy_from_slice(payload);
            }
        }
    }
}

impl<'a> Parseable<NlaBuffer<&'a [u8]>> for PeerNla {
    fn parse(buf: &NlaBuffer<&'a [u8]>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() & !NLA_F_NESTED {
            WGPEER_A_PUBLIC_KEY => {
                if payload.len() != 32 {
                    return Err(DecodeError::from("Invalid PUBLIC_KEY length"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(payload);
                PeerNla::PublicKey(key)
            }
            WGPEER_A_PRESHARED_KEY => {
                if payload.len() != 32 {
                    return Err(DecodeError::from("Invalid PRESHARED_KEY length"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(payload);
                PeerNla::PresharedKey(key)
            }
            WGPEER_A_FLAGS => {
                PeerNla::Flags(netlink_packet_core::parse_u32(payload).map_err(|_| DecodeError::from("Invalid FLAGS"))?)
            }
            WGPEER_A_ENDPOINT => {
                PeerNla::Endpoint(parse_sockaddr(payload)?)
            }
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                PeerNla::PersistentKeepalive(netlink_packet_core::parse_u16(payload).map_err(|_| DecodeError::from("Invalid KEEPALIVE"))?)
            }
            WGPEER_A_LAST_HANDSHAKE_TIME => {
                if payload.len() < 16 {
                    return Err(DecodeError::from("Invalid HANDSHAKE_TIME"));
                }
                let tv_sec = NativeEndian::read_u64(&payload[0..8]);
                let tv_nsec = NativeEndian::read_u64(&payload[8..16]);
                PeerNla::LastHandshakeTime(tv_sec, tv_nsec)
            }
            WGPEER_A_RX_BYTES => {
                PeerNla::RxBytes(netlink_packet_core::parse_u64(payload).map_err(|_| DecodeError::from("Invalid RX_BYTES"))?)
            }
            WGPEER_A_TX_BYTES => {
                PeerNla::TxBytes(netlink_packet_core::parse_u64(payload).map_err(|_| DecodeError::from("Invalid TX_BYTES"))?)
            }
            WGPEER_A_ALLOWEDIPS => {
                let mut ips = vec![];
                for nla_buf in NlasIterator::new(payload) {
                    ips.push(AllowedIpMessage::parse(&nla_buf?)?);
                }
                PeerNla::AllowedIps(ips)
            }
            WGPEER_A_PROTOCOL_VERSION => {
                PeerNla::ProtocolVersion(netlink_packet_core::parse_u32(payload).map_err(|_| DecodeError::from("Invalid PROTOCOL_VERSION"))?)
            }
            _ => PeerNla::Unspec(payload.to_vec()),
        })
    }
}

/// Allowed IP range for a peer
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AllowedIpMessage {
    pub family: u16,
    pub ip: IpAddr,
    pub cidr: u8,
}

impl From<&IpNetwork> for AllowedIpMessage {
    fn from(net: &IpNetwork) -> Self {
        AllowedIpMessage {
            family: match net.ip() {
                IpAddr::V4(_) => libc::AF_INET as u16,
                IpAddr::V6(_) => libc::AF_INET6 as u16,
            },
            ip: net.ip(),
            cidr: net.prefix(),
        }
    }
}

/// Individual NLA attributes for AllowedIp
#[derive(Debug, PartialEq, Eq, Clone)]
enum AllowedIpNla {
    Family(u16),
    IpAddr(IpAddr),
    CidrMask(u8),
}

impl Nla for AllowedIpNla {
    fn value_len(&self) -> usize {
        match self {
            AllowedIpNla::Family(_) => 2,
            AllowedIpNla::IpAddr(IpAddr::V4(_)) => 4,
            AllowedIpNla::IpAddr(IpAddr::V6(_)) => 16,
            AllowedIpNla::CidrMask(_) => 1,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            AllowedIpNla::Family(_) => WGALLOWEDIP_A_FAMILY,
            AllowedIpNla::IpAddr(_) => WGALLOWEDIP_A_IPADDR,
            AllowedIpNla::CidrMask(_) => WGALLOWEDIP_A_CIDR_MASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            AllowedIpNla::Family(family) => {
                NativeEndian::write_u16(buffer, *family);
            }
            AllowedIpNla::IpAddr(IpAddr::V4(addr)) => {
                buffer[..4].copy_from_slice(&addr.octets());
            }
            AllowedIpNla::IpAddr(IpAddr::V6(addr)) => {
                buffer[..16].copy_from_slice(&addr.octets());
            }
            AllowedIpNla::CidrMask(cidr) => {
                buffer[0] = *cidr;
            }
        }
    }
}

impl Nla for AllowedIpMessage {
    fn value_len(&self) -> usize {
        let nlas = vec![
            AllowedIpNla::Family(self.family),
            AllowedIpNla::IpAddr(self.ip),
            AllowedIpNla::CidrMask(self.cidr),
        ];
        nlas.as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        0 | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let nlas = vec![
            AllowedIpNla::Family(self.family),
            AllowedIpNla::IpAddr(self.ip),
            AllowedIpNla::CidrMask(self.cidr),
        ];
        nlas.as_slice().emit(buffer);
    }
}

impl<'a> Parseable<NlaBuffer<&'a [u8]>> for AllowedIpMessage {
    fn parse(buf: &NlaBuffer<&'a [u8]>) -> Result<Self, DecodeError> {
        let mut family = None;
        let mut ip = None;
        let mut cidr = None;

        for nla_buf in NlasIterator::new(buf.value()) {
            let nla = nla_buf?;
            let payload = nla.value();

            match nla.kind() {
                WGALLOWEDIP_A_FAMILY => {
                    family = Some(netlink_packet_core::parse_u16(payload).map_err(|_| DecodeError::from("Invalid FAMILY"))?);
                }
                WGALLOWEDIP_A_IPADDR => {
                    if payload.len() == 4 {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(payload);
                        ip = Some(IpAddr::V4(octets.into()));
                    } else if payload.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(payload);
                        ip = Some(IpAddr::V6(octets.into()));
                    }
                }
                WGALLOWEDIP_A_CIDR_MASK => {
                    cidr = Some(netlink_packet_core::parse_u8(payload).map_err(|_| DecodeError::from("Invalid CIDR"))?);
                }
                _ => {}
            }
        }

        Ok(AllowedIpMessage {
            family: family.ok_or_else(|| DecodeError::from("Missing FAMILY"))?,
            ip: ip.ok_or_else(|| DecodeError::from("Missing IP"))?,
            cidr: cidr.ok_or_else(|| DecodeError::from("Missing CIDR"))?,
        })
    }
}

// Helper functions for sockaddr conversion
fn write_sockaddr(addr: &SocketAddr, buffer: &mut [u8]) {
    match addr {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &sin as *const _ as *const u8,
                    mem::size_of::<libc::sockaddr_in>(),
                )
            };
            buffer[..bytes.len()].copy_from_slice(bytes);
        }
        SocketAddr::V6(addr) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &sin6 as *const _ as *const u8,
                    mem::size_of::<libc::sockaddr_in6>(),
                )
            };
            buffer[..bytes.len()].copy_from_slice(bytes);
        }
    }
}

fn parse_sockaddr(payload: &[u8]) -> Result<SocketAddr, DecodeError> {
    if payload.len() < 2 {
        return Err(DecodeError::from("Sockaddr too short"));
    }

    let family = NativeEndian::read_u16(payload);

    match family as i32 {
        libc::AF_INET => {
            if payload.len() < mem::size_of::<libc::sockaddr_in>() {
                return Err(DecodeError::from("Invalid sockaddr_in"));
            }
            let sin: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const _) };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            if payload.len() < mem::size_of::<libc::sockaddr_in6>() {
                return Err(DecodeError::from("Invalid sockaddr_in6"));
            }
            let sin6: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const _) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(DecodeError::from("Unknown address family")),
    }
}
