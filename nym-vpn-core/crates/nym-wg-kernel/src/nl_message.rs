//! Generic netlink control messages for family ID resolution
//!
//! Based on Mullvad's implementation:
//! https://github.com/mullvad/mullvadvpn-app/blob/main/talpid-wireguard/src/wireguard_kernel/nl_message.rs

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use std::ffi::CStr;
use thiserror::Error;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid family name")]
    InvalidFamilyName,

    #[error("Failed to serialize netlink message")]
    Serialize,
}

/// Generic netlink control message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlinkControlMessage {
    pub cmd: u8,
    pub nlas: Vec<ControlNla>,
}

impl NetlinkControlMessage {
    /// Create a message to query for a netlink family ID by name
    pub fn get_netlink_family_id(family_name: Box<CStr>) -> Result<Self, Error> {
        Ok(NetlinkControlMessage {
            cmd: CTRL_CMD_GETFAMILY,
            nlas: vec![ControlNla::FamilyName(family_name)],
        })
    }
}

/// Netlink control attributes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlNla {
    FamilyId(u16),
    FamilyName(Box<CStr>),
    Unspec(Vec<u8>),
}

impl From<NetlinkControlMessage> for NetlinkMessage<NetlinkControlMessage> {
    fn from(msg: NetlinkControlMessage) -> Self {
        NetlinkMessage::new(
            netlink_packet_core::NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(msg),
        )
    }
}

impl NetlinkSerializable for NetlinkControlMessage {
    fn message_type(&self) -> u16 {
        GENL_ID_CTRL
    }

    fn buffer_len(&self) -> usize {
        // Generic netlink header (4 bytes: cmd + version + reserved)
        let mut len = 4;

        // Add size of all NLAs
        for nla in &self.nlas {
            len += nla.buffer_len();
        }

        len
    }

    fn serialize(&self, buffer: &mut [u8]) {
        // Generic netlink header
        buffer[0] = self.cmd;
        buffer[1] = 1; // version
        buffer[2] = 0; // reserved
        buffer[3] = 0; // reserved

        let mut offset = 4;

        // Serialize NLAs
        for nla in &self.nlas {
            let nla_len = nla.buffer_len();
            nla.serialize(&mut buffer[offset..offset + nla_len]);
            offset += nla_len;
        }
    }
}

impl NetlinkDeserializable for NetlinkControlMessage {
    type Error = netlink_packet_core::DecodeError;

    fn deserialize(_header: &netlink_packet_core::NetlinkHeader, buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() < 4 {
            return Err(netlink_packet_core::DecodeError::from(
                "Buffer too short for generic netlink header",
            ));
        }

        let cmd = buffer[0];
        let mut nlas = Vec::new();
        let mut offset = 4;

        // Parse NLAs
        while offset < buffer.len() {
            if offset + 4 > buffer.len() {
                break;
            }

            let nla_len = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as usize;
            let nla_type = u16::from_ne_bytes([buffer[offset + 2], buffer[offset + 3]]);

            if nla_len < 4 || offset + nla_len > buffer.len() {
                break;
            }

            let nla_data = &buffer[offset + 4..offset + nla_len];
            let nla = ControlNla::deserialize(nla_type, nla_data)?;
            nlas.push(nla);

            // NLAs are aligned to 4 bytes
            offset += ((nla_len + 3) / 4) * 4;
        }

        Ok(NetlinkControlMessage { cmd, nlas })
    }
}

impl ControlNla {
    fn buffer_len(&self) -> usize {
        let data_len = match self {
            ControlNla::FamilyId(_) => 2,
            ControlNla::FamilyName(name) => name.to_bytes_with_nul().len(),
            ControlNla::Unspec(data) => data.len(),
        };

        // NLA header (4 bytes) + data, aligned to 4 bytes
        let total = 4 + data_len;
        ((total + 3) / 4) * 4
    }

    fn serialize(&self, buffer: &mut [u8]) {
        let (nla_type, data): (u16, Vec<u8>) = match self {
            ControlNla::FamilyId(id) => (CTRL_ATTR_FAMILY_ID, id.to_ne_bytes().to_vec()),
            ControlNla::FamilyName(name) => {
                (CTRL_ATTR_FAMILY_NAME, name.to_bytes_with_nul().to_vec())
            }
            ControlNla::Unspec(data) => (0, data.clone()),
        };

        let nla_len = (4 + data.len()) as u16;
        buffer[0..2].copy_from_slice(&nla_len.to_ne_bytes());
        buffer[2..4].copy_from_slice(&nla_type.to_ne_bytes());
        buffer[4..4 + data.len()].copy_from_slice(&data);

        // Zero padding
        let padding_len = self.buffer_len() - 4 - data.len();
        if padding_len > 0 {
            buffer[4 + data.len()..4 + data.len() + padding_len].fill(0);
        }
    }

    fn deserialize(
        nla_type: u16,
        data: &[u8],
    ) -> Result<Self, netlink_packet_core::DecodeError> {
        match nla_type {
            CTRL_ATTR_FAMILY_ID => {
                if data.len() >= 2 {
                    Ok(ControlNla::FamilyId(u16::from_ne_bytes([
                        data[0], data[1],
                    ])))
                } else {
                    Err(netlink_packet_core::DecodeError::from(
                        "Invalid family ID length",
                    ))
                }
            }
            CTRL_ATTR_FAMILY_NAME => {
                let cstr = CStr::from_bytes_until_nul(data)
                    .map_err(|_| netlink_packet_core::DecodeError::from("Invalid CString"))?;
                Ok(ControlNla::FamilyName(Box::from(cstr)))
            }
            _ => Ok(ControlNla::Unspec(data.to_vec())),
        }
    }
}
