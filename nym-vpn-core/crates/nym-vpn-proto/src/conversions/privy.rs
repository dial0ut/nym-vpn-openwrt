// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::proto;

impl From<proto::PrivyDerivationMessage> for nym_vpn_lib_types::PrivyDerivationMessage {
    fn from(message: proto::PrivyDerivationMessage) -> Self {
        Self {
            message: message.message,
        }
    }
}

impl From<nym_vpn_lib_types::PrivyDerivationMessage> for proto::PrivyDerivationMessage {
    fn from(message: nym_vpn_lib_types::PrivyDerivationMessage) -> Self {
        Self {
            message: message.message,
        }
    }
}
