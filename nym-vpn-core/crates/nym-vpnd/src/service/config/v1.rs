// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::service::{
    ConfigSetupError,
    config::{
        VpnServiceConfigExt,
        entry_exit::v1::{EntryPoint, ExitPoint},
        split_shared_pair,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnServiceConfig {
    pub entry_point: EntryPoint,
    pub exit_point: ExitPoint,
}

impl From<VpnServiceConfig> for VpnServiceConfigExt {
    fn from(v1: VpnServiceConfig) -> Self {
        VpnServiceConfigExt::V1(v1)
    }
}

impl TryFrom<VpnServiceConfig> for nym_vpn_lib_types::VpnServiceConfig {
    type Error = ConfigSetupError;

    fn try_from(value: VpnServiceConfig) -> Result<Self, Self::Error> {
        let entry_point = nym_vpn_lib_types::EntryPoint::try_from(value.entry_point)?;

        let exit_point = nym_vpn_lib_types::ExitPoint::try_from(value.exit_point)?;

        let pairs = split_shared_pair(
            entry_point,
            exit_point,
            nym_vpn_lib_types::VpnServiceConfig::default().enable_two_hop,
        );
        let config = nym_vpn_lib_types::VpnServiceConfig {
            entry_point: pairs.entry_point,
            exit_point: pairs.exit_point,
            mixnet_entry_point: pairs.mixnet_entry_point,
            mixnet_exit_point: pairs.mixnet_exit_point,
            killswitch: false,
            legacy_split_tunnel: false,
            stealth_api: false,
            always_on: false,
            dual_tunnel: false,
            gateway_independence: Default::default(),
            ..Default::default()
        };
        Ok(config)
    }
}
