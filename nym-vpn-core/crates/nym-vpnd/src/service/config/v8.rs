// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::service::{
    ConfigSetupError,
    config::{
        VpnServiceConfigExt,
        entry_exit::v2::{EntryPoint, ExitPoint},
        mixnet_traffic::v5::MixnetTrafficConfig,
    },
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnServiceConfig {
    pub entry_point: EntryPoint,
    pub exit_point: ExitPoint,
    pub allow_lan: bool,
    pub disable_ipv6: bool,
    pub enable_two_hop: bool,
    pub enable_bridges: bool,
    pub enable_lewes_protocol: bool,
    pub netstack: bool,
    pub min_gateway_vpn_performance: Option<u8>,
    pub residential_exit: bool,
    pub enable_custom_dns: bool,
    pub custom_dns: Vec<String>,
    pub enable_ad_blocking: bool,
    pub mixnet_traffic: MixnetTrafficConfig,
    #[serde(default = "default_killswitch")]
    pub killswitch: bool,
    #[serde(default)]
    pub legacy_split_tunnel: bool,
    #[serde(default)]
    pub inbound_exemptions: Vec<InboundExemption>,
    #[serde(default)]
    pub stealth_api: bool,
    #[serde(default)]
    pub gateway_independence: GatewayIndependence,
    /// Added after V8 shipped; a file without the key loads with it off.
    #[serde(default)]
    pub always_on: bool,
}

fn default_killswitch() -> bool {
    false
}

fn default_true() -> bool {
    true
}

/// Gateway independence criteria. Its own object with per-field defaults so a
/// file written before a criterion existed loads with that criterion on.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct GatewayIndependence {
    #[serde(default = "default_true")]
    pub enable_notifications: bool,
    #[serde(default = "default_true")]
    pub different_node_family: bool,
    #[serde(default = "default_true")]
    pub different_asn: bool,
    #[serde(default = "default_true")]
    pub different_subnet: bool,
}

impl Default for GatewayIndependence {
    fn default() -> Self {
        Self {
            enable_notifications: true,
            different_node_family: true,
            different_asn: true,
            different_subnet: true,
        }
    }
}

impl From<GatewayIndependence> for nym_vpn_lib_types::GatewayIndependence {
    fn from(value: GatewayIndependence) -> Self {
        Self {
            enable_notifications: value.enable_notifications,
            different_node_family: value.different_node_family,
            different_asn: value.different_asn,
            different_subnet: value.different_subnet,
        }
    }
}

impl From<&nym_vpn_lib_types::GatewayIndependence> for GatewayIndependence {
    fn from(value: &nym_vpn_lib_types::GatewayIndependence) -> Self {
        Self {
            enable_notifications: value.enable_notifications,
            different_node_family: value.different_node_family,
            different_asn: value.different_asn,
            different_subnet: value.different_subnet,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct InboundExemption {
    pub proto: InboundExemptionProtocol,
    pub dport: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum InboundExemptionProtocol {
    Tcp,
    Udp,
}

impl From<VpnServiceConfig> for VpnServiceConfigExt {
    fn from(v8: VpnServiceConfig) -> Self {
        VpnServiceConfigExt::V8(v8)
    }
}

impl TryFrom<VpnServiceConfig> for nym_vpn_lib_types::VpnServiceConfig {
    type Error = ConfigSetupError;

    fn try_from(value: VpnServiceConfig) -> Result<Self, Self::Error> {
        let entry_point = nym_vpn_lib_types::EntryPoint::try_from(value.entry_point)?;

        let exit_point = nym_vpn_lib_types::ExitPoint::try_from(value.exit_point)?;

        let custom_dns: Vec<IpAddr> = value
            .custom_dns
            .iter()
            .map(|dns_str| {
                IpAddr::from_str(dns_str)
                    .map_err(|e| ConfigSetupError::IpAddress { error: Box::new(e) })
            })
            .collect::<Result<_, _>>()?;

        let mixnet_traffic = nym_vpn_lib_types::MixnetTrafficConfig::from(value.mixnet_traffic);

        let config = nym_vpn_lib_types::VpnServiceConfig {
            entry_point,
            exit_point,
            allow_lan: value.allow_lan,
            disable_ipv6: value.disable_ipv6,
            enable_two_hop: value.enable_two_hop,
            enable_bridges: value.enable_bridges,
            enable_lewes_protocol: value.enable_lewes_protocol,
            netstack: value.netstack,
            min_gateway_vpn_performance: value.min_gateway_vpn_performance,
            residential_exit: value.residential_exit,
            mixnet_traffic,
            enable_custom_dns: value.enable_custom_dns,
            custom_dns,
            enable_ad_blocking: value.enable_ad_blocking,
            killswitch: value.killswitch,
            legacy_split_tunnel: value.legacy_split_tunnel,
            inbound_exemptions: value
                .inbound_exemptions
                .into_iter()
                .map(|e| nym_vpn_lib_types::InboundExemption {
                    proto: match e.proto {
                        InboundExemptionProtocol::Tcp => {
                            nym_vpn_lib_types::InboundExemptionProtocol::Tcp
                        }
                        InboundExemptionProtocol::Udp => {
                            nym_vpn_lib_types::InboundExemptionProtocol::Udp
                        }
                    },
                    dport: e.dport,
                    label: e.label,
                })
                .collect(),
            stealth_api: value.stealth_api,
            gateway_independence: value.gateway_independence.into(),
            always_on: value.always_on,
        };

        Ok(config)
    }
}
