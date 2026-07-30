// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::{conversions::ConversionError, proto};
use std::net::IpAddr;

impl TryFrom<proto::VpnServiceConfig> for nym_vpn_lib_types::VpnServiceConfig {
    type Error = ConversionError;

    fn try_from(value: proto::VpnServiceConfig) -> Result<Self, Self::Error> {
        let entry_point = value
            .entry_point
            .map(nym_vpn_lib_types::EntryPoint::try_from)
            .transpose()?
            .ok_or(ConversionError::NoValueSet("VpnServiceConfig.entry_point"))?;

        let exit_point = value
            .exit_point
            .map(nym_vpn_lib_types::ExitPoint::try_from)
            .transpose()?
            .ok_or(ConversionError::NoValueSet("VpnServiceConfig.exit_point"))?;

        let custom_dns: Vec<IpAddr> = match value.custom_dns {
            Some(ip_addr_list) => ip_addr_list.try_into()?,
            None => vec![],
        };

        let mixnet_traffic: nym_vpn_lib_types::MixnetTrafficConfig = value
            .mixnet_traffic
            .ok_or(ConversionError::NoValueSet(
                "VpnServiceConfig.mixnet_traffic",
            ))?
            .into();

        let network_stats = value
            .network_stats
            .ok_or(ConversionError::NoValueSet(
                "VpnServiceConfig.network_stats",
            ))?
            .into();

        let inbound_exemptions = value
            .inbound_exemptions
            .into_iter()
            .filter_map(|e| {
                let proto = match proto::InboundExemptionProtocol::try_from(e.proto).ok()? {
                    proto::InboundExemptionProtocol::Tcp => {
                        nym_vpn_lib_types::InboundExemptionProtocol::Tcp
                    }
                    proto::InboundExemptionProtocol::Udp => {
                        nym_vpn_lib_types::InboundExemptionProtocol::Udp
                    }
                    proto::InboundExemptionProtocol::Unspecified => return None,
                };
                Some(nym_vpn_lib_types::InboundExemption {
                    proto,
                    dport: e.dport as u16,
                    label: e.label,
                })
            })
            .collect();

        let config = nym_vpn_lib_types::VpnServiceConfig {
            entry_point,
            exit_point,
            allow_lan: value.allow_lan,
            disable_ipv6: value.disable_ipv6,
            enable_two_hop: value.enable_two_hop,
            enable_bridges: value.enable_bridges,
            enable_lewes_protocol: value.enable_lewes_protocol,
            netstack: value.netstack,
            min_gateway_vpn_performance: value.min_gateway_vpn_performance.map(|u| u as u8),
            residential_exit: value.residential_exit,
            enable_custom_dns: value.enable_custom_dns,
            custom_dns,
            enable_ad_blocking: value.enable_ad_blocking,
            killswitch: value.killswitch,
            legacy_split_tunnel: value.legacy_split_tunnel,
            mixnet_traffic,
            network_stats,
            inbound_exemptions,
        };
        Ok(config)
    }
}

impl From<nym_vpn_lib_types::VpnServiceConfig> for proto::VpnServiceConfig {
    fn from(value: nym_vpn_lib_types::VpnServiceConfig) -> Self {
        let entry_point = Some(proto::EntryNode::from(value.entry_point));

        let exit_point = Some(proto::ExitNode::from(value.exit_point));

        let custom_dns = Some(proto::IpAddrList::from(value.custom_dns));

        let mixnet_traffic = Some(proto::MixnetTrafficConfig::from(value.mixnet_traffic));

        let network_stats = Some(proto::NetworkStatsConfig::from(value.network_stats));

        let inbound_exemptions = value
            .inbound_exemptions
            .into_iter()
            .map(|e| proto::InboundExemption {
                proto: match e.proto {
                    nym_vpn_lib_types::InboundExemptionProtocol::Tcp => {
                        proto::InboundExemptionProtocol::Tcp as i32
                    }
                    nym_vpn_lib_types::InboundExemptionProtocol::Udp => {
                        proto::InboundExemptionProtocol::Udp as i32
                    }
                },
                dport: e.dport as u32,
                label: e.label,
            })
            .collect();

        proto::VpnServiceConfig {
            entry_point,
            exit_point,
            allow_lan: value.allow_lan,
            disable_ipv6: value.disable_ipv6,
            enable_two_hop: value.enable_two_hop,
            enable_bridges: value.enable_bridges,
            enable_lewes_protocol: value.enable_lewes_protocol,
            netstack: value.netstack,
            min_gateway_vpn_performance: value.min_gateway_vpn_performance.map(|u| u as u32),
            residential_exit: value.residential_exit,
            enable_custom_dns: value.enable_custom_dns,
            custom_dns,
            enable_ad_blocking: value.enable_ad_blocking,
            killswitch: value.killswitch,
            legacy_split_tunnel: value.legacy_split_tunnel,
            mixnet_traffic,
            network_stats,
            inbound_exemptions,
        }
    }
}

impl From<proto::MixnetTrafficConfig> for nym_vpn_lib_types::MixnetTrafficConfig {
    fn from(value: proto::MixnetTrafficConfig) -> Self {
        nym_vpn_lib_types::MixnetTrafficConfig {
            poisson_parameter_for_loop_cover_stream: value.poisson_parameter_for_loop_cover_stream,
            average_packet_delay: value.average_packet_delay,
            message_sending_average_delay: value.message_sending_average_delay,
            disable_poisson_rate: value.disable_poisson_rate,
            disable_background_cover_traffic: value.disable_background_cover_traffic,
            min_mixnode_performance: value.min_mixnode_performance.map(|u| u as u8),
            min_gateway_mixnet_performance: value.min_gateway_mixnet_performance.map(|u| u as u8),
        }
    }
}

impl From<nym_vpn_lib_types::MixnetTrafficConfig> for proto::MixnetTrafficConfig {
    fn from(value: nym_vpn_lib_types::MixnetTrafficConfig) -> Self {
        proto::MixnetTrafficConfig {
            poisson_parameter_for_loop_cover_stream: value.poisson_parameter_for_loop_cover_stream,
            average_packet_delay: value.average_packet_delay,
            message_sending_average_delay: value.message_sending_average_delay,
            disable_poisson_rate: value.disable_poisson_rate,
            disable_background_cover_traffic: value.disable_background_cover_traffic,
            min_mixnode_performance: value.min_mixnode_performance.map(|u| u as u32),
            min_gateway_mixnet_performance: value.min_gateway_mixnet_performance.map(|u| u as u32),
        }
    }
}

impl From<nym_vpn_lib_types::DnsUpstreamOwner> for proto::DnsUpstreamOwnerResponse {
    fn from(value: nym_vpn_lib_types::DnsUpstreamOwner) -> Self {
        use proto::dns_upstream_owner_response::Owner;
        let owner = match value {
            nym_vpn_lib_types::DnsUpstreamOwner::Vpn => Owner::Vpn,
            nym_vpn_lib_types::DnsUpstreamOwner::User => Owner::User,
            nym_vpn_lib_types::DnsUpstreamOwner::NotApplicable => Owner::NotApplicable,
        };
        proto::DnsUpstreamOwnerResponse {
            owner: owner.into(),
        }
    }
}

impl From<proto::DnsUpstreamOwnerResponse> for nym_vpn_lib_types::DnsUpstreamOwner {
    fn from(value: proto::DnsUpstreamOwnerResponse) -> Self {
        use proto::dns_upstream_owner_response::Owner;
        match Owner::try_from(value.owner) {
            Ok(Owner::Vpn) => nym_vpn_lib_types::DnsUpstreamOwner::Vpn,
            Ok(Owner::User) => nym_vpn_lib_types::DnsUpstreamOwner::User,
            // An unspecified owner means a daemon too old to report this, or a
            // host where the question is moot. Both are "nothing to warn about".
            Ok(Owner::NotApplicable) | Ok(Owner::Unspecified) | Err(_) => {
                nym_vpn_lib_types::DnsUpstreamOwner::NotApplicable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_upstream_owner_round_trips() {
        for owner in [
            nym_vpn_lib_types::DnsUpstreamOwner::Vpn,
            nym_vpn_lib_types::DnsUpstreamOwner::User,
            nym_vpn_lib_types::DnsUpstreamOwner::NotApplicable,
        ] {
            let wire = proto::DnsUpstreamOwnerResponse::from(owner);
            assert_eq!(nym_vpn_lib_types::DnsUpstreamOwner::from(wire), owner);
        }
    }

    /// A daemon predating this field leaves the enum at its zero value. That
    /// must read as "nothing to report", never as "your DNS is being ignored" —
    /// a false warning on every older daemon would be worse than silence.
    #[test]
    fn unset_owner_reads_as_not_applicable() {
        let unset = proto::DnsUpstreamOwnerResponse { owner: 0 };
        assert_eq!(
            nym_vpn_lib_types::DnsUpstreamOwner::from(unset),
            nym_vpn_lib_types::DnsUpstreamOwner::NotApplicable
        );
        let garbage = proto::DnsUpstreamOwnerResponse { owner: 99 };
        assert_eq!(
            nym_vpn_lib_types::DnsUpstreamOwner::from(garbage),
            nym_vpn_lib_types::DnsUpstreamOwner::NotApplicable
        );
    }
}
