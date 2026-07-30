// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, net::IpAddr, ops::RangeInclusive};

const LOOP_COVER_DELAY_RANGE: RangeInclusive<u32> = 0..=200;
const AVG_PACKET_DELAY_RANGE: RangeInclusive<u32> = 0..=200;
const MESSAGE_SENDING_DELAY_RANGE: RangeInclusive<u32> = 5..=50;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[cfg(feature = "typescript-bindings")]
use ts_rs::TS;

use crate::{EntryPoint, ExitPoint, NetworkStatisticsConfig, NymNetworkDetails, NymVpnNetwork};

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
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
    pub custom_dns: Vec<IpAddr>,
    pub enable_ad_blocking: bool,
    pub mixnet_traffic: MixnetTrafficConfig,
    pub network_stats: NetworkStatisticsConfig,
    pub killswitch: bool,
    /// Legacy (inclusive) split tunneling: hand routing to `luci-app-pbr`.
    /// When enabled, the daemon withholds the default route into the tunnel so
    /// only PBR-selected traffic is routed in. Mutually exclusive with the
    /// kill-switch (which is forced off in this mode).
    pub legacy_split_tunnel: bool,
    pub inbound_exemptions: Vec<InboundExemption>,
}

/// Whether the DNS servers in [`VpnServiceConfig`] actually reach the system
/// resolver, or whether the daemon has deliberately stepped aside.
///
/// This is observed state, not configuration: `enable_custom_dns` says what the
/// user asked for, this says whether it is in force. The two disagree whenever
/// the router's dnsmasq has a committed `noresolv` (AdGuard Home,
/// https-dns-proxy, stubby), because then the daemon leaves dnsmasq's upstreams
/// alone and the user's own forwards do the resolving.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsUpstreamOwner {
    /// The daemon manages the resolver's upstreams; configured DNS is applied.
    Vpn,
    /// The user manages upstreams themselves; configured DNS is **not** applied.
    /// Their own forwards resolve, riding the tunnel while connected.
    User,
    /// No daemon-managed resolver on this host, so the distinction is moot.
    NotApplicable,
}

impl fmt::Display for DnsUpstreamOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vpn => f.write_str("vpn"),
            Self::User => f.write_str("user"),
            Self::NotApplicable => f.write_str("n/a"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InboundExemptionProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for InboundExemptionProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InboundExemptionProtocol::Tcp => "tcp".fmt(f),
            InboundExemptionProtocol::Udp => "udp".fmt(f),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InboundExemption {
    pub proto: InboundExemptionProtocol,
    pub dport: u16,
    pub label: Option<String>,
}

impl fmt::Display for InboundExemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.proto, self.dport)?;
        if let Some(label) = &self.label {
            write!(f, " ({label})")?;
        }
        Ok(())
    }
}

impl fmt::Display for VpnServiceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "entry point: {:?}, exit point: {:?}",
            self.entry_point, self.exit_point,
        )?;
        writeln!(
            f,
            "allow_lan: {}, disable_ipv6: {}, enable_two_hop: {}, enable_lewes_protocol: {}, netstack: {}",
            self.allow_lan,
            self.disable_ipv6,
            self.enable_two_hop,
            self.enable_lewes_protocol,
            self.netstack
        )?;
        writeln!(
            f,
            "min_gateway_vpn_performance: {:?}",
            self.min_gateway_vpn_performance
        )?;
        writeln!(f, "residential_exit: {}", self.residential_exit)?;
        writeln!(
            f,
            "enable_custom_dns: {}, custom_dns: {}",
            self.enable_custom_dns,
            self.custom_dns
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(f, "enable_ad_blocking: {}", self.enable_ad_blocking)?;
        writeln!(f, "killswitch: {}", self.killswitch)?;
        writeln!(f, "legacy_split_tunnel: {}", self.legacy_split_tunnel)?;
        writeln!(f, "mixnet traffic config: {}", self.mixnet_traffic)?;
        writeln!(f, "networks stats config: {}", self.network_stats)?;

        Ok(())
    }
}

impl Default for VpnServiceConfig {
    fn default() -> Self {
        Self {
            entry_point: EntryPoint::Country {
                two_letter_iso_country_code: "CH".to_owned(),
            },
            exit_point: ExitPoint::Country {
                two_letter_iso_country_code: "CH".to_owned(),
            },
            allow_lan: true,
            // OpenWrt port default: IPv6-into-tunnel OFF. On dual-stack WANs
            // where the exit gateway has no IPv6 egress, accepted-then-dropped
            // IPv6 leaves LAN clients waiting out an IPv6 timeout before every
            // IPv4 fallback; with it off, forwarded IPv6 is rejected fast and
            // clients use IPv4 immediately. Re-enable via LuCI or
            // `nym-vpnc tunnel set --ipv6 on`. Existing config files keep their
            // stored value — this only affects fresh installs.
            disable_ipv6: true,
            enable_two_hop: true,
            enable_bridges: false,
            enable_lewes_protocol: false,
            netstack: false,
            min_gateway_vpn_performance: None,
            residential_exit: false,
            enable_custom_dns: false,
            custom_dns: vec![],
            enable_ad_blocking: false,
            network_stats: Default::default(),
            mixnet_traffic: MixnetTrafficConfig::default(),
            killswitch: true,
            legacy_split_tunnel: false,
            inbound_exemptions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct MixnetTrafficConfig {
    pub poisson_parameter_for_loop_cover_stream: Option<u32>,
    pub average_packet_delay: Option<u32>,
    pub message_sending_average_delay: Option<u32>,

    pub disable_poisson_rate: bool,
    pub disable_background_cover_traffic: bool,

    pub min_mixnode_performance: Option<u8>,
    pub min_gateway_mixnet_performance: Option<u8>,
}

impl fmt::Display for MixnetTrafficConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "poisson_parameter_for_loop_cover_stream: {:?}, average_packet_delay: {:?}, message_sending_average_delay: {:?}",
            self.poisson_parameter_for_loop_cover_stream,
            self.average_packet_delay,
            self.message_sending_average_delay,
        )?;
        writeln!(
            f,
            "disable_poisson_rate: {}, disable_background_cover_traffic: {}",
            self.disable_poisson_rate, self.disable_background_cover_traffic
        )?;
        writeln!(
            f,
            "min_mixnode_performance: {:?}, min_gateway_mixnet_performance: {:?}",
            self.min_mixnode_performance, self.min_gateway_mixnet_performance
        )?;
        Ok(())
    }
}

impl MixnetTrafficConfig {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(v) = self.poisson_parameter_for_loop_cover_stream
            && !LOOP_COVER_DELAY_RANGE.contains(&v)
        {
            return Err(format!(
                "poisson_parameter_for_loop_cover_stream must be between {} and {} ms (got {})",
                LOOP_COVER_DELAY_RANGE.start(),
                LOOP_COVER_DELAY_RANGE.end(),
                v
            ));
        }

        if let Some(v) = self.average_packet_delay
            && !AVG_PACKET_DELAY_RANGE.contains(&v)
        {
            return Err(format!(
                "average_packet_delay must be between {} and {} ms (got {})",
                AVG_PACKET_DELAY_RANGE.start(),
                AVG_PACKET_DELAY_RANGE.end(),
                v
            ));
        }

        if let Some(v) = self.message_sending_average_delay
            && !MESSAGE_SENDING_DELAY_RANGE.contains(&v)
        {
            return Err(format!(
                "message_sending_average_delay must be between {} and {} ms (got {})",
                MESSAGE_SENDING_DELAY_RANGE.start(),
                MESSAGE_SENDING_DELAY_RANGE.end(),
                v
            ));
        }

        Ok(())
    }
}

/// The target tunnel state.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub enum TargetState {
    /// Unsecure the device.
    Unsecured,

    /// Secure the device.
    Secured,
}

impl fmt::Display for TargetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TargetState::Unsecured => "Unsecured",
            TargetState::Secured => "Secured",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct VpnServiceInfo {
    pub version: String,
    #[cfg_attr(feature = "typescript-bindings", ts(as = "String"))]
    #[cfg_attr(feature = "serde", serde(with = "time::serde::iso8601::option"))]
    pub build_timestamp: Option<OffsetDateTime>,
    pub triple: String,
    pub platform: String,
    pub git_commit: String,
    pub nym_network: NymNetworkDetails,
    pub nym_vpn_network: NymVpnNetwork,
}
