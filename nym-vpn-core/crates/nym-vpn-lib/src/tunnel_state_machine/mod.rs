// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Per-state contract. "Pinned" means the account and discovery HTTP clients
//! resolve the API hostnames to the addresses the live policy admits;
//! [`SharedState::enter_idle_firewall`] keeps policy and pins in step, and
//! [`IdleApiAccess`] refreshes the allow-list while idle.
//!
//! Kill-switch on:
//!
//! | State        | Firewall policy                                            | Resolver pins                                                                     | dnsmasq mode                                                   | Refresh timer      |
//! |--------------|------------------------------------------------------------|-----------------------------------------------------------------------------------|----------------------------------------------------------------|--------------------|
//! | Disconnected | Blocked; admits the known API endpoints, root only         | pinned from the retained live resolution; cache-only: unpinned until one succeeds | WAN mirror, or the local custom resolver alone when one is set | hourly, 60 s retry |
//! | Error        | as Disconnected                                            | as Disconnected                                                                   | unchanged on entry; WAN-only mirror on leave                   | as Disconnected    |
//! | Offline      | Blocked; admits nothing                                    | carried over from the previous state                                              | unchanged on entry; WAN-only mirror on leave                   | none               |
//! | Connecting   | Connecting; gateway endpoints, API endpoints once resolved | pinned once resolved                                                              | unchanged                                                      | none               |
//! | Connected    | Connected; tunnel interface                                | unpinned                                                                          | tunnel resolvers                                               | none               |
//!
//! Kill-switch off:
//!
//! | State        | Firewall policy                 | Resolver pins                        | dnsmasq mode                                 | Refresh timer |
//! |--------------|---------------------------------|--------------------------------------|----------------------------------------------|---------------|
//! | Disconnected | reset                           | unpinned                             | WAN mirror plus any local custom resolver    | none          |
//! | Error        | reset                           | unpinned                             | unchanged on entry; WAN-only mirror on leave | none          |
//! | Offline      | forwarding plane only, no block | carried over from the previous state | unchanged on entry; WAN-only mirror on leave | none          |
//! | Connecting   | forwarding plane only, no block | pinned once resolved                 | unchanged                                    | none          |
//! | Connected    | forwarding plane only, no block | unpinned                             | tunnel resolvers                             | none          |

mod account;
pub(crate) mod api_endpoints_cache;
mod dns_handler;
mod gateway_ext;
mod ipv6_availability;
mod route_handler;
mod states;
mod tun_ipv6;
pub mod tunnel;
mod tunnel_monitor;

use futures::{
    FutureExt,
    future::{BoxFuture, Fuse, FusedFuture},
};
use nym_config::defaults::{WG_METADATA_PORT, WG_TUN_DEVICE_IP_ADDRESS_V4};
use nym_dns::ResolvedDnsConfig;
use nym_offline_monitor::ConnectivityHandle;
use nym_registration_client::MixnetClientConfig;
use nym_statistics::StatisticsSender;
use nym_vpn_account_controller::{AccountCommandSender, AccountStateReceiver};
use nym_vpn_api_client::ResolverOverrides;
use nym_vpn_network_config::{DiscoveryRefresherCommand, Network};
use nym_vpn_store::keys::wireguard::WireguardKeysDb;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use nym_dns::{DnsConfig, IdleDns};
use nym_firewall::{
    AllowedClients, AllowedEndpoint, Endpoint, Firewall, FirewallArguments, FirewallPolicy,
    InitialFirewallState, TransportProtocol,
};
use nym_gateway_directory::{
    BlacklistedGateways, Config as GatewayDirectoryConfig, GatewayCacheHandle, NodeIdentity,
    ResolvedConfig,
};
use nym_vpn_lib_types::{
    AccountControllerErrorStateReason, ActionAfterDisconnect, ConnectionData, EntryPoint,
    ErrorStateReason, EstablishConnectionData, EstablishConnectionState, ExitPoint, TunnelEvent,
    TunnelState, TunnelType,
};

use tunnel::SelectedGateways;

use crate::{
    GatewayDirectoryError, UserAgent, bandwidth_controller::Error as BandwidthControllerError,
    mixnet::VpnTopologyServiceHandle,
};

use dns_handler::DnsHandlerHandle;
pub use route_handler::RouteHandler;
pub use route_handler::RoutingParameters;
use states::{DisconnectedState, OfflineState};

#[async_trait::async_trait]
trait TunnelStateHandler: Send {
    async fn handle_event(
        mut self: Box<Self>,
        shutdown_token: &CancellationToken,
        command_rx: &'async_trait mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_state: &'async_trait mut SharedState,
    ) -> NextTunnelState;
}

#[allow(clippy::large_enum_variant)]
enum NextTunnelState {
    NewState((Box<dyn TunnelStateHandler>, PrivateTunnelState)),
    SameState(Box<dyn TunnelStateHandler>),
    Finished,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TunnelConstants {
    /// Private (in-tunnel) entry gateway address
    pub private_entry_gateway_address: IpAddr,

    /// In-tunnel endpoint used for bandwidth queries
    pub in_tunnel_bandwidth_metadata_endpoint: SocketAddr,

    /// Firewall mark used for bypassing the tunnel
    pub fwmark: u32,
}

impl Default for TunnelConstants {
    fn default() -> Self {
        Self {
            private_entry_gateway_address: IpAddr::from(WG_TUN_DEVICE_IP_ADDRESS_V4),
            in_tunnel_bandwidth_metadata_endpoint: SocketAddr::new(
                IpAddr::from(WG_TUN_DEVICE_IP_ADDRESS_V4),
                WG_METADATA_PORT,
            ),
            fwmark: crate::TUNNEL_FWMARK,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunnelSettings {
    /// Whether to enable support for IPv6.
    pub enable_ipv6: bool,

    /// Type of tunnel.
    pub tunnel_type: TunnelType,

    /// Allow LAN connections outside of tunnel.
    pub allow_lan: bool,

    /// Select residential exit gateways only.
    pub residential_exit: bool,

    /// Mixnet tunnel options.
    pub mixnet_tunnel_options: MixnetTunnelOptions,

    /// WireGuard tunnel options.
    pub wireguard_tunnel_options: WireguardTunnelOptions,

    /// Overrides gateway config.
    pub gateway_performance_options: GatewayPerformanceOptions,

    /// Overrides mixnet client config when provided.
    /// Leave `None` to use sane defaults.
    pub mixnet_client_config: Option<MixnetClientConfig>,

    /// Entry node.
    pub entry_point: Box<EntryPoint>,

    /// Exit node.
    pub exit_point: Box<ExitPoint>,

    /// DNS configuration.
    pub dns: DnsOptions,

    /// Kill-switch: enforce firewall rules and default route.
    /// When disabled, firewall policy and default route are skipped (for PBR compatibility).
    pub killswitch: bool,

    /// Legacy (inclusive) split tunneling. When enabled, the default route into
    /// the tunnel is withheld so only externally-selected traffic (e.g. via
    /// `luci-app-pbr`) is routed in. Mutually exclusive with the kill-switch.
    pub legacy_split_tunnel: bool,

    /// Inbound services exempted from the tunnel. Reply traffic for these
    /// `{proto, dport}` pairs is routed via the real WAN instead of the VPN,
    /// so port-forwarded services remain reachable while the kill-switch is on.
    pub inbound_exemptions: Vec<nym_firewall::InboundExemption>,
}

impl TunnelSettings {
    /// Returns resolved DNS config resolved against default DNS IPs.
    pub fn resolved_dns_config(&self) -> ResolvedDnsConfig {
        self.dns.to_dns_config().resolve(&self.dns_ips())
    }

    /// Returns DNS IPs filtering out IPv6 addresses when IPv6 is disabled.
    pub fn dns_ips(&self) -> Vec<IpAddr> {
        match self.dns {
            DnsOptions::Custom(ref addrs) => addrs
                .iter()
                .filter(|ip| ip.is_ipv4() || (ip.is_ipv6() && self.enable_ipv6))
                .copied()
                .collect(),
            DnsOptions::Default => self.default_dns_ips(),
        }
    }

    pub fn default_dns_ips(&self) -> Vec<IpAddr> {
        crate::DEFAULT_DNS_SERVERS
            .iter()
            .filter(|ip| ip.is_ipv4() || (ip.is_ipv6() && self.enable_ipv6))
            .copied()
            .collect()
    }

    /// The daemon's own resolvers plus any private custom DNS server (a LAN
    /// Pi-hole); the idle policies admit the latter on every interface but WAN.
    pub fn idle_dns_ips(&self) -> Vec<IpAddr> {
        let mut ips = self.default_dns_ips();
        ips.extend(self.local_custom_dns_ips());
        ips
    }

    /// Custom DNS servers on private addresses, never routed through the tunnel.
    pub fn local_custom_dns_ips(&self) -> Vec<IpAddr> {
        match self.dns {
            DnsOptions::Custom(_) => self
                .dns_ips()
                .into_iter()
                .filter(|ip| nym_firewall_config::is_local_address(ip) && !ip.is_loopback())
                .collect(),
            DnsOptions::Default => Vec::new(),
        }
    }

    pub fn idle_dns(&self) -> IdleDns {
        IdleDns {
            local_resolvers: self.local_custom_dns_ips(),
            killswitch: self.killswitch,
        }
    }

    pub fn bridges_enabled(&self) -> bool {
        matches!(self.tunnel_type, TunnelType::Wireguard)
            && self.wireguard_tunnel_options.enable_bridges
    }

    pub fn diff(&self, other: &Self) -> Option<TunnelSettingsDiff> {
        let mut diff = TunnelSettingsDiff::new();

        if self.enable_ipv6 != other.enable_ipv6 {
            diff.add(TunnelSettingsDiffFields::EnableIpv6);
        }
        if self.tunnel_type != other.tunnel_type {
            diff.add(TunnelSettingsDiffFields::TunnelType);
        }
        if self.allow_lan != other.allow_lan {
            diff.add(TunnelSettingsDiffFields::AllowLan);
        }
        if self.residential_exit != other.residential_exit {
            diff.add(TunnelSettingsDiffFields::ResidentialExit);
        }
        if self.mixnet_tunnel_options != other.mixnet_tunnel_options {
            diff.add(TunnelSettingsDiffFields::MixnetTunnelOptions);
        }
        if self.wireguard_tunnel_options != other.wireguard_tunnel_options {
            diff.add(TunnelSettingsDiffFields::WireguardTunnelOptions);
            // We care about just the QUIC setting changing.
            if self.wireguard_tunnel_options.enable_bridges
                != other.wireguard_tunnel_options.enable_bridges
            {
                diff.add(TunnelSettingsDiffFields::QUIC);
            }
        }
        if self.gateway_performance_options != other.gateway_performance_options {
            diff.add(TunnelSettingsDiffFields::GatewayPerformanceOptions);
            // We care about just the mixnet performance setting changing.
            if self.gateway_performance_options.mixnet_min_performance
                != other.gateway_performance_options.mixnet_min_performance
            {
                diff.add(TunnelSettingsDiffFields::MixnetPerformanceOptions);
            }
        }
        if self.mixnet_client_config != other.mixnet_client_config {
            diff.add(TunnelSettingsDiffFields::MixnetPerformanceOptions);
        }
        if self.entry_point != other.entry_point {
            diff.add(TunnelSettingsDiffFields::EntryPoint);
        }
        if self.exit_point != other.exit_point {
            diff.add(TunnelSettingsDiffFields::ExitPoint);
        }
        if self.dns != other.dns {
            diff.add(TunnelSettingsDiffFields::Dns);
        }
        if self.killswitch != other.killswitch {
            diff.add(TunnelSettingsDiffFields::Killswitch);
        }
        if self.legacy_split_tunnel != other.legacy_split_tunnel {
            diff.add(TunnelSettingsDiffFields::LegacySplitTunnel);
        }
        if self.inbound_exemptions != other.inbound_exemptions {
            diff.add(TunnelSettingsDiffFields::InboundExemptions);
        }

        if diff.is_empty() { None } else { Some(diff) }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TunnelSettingsDiffFields {
    EnableIpv6 = 0,
    TunnelType,
    AllowLan,
    ResidentialExit,
    MixnetTunnelOptions,
    WireguardTunnelOptions,
    QUIC,
    GatewayPerformanceOptions,
    MixnetPerformanceOptions,
    EntryPoint,
    ExitPoint,
    Dns,
    Killswitch,
    LegacySplitTunnel,
    InboundExemptions,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TunnelSettingsDiff(HashSet<TunnelSettingsDiffFields>);

impl TunnelSettingsDiff {
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    pub fn add(&mut self, field: TunnelSettingsDiffFields) {
        self.0.insert(field);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_field_changed(&self, field: &TunnelSettingsDiffFields) -> bool {
        self.0.contains(field)
    }

    pub fn only_field_changed(&self, field: &TunnelSettingsDiffFields) -> bool {
        self.is_field_changed(field) && self.0.len() == 1
    }

    pub fn allow_lan_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::AllowLan)
    }

    pub fn only_allow_lan_changed(&self) -> bool {
        self.only_field_changed(&TunnelSettingsDiffFields::AllowLan)
    }

    pub fn inbound_exemptions_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::InboundExemptions)
    }

    pub fn killswitch_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::Killswitch)
    }

    pub fn only_inbound_exemptions_changed(&self) -> bool {
        self.only_field_changed(&TunnelSettingsDiffFields::InboundExemptions)
    }

    /// Non-empty diff of only fields re-appliable without a reconnect.
    pub fn only_hot_appliable_changed(&self) -> bool {
        if self.0.is_empty() {
            return false;
        }
        self.0.iter().all(|f| matches!(
            f,
            TunnelSettingsDiffFields::AllowLan | TunnelSettingsDiffFields::InboundExemptions
        ))
    }

    pub fn entry_point_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::EntryPoint)
    }

    pub fn exit_point_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::ExitPoint)
    }

    pub fn quic_changed(&self) -> bool {
        self.is_field_changed(&TunnelSettingsDiffFields::QUIC)
    }

    pub fn only_mixnet_performance_options_changed(&self) -> bool {
        self.only_field_changed(&TunnelSettingsDiffFields::MixnetPerformanceOptions)
    }

    /// Whether the change touches an input `select_gateways` reads. A forced
    /// reconnect reuses the running pair otherwise, so the user is not
    /// silently moved to another server.
    pub fn affects_gateway_selection(&self) -> bool {
        self.0.iter().any(|f| {
            matches!(
                f,
                TunnelSettingsDiffFields::EntryPoint
                    | TunnelSettingsDiffFields::ExitPoint
                    | TunnelSettingsDiffFields::TunnelType
                    | TunnelSettingsDiffFields::QUIC
                    | TunnelSettingsDiffFields::ResidentialExit
                    | TunnelSettingsDiffFields::GatewayPerformanceOptions
            )
        })
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct GatewayPerformanceOptions {
    pub mixnet_min_performance: Option<u8>,
    pub vpn_min_performance: Option<u8>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct MixnetTunnelOptions {
    /// Overrides tunnel interface MTU.
    pub mtu: Option<u16>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub enum WireguardMultihopMode {
    /// Multihop using two tun devices to nest tunnels.
    #[default]
    TunTun,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct WireguardTunnelOptions {
    pub multihop_mode: WireguardMultihopMode,
    pub enable_bridges: bool,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub enum DnsOptions {
    #[default]
    Default,
    Custom(Vec<IpAddr>),
}

impl DnsOptions {
    /// Convert dns options into [DnsConfig].
    fn to_dns_config(&self) -> DnsConfig {
        match self {
            Self::Default => DnsConfig::default(),
            Self::Custom(addrs) => {
                if addrs.is_empty() {
                    DnsConfig::default()
                } else {
                    let (non_tunnel_config, tunnel_config): (Vec<_>, Vec<_>) = addrs
                        .iter()
                        // Private IP ranges should not be tunneled
                        .partition(|&addr| nym_firewall_config::is_local_address(addr));
                    DnsConfig::from_addresses(&tunnel_config, &non_tunnel_config)
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum TunnelCommand {
    /// Connect the tunnel.
    Connect,

    /// Disconnect the tunnel.
    Disconnect,

    /// Set new tunnel settings.
    SetTunnelSettings(TunnelSettings),
}

impl From<PrivateTunnelState> for TunnelState {
    fn from(value: PrivateTunnelState) -> Self {
        match value {
            PrivateTunnelState::Disconnected => Self::Disconnected,
            PrivateTunnelState::Connected { connection_data } => {
                Self::Connected { connection_data }
            }
            PrivateTunnelState::Connecting {
                retry_attempt,
                state,
                tunnel_type,
                connection_data,
            } => Self::Connecting {
                retry_attempt,
                state,
                tunnel_type,
                connection_data,
            },
            PrivateTunnelState::Disconnecting { after_disconnect } => Self::Disconnecting {
                after_disconnect: ActionAfterDisconnect::from(after_disconnect),
            },
            PrivateTunnelState::Error(reason) => Self::Error(reason),
            PrivateTunnelState::Offline { reconnect } => Self::Offline { reconnect },
        }
    }
}

/// Private enum describing the tunnel state
#[derive(Debug, Clone)]
enum PrivateTunnelState {
    Disconnected,
    Connecting {
        /// Connection attempt.
        retry_attempt: u32,
        state: EstablishConnectionState,
        tunnel_type: TunnelType,
        connection_data: Option<EstablishConnectionData>,
    },
    Connected {
        connection_data: ConnectionData,
    },
    Disconnecting {
        after_disconnect: PrivateActionAfterDisconnect,
    },
    Error(ErrorStateReason),
    Offline {
        /// Whether to reconnect after gaining the network connectivity.
        reconnect: bool,
    },
}

impl From<PrivateActionAfterDisconnect> for ActionAfterDisconnect {
    fn from(value: PrivateActionAfterDisconnect) -> Self {
        match value {
            PrivateActionAfterDisconnect::Nothing => Self::Nothing,
            PrivateActionAfterDisconnect::Reconnect { .. } => Self::Reconnect,
            PrivateActionAfterDisconnect::Offline { .. } => Self::Offline,
            PrivateActionAfterDisconnect::Error(_) => Self::Error,
        }
    }
}

/// Private enum describing action to perform after disconnect
#[derive(Debug, Clone)]
enum PrivateActionAfterDisconnect {
    /// Do nothing after disconnect
    Nothing,

    /// Reconnect after disconnect
    Reconnect {
        /// Gateways to reuse on reconnect, when the reason for disconnecting
        /// does not invalidate the current selection. `None` re-runs gateway
        /// selection from scratch.
        gateways: Option<SelectedGateways>,
    },

    /// Enter offline state after disconnect
    Offline {
        /// Whether to reconnect the tunnel once back online.
        reconnect: bool,

        /// The last known gateways passed to connecting state upon reconnect.
        gateways: Option<SelectedGateways>,
    },

    /// Enter error state
    Error(ErrorStateReason),
}

/// Describes tunnel interfaces used to maintain the tunnel.
#[derive(Debug, Clone)]
pub enum TunnelInterface {
    One(TunnelMetadata),
    Two {
        entry: TunnelMetadata,
        exit: TunnelMetadata,
    },
}

impl TunnelInterface {
    /// Returns exit tunnel metadata
    pub fn exit_tunnel_metadata(&self) -> &TunnelMetadata {
        match self {
            Self::One(metadata) => metadata,
            Self::Two { exit, .. } => exit,
        }
    }
}

/// Describes tunnel interface configuration.
#[derive(Debug, Clone)]
pub struct TunnelMetadata {
    interface: String,
    ips: Vec<IpAddr>,
    ipv4_gateway: Option<Ipv4Addr>,
    ipv6_gateway: Option<Ipv6Addr>,
}

impl From<TunnelMetadata> for nym_firewall::TunnelMetadata {
    fn from(value: TunnelMetadata) -> Self {
        Self {
            interface: value.interface,
            ips: value.ips,
            ipv4_gateway: value.ipv4_gateway,
            ipv6_gateway: value.ipv6_gateway,
        }
    }
}

impl From<TunnelInterface> for nym_firewall::TunnelInterface {
    fn from(value: TunnelInterface) -> Self {
        match value {
            TunnelInterface::One(metadata) => {
                nym_firewall::TunnelInterface::One(nym_firewall::TunnelMetadata::from(metadata))
            }
            TunnelInterface::Two { entry, exit } => nym_firewall::TunnelInterface::Two {
                entry: nym_firewall::TunnelMetadata::from(entry),
                exit: nym_firewall::TunnelMetadata::from(exit),
            },
        }
    }
}

/// How long after a drop reconnect failures are blamed on the local network
/// rather than the entry gateway (no blacklist, no re-selection). Sized to
/// outlast a PPPoE/LTE resync; a reachable API ends the shield early.
const GATEWAY_BLAME_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

pub struct SharedState {
    route_handler: RouteHandler,
    firewall: Firewall,
    dns_handler: DnsHandlerHandle,
    connectivity_handle: ConnectivityHandle,
    nym_config: NymConfig,
    tunnel_settings: TunnelSettings,
    tunnel_constants: TunnelConstants,
    status_listener_handle: Option<JoinHandle<()>>,
    account_command_tx: AccountCommandSender,
    account_controller_state: AccountStateReceiver,
    statistics_event_sender: StatisticsSender,
    gateway_cache_handle: GatewayCacheHandle,
    topology_service: VpnTopologyServiceHandle,
    discovery_refresher_command_tx: mpsc::UnboundedSender<DiscoveryRefresherCommand>,
    wg_keys_db: WireguardKeysDb,
    user_agent: UserAgent,
    blacklisted_entry_gateways: BlacklistedGateways,
    /// Entry gateway shielded from blame after a drop; see [`GATEWAY_BLAME_GRACE`].
    entry_gateway_grace: Option<(NodeIdentity, std::time::Instant)>,
    /// API socket addresses from the most recent resolution; the Blocked
    /// policy admits exactly these, root-scoped.
    api_endpoints: Vec<SocketAddr>,
    /// The last live resolution and its time. Both `None` after a cold
    /// start: the on-disk cache carries addresses but no hostname map, so the
    /// idle states cannot pin until they resolve again.
    api_resolution: Option<ResolvedConfig>,
    api_endpoints_resolved_at: Option<Instant>,
}

type ResolveApiAddrsFuture = BoxFuture<'static, Result<ResolvedConfig>>;

/// Well inside the cache's seven-day bound.
pub(crate) const API_ENDPOINT_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub(crate) const API_ENDPOINT_RETRY_DELAY: Duration = Duration::from_secs(60);
pub(crate) const API_ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The one resolver for Connecting and the idle states: anything that changes
/// what the kill-switch admits goes through here.
pub(crate) fn resolve_api_endpoints(
    gateway_config: GatewayDirectoryConfig,
) -> BoxFuture<'static, Result<ResolvedConfig>> {
    async move {
        // With the kill switch up sysntpd cannot fix a cold clock, and a clock
        // predating this binary fails every TLS handshake. No-op when sane.
        #[cfg(target_os = "linux")]
        crate::clock_bootstrap::ensure_sane_clock().await;

        match tokio::time::timeout(
            API_ENDPOINT_RESOLVE_TIMEOUT,
            nym_gateway_directory::resolve_config(&gateway_config),
        )
        .await
        {
            Ok(result) => result.map_err(|err| Error::ResolveApiHostnames(Box::new(err))),
            Err(_elapsed) => Err(Error::ResolveApiHostnamesTimeout(
                API_ENDPOINT_RESOLVE_TIMEOUT,
            )),
        }
    }
    .boxed()
}

pub(crate) fn api_endpoints_need_refresh(
    killswitch: bool,
    endpoints_known: bool,
    resolved_at: Option<Instant>,
    now: Instant,
) -> bool {
    if !killswitch {
        return false;
    }
    match resolved_at {
        None => true,
        Some(at) => !endpoints_known || now.duration_since(at) >= API_ENDPOINT_REFRESH_INTERVAL,
    }
}

/// The between-sessions Blocked policy. With no endpoints it is Blocked with
/// none, never anything wider.
pub(crate) fn idle_blocked_policy(
    tunnel_settings: &TunnelSettings,
    api_endpoints: &[SocketAddr],
) -> FirewallPolicy {
    let enable_ipv6 = tunnel_settings.enable_ipv6;
    let allowed_endpoints = api_endpoints
        .iter()
        .filter(|addr| addr.is_ipv4() || (enable_ipv6 && addr.is_ipv6()))
        .map(|addr| {
            AllowedEndpoint::new(
                Endpoint::from_socket_address(*addr, TransportProtocol::Tcp),
                AllowedClients::Root,
            )
        })
        .collect();
    FirewallPolicy::Blocked {
        allow_lan: tunnel_settings.allow_lan,
        allowed_endpoints,
        dns_servers: tunnel_settings.idle_dns_ips(),
    }
}

/// The pins follow the policy: only a Blocked policy built from a live
/// resolution admits addresses worth pinning to.
pub(crate) fn idle_resolver_pins(
    killswitch: bool,
    resolution: Option<&ResolvedConfig>,
) -> Option<ResolverOverrides> {
    resolution
        .filter(|resolved| killswitch && resolved.has_resolver_overrides())
        .map(|resolved| resolved.nym_vpn_api_resolver_overrides.clone())
}

impl SharedState {
    /// Notify discovery and account controller when network is unrestricted.
    async fn allow_networking(&self) {
        self.discovery_refresher_command_tx
            .send(DiscoveryRefresherCommand::Pause(false))
            .ok();
        self.account_command_tx
            .set_vpn_api_firewall_down()
            .await
            .ok();
    }

    /// Notify discovery and account controller when network is restricted.
    async fn disallow_networking(&self) {
        self.discovery_refresher_command_tx
            .send(DiscoveryRefresherCommand::Pause(true))
            .ok();
        self.account_command_tx.set_vpn_api_firewall_up().await.ok();
    }

    /// Set DNS resolver overrides on HTTP clients used by discovery and account controller
    /// Returns `true` on success, otherwise `false`
    async fn set_resolver_overrides(
        &self,
        nym_vpn_api_resolver_overrides: ResolverOverrides,
    ) -> bool {
        self.discovery_refresher_command_tx
            .send(DiscoveryRefresherCommand::UseResolverOverrides(Some(
                Box::new(nym_vpn_api_resolver_overrides.clone()),
            )))
            .ok();
        if let Err(err) = self
            .account_command_tx
            .set_resolver_overrides(Some(nym_vpn_api_resolver_overrides))
            .await
        {
            nym_common::trace_err_chain!(
                err,
                "Failed to set resolver overrides for account controller"
            );
            false
        } else {
            true
        }
    }

    /// Reset DNS resolver overrides on HTTP clients used by discovery and account controller
    async fn reset_resolver_overrides(&self) {
        self.discovery_refresher_command_tx
            .send(DiscoveryRefresherCommand::UseResolverOverrides(None))
            .ok();
        if let Err(err) = self.account_command_tx.set_resolver_overrides(None).await {
            nym_common::trace_err_chain!(err, "Failed to unset static API addresses");
        }
    }

    /// Idle firewall and the pins that go with it (see the module table).
    /// Failures propagate; `DisconnectedState` escalates, `ErrorState` logs.
    async fn enter_idle_firewall(&mut self) -> Result<()> {
        // The firewall caches the kill-switch flag; sync a runtime toggle.
        self.firewall
            .set_killswitch(self.tunnel_settings.killswitch);
        if self.tunnel_settings.killswitch {
            let policy = idle_blocked_policy(&self.tunnel_settings, &self.api_endpoints);
            self.firewall.apply_policy(policy)
        } else {
            self.firewall.reset_policy()
        }
        .map_err(Error::SetFirewallPolicy)?;

        match idle_resolver_pins(
            self.tunnel_settings.killswitch,
            self.api_resolution.as_ref(),
        ) {
            Some(pins) => {
                self.set_resolver_overrides(pins).await;
            }
            None => self.reset_resolver_overrides().await,
        }
        Ok(())
    }

    fn api_endpoints_need_refresh(&self) -> bool {
        api_endpoints_need_refresh(
            self.tunnel_settings.killswitch,
            !self.api_endpoints.is_empty(),
            self.api_endpoints_resolved_at,
            Instant::now(),
        )
    }

    fn api_endpoints_refresh_due(&self) -> Instant {
        match self.api_endpoints_resolved_at {
            Some(at) if !self.api_endpoints.is_empty() => at + API_ENDPOINT_REFRESH_INTERVAL,
            _ => Instant::now(),
        }
    }

    /// The one path that updates the allow-list, so cache and memory agree.
    fn adopt_resolved_api_endpoints(&mut self, resolved: &ResolvedConfig) {
        self.api_endpoints = resolved.all_socket_addrs();
        self.api_resolution = Some(resolved.clone());
        self.api_endpoints_resolved_at = Some(Instant::now());
        api_endpoints_cache::save(self.nym_config.data_path.as_deref(), &self.api_endpoints);
    }

    /// Idle counterpart of Connecting's `handle_resolved_gateway_config`.
    async fn install_idle_api_access(&mut self, resolved: &ResolvedConfig) -> Result<()> {
        self.adopt_resolved_api_endpoints(resolved);
        self.enter_idle_firewall().await?;
        tracing::info!(
            "Kill-switch: admitted {} API endpoint(s) while idle",
            self.api_endpoints.len()
        );
        Ok(())
    }

    /// With the kill-switch on the Blocked policy outlives the daemon: a
    /// restart, upgrade or crash loop must not open WAN egress. Only an
    /// explicit init-script `stop` opens the router.
    fn release_firewall_on_shutdown(&mut self) -> Result<(), nym_firewall::Error> {
        if self.tunnel_settings.killswitch {
            tracing::info!("Kill-switch on: leaving the firewall policy in place on shutdown");
            Ok(())
        } else {
            self.firewall.reset_policy()
        }
    }
}

/// Allow-list upkeep shared by the idle states: resolve when nothing live is
/// known, otherwise wait for the allow-list to age out. Until a resolution
/// succeeds the firewall stays Blocked with whatever the cache offered.
pub(crate) struct IdleApiAccess {
    pub(crate) resolve_fut: Fuse<ResolveApiAddrsFuture>,
    pub(crate) timer_fut: Fuse<BoxFuture<'static, ()>>,
}

impl IdleApiAccess {
    fn new() -> Self {
        Self {
            resolve_fut: Fuse::terminated(),
            timer_fut: Fuse::terminated(),
        }
    }

    pub(crate) fn start(shared_state: &SharedState) -> Self {
        let mut access = Self::new();
        access.schedule(shared_state);
        access
    }

    pub(crate) fn schedule(&mut self, shared_state: &SharedState) {
        let gateway_config = &shared_state.nym_config.gateway_config;
        self.plan(
            shared_state.tunnel_settings.killswitch,
            shared_state.api_endpoints_need_refresh(),
            shared_state.api_endpoints_refresh_due(),
            || resolve_api_endpoints(gateway_config.clone()),
        );
    }

    fn plan(
        &mut self,
        killswitch: bool,
        need_refresh: bool,
        due: Instant,
        resolve: impl FnOnce() -> ResolveApiAddrsFuture,
    ) {
        if !killswitch {
            self.resolve_fut = Fuse::terminated();
            self.timer_fut = Fuse::terminated();
        } else if need_refresh {
            // A settings change must not restart a resolution in flight.
            if !self.resolving() {
                tracing::info!(
                    "Kill-switch on while idle: resolving the API endpoints through the DNS hatch"
                );
                self.resolve_fut = resolve().fuse();
            }
            self.timer_fut = Fuse::terminated();
        } else {
            self.arm_timer(due);
        }
    }

    fn arm_timer(&mut self, due: Instant) {
        self.timer_fut = tokio::time::sleep_until(due.into()).boxed().fuse();
    }

    fn resolving(&self) -> bool {
        !self.resolve_fut.is_terminated()
    }

    #[cfg(test)]
    fn timer_armed(&self) -> bool {
        !self.timer_fut.is_terminated()
    }

    /// `Err` only when the firewall refused the new allow-list; a failed
    /// resolution is retried after [`API_ENDPOINT_RETRY_DELAY`].
    pub(crate) async fn handle_resolved(
        &mut self,
        result: Result<ResolvedConfig>,
        shared_state: &mut SharedState,
    ) -> Result<()> {
        match result {
            Ok(resolved) => {
                shared_state.install_idle_api_access(&resolved).await?;
                self.arm_timer(shared_state.api_endpoints_refresh_due());
            }
            Err(e) => {
                nym_common::trace_err_chain!(
                    e,
                    "Failed to resolve the API endpoints while idle; API access stays blocked, retrying in {:?}",
                    API_ENDPOINT_RETRY_DELAY
                );
                self.arm_timer(Instant::now() + API_ENDPOINT_RETRY_DELAY);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NymConfig {
    pub config_path: Option<PathBuf>,
    pub data_path: Option<PathBuf>,
    pub gateway_config: GatewayDirectoryConfig,
    pub network_rx: watch::Receiver<Box<Network>>,
}

pub struct TunnelStateMachine {
    current_state_handler: Box<dyn TunnelStateHandler>,
    shared_state: SharedState,
    command_receiver: mpsc::UnboundedReceiver<TunnelCommand>,
    event_sender: mpsc::UnboundedSender<TunnelEvent>,
    dns_handler_task: JoinHandle<()>,
    dns_handler_shutdown_token: CancellationToken,
    shutdown_token: CancellationToken,
}

impl TunnelStateMachine {
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        command_receiver: mpsc::UnboundedReceiver<TunnelCommand>,
        event_sender: mpsc::UnboundedSender<TunnelEvent>,
        nym_config: NymConfig,
        tunnel_settings: TunnelSettings,
        tunnel_constants: TunnelConstants,
        account_command_tx: AccountCommandSender,
        account_controller_state: AccountStateReceiver,
        statistics_event_sender: StatisticsSender,
        gateway_cache_handle: GatewayCacheHandle,
        topology_service: VpnTopologyServiceHandle,
        connectivity_handle: ConnectivityHandle,
        discovery_refresher_command_tx: mpsc::UnboundedSender<DiscoveryRefresherCommand>,
        wg_keys_db: WireguardKeysDb,
        route_handler: RouteHandler,
        user_agent: UserAgent,
        shutdown_token: CancellationToken,
    ) -> Result<JoinHandle<()>> {
        let dns_handler_shutdown_token = CancellationToken::new();

        let (dns_handler, dns_handler_task) = DnsHandlerHandle::spawn(
            &route_handler,
            dns_handler_shutdown_token.child_token(),
        )
        .map_err(Error::CreateDnsHandler)?;

        let firewall = Firewall::from_args(FirewallArguments {
            allow_lan: tunnel_settings.allow_lan,
            initial_state: InitialFirewallState::None,
            fwmark: tunnel_constants.fwmark,
            killswitch: tunnel_settings.killswitch,
        })
        .map_err(Error::CreateFirewall)?;

        // The cache only covers the gap until the first live resolution.
        let api_endpoints =
            api_endpoints_cache::load(nym_config.data_path.as_deref());

        let mut shared_state = SharedState {
            route_handler,
            firewall,
            dns_handler,
            connectivity_handle,
            nym_config,
            tunnel_settings,
            tunnel_constants,
            status_listener_handle: None,
            account_command_tx,
            account_controller_state,
            statistics_event_sender,
            gateway_cache_handle,
            topology_service,
            discovery_refresher_command_tx,
            wg_keys_db,
            user_agent,
            blacklisted_entry_gateways: BlacklistedGateways::new(),
            entry_gateway_grace: None,
            api_endpoints,
            api_resolution: None,
            api_endpoints_resolved_at: None,
        };

        let (current_state_handler, _) = if shared_state
            .connectivity_handle
            .connectivity()
            .await
            .is_offline()
        {
            OfflineState::enter(false, None, &mut shared_state).await
        } else {
            DisconnectedState::enter(None, &mut shared_state).await
        };

        let tunnel_state_machine = Self {
            current_state_handler,
            shared_state,
            command_receiver,
            event_sender,
            dns_handler_task,
            dns_handler_shutdown_token,
            shutdown_token,
        };

        Ok(tokio::spawn(tunnel_state_machine.run()))
    }

    async fn run(mut self) {
        loop {
            let next_state = self
                .current_state_handler
                .handle_event(
                    &self.shutdown_token,
                    &mut self.command_receiver,
                    &mut self.shared_state,
                )
                .await;

            match next_state {
                NextTunnelState::NewState((new_state_handler, new_state)) => {
                    self.current_state_handler = new_state_handler;
                    let state = TunnelState::from(new_state);
                    tracing::info!("New tunnel state: {}", state);
                    self.shared_state
                        .statistics_event_sender
                        .report_tunnel_state(state.clone());
                    let _ = self.event_sender.send(TunnelEvent::NewState(state));
                }
                NextTunnelState::SameState(same_state) => {
                    self.current_state_handler = same_state;
                }
                NextTunnelState::Finished => break,
            }
        }

        tracing::debug!("Tunnel state machine is exiting...");

        self.dns_handler_shutdown_token.cancel();
        if let Err(e) = self.dns_handler_task.await {
            tracing::error!("Failed to join on dns handler task: {}", e)
        }

        self.shared_state.route_handler.stop().await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to create a route handler")]
    CreateRouteHandler(#[source] route_handler::Error),

    #[error("failed to create a dns handler")]
    CreateDnsHandler(#[source] dns_handler::Error),

    #[error("failed to create firewall")]
    CreateFirewall(#[source] nym_firewall::Error),

    #[error("failed to set firewall policy")]
    SetFirewallPolicy(#[source] nym_firewall::Error),

    #[error("failed to resolve API hostnames")]
    ResolveApiHostnames(#[source] Box<nym_gateway_directory::Error>),

    #[error("resolving API hostnames took longer than {0:?}")]
    ResolveApiHostnamesTimeout(Duration),

    #[error("failed to create tunnel device")]
    CreateTunDevice(#[source] tun::Error),

    #[error("failed to obtain route handle")]
    GetRouteHandle(#[source] route_handler::Error),

    #[error("failed to get tunnel device name")]
    GetTunDeviceName(#[source] tun::Error),

    #[error("failed to get the interface IP sender")]
    GetInterfaceIpSender,

    #[error("failed to set tunnel device ipv6 address")]
    SetTunDeviceIpv6Addr(#[source] std::io::Error),

    #[error("failed to add routes")]
    AddRoutes(#[source] route_handler::Error),

    #[error("failed to set dns")]
    SetDns(#[source] dns_handler::Error),

    #[error("tunnel error")]
    Tunnel(#[from] Box<tunnel::Error>),

    #[error(transparent)]
    Account(#[from] account::Error),

    #[error("ipv6 is disabled in the system")]
    Ipv6Unavailable,

    #[error("wireguard key database")]
    WireguardKeyDb(#[source] nym_vpn_store::keys::wireguard::KeysDbError),

    #[error("failed to create gateway directory client")]
    GatewayDirectoryClient(#[source] nym_gateway_directory::Error),

    #[error("failed to create icmp probe")]
    CreateIcmpProbe(#[source] nym_connection_monitor::IcmpProbeError),

    #[error("failed to create tcp probe")]
    CreateTcpProbe(#[source] nym_connection_monitor::TcpProbeError),

    #[error("failed to configure probe due to missing IPv4 interface address")]
    ProbeRequiresIPv4Addr,
}

impl Error {
    fn error_state_reason(self) -> Option<ErrorStateReason> {
        Some(match self {
            Self::CreateRouteHandler(_) | Self::CreateDnsHandler(_) | Self::CreateFirewall(_) => {
                None?
            }
            Self::AddRoutes(_) => ErrorStateReason::SetRouting,
            Self::SetDns(_) => ErrorStateReason::SetDns,
            Self::SetFirewallPolicy(_) => ErrorStateReason::SetFirewallPolicy,
            Self::CreateTunDevice(_) => ErrorStateReason::TunDevice,
            Self::SetTunDeviceIpv6Addr(_) => ErrorStateReason::TunDevice,
            Self::GetTunDeviceName(_) => ErrorStateReason::TunDevice,
            Self::GetInterfaceIpSender => ErrorStateReason::Internal(self.to_string()),
            Self::ResolveApiHostnames(_) | Self::ResolveApiHostnamesTimeout(_) => None?,
            Self::Tunnel(e) => e.error_state_reason()?,
            Self::GetRouteHandle(e) => ErrorStateReason::Internal(e.to_string()),
            Self::Account(e) => e.error_state_reason()?,
            Self::Ipv6Unavailable => ErrorStateReason::Ipv6Unavailable,
            Self::WireguardKeyDb(e) => ErrorStateReason::Internal(e.to_string()),
            Self::GatewayDirectoryClient(e) => ErrorStateReason::Internal(e.to_string()),
            Self::CreateIcmpProbe(e) => ErrorStateReason::Internal(e.to_string()),
            Self::CreateTcpProbe(e) => ErrorStateReason::Internal(e.to_string()),
            Self::ProbeRequiresIPv4Addr => ErrorStateReason::Internal(self.to_string()),
        })
    }
}

impl tunnel::Error {
    fn error_state_reason(self) -> Option<ErrorStateReason> {
        match self {
            Self::SelectGateways(e) => match *e {
                GatewayDirectoryError::SameEntryAndExitGateway { .. } => {
                    Some(ErrorStateReason::SameEntryAndExitGateway)
                }
                GatewayDirectoryError::EntryGatewayUnavailable { .. } => {
                    Some(ErrorStateReason::PerformantEntryGatewayUnavailable)
                }
                GatewayDirectoryError::ExitGatewayUnavailable { .. } => {
                    Some(ErrorStateReason::PerformantExitGatewayUnavailable)
                }
                GatewayDirectoryError::SelectEntryGateway(source) => match source {
                    nym_gateway_directory::Error::NoMatchingEntryGatewayForLocation { .. } => {
                        Some(ErrorStateReason::InvalidEntryGatewayCountry)
                    }
                    nym_gateway_directory::Error::NoMatchingGateway { .. } => {
                        Some(ErrorStateReason::InvalidEntryGatewayIdentity)
                    }
                    _ => None,
                },
                GatewayDirectoryError::SelectExitGateway(source) => match source {
                    nym_gateway_directory::Error::NoMatchingExitGatewayForLocation { .. } => {
                        Some(ErrorStateReason::InvalidExitGatewayCountry)
                    }
                    nym_gateway_directory::Error::NoMatchingGateway { .. } => {
                        Some(ErrorStateReason::InvalidExitGatewayIdentity)
                    }
                    _ => None,
                },
                _ => None,
            },
            Self::BandwidthController(BandwidthControllerError::EntryGateway(error)) => {
                if error.is_no_retry() {
                    Some(ErrorStateReason::CredentialWastedOnEntryGateway)
                } else {
                    None
                }
            }
            Self::BandwidthController(BandwidthControllerError::ExitGateway(error)) => {
                if error.is_no_retry() {
                    Some(ErrorStateReason::CredentialWastedOnExitGateway)
                } else {
                    None
                }
            }
            Self::RegistrationClient(e) => match *e {
                nym_registration_client::RegistrationClientError::WireguardEntryRegistrationCredentialSent { .. } => Some(ErrorStateReason::CredentialWastedOnEntryGateway),
                nym_registration_client::RegistrationClientError::WireguardExitRegistrationCredentialSent { .. } => Some(ErrorStateReason::CredentialWastedOnExitGateway),
                _ => None,
            }
            Self::DupFd(_) => Some(ErrorStateReason::Internal(
                "Failed to dup tunnel fd".to_owned(),
            )),
            Self::NoIpAddressAnnounced { .. }
            | Self::MixnetClient(_)
            | Self::BandwidthController(_)
            | Self::Wireguard(_)
            | Self::Cancelled
            | Self::Transport(_) => None,
        }
    }
}

impl account::Error {
    fn error_state_reason(self) -> Option<ErrorStateReason> {
        use nym_vpn_lib_types::AccountControllerError as AcError;
        match self {
            Self::Command(e) => Some(ErrorStateReason::Internal(e.to_string())),
            Self::Cancelled => None,
            Self::ControllerState(e) => match e {
                AcError::Offline => None,
                AcError::NoAccountStored => Some(ErrorStateReason::DeviceLoggedOut),
                AcError::Internal(e) => Some(ErrorStateReason::Internal(e.to_string())),
                AcError::ErrorState(
                    AccountControllerErrorStateReason::AccountStatusNotActive { .. },
                ) => Some(ErrorStateReason::InactiveAccount),
                AcError::ErrorState(AccountControllerErrorStateReason::BandwidthExceeded {
                    ..
                }) => Some(ErrorStateReason::BandwidthExceeded),
                AcError::ErrorState(AccountControllerErrorStateReason::InactiveSubscription) => {
                    Some(ErrorStateReason::InactiveSubscription)
                }
                AcError::ErrorState(AccountControllerErrorStateReason::MaxDeviceReached) => {
                    Some(ErrorStateReason::MaxDevicesReached)
                }
                AcError::ErrorState(AccountControllerErrorStateReason::DeviceTimeDesynced) => {
                    Some(ErrorStateReason::DeviceTimeOutOfSync)
                }
                AcError::ErrorState(AccountControllerErrorStateReason::Internal {
                    context,
                    details,
                }) => Some(ErrorStateReason::Internal(format!(
                    "Internal account controller error: {context} {details}"
                ))),
                AcError::ErrorState(AccountControllerErrorStateReason::Storage {
                    context,
                    details,
                }) => Some(ErrorStateReason::Internal(format!(
                    "Failed to initialize account storage: {context} {details}",
                ))),
                AcError::ErrorState(AccountControllerErrorStateReason::ApiFailure {
                    context,
                    details,
                }) => Some(ErrorStateReason::Internal(format!(
                    "Account API failure: {context} {details}"
                ))),
            },
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<tunnel::Error> for Error {
    fn from(value: tunnel::Error) -> Self {
        Self::Tunnel(Box::new(value))
    }
}

impl From<tunnel::transports::TransportError> for Error {
    fn from(value: tunnel::transports::TransportError) -> Self {
        Self::Tunnel(Box::new(tunnel::Error::Transport(value)))
    }
}

impl From<nym_registration_client::RegistrationClientError> for Error {
    fn from(value: nym_registration_client::RegistrationClientError) -> Self {
        Self::Tunnel(Box::new(tunnel::Error::RegistrationClient(Box::new(value))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> TunnelSettings {
        TunnelSettings {
            enable_ipv6: false,
            tunnel_type: TunnelType::Wireguard,
            allow_lan: true,
            residential_exit: false,
            mixnet_tunnel_options: MixnetTunnelOptions::default(),
            wireguard_tunnel_options: WireguardTunnelOptions::default(),
            gateway_performance_options: GatewayPerformanceOptions::default(),
            mixnet_client_config: None,
            entry_point: Box::new(EntryPoint::Country {
                two_letter_iso_country_code: "DE".to_owned(),
            }),
            exit_point: Box::new(ExitPoint::Country {
                two_letter_iso_country_code: "FR".to_owned(),
            }),
            dns: DnsOptions::Default,
            killswitch: true,
            legacy_split_tunnel: false,
            inbound_exemptions: Vec::new(),
        }
    }

    fn diff_of(mutate: impl FnOnce(&mut TunnelSettings)) -> TunnelSettingsDiff {
        let old = settings();
        let mut new = old.clone();
        mutate(&mut new);
        old.diff(&new).expect("settings must differ")
    }

    fn ep(a: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((a, port))
    }

    fn live_resolution() -> ResolvedConfig {
        ResolvedConfig {
            nyxd_socket_addrs: vec![ep([76, 76, 21, 21], 443)],
            nym_api_resolver_overrides: ResolverOverrides::default(),
            nym_vpn_api_resolver_overrides: ResolverOverrides::from_domain(
                "nymvpn.com",
                [ep([151, 101, 1, 194], 443)],
            ),
        }
    }

    fn never_resolves() -> ResolveApiAddrsFuture {
        futures::future::pending().boxed()
    }

    /// Disconnected and Error both enter through `enter_idle_firewall` and
    /// `IdleApiAccess::start`, so one decision covers both.
    #[tokio::test]
    async fn retained_resolution_pins_on_entry_without_resolving_again() {
        let resolved = live_resolution();
        assert_eq!(
            idle_resolver_pins(true, Some(&resolved)),
            Some(resolved.nym_vpn_api_resolver_overrides.clone())
        );

        let at = Instant::now();
        let mut access = IdleApiAccess::new();
        access.plan(
            true,
            api_endpoints_need_refresh(true, true, Some(at), at),
            at + API_ENDPOINT_REFRESH_INTERVAL,
            never_resolves,
        );
        assert!(!access.resolving());
        assert!(access.timer_armed());
    }

    #[test]
    fn cache_only_start_is_unpinned_with_a_resolution_in_flight() {
        assert_eq!(idle_resolver_pins(true, None), None);

        let now = Instant::now();
        let mut access = IdleApiAccess::new();
        access.plan(
            true,
            api_endpoints_need_refresh(true, true, None, now),
            now,
            never_resolves,
        );
        assert!(access.resolving());
        assert!(!access.timer_armed());
    }

    #[test]
    fn kill_switch_off_neither_pins_nor_refreshes() {
        let resolved = live_resolution();
        assert_eq!(idle_resolver_pins(false, Some(&resolved)), None);

        let mut access = IdleApiAccess::new();
        access.plan(false, false, Instant::now(), never_resolves);
        assert!(!access.resolving());
        assert!(!access.timer_armed());
    }

    #[test]
    fn settings_change_keeps_a_resolution_in_flight() {
        let now = Instant::now();
        let mut access = IdleApiAccess::new();
        access.plan(true, true, now, never_resolves);
        access.plan(true, true, now, || {
            panic!("must not restart the resolution")
        });
        assert!(access.resolving());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_access_refreshes_on_the_interval() {
        let at = Instant::now();
        let mut access = IdleApiAccess::new();
        access.plan(
            true,
            false,
            at + API_ENDPOINT_REFRESH_INTERVAL,
            never_resolves,
        );

        tokio::time::advance(API_ENDPOINT_REFRESH_INTERVAL - Duration::from_secs(1)).await;
        assert!(futures::poll!(&mut access.timer_fut).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures::poll!(&mut access.timer_fut).is_ready());

        // The timer hands back to `schedule`, which now sees a stale stamp.
        let now = at + API_ENDPOINT_REFRESH_INTERVAL + Duration::from_secs(1);
        access.plan(
            true,
            api_endpoints_need_refresh(true, true, Some(at), now),
            now,
            never_resolves,
        );
        assert!(access.resolving());
        assert!(!access.timer_armed());
    }

    #[test]
    fn idle_refresh_is_needed_when_nothing_is_known_or_only_cached() {
        let now = Instant::now();
        assert!(!api_endpoints_need_refresh(false, false, None, now));
        assert!(api_endpoints_need_refresh(true, false, None, now));
        // Cold start from the on-disk cache: known, but never resolved live.
        assert!(api_endpoints_need_refresh(true, true, None, now));
        assert!(api_endpoints_need_refresh(true, false, Some(now), now));
    }

    #[test]
    fn idle_refresh_follows_the_interval() {
        let at = Instant::now();
        assert!(!api_endpoints_need_refresh(true, true, Some(at), at));
        assert!(!api_endpoints_need_refresh(
            true,
            true,
            Some(at),
            at + API_ENDPOINT_REFRESH_INTERVAL - Duration::from_secs(1)
        ));
        assert!(api_endpoints_need_refresh(
            true,
            true,
            Some(at),
            at + API_ENDPOINT_REFRESH_INTERVAL
        ));
    }

    #[test]
    fn idle_policy_without_endpoints_is_blocked_with_none() {
        let mut s = settings();
        s.killswitch = true;
        match idle_blocked_policy(&s, &[]) {
            FirewallPolicy::Blocked {
                allowed_endpoints,
                allow_lan,
                ..
            } => {
                assert!(allowed_endpoints.is_empty());
                assert!(allow_lan);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn idle_policy_admits_resolved_endpoints_for_the_daemon_only() {
        let mut s = settings();
        s.killswitch = true;
        s.enable_ipv6 = false;
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let endpoints = [ep([76, 76, 21, 21], 443), ep([151, 101, 1, 194], 443), v6];
        match idle_blocked_policy(&s, &endpoints) {
            FirewallPolicy::Blocked {
                allowed_endpoints, ..
            } => {
                assert_eq!(allowed_endpoints.len(), 2);
                for ep in &allowed_endpoints {
                    assert_eq!(ep.clients, AllowedClients::Root);
                    assert_eq!(ep.endpoint.protocol, TransportProtocol::Tcp);
                }
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    /// Toggling IPv6 forces a reconnect; it is not a selection input, so the
    /// running pair must survive it.
    #[test]
    fn ipv6_toggle_does_not_affect_gateway_selection() {
        assert!(!diff_of(|s| s.enable_ipv6 = true).affects_gateway_selection());
    }

    #[test]
    fn non_selection_settings_reuse_the_current_pair() {
        assert!(!diff_of(|s| s.killswitch = false).affects_gateway_selection());
        assert!(!diff_of(|s| s.legacy_split_tunnel = true).affects_gateway_selection());
        assert!(
            !diff_of(|s| s.dns = DnsOptions::Custom(vec!["1.1.1.1".parse().unwrap()]))
                .affects_gateway_selection()
        );
        assert!(!diff_of(|s| s.allow_lan = false).affects_gateway_selection());
    }

    #[test]
    fn selection_inputs_force_reselection() {
        assert!(
            diff_of(|s| s.entry_point = Box::new(EntryPoint::Random)).affects_gateway_selection()
        );
        assert!(
            diff_of(|s| s.exit_point = Box::new(ExitPoint::Random)).affects_gateway_selection()
        );
        assert!(diff_of(|s| s.tunnel_type = TunnelType::Mixnet).affects_gateway_selection());
        assert!(diff_of(|s| s.residential_exit = true).affects_gateway_selection());
        assert!(
            diff_of(|s| s.wireguard_tunnel_options.enable_bridges = true)
                .affects_gateway_selection()
        );
        assert!(
            diff_of(|s| s.gateway_performance_options.mixnet_min_performance = Some(80))
                .affects_gateway_selection()
        );
    }

    #[test]
    fn hot_appliable_changes_never_force_reselection() {
        for diff in [
            diff_of(|s| s.allow_lan = false),
            diff_of(|s| {
                s.inbound_exemptions.push(nym_firewall::InboundExemption::new(
                    nym_firewall::TransportProtocol::Tcp,
                    443,
                ))
            }),
        ] {
            assert!(diff.only_hot_appliable_changed());
            assert!(!diff.affects_gateway_selection());
        }
    }
}
