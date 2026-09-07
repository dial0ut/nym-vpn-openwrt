// Copyright 2016-2024 Mullvad VPN AB. All Rights Reserved.
// Copyright 2024 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, net::IpAddr};

use nym_routing::RouteManagerHandle;

#[path = "linux/mod.rs"]
mod imp;

pub use imp::{UpstreamOwner, current_upstream_owner, will_use_nm};

pub use self::imp::Error;

/// DNS configuration
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfig {
    config: InnerDnsConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            config: InnerDnsConfig::Default,
        }
    }
}

impl DnsConfig {
    /// Use the specified addresses for DNS resolution
    pub fn from_addresses(tunnel_config: &[IpAddr], non_tunnel_config: &[IpAddr]) -> Self {
        DnsConfig {
            config: InnerDnsConfig::Override {
                tunnel_config: tunnel_config.to_owned(),
                non_tunnel_config: non_tunnel_config.to_owned(),
            },
        }
    }
}

impl DnsConfig {
    pub fn resolve(&self, default_tun_config: &[IpAddr]) -> ResolvedDnsConfig {
        match &self.config {
            InnerDnsConfig::Default => ResolvedDnsConfig {
                tunnel_config: default_tun_config.to_owned(),
                non_tunnel_config: vec![],
            },
            InnerDnsConfig::Override {
                tunnel_config,
                non_tunnel_config,
            } => ResolvedDnsConfig {
                tunnel_config: tunnel_config.to_owned(),
                non_tunnel_config: non_tunnel_config.to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum InnerDnsConfig {
    /// Use gateway addresses from the tunnel config
    Default,
    /// Use the specified addresses for DNS resolution
    Override {
        /// Addresses to configure on the tunnel interface
        tunnel_config: Vec<IpAddr>,
        /// Addresses to allow on non-tunnel interface.
        /// For the most part, the tunnel state machine will not handle any of this configuration
        /// on non-tunnel interface, only allow them in the firewall.
        non_tunnel_config: Vec<IpAddr>,
    },
}

/// DNS configuration with `DnsConfig::Default` resolved
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDnsConfig {
    /// Addresses to configure on the tunnel interface
    tunnel_config: Vec<IpAddr>,
    /// Addresses to allow on non-tunnel interface.
    /// For the most part, the tunnel state machine will not handle any of this configuration
    /// on non-tunnel interface, only allow them in the firewall.
    non_tunnel_config: Vec<IpAddr>,
}

impl fmt::Display for ResolvedDnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tunnel DNS: ")?;
        Self::fmt_addr_set(f, &self.tunnel_config)?;

        f.write_str(" Non-tunnel DNS: ")?;
        Self::fmt_addr_set(f, &self.non_tunnel_config)?;

        Ok(())
    }
}

impl ResolvedDnsConfig {
    fn fmt_addr_set(f: &mut fmt::Formatter<'_>, addrs: &[IpAddr]) -> fmt::Result {
        f.write_str("{")?;
        for (i, addr) in addrs.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{addr}")?;
        }
        f.write_str("}")
    }

    /// Addresses to configure on the tunnel interface
    pub fn tunnel_config(&self) -> &[IpAddr] {
        &self.tunnel_config
    }

    /// Addresses to allow on non-tunnel interface.
    /// For the most part, the tunnel state machine will not handle any of this configuration
    /// on non-tunnel interface, only allow them in the firewall.
    pub fn non_tunnel_config(&self) -> &[IpAddr] {
        &self.non_tunnel_config
    }

    /// Consume `self` and return a vector of all addresses
    pub fn addresses(self) -> impl Iterator<Item = IpAddr> {
        self.non_tunnel_config.into_iter().chain(self.tunnel_config)
    }

    /// Return whether the config contains only (and at least one) loopback addresses, and zero
    /// non-loopback addresses
    pub fn is_loopback(&self) -> bool {
        let (loopback_addrs, non_loopback_addrs) = self
            .tunnel_config
            .iter()
            .chain(self.non_tunnel_config.iter())
            .copied()
            .partition::<Vec<_>, _>(|ip| ip.is_loopback());

        !loopback_addrs.is_empty() && non_loopback_addrs.is_empty()
    }
}

/// What the system resolver should use while the tunnel is down.
///
/// Only the OpenWrt dnsmasq backend acts on this; every other backend treats
/// an idle reset as a plain [`DnsMonitor::reset`]. `local_resolvers` are the
/// user's custom DNS servers on private addresses (a LAN Pi-hole): the
/// kill-switch admits them on every interface but the WAN, so they keep
/// working while disconnected. The WAN-provided resolvers are kept only when
/// the kill-switch is off or there is no local resolver: with the kill-switch
/// on they are unreachable, and listing them would only make dnsmasq burn its
/// retries on rejected upstreams.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdleDns {
    pub local_resolvers: Vec<IpAddr>,
    pub killswitch: bool,
}

impl IdleDns {
    /// The stock behaviour: mirror whatever the WAN handed out.
    pub fn wan_only() -> Self {
        Self::default()
    }

    /// Whether the WAN-provided resolvers belong in the idle resolv file.
    pub fn includes_wan(&self) -> bool {
        !self.killswitch || self.local_resolvers.is_empty()
    }
}

/// Sets and monitors system DNS settings. Makes sure the desired DNS servers are being used.
pub struct DnsMonitor {
    inner: imp::DnsMonitor,
}

impl DnsMonitor {
    /// Returns a new `DnsMonitor` that can set and monitor the system DNS.
    pub fn new(route_manager: RouteManagerHandle) -> Result<Self, Error> {
        Ok(DnsMonitor {
            inner: imp::DnsMonitor::new(route_manager)?,
        })
    }

    /// Set DNS to the given servers. And start monitoring the system for changes.
    pub async fn set(&mut self, interface: &str, config: ResolvedDnsConfig) -> Result<(), Error> {
        tracing::info!("Setting DNS servers: {config}");
        self.inner.set(interface, config).await
    }

    /// Reset system DNS settings to what it was before being set by this instance.
    /// This succeeds if the interface does not exist.
    pub async fn reset(&mut self) -> Result<(), Error> {
        tracing::info!("Resetting DNS");
        self.inner.reset().await
    }

    /// Reset system DNS for the idle (tunnel down) state, keeping the user's
    /// private custom resolvers in play where the backend supports it.
    pub async fn reset_idle(&mut self, idle: IdleDns) -> Result<(), Error> {
        tracing::info!(
            "Resetting DNS for idle: local resolvers {:?}, WAN resolvers {}",
            idle.local_resolvers,
            if idle.includes_wan() {
                "kept"
            } else {
                "dropped (kill-switch on)"
            }
        );
        self.inner.reset_idle(idle).await
    }

    /// Reset DNS settings to what they were before being set by this instance.
    /// If the settings only affect a specific interface, this can be a no-op,
    /// as the interface will be destroyed.
    pub async fn reset_before_interface_removal(&mut self) -> Result<(), Error> {
        tracing::info!("Resetting DNS");
        self.inner.reset_before_interface_removal().await
    }
}

trait DnsMonitorT: Sized {
    type Error: std::error::Error;

    fn new(route_manager: RouteManagerHandle) -> Result<Self, Self::Error>;

    async fn set(&mut self, interface: &str, servers: ResolvedDnsConfig)
    -> Result<(), Self::Error>;

    async fn reset(&mut self) -> Result<(), Self::Error>;

    async fn reset_idle(&mut self, _idle: IdleDns) -> Result<(), Self::Error> {
        self.reset().await
    }

    async fn reset_before_interface_removal(&mut self) -> Result<(), Self::Error> {
        self.reset().await
    }
}
