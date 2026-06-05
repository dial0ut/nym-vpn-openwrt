// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use nym_registration_common::WireguardConfiguration;
use nym_wg_gotatun::{PresharedKey, PrivateKey, PublicKey, amnezia::AmneziaConfig};
use nym_wg_gotatun::PeerConfig;
use nym_wg_gotatun::wireguard_go;

#[derive(Debug, Clone)]
pub struct WgNodeConfig {
    /// Interface configuration
    pub interface: WgInterface,

    /// Peer configuration
    pub peer: WgPeer,

    /// IPs that are allowed to be routed over the tunnel interface.
    pub allowed_ips: AllowedIps,
}

#[derive(Clone)]
pub struct WgInterface {
    /// WG client port.
    pub listen_port: Option<u16>,

    /// Private key used by wg client.
    pub private_key: PrivateKey,

    /// Addresses assigned on wg interface.
    pub addresses: Vec<IpNetwork>,

    /// DNS addresses.
    pub dns: Vec<IpAddr>,

    /// Device MTU.
    pub mtu: u16,

    /// Mark used for mark-based routing.
    pub fwmark: Option<u32>,

    /// Amnezia Configuration
    pub azwg_config: Option<nym_wg_gotatun::amnezia::AmneziaConfig>,
}

impl fmt::Debug for WgInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("WgInterface");
        d.field("listen_port", &self.listen_port)
            .field("private_key", &"(hidden)")
            .field("address", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu);
        d.field("fwmark", &self.fwmark);
        d.field("amnezia", &self.azwg_config);
        d.finish()
    }
}

/// IPs that are allowed to be routed over the tunnel interface.
#[derive(Debug, Clone)]
pub enum AllowedIps {
    /// All IPs are allowed.
    All,

    /// Specific IPs are allowed.
    Specific(Vec<IpNetwork>),
}

#[derive(Clone)]
pub struct WgPeer {
    /// Gateway public key.
    pub public_key: PublicKey,

    /// Optional WireGuard pre-shared key. Populated only on the Lewes Protocol
    /// path (the post-quantum PSK derived by nym-lp); `None` on the legacy path.
    pub preshared_key: Option<PresharedKey>,

    /// Gateway endpoint
    pub endpoint: SocketAddr,
}

impl fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("WgPeer")
            .field("public_key", &self.public_key)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "(hidden)"))
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl WgNodeConfig {
    pub fn into_wireguard_config(self) -> wireguard_go::Config {
        let allowed_ips = self.allowed_ips();
        wireguard_go::Config {
            interface: wireguard_go::InterfaceConfig {
                listen_port: self.interface.listen_port,
                private_key: self.interface.private_key,
                mtu: self.interface.mtu,
                fwmark: self.interface.fwmark,
                azwg_config: self.interface.azwg_config,
            },
            peers: vec![PeerConfig {
                public_key: self.peer.public_key,
                preshared_key: self.peer.preshared_key,
                endpoint: self.peer.endpoint,
                allowed_ips,
            }],
        }
    }

    pub fn allowed_ips(&self) -> Vec<IpNetwork> {
        let mut allowed_ips = vec![];
        match self.allowed_ips {
            AllowedIps::All => {
                if self.interface.addresses.iter().any(|x| x.ip().is_ipv4()) {
                    allowed_ips.push("0.0.0.0/0".parse().unwrap());
                }
                if self.interface.addresses.iter().any(|x| x.ip().is_ipv6()) {
                    allowed_ips.push("::/0".parse().unwrap());
                }
            }
            AllowedIps::Specific(ref ips) => {
                allowed_ips.extend(ips);
            }
        }
        allowed_ips
    }
}

impl WgNodeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn with_gateway_data(
        gateway_data: &WireguardConfiguration,
        endpoint: SocketAddr,
        private_key: &nym_crypto::asymmetric::encryption::PrivateKey,
        allowed_ips: AllowedIps,
        dns: Vec<IpAddr>,
        mtu: u16,
        enable_ipv6: bool,
        fwmark: Option<u32>,
    ) -> Self {
        // Build address list based on IPv6 setting
        // Some systems (e.g., GL.iNet routers) have IPv6 disabled at kernel level
        // and will reject IPv6 address assignment via netlink
        let mut addresses = vec![IpNetwork::V4(Ipv4Network::from(gateway_data.private_ipv4))];
        if enable_ipv6 {
            addresses.push(IpNetwork::V6(Ipv6Network::from(gateway_data.private_ipv6)));
        }

        Self {
            interface: WgInterface {
                listen_port: None,
                private_key: PrivateKey::from(private_key.to_bytes()),
                addresses,
                dns,
                mtu,
                fwmark,
                azwg_config: Some(AmneziaConfig::OFF),
            },
            peer: WgPeer {
                public_key: PublicKey::from(*gateway_data.public_key.as_bytes()),
                // Carries the post-quantum PSK on the Lewes path; None on legacy
                // (gateway_data.psk is None until LP registration is enabled).
                preshared_key: gateway_data
                    .psk
                    .as_ref()
                    .map(|psk| PresharedKey::from(*psk.as_bytes())),
                endpoint,
            },
            allowed_ips,
        }
    }

    /// Enable Amnezia wireguard features
    pub fn with_amnezia_config(mut self, azwg_config: AmneziaConfig) -> Self {
        self.interface.azwg_config = Some(azwg_config);
        self
    }
}
