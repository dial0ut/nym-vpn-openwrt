// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Stub netstack types.
//!
//! gotatun does not have a netstack equivalent. These types exist only so that
//! shared config-building code (e.g. `WgNodeConfig::into_netstack_config`)
//! continues to compile. They are never used to start a tunnel on Linux.

use std::net::IpAddr;

use crate::{PeerConfig, PrivateKey};
#[cfg(feature = "amnezia")]
use crate::amnezia::AmneziaConfig;

/// Netstack interface configuration (stub).
pub struct InterfaceConfig {
    pub private_key: PrivateKey,
    pub local_addrs: Vec<IpAddr>,
    pub dns_addrs: Vec<IpAddr>,
    pub mtu: u16,
    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
    #[cfg(feature = "amnezia")]
    pub azwg_config: Option<AmneziaConfig>,
}

/// Netstack tunnel configuration (stub).
pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}
