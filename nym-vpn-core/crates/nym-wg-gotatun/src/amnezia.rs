//! Amnezia WireGuard configuration.
//!
//! This module defines the [`AmneziaConfig`] type which parameterizes AmneziaWG obfuscation.
//! The config is applied to the gotatun backend via [`crate::amnezia_udp::AmneziaUdpFactory`].

use rand::{Rng, RngCore};

const OFF: AmneziaConfig = AmneziaConfig {
    junk_pkt_count: 0,
    junk_pkt_min_size: 0,
    junk_pkt_max_size: 0,
    init_pkt_junk_size: 0,
    response_pkt_junk_size: 0,
    init_pkt_magic_header: 1,
    response_pkt_magic_header: 2,
    under_load_pkt_magic_header: 3,
    transport_pkt_magic_header: 4,
};

const BASE: AmneziaConfig = AmneziaConfig {
    junk_pkt_count: 4,
    junk_pkt_min_size: 40,
    junk_pkt_max_size: 70,
    init_pkt_junk_size: 0,
    response_pkt_junk_size: 0,
    init_pkt_magic_header: 1,
    response_pkt_magic_header: 2,
    under_load_pkt_magic_header: 3,
    transport_pkt_magic_header: 4,
};

/// Amnezia WireGuard configuration parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct AmneziaConfig {
    pub junk_pkt_count: u8,
    pub junk_pkt_min_size: u16,
    pub junk_pkt_max_size: u16,
    pub init_pkt_junk_size: u16,
    pub response_pkt_junk_size: u16,
    pub init_pkt_magic_header: i32,
    pub response_pkt_magic_header: i32,
    pub under_load_pkt_magic_header: i32,
    pub transport_pkt_magic_header: i32,
}

impl Default for AmneziaConfig {
    fn default() -> Self {
        OFF.clone()
    }
}

impl AmneziaConfig {
    /// Disabled Amnezia Configuration
    pub const OFF: Self = OFF;
    /// Enables only the minimum Amnezia features, while ensuring compatibility with plain
    /// wireguard peers.
    pub const BASE: Self = BASE;

    /// Creates a randomized configuration with parameters within suggested ranges.
    pub fn rand(rng: &mut impl RngCore) -> Self {
        for _ in 0..16 {
            let c = Self {
                junk_pkt_count: rng.gen_range(3..10),
                junk_pkt_min_size: rng.gen_range(0..900),
                junk_pkt_max_size: 1000,
                init_pkt_junk_size: rng.gen_range(15..150),
                response_pkt_junk_size: rng.gen_range(15..150),
                init_pkt_magic_header: rng.gen_range(5..i32::MAX),
                response_pkt_magic_header: rng.gen_range(5..i32::MAX),
                under_load_pkt_magic_header: rng.gen_range(5..i32::MAX),
                transport_pkt_magic_header: rng.gen_range(5..i32::MAX),
            };
            if c.validate() {
                return c;
            }
        }
        panic!("this should not be possible");
    }

    /// Returns true if this config represents Amnezia being disabled.
    pub fn is_off(&self) -> bool {
        *self == OFF
    }

    /// Check if the provided configuration is valid
    pub fn validate(&self) -> bool {
        if self.junk_pkt_count > 128
            || self.junk_pkt_max_size > 1280
            || self.junk_pkt_min_size > self.junk_pkt_max_size
            || self.init_pkt_junk_size > 1280
            || self.response_pkt_junk_size > 1280
            || [
                self.response_pkt_magic_header,
                self.under_load_pkt_magic_header,
                self.transport_pkt_magic_header,
            ]
            .contains(&self.init_pkt_magic_header)
            || [
                self.init_pkt_magic_header,
                self.under_load_pkt_magic_header,
                self.transport_pkt_magic_header,
            ]
            .contains(&self.response_pkt_magic_header)
            || [
                self.init_pkt_magic_header,
                self.response_pkt_magic_header,
                self.transport_pkt_magic_header,
            ]
            .contains(&self.under_load_pkt_magic_header)
            || [
                self.init_pkt_magic_header,
                self.response_pkt_magic_header,
                self.under_load_pkt_magic_header,
            ]
            .contains(&self.transport_pkt_magic_header)
        {
            return false;
        }
        true
    }
}
