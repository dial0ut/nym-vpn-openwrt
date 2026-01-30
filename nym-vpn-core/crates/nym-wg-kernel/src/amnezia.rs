// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Amnezia-WireGuard configuration for kernel netlink interface
//!
//! This module provides the `AmneziaConfig` struct for configuring Amnezia-WireGuard
//! obfuscation parameters. These parameters are sent via netlink attributes to the
//! amneziawg kernel module.
//!
//! All parameters except Jc must match between client and server for the connection
//! to work. The Jc (junk packet count) can vary between endpoints.

use crate::DeviceNla;

/// Predefined OFF configuration (no obfuscation)
///
/// Uses default WireGuard packet headers (1, 2, 3, 4) with no junk packets.
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

/// Predefined BASE configuration (minimal obfuscation)
///
/// Adds junk packets before handshake but keeps standard packet headers,
/// maintaining compatibility with plain WireGuard peers that support it.
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

/// Amnezia-WireGuard obfuscation configuration
///
/// All parameters should be the same between Client and Server, except Jc - it can vary.
///
/// ## Parameter Constraints
///
/// - **Jc**: 1 ≤ Jc ≤ 128; recommended range is 3 to 10 inclusive
/// - **Jmin**: Jmin < Jmax; recommended value is 50
/// - **Jmax**: Jmin < Jmax ≤ 1280; recommended value is 1000
/// - **S1**: S1 < 1280; S1 + 56 ≠ S2; recommended range is 15 to 150 inclusive
/// - **S2**: S2 < 1280; recommended range is 15 to 150 inclusive
/// - **H1/H2/H3/H4**: must be unique among each other;
///   recommended range is from 5 to 2^31 - 1 inclusive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziaConfig {
    /// Jc - Count of junk packets to send BEFORE sending the handshake Init message
    pub junk_pkt_count: u8,
    /// Jmin - Minimum size in bytes of the junk packets
    pub junk_pkt_min_size: u16,
    /// Jmax - Maximum size in bytes of the junk packets
    pub junk_pkt_max_size: u16,
    /// S1 - Number of bytes to PREPEND to the Handshake init message
    pub init_pkt_junk_size: u16,
    /// S2 - Number of bytes to PREPEND to the Handshake response message
    pub response_pkt_junk_size: u16,
    /// H1 - Re-map handshake Init packet header type indicator to this value
    pub init_pkt_magic_header: i32,
    /// H2 - Re-map handshake response packet header type indicator to this value
    pub response_pkt_magic_header: i32,
    /// H3 - Re-map under load packet header type indicator to this value
    pub under_load_pkt_magic_header: i32,
    /// H4 - Re-map transport packet header type indicator to this value
    pub transport_pkt_magic_header: i32,
}

impl Default for AmneziaConfig {
    fn default() -> Self {
        OFF
    }
}

impl AmneziaConfig {
    /// Disabled Amnezia configuration - runs as standard WireGuard
    pub const OFF: Self = OFF;

    /// Base Amnezia configuration with minimal obfuscation
    ///
    /// Adds junk packets before handshake but keeps standard packet headers.
    pub const BASE: Self = BASE;

    /// Returns true if this is the OFF configuration (no obfuscation)
    pub fn is_off(&self) -> bool {
        self == &OFF
    }

    /// Convert to DeviceNla attributes for netlink transmission
    ///
    /// Returns an empty vec if the config is OFF (standard WireGuard).
    pub fn to_device_nlas(&self) -> Vec<DeviceNla> {
        if self.is_off() {
            return vec![];
        }

        vec![
            DeviceNla::Jc(self.junk_pkt_count as u32),
            DeviceNla::Jmin(self.junk_pkt_min_size as u32),
            DeviceNla::Jmax(self.junk_pkt_max_size as u32),
            DeviceNla::S1(self.init_pkt_junk_size as u32),
            DeviceNla::S2(self.response_pkt_junk_size as u32),
            DeviceNla::H1(self.init_pkt_magic_header),
            DeviceNla::H2(self.response_pkt_magic_header),
            DeviceNla::H3(self.under_load_pkt_magic_header),
            DeviceNla::H4(self.transport_pkt_magic_header),
        ]
    }

    /// Validate the configuration parameters
    ///
    /// Checks that all parameters are within valid ranges and that
    /// H1, H2, H3, H4 are all unique values.
    pub fn validate(&self) -> bool {
        // Check numeric ranges
        if self.junk_pkt_count > 128
            || self.junk_pkt_max_size > 1280
            || self.junk_pkt_min_size > self.junk_pkt_max_size
            || self.init_pkt_junk_size > 1280
            || self.response_pkt_junk_size > 1280
        {
            return false;
        }

        // H1, H2, H3, H4 must all be unique
        let headers = [
            self.init_pkt_magic_header,
            self.response_pkt_magic_header,
            self.under_load_pkt_magic_header,
            self.transport_pkt_magic_header,
        ];

        for i in 0..headers.len() {
            for j in (i + 1)..headers.len() {
                if headers[i] == headers[j] {
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_off_is_default() {
        assert_eq!(AmneziaConfig::default(), AmneziaConfig::OFF);
    }

    #[test]
    fn test_off_is_off() {
        assert!(AmneziaConfig::OFF.is_off());
    }

    #[test]
    fn test_base_is_not_off() {
        assert!(!AmneziaConfig::BASE.is_off());
    }

    #[test]
    fn test_off_produces_no_nlas() {
        assert!(AmneziaConfig::OFF.to_device_nlas().is_empty());
    }

    #[test]
    fn test_base_produces_nlas() {
        let nlas = AmneziaConfig::BASE.to_device_nlas();
        assert!(!nlas.is_empty());
        assert_eq!(nlas.len(), 9); // Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4
    }

    #[test]
    fn test_validation_off() {
        assert!(AmneziaConfig::OFF.validate());
    }

    #[test]
    fn test_validation_base() {
        assert!(AmneziaConfig::BASE.validate());
    }

    #[test]
    fn test_validation_duplicate_h_values() {
        let invalid = AmneziaConfig {
            init_pkt_magic_header: 1,
            response_pkt_magic_header: 1, // Duplicate!
            ..AmneziaConfig::BASE
        };
        assert!(!invalid.validate());
    }

    #[test]
    fn test_validation_jmax_too_large() {
        let invalid = AmneziaConfig {
            junk_pkt_max_size: 1500, // > 1280
            ..AmneziaConfig::BASE
        };
        assert!(!invalid.validate());
    }

    #[test]
    fn test_validation_jmin_greater_than_jmax() {
        let invalid = AmneziaConfig {
            junk_pkt_min_size: 100,
            junk_pkt_max_size: 50, // min > max
            ..AmneziaConfig::BASE
        };
        assert!(!invalid.validate());
    }
}
