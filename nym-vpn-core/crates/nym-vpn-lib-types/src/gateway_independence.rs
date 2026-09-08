// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway independence: the criteria under which an entry and an exit gateway
//! are considered to belong to unrelated operators, so that no single party
//! sees both ends of the two-hop tunnel.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "typescript-bindings")]
use ts_rs::TS;

use crate::Gateway;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct GatewayIndependence {
    /// Remind the user when the selected pair is not independent.
    pub enable_notifications: bool,
    /// Entry and exit must not share a node family.
    pub different_node_family: bool,
    /// Entry and exit must sit in different autonomous systems.
    pub different_asn: bool,
    /// Entry and exit must sit in non-overlapping announced prefixes.
    pub different_subnet: bool,
}

impl GatewayIndependence {
    /// Turn every criterion on or off at once; notifications are untouched.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.different_node_family = enabled;
        self.different_asn = enabled;
        self.different_subnet = enabled;
    }

    /// Every criterion off, notifications left at their default.
    pub fn disabled() -> Self {
        let mut criteria = Self::default();
        criteria.set_enabled(false);
        criteria
    }

    /// At least one criterion is on.
    pub fn active(&self) -> bool {
        self.different_node_family || self.different_asn || self.different_subnet
    }

    pub fn full_disabled(&self) -> bool {
        !self.different_node_family && !self.different_asn && !self.different_subnet
    }

    pub fn full_enabled(&self) -> bool {
        self.different_node_family && self.different_asn && self.different_subnet
    }
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

impl fmt::Display for GatewayIndependence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "enabled notifications: {}; ", self.enable_notifications)?;
        write!(
            f,
            "different node family: {}; different asn: {}; different subnet: {}",
            self.different_node_family, self.different_asn, self.different_subnet
        )
    }
}

/// The pair the daemon would most likely connect through right now, computed
/// from the live settings without touching key material or the tunnel.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub enum TentativeGateways {
    /// A pair satisfying the settings (and the independence criteria, when
    /// active) exists.
    Selected {
        entry: Box<Gateway>,
        exit: Box<Gateway>,
    },
    /// A pair exists only once the independence criteria are relaxed.
    NeedsRelaxedIndependenceCriteria,
    /// No pair satisfies the settings even with the criteria relaxed.
    NoGatewaysAvailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_both_criteria_active() {
        let gi = GatewayIndependence::default();
        assert!(gi.different_node_family);
        assert!(gi.different_asn);
    }

    #[test]
    fn deactivated_has_no_criteria() {
        let gi = GatewayIndependence {
            different_node_family: false,
            different_asn: false,
            different_subnet: false,
            ..Default::default()
        };
        assert!(!gi.different_node_family);
        assert!(!gi.different_asn);
    }

    #[test]
    fn active_returns_true_for_default() {
        assert!(GatewayIndependence::default().active());
    }

    #[test]
    fn active_returns_false_when_fully_deactivated() {
        assert!(
            !GatewayIndependence {
                different_node_family: false,
                different_asn: false,
                different_subnet: false,
                ..Default::default()
            }
            .active()
        );
    }

    #[test]
    fn active_returns_true_with_only_asn_enabled() {
        let gi = GatewayIndependence {
            different_asn: true,
            different_node_family: false,
            different_subnet: false,
            ..Default::default()
        };
        assert!(gi.active());
    }

    #[test]
    fn active_returns_true_with_only_family_enabled() {
        let gi = GatewayIndependence {
            different_asn: false,
            different_node_family: true,
            different_subnet: false,
            ..Default::default()
        };
        assert!(gi.active());
    }

    #[test]
    fn active_returns_true_with_only_subnet_enabled() {
        let gi = GatewayIndependence {
            different_asn: false,
            different_node_family: false,
            different_subnet: true,
            ..Default::default()
        };
        assert!(gi.active());
    }

    #[test]
    fn set_enabled_toggles_every_criterion_but_not_notifications() {
        let mut gi = GatewayIndependence {
            enable_notifications: false,
            ..Default::default()
        };
        gi.set_enabled(false);
        assert!(gi.full_disabled());
        assert!(!gi.enable_notifications);
        gi.set_enabled(true);
        assert!(gi.full_enabled());
        assert!(!gi.enable_notifications);
        assert!(GatewayIndependence::disabled().full_disabled());
        assert!(GatewayIndependence::disabled().enable_notifications);
    }
}
