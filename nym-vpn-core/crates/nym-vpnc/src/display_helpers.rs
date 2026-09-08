// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_vpn_lib_types::{ErrorStateReason, GatewayIndependence};

pub fn display_on_off(value: bool) -> &'static str {
    match value {
        true => "on",
        false => "off",
    }
}

/// The tunnel monitor negotiates LP per registration and never consults the
/// stored `enable_lewes_protocol` flag, so the CLI reports "auto".
pub const LEWES_PROTOCOL_STATE: &str = "auto";

/// Shared with the rpcd bridge's `raw_config` reconstruction.
pub const LEWES_PROTOCOL_LINE: &str = "Lewes protocol: auto (used when the gateway supports it)";

/// `tunnel get` value for the gateway independence criteria: "on" followed by
/// the active criteria, or "off". Shared with the rpcd bridge's `raw_config`.
pub fn gateway_independence_summary(gateway_independence: &GatewayIndependence) -> String {
    if !gateway_independence.active() {
        return "off".to_owned();
    }
    let mut criteria = Vec::new();
    if gateway_independence.different_node_family {
        criteria.push("family");
    }
    if gateway_independence.different_asn {
        criteria.push("ASN");
    }
    if gateway_independence.different_subnet {
        criteria.push("subnet");
    }
    format!("on ({})", criteria.join(", "))
}

/// What to do about an entry/exit pair the independence criteria rule out.
pub const RELAX_INDEPENDENCE_HINT: &str = "the selected entry and exit are not independent \
                                           (same operator family/ASN/subnet); reconnect with \
                                           --relax-independence or change gateways";

/// Advice for error states the user can act on themselves.
pub fn error_state_hint(reason: &ErrorStateReason) -> Option<&'static str> {
    match reason {
        ErrorStateReason::NeedsRelaxedIndependenceCriteria => Some(RELAX_INDEPENDENCE_HINT),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relax_hint_is_a_single_line_without_runs_of_spaces() {
        assert!(!RELAX_INDEPENDENCE_HINT.contains('\n'));
        assert!(!RELAX_INDEPENDENCE_HINT.contains("  "));
        assert!(RELAX_INDEPENDENCE_HINT.contains("(same operator family/ASN/subnet)"));
    }

    #[test]
    fn independence_summary_lists_active_criteria() {
        assert_eq!(
            gateway_independence_summary(&GatewayIndependence::default()),
            "on (family, ASN, subnet)"
        );
        assert_eq!(
            gateway_independence_summary(&GatewayIndependence::disabled()),
            "off"
        );
        let asn_only = GatewayIndependence {
            different_node_family: false,
            different_asn: true,
            different_subnet: false,
            ..Default::default()
        };
        assert_eq!(gateway_independence_summary(&asn_only), "on (ASN)");
    }
}
