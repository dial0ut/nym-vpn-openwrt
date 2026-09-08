// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway independence: whether an entry and an exit gateway can be assumed
//! to be run by unrelated parties, so that nobody sees both ends of the tunnel.

use nym_gateway_directory::Gateway;
use nym_vpn_lib_types::GatewayIndependence;

/// A criterion two gateways failed to satisfy, for logs and error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndependenceViolation {
    SameGateway,
    SameAsn,
    MissingAsn,
    SameNodeFamily,
    OverlappingSubnet,
    MissingSubnet,
}

impl IndependenceViolation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SameGateway => "same gateway",
            Self::SameAsn => "same ASN",
            Self::MissingAsn => "ASN unknown",
            Self::SameNodeFamily => "same node family",
            Self::OverlappingSubnet => "overlapping subnet",
            Self::MissingSubnet => "subnet unknown",
        }
    }
}

/// Every criterion in `criteria` that `gw1` and `gw2` fail. Empty means the
/// pair is independent.
pub(crate) fn independence_violations(
    gw1: &Gateway,
    gw2: &Gateway,
    criteria: GatewayIndependence,
) -> Vec<IndependenceViolation> {
    let mut violations = Vec::new();
    if gw1.identity() == gw2.identity() {
        violations.push(IndependenceViolation::SameGateway);
        return violations;
    }
    let asn1 = gw1.location.as_ref().and_then(|l| l.asn.as_ref());
    let asn2 = gw2.location.as_ref().and_then(|l| l.asn.as_ref());
    if criteria.different_asn {
        match (asn1, asn2) {
            // all gateways should have an ASN, if they don't we assume they can't be independent
            (Some(asn1), Some(asn2)) => {
                if asn1.asn == asn2.asn {
                    violations.push(IndependenceViolation::SameAsn);
                }
            }
            _ => violations.push(IndependenceViolation::MissingAsn),
        }
    }
    // node family not present is assumed that they are independent, as no node family is the
    // default node configuration
    if criteria.different_node_family
        && let (Some(nf1), Some(nf2)) = (&gw1.family_data, &gw2.family_data)
        && nf1.id == nf2.id
    {
        violations.push(IndependenceViolation::SameNodeFamily);
    }
    if criteria.different_subnet {
        match (asn1.and_then(|a| a.route), asn2.and_then(|a| a.route)) {
            // all gateways should have an ASN with a route, if they don't we assume they can't be
            // independent
            (Some(route1), Some(route2)) => {
                let overlaps = match (route1, route2) {
                    (ipnetwork::IpNetwork::V4(v4_route1), ipnetwork::IpNetwork::V4(v4_route2)) => {
                        v4_route1.overlaps(v4_route2)
                    }
                    (ipnetwork::IpNetwork::V6(v6_route1), ipnetwork::IpNetwork::V6(v6_route2)) => {
                        v6_route1.overlaps(v6_route2)
                    }
                    _ => false,
                };
                if overlaps {
                    violations.push(IndependenceViolation::OverlappingSubnet);
                }
            }
            _ => violations.push(IndependenceViolation::MissingSubnet),
        }
    }
    violations
}

/// Whether `gw1` and `gw2` satisfy every active criterion. The same gateway is
/// never independent of itself, whatever the criteria.
pub(crate) fn gateways_are_independent(
    gw1: &Gateway,
    gw2: &Gateway,
    criteria: GatewayIndependence,
) -> bool {
    independence_violations(gw1, gw2, criteria).is_empty()
}

/// Human-readable list of failed criteria, e.g. "same ASN, overlapping subnet".
pub(crate) fn describe_violations(violations: &[IndependenceViolation]) -> String {
    violations
        .iter()
        .map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use ipnetwork::IpNetwork;
    use nym_gateway_directory::{Asn, AsnKind, Gateway, Location, NodeFamily};

    use super::*;

    const GW_ID_1: &str = "2zHiExNRKiCXVKS35SNKtK4apGfZELMpA1jJ2gVevJoz";
    const GW_ID_2: &str = "38zcSsvjXsAX7C28ko2H3Lt55X4TYxfZYkPADxKXZHUj";

    fn make_gateway(id: &str) -> Gateway {
        Gateway::builder().identity(id.parse().unwrap()).build()
    }

    fn make_gateway_with_asn(id: &str, asn_number: &str) -> Gateway {
        Gateway::builder()
            .identity(id.parse().unwrap())
            .location(Location {
                asn: Some(Asn {
                    asn: asn_number.to_string(),
                    name: "Test ISP".to_string(),
                    route: Some("10.10.10.10/16".parse().unwrap()),
                    kind: AsnKind::Other,
                }),
                ..Default::default()
            })
            .build()
    }

    fn make_gateway_with_family(id: &str, family_id: u32) -> Gateway {
        Gateway::builder()
            .identity(id.parse().unwrap())
            .family_data(Some(NodeFamily {
                id: family_id,
                name: "Test Family".to_string(),
                description: String::new(),
                family_stake: 0,
                members: 0,
            }))
            .build()
    }

    fn make_gateway_with_subnet(id: &str, route: IpNetwork) -> Gateway {
        Gateway::builder()
            .identity(id.parse().unwrap())
            .location(Location {
                asn: Some(Asn {
                    asn: "ASTEST".to_string(),
                    name: "Test ISP".to_string(),
                    route: Some(route),
                    kind: AsnKind::Other,
                }),
                ..Default::default()
            })
            .build()
    }

    fn asn_only() -> GatewayIndependence {
        GatewayIndependence {
            different_asn: true,
            different_node_family: false,
            different_subnet: false,
            ..Default::default()
        }
    }

    fn family_only() -> GatewayIndependence {
        GatewayIndependence {
            different_asn: false,
            different_node_family: true,
            different_subnet: false,
            ..Default::default()
        }
    }

    fn subnet_only() -> GatewayIndependence {
        GatewayIndependence {
            different_asn: false,
            different_node_family: false,
            different_subnet: true,
            ..Default::default()
        }
    }

    #[test]
    fn same_identity_not_independent_regardless_of_criteria() {
        let gw = make_gateway(GW_ID_1);
        assert!(!gateways_are_independent(
            &gw,
            &gw,
            GatewayIndependence {
                different_node_family: false,
                different_asn: false,
                different_subnet: false,
                ..Default::default()
            }
        ));
        assert!(!gateways_are_independent(&gw, &gw, asn_only()));
        assert!(!gateways_are_independent(&gw, &gw, family_only()));
        assert!(!gateways_are_independent(&gw, &gw, subnet_only()));
        assert!(!gateways_are_independent(
            &gw,
            &gw,
            GatewayIndependence::default()
        ));
    }

    #[test]
    fn different_identity_no_criteria_is_independent() {
        let gw1 = make_gateway(GW_ID_1);
        let gw2 = make_gateway(GW_ID_2);
        assert!(gateways_are_independent(
            &gw1,
            &gw2,
            GatewayIndependence {
                different_node_family: false,
                different_asn: false,
                different_subnet: false,
                ..Default::default()
            }
        ));
    }

    #[test]
    fn same_asn_not_independent_when_asn_criterion_active() {
        let gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        let gw2 = make_gateway_with_asn(GW_ID_2, "AS12345");
        assert!(!gateways_are_independent(&gw1, &gw2, asn_only()));
    }

    #[test]
    fn different_subnets_independent_when_subnet_criterion_active() {
        let gw1 = make_gateway_with_subnet(GW_ID_1, "10.10.10.10/16".parse().unwrap());
        let gw2 = make_gateway_with_subnet(GW_ID_2, "10.11.10.10/16".parse().unwrap());
        assert!(gateways_are_independent(&gw1, &gw2, subnet_only()));
    }

    #[test]
    fn missing_subnet_not_independent_when_subnet_criterion_active() {
        let gw1 = make_gateway(GW_ID_1);
        let gw2 = make_gateway(GW_ID_2);
        assert!(!gateways_are_independent(&gw1, &gw2, subnet_only()));
    }

    #[test]
    fn one_missing_subnet_not_independent_when_subnet_criterion_active() {
        let gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        let gw2 = make_gateway(GW_ID_2);
        assert!(!gateways_are_independent(&gw1, &gw2, subnet_only()));
    }

    #[test]
    fn asn_without_route_not_independent_when_subnet_criterion_active() {
        let mut gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        gw1.location.as_mut().unwrap().asn.as_mut().unwrap().route = None;
        let gw2 = make_gateway_with_asn(GW_ID_2, "AS99999");
        assert!(!gateways_are_independent(&gw1, &gw2, subnet_only()));
        assert_eq!(
            independence_violations(&gw1, &gw2, subnet_only()),
            vec![IndependenceViolation::MissingSubnet]
        );
    }

    #[test]
    fn same_subnet_not_independent_when_subnet_criterion_active() {
        let gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        let gw2 = make_gateway_with_asn(GW_ID_2, "AS12345");
        assert!(!gateways_are_independent(&gw1, &gw2, subnet_only()));
    }

    #[test]
    fn different_asns_independent_when_asn_criterion_active() {
        let gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        let gw2 = make_gateway_with_asn(GW_ID_2, "AS99999");
        assert!(gateways_are_independent(&gw1, &gw2, asn_only()));
    }

    #[test]
    fn missing_asn_not_independent_when_asn_criterion_active() {
        let gw1 = make_gateway(GW_ID_1);
        let gw2 = make_gateway(GW_ID_2);
        assert!(!gateways_are_independent(&gw1, &gw2, asn_only()));
    }

    #[test]
    fn one_missing_asn_not_independent_when_asn_criterion_active() {
        let gw1 = make_gateway_with_asn(GW_ID_1, "AS12345");
        let gw2 = make_gateway(GW_ID_2);
        assert!(!gateways_are_independent(&gw1, &gw2, asn_only()));
    }

    #[test]
    fn same_family_not_independent_when_family_criterion_active() {
        let gw1 = make_gateway_with_family(GW_ID_1, 42);
        let gw2 = make_gateway_with_family(GW_ID_2, 42);
        assert!(!gateways_are_independent(&gw1, &gw2, family_only()));
    }

    #[test]
    fn different_family_independent_when_family_criterion_active() {
        let gw1 = make_gateway_with_family(GW_ID_1, 42);
        let gw2 = make_gateway_with_family(GW_ID_2, 99);
        assert!(gateways_are_independent(&gw1, &gw2, family_only()));
    }

    #[test]
    fn one_missing_family_independent_when_family_criterion_active() {
        let gw1 = make_gateway_with_family(GW_ID_1, 42);
        let gw2 = make_gateway(GW_ID_2);
        assert!(gateways_are_independent(&gw1, &gw2, family_only()));
    }

    fn full_gateway(id: &str, asn: &str, route: &str, family_id: u32) -> Gateway {
        Gateway::builder()
            .identity(id.parse().unwrap())
            .location(Location {
                asn: Some(Asn {
                    asn: asn.to_string(),
                    name: "ISP".to_string(),
                    route: Some(route.parse().unwrap()),
                    kind: AsnKind::Other,
                }),
                ..Default::default()
            })
            .family_data(Some(NodeFamily {
                id: family_id,
                name: String::new(),
                description: String::new(),
                family_stake: 0,
                members: 0,
            }))
            .build()
    }

    #[test]
    fn full_criteria_passes_when_all_differ() {
        let gw1 = full_gateway(GW_ID_1, "AS100", "10.10.10.10/16", 1);
        let gw2 = full_gateway(GW_ID_2, "AS200", "10.11.10.10/16", 2);
        assert!(gateways_are_independent(
            &gw1,
            &gw2,
            GatewayIndependence::default()
        ));
    }

    #[test]
    fn full_criteria_fails_when_asn_matches_despite_rest_different() {
        let gw1 = full_gateway(GW_ID_1, "AS100", "10.10.10.10/16", 1);
        let gw2 = full_gateway(GW_ID_2, "AS100", "10.11.10.10/16", 2);
        assert!(!gateways_are_independent(
            &gw1,
            &gw2,
            GatewayIndependence::default()
        ));
        assert_eq!(
            independence_violations(&gw1, &gw2, GatewayIndependence::default()),
            vec![IndependenceViolation::SameAsn]
        );
    }

    #[test]
    fn full_criteria_fails_when_subnet_matches_despite_rest_different() {
        let gw1 = full_gateway(GW_ID_1, "AS100", "10.10.11.10/16", 1);
        let gw2 = full_gateway(GW_ID_2, "AS101", "10.10.10.10/16", 2);
        assert!(!gateways_are_independent(
            &gw1,
            &gw2,
            GatewayIndependence::default()
        ));
    }

    #[test]
    fn violations_list_every_failed_criterion() {
        let gw1 = full_gateway(GW_ID_1, "AS100", "10.10.11.10/16", 7);
        let gw2 = full_gateway(GW_ID_2, "AS100", "10.10.10.10/16", 7);
        let violations = independence_violations(&gw1, &gw2, GatewayIndependence::default());
        assert_eq!(
            violations,
            vec![
                IndependenceViolation::SameAsn,
                IndependenceViolation::SameNodeFamily,
                IndependenceViolation::OverlappingSubnet,
            ]
        );
        assert_eq!(
            describe_violations(&violations),
            "same ASN, same node family, overlapping subnet"
        );
    }
}
