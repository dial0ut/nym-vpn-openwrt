// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_vpn_lib_types::{Gateway, GatewayIndependence, TentativeGateways};

use crate::{conversions::ConversionError, proto};

impl From<GatewayIndependence> for proto::GatewayIndependence {
    fn from(value: GatewayIndependence) -> Self {
        Self {
            different_node_family: value.different_node_family,
            different_asn: value.different_asn,
            different_subnet: value.different_subnet,
            enable_notifications: value.enable_notifications,
        }
    }
}

impl From<proto::GatewayIndependence> for GatewayIndependence {
    fn from(value: proto::GatewayIndependence) -> Self {
        Self {
            enable_notifications: value.enable_notifications,
            different_node_family: value.different_node_family,
            different_asn: value.different_asn,
            different_subnet: value.different_subnet,
        }
    }
}

impl From<TentativeGateways> for proto::TentativeGateways {
    fn from(value: TentativeGateways) -> Self {
        use proto::tentative_gateways::{
            NeedsRelaxedIndependenceCriteria, NoGatewaysAvailable, Selected,
            TentativeGateways as Kind,
        };
        let kind = match value {
            TentativeGateways::Selected { entry, exit } => Kind::Selected(Selected {
                entry: Some(proto::GatewayResponse::from(*entry)),
                exit: Some(proto::GatewayResponse::from(*exit)),
            }),
            TentativeGateways::NeedsRelaxedIndependenceCriteria => {
                Kind::NeedsRelaxedIndependenceCriteria(NeedsRelaxedIndependenceCriteria {})
            }
            TentativeGateways::NoGatewaysAvailable => {
                Kind::NoGatewaysAvailable(NoGatewaysAvailable {})
            }
        };
        Self {
            tentative_gateways: Some(kind),
        }
    }
}

impl TryFrom<proto::TentativeGateways> for TentativeGateways {
    type Error = ConversionError;

    fn try_from(value: proto::TentativeGateways) -> Result<Self, Self::Error> {
        use proto::tentative_gateways::TentativeGateways as Kind;
        let kind = value.tentative_gateways.ok_or(ConversionError::NoValueSet(
            "TentativeGateways.tentative_gateways",
        ))?;
        Ok(match kind {
            Kind::Selected(selected) => {
                let entry = selected
                    .entry
                    .ok_or(ConversionError::NoValueSet("TentativeGateways.entry"))?;
                let exit = selected
                    .exit
                    .ok_or(ConversionError::NoValueSet("TentativeGateways.exit"))?;
                TentativeGateways::Selected {
                    entry: Box::new(Gateway::try_from(entry)?),
                    exit: Box::new(Gateway::try_from(exit)?),
                }
            }
            Kind::NeedsRelaxedIndependenceCriteria(_) => {
                TentativeGateways::NeedsRelaxedIndependenceCriteria
            }
            Kind::NoGatewaysAvailable(_) => TentativeGateways::NoGatewaysAvailable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(id: &str, family: Option<&str>) -> Gateway {
        Gateway {
            identity_key: id.to_owned(),
            name: format!("name-{id}"),
            description: None,
            location: Some(nym_vpn_lib_types::Location {
                two_letter_iso_country_code: "DE".to_owned(),
                latitude: 1.0,
                longitude: 2.0,
                city: "Berlin".to_owned(),
                region: "BE".to_owned(),
                asn: None,
            }),
            last_probe: None,
            mixnet_performance: None,
            bridge_params: None,
            performance: None,
            exit_ipv4s: vec![],
            exit_ipv6s: vec![],
            build_version: None,
            lewes_protocol_details: None,
            node_family_name: family.map(str::to_owned),
        }
    }

    #[test]
    fn gateway_independence_round_trips() {
        for value in [
            GatewayIndependence::default(),
            GatewayIndependence::disabled(),
            GatewayIndependence {
                enable_notifications: false,
                different_node_family: true,
                different_asn: false,
                different_subnet: true,
            },
        ] {
            let wire = proto::GatewayIndependence::from(value);
            assert_eq!(GatewayIndependence::from(wire), value);
        }
    }

    #[test]
    fn tentative_gateways_round_trip() {
        let selected = TentativeGateways::Selected {
            entry: Box::new(gateway("entry", Some("fam"))),
            exit: Box::new(gateway("exit", None)),
        };
        let wire = proto::TentativeGateways::from(selected);
        match TentativeGateways::try_from(wire).unwrap() {
            TentativeGateways::Selected { entry, exit } => {
                assert_eq!(entry.identity_key, "entry");
                assert_eq!(entry.node_family_name.as_deref(), Some("fam"));
                assert_eq!(exit.identity_key, "exit");
                assert_eq!(exit.node_family_name, None);
                assert_eq!(exit.location.unwrap().two_letter_iso_country_code, "DE");
            }
            other => panic!("expected Selected, got {other:?}"),
        }

        let wire =
            proto::TentativeGateways::from(TentativeGateways::NeedsRelaxedIndependenceCriteria);
        assert!(matches!(
            TentativeGateways::try_from(wire).unwrap(),
            TentativeGateways::NeedsRelaxedIndependenceCriteria
        ));

        let wire = proto::TentativeGateways::from(TentativeGateways::NoGatewaysAvailable);
        assert!(matches!(
            TentativeGateways::try_from(wire).unwrap(),
            TentativeGateways::NoGatewaysAvailable
        ));
    }

    #[test]
    fn empty_tentative_gateways_is_an_error() {
        let wire = proto::TentativeGateways {
            tentative_gateways: None,
        };
        assert!(TentativeGateways::try_from(wire).is_err());
    }
}
