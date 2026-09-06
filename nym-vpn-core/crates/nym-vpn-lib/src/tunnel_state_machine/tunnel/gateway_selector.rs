// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use nym_crypto::asymmetric::x25519::KeyPair;
use nym_gateway_directory::{
    BlacklistedGateways, EntryPoint, ExitPoint, Gateway, GatewayCacheHandle, GatewayFilter,
    GatewayFilters, GatewayList, GatewayType,
};
use nym_vpn_lib_types::GatewayIndependence;
use nym_vpn_store::keys::wireguard::{WireguardKeyStore, WireguardKeysDb};

use super::independence::{describe_violations, gateways_are_independent, independence_violations};
use crate::{
    GatewayDirectoryError,
    tunnel_state_machine::{TunnelSettings, TunnelType},
};

#[derive(Clone)]
pub struct GatewayWithKeys {
    gateway: Gateway,
    keys: Arc<KeyPair>,
}

impl std::fmt::Debug for GatewayWithKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayWithKeys")
            .field("gateway", &self.gateway)
            .field("client_wireguard_public_key", &self.keys.public_key())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SelectedGateways {
    entry: Box<GatewayWithKeys>,
    exit: Box<GatewayWithKeys>,
}

impl SelectedGateways {
    pub fn entry_gateway(&self) -> &Gateway {
        &self.entry.gateway
    }

    pub fn exit_gateway(&self) -> &Gateway {
        &self.exit.gateway
    }

    pub fn entry_keypair(&self) -> &Arc<KeyPair> {
        &self.entry.keys
    }

    pub fn exit_keypair(&self) -> &Arc<KeyPair> {
        &self.exit.keys
    }
}

/// The constraints one selection runs under: the configured entry and exit
/// points plus the filters derived from the settings and the blacklist.
struct PairSelection {
    entry_point: EntryPoint,
    exit_point: ExitPoint,
    entry_filters: GatewayFilters,
    exit_filters: GatewayFilters,
}

impl PairSelection {
    fn new(
        tunnel_settings: &TunnelSettings,
        blacklisted_entry_gateways: &BlacklistedGateways,
    ) -> Self {
        let exit_filters = if tunnel_settings.residential_exit {
            GatewayFilters::from(&[GatewayFilter::Residential, GatewayFilter::Exit])
        } else {
            GatewayFilters::default()
        };

        let entry_filters = if blacklisted_entry_gateways.is_empty().unwrap_or(true) {
            GatewayFilters::default()
        } else {
            GatewayFilters::from(&[GatewayFilter::NotBlacklisted(
                blacklisted_entry_gateways.clone(),
            )])
        };

        Self {
            entry_point: EntryPoint::from(*tunnel_settings.entry_point.clone()),
            exit_point: ExitPoint::from(*tunnel_settings.exit_point.clone()),
            entry_filters,
            exit_filters,
        }
    }

    /// Pick an entry/exit pair honouring `criteria`. When the criteria are
    /// active and rule every pair out, check whether relaxing them would yield
    /// one: if so the caller gets [`GatewayDirectoryError::NeedsRelaxedIndependenceCriteria`]
    /// so the user can be asked, otherwise the original selection error.
    fn select(
        &self,
        entry_gateways: &GatewayList,
        exit_gateways: &GatewayList,
        criteria: GatewayIndependence,
    ) -> Result<(Gateway, Gateway), GatewayDirectoryError> {
        let strict_error = match self.select_with_criteria(entry_gateways, exit_gateways, criteria)
        {
            Ok(pair) => return Ok(pair),
            Err(err) if !criteria.active() => return Err(err),
            Err(err) => err,
        };

        match self.select_with_criteria(
            entry_gateways,
            exit_gateways,
            GatewayIndependence::disabled(),
        ) {
            Ok((entry_gateway, exit_gateway)) => {
                let violations = independence_violations(&entry_gateway, &exit_gateway, criteria);
                let violated = describe_violations(&violations);
                tracing::warn!(
                    "No independent gateway pair for the current settings; entry {} and exit {} \
                     would work but are not independent: {violated}",
                    entry_gateway.identity(),
                    exit_gateway.identity(),
                );
                Err(GatewayDirectoryError::NeedsRelaxedIndependenceCriteria { violated })
            }
            Err(relaxed_error) => {
                tracing::debug!(
                    "Relaxing the independence criteria would not help either: {relaxed_error}"
                );
                Err(strict_error)
            }
        }
    }

    /// The set of exit gateways is smaller than the set of entry gateways, so
    /// start with the exit and then pick an entry that is independent of it
    /// (with no criteria active that only rules out the exit itself). When an
    /// exit leaves no acceptable entry, drop it and try the next best exit.
    fn select_with_criteria(
        &self,
        entry_gateways: &GatewayList,
        exit_gateways: &GatewayList,
        criteria: GatewayIndependence,
    ) -> Result<(Gateway, Gateway), GatewayDirectoryError> {
        // An entry point that matches nothing before any exit is excluded (a
        // pinned identity missing from the directory, an unserved country)
        // fails the same way for every exit; say so at once instead of
        // walking the whole exit list.
        entry_gateways
            .find_best_entry_gateway(&self.entry_point, &self.entry_filters)
            .map_err(GatewayDirectoryError::EntryGatewayUnavailable)?;

        let mut exit_candidates = exit_gateways.clone();
        let mut entry_error = None;
        loop {
            let exit_gateway = match exit_candidates
                .find_best_exit_gateway(&self.exit_point, &self.exit_filters)
            {
                Ok(exit_gateway) => exit_gateway,
                // The first exit error is the informative one only if no exit
                // was ever acceptable; otherwise report why entries failed.
                Err(err) => {
                    return Err(
                        entry_error.unwrap_or(GatewayDirectoryError::ExitGatewayUnavailable(err))
                    );
                }
            };

            let entry_candidates = GatewayList::new(
                entry_gateways.gw_type(),
                entry_gateways
                    .clone()
                    .into_iter()
                    .filter(|entry_gateway| {
                        gateways_are_independent(entry_gateway, &exit_gateway, criteria)
                    })
                    .collect(),
            );

            match entry_candidates.find_best_entry_gateway(&self.entry_point, &self.entry_filters) {
                Ok(entry_gateway) => return Ok((entry_gateway, exit_gateway)),
                Err(err) => {
                    tracing::debug!(
                        "No entry gateway pairs with exit {}: {err}",
                        exit_gateway.identity()
                    );
                    entry_error = Some(GatewayDirectoryError::EntryGatewayUnavailable(err));
                    exit_candidates.remove_gateway(&exit_gateway);
                }
            }
        }
    }
}

/// Entry and exit candidate lists for the configured tunnel type. With bridges
/// on, only entry gateways announcing bridge parameters qualify.
async fn candidate_lists(
    gateway_cache_handle: &GatewayCacheHandle,
    tunnel_settings: &TunnelSettings,
) -> Result<(GatewayList, GatewayList), GatewayDirectoryError> {
    match tunnel_settings.tunnel_type {
        TunnelType::Wireguard => {
            let all_gateways = gateway_cache_handle
                .lookup_gateways(GatewayType::Wg)
                .await
                .map_err(GatewayDirectoryError::LookupGateways)?;

            let entry_gateways = if tunnel_settings.bridges_enabled() {
                GatewayList::new(
                    all_gateways.gw_type(),
                    all_gateways
                        .clone()
                        .into_iter()
                        .filter(|gw| gw.bridge_params.is_some())
                        .collect(),
                )
            } else {
                all_gateways.clone()
            };

            Ok((entry_gateways, all_gateways))
        }
        TunnelType::Mixnet => {
            // Setup the gateway that we will use as the exit point
            let exit_gateways = gateway_cache_handle
                .lookup_gateways(GatewayType::MixnetExit)
                .await
                .map_err(GatewayDirectoryError::LookupGateways)?;
            // Setup the gateway that we will use as the entry point
            let entry_gateways = gateway_cache_handle
                .lookup_gateways(GatewayType::MixnetEntry)
                .await
                .map_err(GatewayDirectoryError::LookupGateways)?;
            Ok((entry_gateways, exit_gateways))
        }
    }
}

/// Resolve the entry and exit gateway identities for `tunnel_settings` under
/// the given independence `criteria`, without touching key material. This is
/// what a connect runs first, and what a preview of the probable pair runs on
/// its own.
pub async fn select_gateway_pair(
    gateway_cache_handle: &GatewayCacheHandle,
    blacklisted_entry_gateways: &BlacklistedGateways,
    tunnel_settings: &TunnelSettings,
    criteria: GatewayIndependence,
) -> Result<(Gateway, Gateway), GatewayDirectoryError> {
    let selection = PairSelection::new(tunnel_settings, blacklisted_entry_gateways);

    if let (
        EntryPoint::Gateway {
            identity: entry_identity,
        },
        ExitPoint::Gateway {
            identity: exit_identity,
        },
    ) = (&selection.entry_point, &selection.exit_point)
        && entry_identity == exit_identity
    {
        return Err(GatewayDirectoryError::SameEntryAndExitGateway {
            identity: entry_identity.to_string(),
        });
    };

    let (entry_gateways, exit_gateways) =
        candidate_lists(gateway_cache_handle, tunnel_settings).await?;

    tracing::info!("Found {} entry gateways", entry_gateways.len());
    tracing::info!("Found {} exit gateways", exit_gateways.len());
    if criteria.active() {
        tracing::info!("Gateway independence criteria: {criteria}");
    } else {
        tracing::info!("Gateway independence criteria: off");
    }

    let (entry_gateway, exit_gateway) =
        selection.select(&entry_gateways, &exit_gateways, criteria)?;

    tracing::info!(
        "Using entry gateway: {}, location: {}, family: {}, performance: {}",
        entry_gateway.identity(),
        entry_gateway
            .two_letter_iso_country_code()
            .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
        entry_gateway
            .family_data
            .as_ref()
            .map_or("none", |family| family.name.as_str()),
        entry_gateway
            .mixnet_performance
            .map_or_else(|| "unknown".to_string(), |perf| perf.to_string()),
    );
    tracing::info!(
        "Using exit gateway: {}, location: {}, family: {}, performance: {}",
        exit_gateway.identity(),
        exit_gateway
            .two_letter_iso_country_code()
            .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
        exit_gateway
            .family_data
            .as_ref()
            .map_or("none", |family| family.name.as_str()),
        exit_gateway
            .mixnet_performance
            .map_or_else(|| "unknown".to_string(), |perf| perf.to_string()),
    );
    tracing::info!(
        "Using exit router address {}",
        exit_gateway
            .ipr_address
            .map_or_else(|| "none".to_string(), |ipr| ipr.to_string())
    );

    Ok((entry_gateway, exit_gateway))
}

pub async fn select_gateways(
    gateway_cache_handle: GatewayCacheHandle,
    blacklisted_entry_gateways: &BlacklistedGateways,
    tunnel_settings: &TunnelSettings,
    criteria: GatewayIndependence,
    wg_keys_db: WireguardKeysDb,
) -> Result<SelectedGateways, GatewayDirectoryError> {
    let (entry_gateway, exit_gateway) = select_gateway_pair(
        &gateway_cache_handle,
        blacklisted_entry_gateways,
        tunnel_settings,
        criteria,
    )
    .await?;

    let entry_keys = wg_keys_db
        .load_or_create_keys(&entry_gateway.identity().to_string())
        .await
        .map_err(|source| GatewayDirectoryError::LoadKeypair {
            identity: entry_gateway.identity().to_string(),
            source,
        })?
        .entry_keypair()
        .clone();
    let exit_keys = wg_keys_db
        .load_or_create_keys(&exit_gateway.identity().to_string())
        .await
        .map_err(|source| GatewayDirectoryError::LoadKeypair {
            identity: exit_gateway.identity().to_string(),
            source,
        })?
        .exit_keypair()
        .clone();

    tracing::debug!("Using entry public key: {}", entry_keys.public_key());
    tracing::debug!("Using exit public key: {}", exit_keys.public_key());

    Ok(SelectedGateways {
        entry: Box::new(GatewayWithKeys {
            gateway: entry_gateway,
            keys: entry_keys,
        }),
        exit: Box::new(GatewayWithKeys {
            gateway: exit_gateway,
            keys: exit_keys,
        }),
    })
}

#[cfg(test)]
mod tests {
    use nym_gateway_directory::{
        Asn, AsnKind, Location, NodeFamily, NodeIdentity, Performance, ScoreValue,
    };

    use super::*;

    // Valid ed25519 identities borrowed from the directory test fixtures.
    const IDS: [&str; 6] = [
        "2djmrzZ62M8jpzpYb7MMq6QjP15CkbnKHf3ZV3kSCXUE",
        "3UBiq22tkNSRhyRNjL5mnw5Yk4z6FvgvjizT4ukeEaeB",
        "6tGNU195QKNMaTxkvm917d3NNGLkpTp8mTfxqLzATbtB",
        "7CWjY3QFoA9dgE535u9bQiXCfzgMZvSpJu842GA1Wn42",
        "B4r2xMJYc4VgoEhPmccmNSawQWdYP9zGp9DJqjcz6PoX",
        "DoezvC92kAVDhFpBbsRj52rErhikj2vtPi1Lup2EhbZ4",
    ];

    fn identity(index: usize) -> NodeIdentity {
        NodeIdentity::from_base58_string(IDS[index]).unwrap()
    }

    /// A WireGuard gateway with a high score in `country`, in `asn`/`route`
    /// and optionally a node family.
    fn gateway(
        index: usize,
        country: &str,
        asn: &str,
        route: &str,
        family: Option<u32>,
    ) -> Gateway {
        Gateway::builder()
            .identity(identity(index))
            .name(format!("gw-{index}"))
            .location(Location {
                two_letter_iso_country_code: country.to_owned(),
                asn: Some(Asn {
                    asn: asn.to_owned(),
                    name: asn.to_owned(),
                    route: Some(route.parse().unwrap()),
                    kind: AsnKind::Other,
                }),
                ..Default::default()
            })
            .performance(Performance {
                last_updated_utc: "2026-01-01T00:00:00Z".to_owned(),
                score: ScoreValue::High,
                mixnet_score: ScoreValue::High,
                load: ScoreValue::Low,
                uptime_percentage_last_24_hours: 0.99,
            })
            .family_data(family.map(|id| NodeFamily {
                id,
                name: format!("family-{id}"),
                description: String::new(),
                family_stake: 0,
                members: 2,
            }))
            .build()
    }

    fn list(gateways: Vec<Gateway>) -> GatewayList {
        GatewayList::new(Some(GatewayType::Wg), gateways)
    }

    fn selection(entry_point: EntryPoint, exit_point: ExitPoint) -> PairSelection {
        PairSelection {
            entry_point,
            exit_point,
            entry_filters: GatewayFilters::default(),
            exit_filters: GatewayFilters::default(),
        }
    }

    fn country(code: &str) -> (EntryPoint, ExitPoint) {
        (
            EntryPoint::Country {
                two_letter_iso_country_code: code.to_owned(),
            },
            ExitPoint::Country {
                two_letter_iso_country_code: code.to_owned(),
            },
        )
    }

    /// Two operators in DE: gateways 0 and 1 share family 1, ASN and prefix;
    /// gateway 2 is unrelated to both.
    fn two_operators() -> GatewayList {
        list(vec![
            gateway(0, "DE", "AS100", "10.1.0.0/16", Some(1)),
            gateway(1, "DE", "AS100", "10.1.0.0/16", Some(1)),
            gateway(2, "DE", "AS200", "10.2.0.0/16", Some(2)),
        ])
    }

    #[test]
    fn picks_an_independent_pair_when_one_exists() {
        let gateways = two_operators();
        let (entry_point, exit_point) = country("DE");
        let selection = selection(entry_point, exit_point);

        // Whatever exit the random pick lands on, the entry must be independent.
        for _ in 0..20 {
            let (entry, exit) = selection
                .select(&gateways, &gateways, GatewayIndependence::default())
                .unwrap();
            assert!(gateways_are_independent(
                &entry,
                &exit,
                GatewayIndependence::default()
            ));
            assert!(entry.identity() == identity(2) || exit.identity() == identity(2));
        }
    }

    #[test]
    fn asks_to_relax_when_only_related_pairs_exist() {
        // Both DE gateways belong to the same operator.
        let gateways = list(vec![
            gateway(0, "DE", "AS100", "10.1.0.0/16", Some(1)),
            gateway(1, "DE", "AS100", "10.1.0.0/16", Some(1)),
        ]);
        let (entry_point, exit_point) = country("DE");
        let err = selection(entry_point, exit_point)
            .select(&gateways, &gateways, GatewayIndependence::default())
            .unwrap_err();
        match err {
            GatewayDirectoryError::NeedsRelaxedIndependenceCriteria { violated } => {
                assert_eq!(violated, "same ASN, same node family, overlapping subnet");
            }
            other => panic!("expected NeedsRelaxedIndependenceCriteria, got {other:?}"),
        }
    }

    #[test]
    fn relaxed_criteria_accept_related_pairs() {
        let gateways = list(vec![
            gateway(0, "DE", "AS100", "10.1.0.0/16", Some(1)),
            gateway(1, "DE", "AS100", "10.1.0.0/16", Some(1)),
        ]);
        let (entry_point, exit_point) = country("DE");
        let (entry, exit) = selection(entry_point, exit_point)
            .select(&gateways, &gateways, GatewayIndependence::disabled())
            .unwrap();
        assert_ne!(entry.identity(), exit.identity());
    }

    #[test]
    fn reports_the_ordinary_error_when_relaxing_would_not_help() {
        let gateways = two_operators();
        let (entry_point, _) = country("DE");
        let exit_point = ExitPoint::Country {
            two_letter_iso_country_code: "FR".to_owned(),
        };
        let err = selection(entry_point, exit_point)
            .select(&gateways, &gateways, GatewayIndependence::default())
            .unwrap_err();
        assert!(
            matches!(err, GatewayDirectoryError::ExitGatewayUnavailable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn explicit_related_pair_needs_relaxed_criteria() {
        let gateways = two_operators();
        let selection = selection(
            EntryPoint::Gateway {
                identity: identity(0),
            },
            ExitPoint::Gateway {
                identity: identity(1),
            },
        );
        let err = selection
            .select(&gateways, &gateways, GatewayIndependence::default())
            .unwrap_err();
        assert!(
            matches!(
                err,
                GatewayDirectoryError::NeedsRelaxedIndependenceCriteria { .. }
            ),
            "got {err:?}"
        );

        let (entry, exit) = selection
            .select(&gateways, &gateways, GatewayIndependence::disabled())
            .unwrap();
        assert_eq!(entry.identity(), identity(0));
        assert_eq!(exit.identity(), identity(1));
    }

    #[test]
    fn explicit_independent_pair_is_kept() {
        let gateways = two_operators();
        let (entry, exit) = selection(
            EntryPoint::Gateway {
                identity: identity(0),
            },
            ExitPoint::Gateway {
                identity: identity(2),
            },
        )
        .select(&gateways, &gateways, GatewayIndependence::default())
        .unwrap();
        assert_eq!(entry.identity(), identity(0));
        assert_eq!(exit.identity(), identity(2));
    }

    #[test]
    fn single_criterion_only_rules_out_that_relation() {
        // Same ASN and prefix, different families: fine for the family
        // criterion alone, rejected once the ASN criterion is on.
        let gateways = list(vec![
            gateway(0, "DE", "AS100", "10.1.0.0/16", Some(1)),
            gateway(1, "DE", "AS100", "10.1.0.0/16", Some(2)),
        ]);
        let (entry_point, exit_point) = country("DE");
        let selection = selection(entry_point, exit_point);
        let family_only = GatewayIndependence {
            different_node_family: true,
            different_asn: false,
            different_subnet: false,
            ..Default::default()
        };
        assert!(selection.select(&gateways, &gateways, family_only).is_ok());
        let asn_only = GatewayIndependence {
            different_node_family: false,
            different_asn: true,
            different_subnet: false,
            ..Default::default()
        };
        assert!(matches!(
            selection.select(&gateways, &gateways, asn_only),
            Err(GatewayDirectoryError::NeedsRelaxedIndependenceCriteria { .. })
        ));
    }

    #[test]
    fn exit_is_never_reused_as_entry() {
        // One gateway only: the exit takes it, no entry is left.
        let gateways = list(vec![gateway(0, "DE", "AS100", "10.1.0.0/16", None)]);
        let (entry_point, exit_point) = country("DE");
        let err = selection(entry_point, exit_point)
            .select(&gateways, &gateways, GatewayIndependence::disabled())
            .unwrap_err();
        assert!(
            matches!(err, GatewayDirectoryError::EntryGatewayUnavailable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn unmatched_entry_point_fails_without_trying_every_exit() {
        let gateways = two_operators();
        let (_, exit_point) = country("DE");
        // Gateway 3 is not in the list, so no exit choice can help.
        let err = selection(
            EntryPoint::Gateway {
                identity: identity(3),
            },
            exit_point,
        )
        .select(&gateways, &gateways, GatewayIndependence::default())
        .unwrap_err();
        assert!(
            matches!(err, GatewayDirectoryError::EntryGatewayUnavailable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn pinned_entry_moves_the_random_exit_elsewhere() {
        // With independence off the exit pick must still avoid the pinned
        // entry: the exit candidates are retried until one differs.
        let gateways = list(vec![
            gateway(0, "DE", "AS100", "10.1.0.0/16", None),
            gateway(1, "DE", "AS200", "10.2.0.0/16", None),
        ]);
        let (_, exit_point) = country("DE");
        let selection = selection(
            EntryPoint::Gateway {
                identity: identity(0),
            },
            exit_point,
        );
        for _ in 0..20 {
            let (entry, exit) = selection
                .select(&gateways, &gateways, GatewayIndependence::disabled())
                .unwrap();
            assert_eq!(entry.identity(), identity(0));
            assert_eq!(exit.identity(), identity(1));
        }
    }
}
