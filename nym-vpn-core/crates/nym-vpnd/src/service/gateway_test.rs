// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! `nym-vpnc gateway test`: pick the gateways to probe, resolve their
//! addresses from the directory and ping them from the daemon.

use std::{collections::HashMap, net::IpAddr, time::Duration};

use nym_gateway_directory::{Gateway, GatewayFilter, GatewayFilters, GatewayType, ScoreValue};
use nym_vpn_lib::{
    NodeIdentity,
    gateway_directory::GatewayCacheHandle,
    gateway_probe::{self, ProbeOutcome, ProbeParams},
};
use nym_vpn_lib_types::{
    EntryPoint, ExitPoint, GatewayTestParams, GatewayTestReport, GatewayTestResult,
    GatewayTestRole, GatewayTestSelector,
};

use super::error::GatewayTestError;

/// Daemon state a test needs, snapshotted so the probing can run off the
/// service loop.
pub(super) struct GatewayTestContext {
    pub gateway_cache: GatewayCacheHandle,
    pub entry_point: EntryPoint,
    pub exit_point: ExitPoint,
    /// WireGuard (two-hop) mode picks from the `Wg` list for both roles;
    /// mixnet mode from the entry and exit lists.
    pub two_hop: bool,
    /// The pair the tunnel is currently using, when connected.
    pub active: Option<(String, String)>,
}

/// How the gateways for one role are chosen.
enum Candidates {
    /// One gateway by identity.
    Gateway(String),
    /// The best-scored gateways matching the filters.
    Filtered(Vec<GatewayFilter>),
}

impl From<GatewayTestSelector> for Candidates {
    fn from(selector: GatewayTestSelector) -> Self {
        match selector {
            GatewayTestSelector::Gateway(id) => Candidates::Gateway(id),
            GatewayTestSelector::Country(cc) => {
                Candidates::Filtered(vec![GatewayFilter::Country(cc)])
            }
        }
    }
}

impl From<&EntryPoint> for Candidates {
    fn from(entry_point: &EntryPoint) -> Self {
        match entry_point {
            EntryPoint::Gateway { identity } => Candidates::Gateway(identity.to_base58_string()),
            EntryPoint::Country {
                two_letter_iso_country_code,
            } => Candidates::Filtered(vec![GatewayFilter::Country(
                two_letter_iso_country_code.clone(),
            )]),
            EntryPoint::Region { region } => {
                Candidates::Filtered(vec![GatewayFilter::Region(region.clone())])
            }
            EntryPoint::Random => Candidates::Filtered(Vec::new()),
        }
    }
}

impl From<&ExitPoint> for Candidates {
    fn from(exit_point: &ExitPoint) -> Self {
        match exit_point {
            ExitPoint::Address { address } => {
                Candidates::Gateway(address.gateway().to_base58_string())
            }
            ExitPoint::Gateway { identity } => Candidates::Gateway(identity.to_base58_string()),
            ExitPoint::Country {
                two_letter_iso_country_code,
            } => Candidates::Filtered(vec![GatewayFilter::Country(
                two_letter_iso_country_code.clone(),
            )]),
            ExitPoint::Region { region } => {
                Candidates::Filtered(vec![GatewayFilter::Region(region.clone())])
            }
            ExitPoint::Random => Candidates::Filtered(Vec::new()),
        }
    }
}

/// A gateway selected for probing, with whatever the directory knew about it.
struct Target {
    id: String,
    role: GatewayTestRole,
    name: Option<String>,
    country_code: Option<String>,
    address: Option<IpAddr>,
    error: Option<String>,
}

pub(super) async fn run(
    ctx: GatewayTestContext,
    params: GatewayTestParams,
) -> Result<GatewayTestReport, GatewayTestError> {
    let top = params.effective_top() as usize;
    let probe_params = ProbeParams {
        count: params.effective_count(),
        timeout: Duration::from_millis(u64::from(params.effective_timeout_ms())),
    };

    let (entry_type, exit_type) = if ctx.two_hop {
        (GatewayType::Wg, GatewayType::Wg)
    } else {
        (GatewayType::MixnetEntry, GatewayType::MixnetExit)
    };

    let mut targets = Vec::new();

    if !params.explicit_only() {
        let (entry, exit) = match (&params.entry, &params.exit, &ctx.active) {
            // Nothing asked for while connected: test the pair in use.
            (None, None, Some((entry_id, exit_id))) => (
                Candidates::Gateway(entry_id.clone()),
                Candidates::Gateway(exit_id.clone()),
            ),
            (entry, exit, _) => (
                entry
                    .clone()
                    .map(Candidates::from)
                    .unwrap_or_else(|| Candidates::from(&ctx.entry_point)),
                exit.clone()
                    .map(Candidates::from)
                    .unwrap_or_else(|| Candidates::from(&ctx.exit_point)),
            ),
        };
        targets.extend(
            resolve(
                &ctx.gateway_cache,
                entry_type,
                entry,
                top,
                GatewayTestRole::Entry,
            )
            .await?,
        );
        targets.extend(
            resolve(
                &ctx.gateway_cache,
                exit_type,
                exit,
                top,
                GatewayTestRole::Exit,
            )
            .await?,
        );
    }

    for id in &params.gateways {
        // Explicit ids may be any gateway; the entry list is the wider one in
        // both modes, so look there and fall back to a directory-wide lookup.
        targets.extend(
            resolve(
                &ctx.gateway_cache,
                entry_type,
                Candidates::Gateway(id.clone()),
                top,
                GatewayTestRole::Any,
            )
            .await?,
        );
    }

    if targets.is_empty() {
        return Err(GatewayTestError::NoTargets);
    }

    // Probe each address once even if it is listed under both roles.
    let mut addresses: Vec<IpAddr> = Vec::new();
    for target in &targets {
        if let Some(address) = target.address
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    let outcomes = gateway_probe::probe_targets(&addresses, probe_params)
        .await
        .map_err(GatewayTestError::Probe)?;
    let outcomes: HashMap<IpAddr, ProbeOutcome> = addresses.into_iter().zip(outcomes).collect();

    let results = targets
        .into_iter()
        .map(|target| {
            let outcome = target.address.and_then(|address| outcomes.get(&address));
            to_result(target, outcome)
        })
        .collect();

    Ok(GatewayTestReport::new(results))
}

/// Turn a candidate description into concrete targets, looking the gateways
/// up in the `gw_type` list and, for identities not in that list, in the
/// wider directory.
async fn resolve(
    cache: &GatewayCacheHandle,
    gw_type: GatewayType,
    candidates: Candidates,
    top: usize,
    role: GatewayTestRole,
) -> Result<Vec<Target>, GatewayTestError> {
    let list = cache
        .lookup_gateways(gw_type)
        .await
        .map_err(|source| GatewayTestError::GetGateways { gw_type, source })?;

    match candidates {
        Candidates::Gateway(id) => {
            let identity = NodeIdentity::from_base58_string(&id)
                .map_err(|_| GatewayTestError::InvalidGatewayId(id.clone()))?;
            let target = match list.gateway_with_identity(&identity) {
                Some(gateway) => Target::from_gateway(gateway, role),
                None => match cache.lookup_gateway_ip(id.clone()).await {
                    Ok(address) => Target {
                        id,
                        role,
                        name: None,
                        country_code: None,
                        address: Some(address),
                        error: None,
                    },
                    Err(err) => Target {
                        id,
                        role,
                        name: None,
                        country_code: None,
                        address: None,
                        error: Some(format!("not found in the gateway directory: {err}")),
                    },
                },
            };
            Ok(vec![target])
        }
        Candidates::Filtered(filters) => {
            let mut gateways = list.filter(&GatewayFilters::from(filters.iter()));
            gateways.retain(|gateway| score_rank(gateway, gw_type) > 0);
            gateways.sort_by_key(|gateway| std::cmp::Reverse(score_rank(gateway, gw_type)));
            Ok(gateways
                .iter()
                .take(top)
                .map(|gateway| Target::from_gateway(gateway, role))
                .collect())
        }
    }
}

/// Directory score as a sortable rank; offline and unscored gateways rank 0.
fn score_rank(gateway: &Gateway, gw_type: GatewayType) -> u8 {
    let Some(performance) = &gateway.performance else {
        return 0;
    };
    let score = match gw_type {
        GatewayType::Wg => performance.score,
        GatewayType::MixnetEntry | GatewayType::MixnetExit => performance.mixnet_score,
    };
    match score {
        ScoreValue::Offline => 0,
        ScoreValue::Low => 1,
        ScoreValue::Medium => 2,
        ScoreValue::High => 3,
    }
}

impl Target {
    fn from_gateway(gateway: &Gateway, role: GatewayTestRole) -> Self {
        // Prefer IPv4: most routers have no IPv6 WAN, and the tunnel itself
        // is set up over IPv4 in that case.
        let address = gateway
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| gateway.ips.first())
            .copied();
        Self {
            id: gateway.identity.to_base58_string(),
            role,
            name: Some(gateway.name.clone()),
            country_code: gateway.two_letter_iso_country_code().map(ToOwned::to_owned),
            address,
            error: address
                .is_none()
                .then(|| "gateway has no IP address in the directory".to_owned()),
        }
    }
}

fn to_result(target: Target, outcome: Option<&ProbeOutcome>) -> GatewayTestResult {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let (sent, received, min, avg, max, probe_error) = match outcome {
        Some(o) => (
            o.sent,
            o.received,
            o.min().map(ms),
            o.avg().map(ms),
            o.max().map(ms),
            o.error.clone(),
        ),
        None => (0, 0, None, None, None, None),
    };
    GatewayTestResult {
        id: target.id,
        name: target.name,
        country_code: target.country_code,
        role: target.role,
        address: target.address,
        sent,
        received,
        rtt_min_ms: min,
        rtt_avg_ms: avg,
        rtt_max_ms: max,
        error: target.error.or(probe_error),
    }
}
