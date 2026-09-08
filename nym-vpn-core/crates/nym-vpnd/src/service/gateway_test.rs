// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! `nym-vpnc gateway test`: pick the gateways to probe, resolve their
//! addresses from the directory and ping them from the daemon.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use nym_gateway_directory::{Gateway, GatewayFilter, GatewayFilters, GatewayType, ScoreValue};
use nym_vpn_lib::{
    NodeIdentity,
    gateway_directory::GatewayCacheHandle,
    gateway_probe::{self, MAX_CONCURRENT_TARGETS, PROBE_INTERVAL, ProbeOutcome, ProbeParams},
};
use nym_vpn_lib_types::{
    EntryPoint, ExitPoint, GatewayTestParams, GatewayTestReport, GatewayTestResult,
    GatewayTestRole, GatewayTestSelector,
};

use super::error::GatewayTestError;

/// Time allowed on top of the probes themselves for directory lookups (up to
/// one round trip per unknown explicit identity).
const LOOKUP_SLACK: Duration = Duration::from_secs(30);
/// Hard ceiling on one run, whatever the request asks for.
const MAX_DEADLINE: Duration = Duration::from_secs(300);

/// Worst-case wall time of a run with these parameters: every candidate slot
/// filled, every probe timing out, targets probed [`MAX_CONCURRENT_TARGETS`]
/// at a time. The daemon aborts a run that outlives this.
pub(super) fn deadline(params: &GatewayTestParams) -> Duration {
    let per_probe =
        Duration::from_millis(u64::from(params.effective_timeout_ms())) + PROBE_INTERVAL;
    let per_target = per_probe * params.effective_count();
    let role_targets = if params.explicit_only() {
        0
    } else {
        2 * params.effective_top() as usize
    };
    let targets = role_targets + params.gateways.len();
    let waves = targets.div_ceil(MAX_CONCURRENT_TARGETS).max(1) as u32;
    (per_target * waves + LOOKUP_SLACK).min(MAX_DEADLINE)
}

/// The single permission to run a gateway test. The kill-switch probe hatch
/// is rate limited for one run ([`MAX_CONCURRENT_TARGETS`] targets at
/// [`PROBE_INTERVAL`]); two runs at once would push probes into the limiter
/// and report the drops as gateway loss.
#[derive(Clone)]
pub(super) struct GatewayTestSlot(Arc<tokio::sync::Semaphore>);

impl GatewayTestSlot {
    pub(super) fn new() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(1)))
    }

    /// The permit for one run, or `None` while another run holds it. The run
    /// is over when the permit drops.
    pub(super) fn try_take(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.0.clone().try_acquire_owned().ok()
    }
}

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

enum Candidates {
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
    mut params: GatewayTestParams,
) -> Result<GatewayTestReport, GatewayTestError> {
    // The RPC boundary already did this; repeated here so the bound holds for
    // any other caller too.
    params.dedup_gateways();
    params.validate().map_err(GatewayTestError::Params)?;

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
    let mut seen = HashSet::new();
    let addresses: Vec<IpAddr> = targets
        .iter()
        .filter_map(|target| target.address)
        .filter(|address| seen.insert(*address))
        .collect();
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

/// Identities not in the `gw_type` list fall back to the wider directory.
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

#[cfg(test)]
mod tests {
    use super::*;
    use nym_vpn_lib::gateway_probe::ProbeError;
    use nym_vpn_lib_types::{
        DEFAULT_PROBE_COUNT, DEFAULT_PROBE_TIMEOUT_MS, DEFAULT_TOP_CANDIDATES,
        MAX_EXPLICIT_GATEWAYS,
    };

    #[test]
    fn deadline_covers_the_worst_case_and_is_capped() {
        // Defaults: 2 roles x 5 candidates = 10 targets -> 2 waves of
        // 5 probes x (2000 + 200) ms, plus lookup slack.
        assert_eq!(DEFAULT_TOP_CANDIDATES, 5, "test assumes 2 waves");
        let d = deadline(&GatewayTestParams::default());
        let per_target =
            Duration::from_millis(u64::from(DEFAULT_PROBE_TIMEOUT_MS) + 200) * DEFAULT_PROBE_COUNT;
        assert_eq!(d, per_target * 2 + LOOKUP_SLACK);

        // One explicit id: a single wave.
        let one = GatewayTestParams {
            gateways: vec!["A".into()],
            count: 1,
            timeout_ms: 1000,
            ..Default::default()
        };
        assert_eq!(deadline(&one), Duration::from_millis(1200) + LOOKUP_SLACK);

        // Everything at its maximum stays under the ceiling.
        let max = GatewayTestParams {
            gateways: vec!["A".into(); MAX_EXPLICIT_GATEWAYS],
            count: u32::MAX,
            timeout_ms: u32::MAX,
            top: u32::MAX,
            ..Default::default()
        };
        assert_eq!(deadline(&max), MAX_DEADLINE);
    }

    #[test]
    fn slot_admits_one_run_at_a_time() {
        let slot = GatewayTestSlot::new();
        let first = slot.try_take().expect("free slot");
        assert!(slot.try_take().is_none(), "second run must be refused");
        drop(first);
        assert!(slot.try_take().is_some(), "slot is free once the run ends");
    }

    #[test]
    fn error_chain_reaches_the_os_error() {
        let eperm = std::io::Error::from_raw_os_error(1);
        let err = GatewayTestError::Probe(ProbeError::OpenSocket(eperm));
        let chain = err.chain();
        assert!(chain.starts_with("failed to probe gateways: failed to open ICMP socket: "));
        assert!(
            chain.to_lowercase().contains("not permitted"),
            "OS error text must survive: {chain}"
        );
        // Display alone loses it, which is why `chain` exists.
        assert_eq!(err.to_string(), "failed to probe gateways");
    }
}
