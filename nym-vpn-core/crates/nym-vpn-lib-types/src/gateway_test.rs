// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Parameters and results of the daemon-side gateway latency / packet-loss
//! probe behind `nym-vpnc gateway test`.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::net::IpAddr;

/// Echo requests per gateway when the request leaves `count` at zero.
pub const DEFAULT_PROBE_COUNT: u32 = 5;
/// Per-probe timeout when the request leaves `timeout_ms` at zero.
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 2000;
/// Candidates per country when the request leaves `top` at zero.
pub const DEFAULT_TOP_CANDIDATES: u32 = 5;

/// Upper bounds the daemon clamps a request to, so one call stays bounded.
pub const MAX_PROBE_COUNT: u32 = 20;
pub const MAX_PROBE_TIMEOUT_MS: u32 = 10_000;
pub const MAX_TOP_CANDIDATES: u32 = 20;

/// Which gateways to probe for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayTestSelector {
    /// One gateway, by base58 identity.
    Gateway(String),
    /// The best-scored gateways in a country (two-letter ISO code).
    Country(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayTestParams {
    /// Entry-role gateways. `None` means the configured (or, when connected,
    /// the active) entry point.
    pub entry: Option<GatewayTestSelector>,
    /// Exit-role gateways, likewise.
    pub exit: Option<GatewayTestSelector>,
    /// Identities probed without a role. When neither selector is set and
    /// this is non-empty, only these are probed.
    pub gateways: Vec<String>,
    /// Echo requests per gateway; 0 selects [`DEFAULT_PROBE_COUNT`].
    pub count: u32,
    /// Per-probe timeout; 0 selects [`DEFAULT_PROBE_TIMEOUT_MS`].
    pub timeout_ms: u32,
    /// Candidates per country selector; 0 selects [`DEFAULT_TOP_CANDIDATES`].
    pub top: u32,
}

impl GatewayTestParams {
    pub fn effective_count(&self) -> u32 {
        clamp_or_default(self.count, DEFAULT_PROBE_COUNT, MAX_PROBE_COUNT)
    }

    pub fn effective_timeout_ms(&self) -> u32 {
        clamp_or_default(
            self.timeout_ms,
            DEFAULT_PROBE_TIMEOUT_MS,
            MAX_PROBE_TIMEOUT_MS,
        )
    }

    pub fn effective_top(&self) -> u32 {
        clamp_or_default(self.top, DEFAULT_TOP_CANDIDATES, MAX_TOP_CANDIDATES)
    }

    /// True when only the explicit `gateways` list is to be probed.
    pub fn explicit_only(&self) -> bool {
        self.entry.is_none() && self.exit.is_none() && !self.gateways.is_empty()
    }
}

fn clamp_or_default(value: u32, default: u32, max: u32) -> u32 {
    if value == 0 { default } else { value.min(max) }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTestRole {
    Entry,
    Exit,
    /// Probed on request, without a role in the pair.
    Any,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayTestResult {
    /// Base58 gateway identity.
    pub id: String,
    pub name: Option<String>,
    /// Two-letter ISO country code from the directory.
    pub country_code: Option<String>,
    pub role: GatewayTestRole,
    /// Address the probes went to; `None` when the gateway could not be
    /// resolved (see `error`).
    pub address: Option<IpAddr>,
    pub sent: u32,
    pub received: u32,
    pub rtt_min_ms: Option<f64>,
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    /// Why the gateway was not (fully) probed: unknown identity, no address
    /// in the directory, or a socket error such as network unreachable.
    pub error: Option<String>,
}

impl GatewayTestResult {
    /// Loss in percent; `None` when nothing was sent.
    pub fn loss_percent(&self) -> Option<f64> {
        if self.sent == 0 {
            return None;
        }
        let lost = self.sent.saturating_sub(self.received);
        Some(100.0 * f64::from(lost) / f64::from(self.sent))
    }

    pub fn reachable(&self) -> bool {
        self.received > 0
    }
}

/// An entry/exit combination and the summed RTT of its two halves.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayPairResult {
    pub entry_id: String,
    pub exit_id: String,
    /// `entry.rtt_avg_ms + exit.rtt_avg_ms`: a proxy for the pair's round
    /// trip as seen from the router.
    pub rtt_sum_ms: f64,
    /// The worse loss figure of the two gateways.
    pub loss_percent: f64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayTestReport {
    pub results: Vec<GatewayTestResult>,
    /// Every reachable entry paired with every reachable exit, best first.
    pub pairs: Vec<GatewayPairResult>,
}

impl GatewayTestReport {
    pub fn new(results: Vec<GatewayTestResult>) -> Self {
        let pairs = pair_results(&results);
        Self { results, pairs }
    }
}

/// Combine every reachable entry with every reachable exit, ordered by summed
/// average RTT. Gateways probed without a role take no part, and a gateway
/// is never paired with itself.
pub fn pair_results(results: &[GatewayTestResult]) -> Vec<GatewayPairResult> {
    let with_role = |role: GatewayTestRole| {
        results
            .iter()
            .filter(move |r| r.role == role)
            .filter_map(|r| r.rtt_avg_ms.map(|avg| (r, avg)))
    };

    let mut pairs = Vec::new();
    for (entry, entry_avg) in with_role(GatewayTestRole::Entry) {
        for (exit, exit_avg) in with_role(GatewayTestRole::Exit) {
            if entry.id == exit.id {
                continue;
            }
            let loss_percent = entry
                .loss_percent()
                .unwrap_or(0.0)
                .max(exit.loss_percent().unwrap_or(0.0));
            pairs.push(GatewayPairResult {
                entry_id: entry.id.clone(),
                exit_id: exit.id.clone(),
                rtt_sum_ms: entry_avg + exit_avg,
                loss_percent,
            });
        }
    }
    pairs.sort_by(|a, b| a.rtt_sum_ms.total_cmp(&b.rtt_sum_ms));
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        id: &str,
        role: GatewayTestRole,
        sent: u32,
        received: u32,
        avg: Option<f64>,
    ) -> GatewayTestResult {
        GatewayTestResult {
            id: id.to_owned(),
            name: None,
            country_code: None,
            role,
            address: None,
            sent,
            received,
            rtt_min_ms: avg,
            rtt_avg_ms: avg,
            rtt_max_ms: avg,
            error: None,
        }
    }

    #[test]
    fn params_fall_back_to_defaults_and_are_capped() {
        let zero = GatewayTestParams::default();
        assert_eq!(zero.effective_count(), DEFAULT_PROBE_COUNT);
        assert_eq!(zero.effective_timeout_ms(), DEFAULT_PROBE_TIMEOUT_MS);
        assert_eq!(zero.effective_top(), DEFAULT_TOP_CANDIDATES);

        let huge = GatewayTestParams {
            count: 1000,
            timeout_ms: 1_000_000,
            top: 1000,
            ..Default::default()
        };
        assert_eq!(huge.effective_count(), MAX_PROBE_COUNT);
        assert_eq!(huge.effective_timeout_ms(), MAX_PROBE_TIMEOUT_MS);
        assert_eq!(huge.effective_top(), MAX_TOP_CANDIDATES);

        let plain = GatewayTestParams {
            count: 3,
            ..Default::default()
        };
        assert_eq!(plain.effective_count(), 3);
    }

    #[test]
    fn explicit_only_requires_ids_and_no_selectors() {
        let mut params = GatewayTestParams {
            gateways: vec!["A".into()],
            ..Default::default()
        };
        assert!(params.explicit_only());
        params.entry = Some(GatewayTestSelector::Country("DE".into()));
        assert!(!params.explicit_only());
        assert!(!GatewayTestParams::default().explicit_only());
    }

    #[test]
    fn loss_percent() {
        assert_eq!(
            result("A", GatewayTestRole::Any, 5, 5, None).loss_percent(),
            Some(0.0)
        );
        assert_eq!(
            result("A", GatewayTestRole::Any, 5, 3, None).loss_percent(),
            Some(40.0)
        );
        assert_eq!(
            result("A", GatewayTestRole::Any, 4, 0, None).loss_percent(),
            Some(100.0)
        );
        assert_eq!(
            result("A", GatewayTestRole::Any, 0, 0, None).loss_percent(),
            None
        );
    }

    #[test]
    fn pairs_are_sorted_by_summed_rtt_and_skip_unreachable_and_roleless() {
        let results = vec![
            result("E1", GatewayTestRole::Entry, 5, 5, Some(30.0)),
            result("E2", GatewayTestRole::Entry, 5, 4, Some(10.0)),
            result("E3", GatewayTestRole::Entry, 5, 0, None),
            result("X1", GatewayTestRole::Exit, 5, 5, Some(50.0)),
            result("X2", GatewayTestRole::Exit, 5, 5, Some(20.0)),
            result("A1", GatewayTestRole::Any, 5, 5, Some(1.0)),
        ];
        let pairs = pair_results(&results);
        let order: Vec<(&str, &str, f64)> = pairs
            .iter()
            .map(|p| (p.entry_id.as_str(), p.exit_id.as_str(), p.rtt_sum_ms))
            .collect();
        assert_eq!(
            order,
            vec![
                ("E2", "X2", 30.0),
                ("E1", "X2", 50.0),
                ("E2", "X1", 60.0),
                ("E1", "X1", 80.0),
            ]
        );
        // The pair inherits the worse loss of its two halves.
        assert_eq!(pairs[0].loss_percent, 20.0);
        assert_eq!(pairs[1].loss_percent, 0.0);
    }

    #[test]
    fn a_gateway_is_never_paired_with_itself() {
        let results = vec![
            result("G", GatewayTestRole::Entry, 5, 5, Some(10.0)),
            result("G", GatewayTestRole::Exit, 5, 5, Some(10.0)),
            result("X", GatewayTestRole::Exit, 5, 5, Some(10.0)),
        ];
        let pairs = pair_results(&results);
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            (pairs[0].entry_id.as_str(), pairs[0].exit_id.as_str()),
            ("G", "X")
        );
    }

    #[test]
    fn report_new_fills_pairs() {
        let report = GatewayTestReport::new(vec![
            result("E", GatewayTestRole::Entry, 5, 5, Some(10.0)),
            result("X", GatewayTestRole::Exit, 5, 5, Some(15.0)),
        ]);
        assert_eq!(report.pairs.len(), 1);
        assert_eq!(report.pairs[0].rtt_sum_ms, 25.0);
        assert!(GatewayTestReport::new(vec![]).pairs.is_empty());
    }
}
