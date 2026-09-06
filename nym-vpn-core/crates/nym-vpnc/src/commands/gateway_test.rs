// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Table output for `nym-vpnc gateway test`.

use tabled::Table;

use nym_vpn_lib_types::{GatewayPairResult, GatewayTestReport, GatewayTestResult, GatewayTestRole};

use crate::table_style::TableStyle;

/// Characters of the base58 identity shown in tables. `--json` has the full id.
const SHORT_ID_LEN: usize = 8;

#[derive(tabled::Tabled)]
pub struct GatewayTestRow {
    #[tabled(rename = "ID")]
    pub id: String,
    #[tabled(rename = "Country")]
    pub country: String,
    #[tabled(rename = "Role")]
    pub role: String,
    #[tabled(rename = "Address")]
    pub address: String,
    #[tabled(rename = "Loss")]
    pub loss: String,
    #[tabled(rename = "RTT min")]
    pub rtt_min: String,
    #[tabled(rename = "RTT avg")]
    pub rtt_avg: String,
    #[tabled(rename = "RTT max")]
    pub rtt_max: String,
    #[tabled(rename = "Note")]
    pub note: String,
}

impl From<&GatewayTestResult> for GatewayTestRow {
    fn from(result: &GatewayTestResult) -> Self {
        Self {
            id: short_id(&result.id),
            country: result
                .country_code
                .clone()
                .unwrap_or_else(|| "-".to_owned()),
            role: display_role(result.role).to_owned(),
            address: result
                .address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            loss: fmt_loss(result),
            rtt_min: fmt_ms(result.rtt_min_ms),
            rtt_avg: fmt_ms(result.rtt_avg_ms),
            rtt_max: fmt_ms(result.rtt_max_ms),
            note: result.error.clone().unwrap_or_default(),
        }
    }
}

#[derive(tabled::Tabled)]
pub struct GatewayPairRow {
    #[tabled(rename = "Entry")]
    pub entry: String,
    #[tabled(rename = "Exit")]
    pub exit: String,
    #[tabled(rename = "Pair RTT")]
    pub rtt_sum: String,
    #[tabled(rename = "Loss")]
    pub loss: String,
}

impl GatewayPairRow {
    fn new(pair: &GatewayPairResult, report: &GatewayTestReport) -> Self {
        let label = |id: &str| match country_of(report, id) {
            Some(cc) => format!("{} [{cc}]", short_id(id)),
            None => short_id(id),
        };
        Self {
            entry: label(&pair.entry_id),
            exit: label(&pair.exit_id),
            rtt_sum: fmt_ms(Some(pair.rtt_sum_ms)),
            loss: fmt_percent(pair.loss_percent),
        }
    }
}

fn country_of<'r>(report: &'r GatewayTestReport, id: &str) -> Option<&'r str> {
    report
        .results
        .iter()
        .find(|r| r.id == id)
        .and_then(|r| r.country_code.as_deref())
}

pub fn short_id(id: &str) -> String {
    match id.char_indices().nth(SHORT_ID_LEN) {
        Some((cut, _)) => format!("{}…", &id[..cut]),
        None => id.to_owned(),
    }
}

pub fn display_role(role: GatewayTestRole) -> &'static str {
    match role {
        GatewayTestRole::Entry => "entry",
        GatewayTestRole::Exit => "exit",
        GatewayTestRole::Any => "-",
    }
}

pub fn fmt_ms(value: Option<f64>) -> String {
    match value {
        Some(ms) => format!("{ms:.1} ms"),
        None => "-".to_owned(),
    }
}

fn fmt_percent(value: f64) -> String {
    format!("{value:.0}%")
}

pub fn fmt_loss(result: &GatewayTestResult) -> String {
    match result.loss_percent() {
        Some(loss) => fmt_percent(loss),
        None => "-".to_owned(),
    }
}

pub fn print_report(report: &GatewayTestReport, style: TableStyle) {
    let rows = report.results.iter().map(GatewayTestRow::from);
    let mut table = Table::new(rows);
    style.apply_style(&mut table);
    println!("{table}");

    if !report.pairs.is_empty() {
        println!();
        println!("Pairs (entry RTT + exit RTT, best first):");
        let rows = report
            .pairs
            .iter()
            .map(|pair| GatewayPairRow::new(pair, report));
        let mut table = Table::new(rows);
        style.apply_style(&mut table);
        println!("{table}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, role: GatewayTestRole) -> GatewayTestResult {
        GatewayTestResult {
            id: id.to_owned(),
            name: Some("gw".to_owned()),
            country_code: Some("DE".to_owned()),
            role,
            address: Some("203.0.113.7".parse().unwrap()),
            sent: 5,
            received: 4,
            rtt_min_ms: Some(10.04),
            rtt_avg_ms: Some(12.5),
            rtt_max_ms: Some(20.96),
            error: None,
        }
    }

    #[test]
    fn short_id_truncates_with_ellipsis() {
        assert_eq!(short_id("ABCDEFGHIJKLMNOP"), "ABCDEFGH…");
        assert_eq!(short_id("ABCDEFGH"), "ABCDEFGH");
        assert_eq!(short_id("ABC"), "ABC");
    }

    #[test]
    fn formats_milliseconds_and_loss() {
        assert_eq!(fmt_ms(Some(12.5)), "12.5 ms");
        assert_eq!(fmt_ms(Some(0.049)), "0.0 ms");
        assert_eq!(fmt_ms(None), "-");
        assert_eq!(fmt_loss(&result("A", GatewayTestRole::Entry)), "20%");
        let mut unsent = result("A", GatewayTestRole::Entry);
        unsent.sent = 0;
        unsent.received = 0;
        assert_eq!(fmt_loss(&unsent), "-");
    }

    #[test]
    fn row_for_reachable_gateway() {
        let row = GatewayTestRow::from(&result("ABCDEFGHIJKLMNOP", GatewayTestRole::Exit));
        assert_eq!(row.id, "ABCDEFGH…");
        assert_eq!(row.country, "DE");
        assert_eq!(row.role, "exit");
        assert_eq!(row.address, "203.0.113.7");
        assert_eq!(row.loss, "20%");
        assert_eq!(row.rtt_min, "10.0 ms");
        assert_eq!(row.rtt_avg, "12.5 ms");
        assert_eq!(row.rtt_max, "21.0 ms");
        assert_eq!(row.note, "");
    }

    #[test]
    fn row_for_unresolved_gateway_shows_error() {
        let unresolved = GatewayTestResult {
            id: "ZZZZZZZZZZZZ".to_owned(),
            name: None,
            country_code: None,
            role: GatewayTestRole::Any,
            address: None,
            sent: 0,
            received: 0,
            rtt_min_ms: None,
            rtt_avg_ms: None,
            rtt_max_ms: None,
            error: Some("not found in the gateway directory".to_owned()),
        };
        let row = GatewayTestRow::from(&unresolved);
        assert_eq!(row.country, "-");
        assert_eq!(row.role, "-");
        assert_eq!(row.address, "-");
        assert_eq!(row.loss, "-");
        assert_eq!(row.rtt_avg, "-");
        assert_eq!(row.note, "not found in the gateway directory");
    }

    #[test]
    fn pair_row_labels_with_country() {
        let mut exit = result("EXITEXITEXIT", GatewayTestRole::Exit);
        exit.country_code = None;
        let report = GatewayTestReport::new(vec![
            result("ENTRYENTRYENTRY", GatewayTestRole::Entry),
            exit,
        ]);
        assert_eq!(report.pairs.len(), 1);
        let row = GatewayPairRow::new(&report.pairs[0], &report);
        assert_eq!(row.entry, "ENTRYENT… [DE]");
        assert_eq!(row.exit, "EXITEXIT…");
        assert_eq!(row.rtt_sum, "25.0 ms");
        assert_eq!(row.loss, "20%");
    }
}
