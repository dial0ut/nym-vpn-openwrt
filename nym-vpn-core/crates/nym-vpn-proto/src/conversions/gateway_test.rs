// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_vpn_lib_types::{
    GatewayTestParams, GatewayTestReport, GatewayTestResult, GatewayTestRole, GatewayTestSelector,
};

use crate::{conversions::ConversionError, proto};

impl From<GatewayTestSelector> for proto::GatewayTestSelector {
    fn from(value: GatewayTestSelector) -> Self {
        let selector = match value {
            GatewayTestSelector::Gateway(id) => {
                proto::gateway_test_selector::Selector::Gateway(proto::GatewayId { id })
            }
            GatewayTestSelector::Country(two_letter_iso_country_code) => {
                proto::gateway_test_selector::Selector::Country(proto::Country {
                    two_letter_iso_country_code,
                })
            }
        };
        Self {
            selector: Some(selector),
        }
    }
}

impl TryFrom<proto::GatewayTestSelector> for GatewayTestSelector {
    type Error = ConversionError;

    fn try_from(value: proto::GatewayTestSelector) -> Result<Self, Self::Error> {
        let selector = value
            .selector
            .ok_or(ConversionError::NoValueSet("GatewayTestSelector.selector"))?;
        Ok(match selector {
            proto::gateway_test_selector::Selector::Gateway(gateway) => {
                GatewayTestSelector::Gateway(gateway.id)
            }
            proto::gateway_test_selector::Selector::Country(country) => {
                GatewayTestSelector::Country(country.two_letter_iso_country_code)
            }
        })
    }
}

impl From<GatewayTestParams> for proto::GatewayTestParams {
    fn from(value: GatewayTestParams) -> Self {
        Self {
            entry: value.entry.map(Into::into),
            exit: value.exit.map(Into::into),
            gateways: value
                .gateways
                .into_iter()
                .map(|id| proto::GatewayId { id })
                .collect(),
            count: value.count,
            timeout_ms: value.timeout_ms,
            top: value.top,
        }
    }
}

impl TryFrom<proto::GatewayTestParams> for GatewayTestParams {
    type Error = ConversionError;

    fn try_from(value: proto::GatewayTestParams) -> Result<Self, Self::Error> {
        let mut params = Self {
            entry: value.entry.map(TryInto::try_into).transpose()?,
            exit: value.exit.map(TryInto::try_into).transpose()?,
            gateways: value.gateways.into_iter().map(|g| g.id).collect(),
            count: value.count,
            timeout_ms: value.timeout_ms,
            top: value.top,
        };
        // The explicit list is the one knob that is rejected rather than
        // clamped; do it here so the daemon answers INVALID_ARGUMENT before
        // any work starts.
        params.dedup_gateways();
        params
            .validate()
            .map_err(|e| ConversionError::Generic(e.to_string()))?;
        Ok(params)
    }
}

impl From<GatewayTestRole> for proto::GatewayTestRole {
    fn from(value: GatewayTestRole) -> Self {
        match value {
            GatewayTestRole::Any => proto::GatewayTestRole::Any,
            GatewayTestRole::Entry => proto::GatewayTestRole::Entry,
            GatewayTestRole::Exit => proto::GatewayTestRole::Exit,
        }
    }
}

impl From<proto::GatewayTestRole> for GatewayTestRole {
    fn from(value: proto::GatewayTestRole) -> Self {
        match value {
            proto::GatewayTestRole::Any => GatewayTestRole::Any,
            proto::GatewayTestRole::Entry => GatewayTestRole::Entry,
            proto::GatewayTestRole::Exit => GatewayTestRole::Exit,
        }
    }
}

impl From<GatewayTestResult> for proto::GatewayTestResult {
    fn from(value: GatewayTestResult) -> Self {
        Self {
            id: value.id,
            name: value.name,
            country_code: value.country_code,
            role: proto::GatewayTestRole::from(value.role) as i32,
            address: value.address.map(|ip| ip.to_string()),
            sent: value.sent,
            received: value.received,
            rtt_min_ms: value.rtt_min_ms,
            rtt_avg_ms: value.rtt_avg_ms,
            rtt_max_ms: value.rtt_max_ms,
            error: value.error,
        }
    }
}

impl TryFrom<proto::GatewayTestResult> for GatewayTestResult {
    type Error = ConversionError;

    fn try_from(value: proto::GatewayTestResult) -> Result<Self, Self::Error> {
        let role = proto::GatewayTestRole::try_from(value.role)
            .map_err(|err| ConversionError::Decode("GatewayTestRole", err))?;
        let address = value
            .address
            .map(|ip| ip.parse())
            .transpose()
            .map_err(|err| ConversionError::ParseAddr("GatewayTestResult.address", err))?;
        Ok(Self {
            id: value.id,
            name: value.name,
            country_code: value.country_code,
            role: role.into(),
            address,
            sent: value.sent,
            received: value.received,
            rtt_min_ms: value.rtt_min_ms,
            rtt_avg_ms: value.rtt_avg_ms,
            rtt_max_ms: value.rtt_max_ms,
            error: value.error,
        })
    }
}

impl From<GatewayTestReport> for proto::GatewayTestReport {
    fn from(value: GatewayTestReport) -> Self {
        // Pairs are derived from the results on the receiving side.
        Self {
            results: value.results.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::GatewayTestReport> for GatewayTestReport {
    type Error = ConversionError;

    fn try_from(value: proto::GatewayTestReport) -> Result<Self, Self::Error> {
        let results = value
            .results
            .into_iter()
            .map(GatewayTestResult::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GatewayTestReport::new(results))
    }
}
