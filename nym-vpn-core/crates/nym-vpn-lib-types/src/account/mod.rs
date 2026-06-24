// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

pub mod controller_error;
pub mod controller_event;
pub mod controller_state;
pub mod deeplink;
pub mod request_zknym;
pub mod ticketbooks;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct RegisterAccountResponse {
    pub account_token: String,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountCommandError {
    // Internal error that should not happen
    #[error("internal error: {0}")]
    Internal(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("vpn-api error")]
    VpnApi(#[from] VpnApiError),

    #[error("unexpected vpn-api response: {0}")]
    UnexpectedVpnApiResponse(String),

    #[error("failed to connect to nyxd instance: {0}")]
    NyxdConnectionFailure(String),

    #[error("failed to resolve query to a nyxd instance: {0}")]
    NyxdQueryFailure(String),

    #[error("account doesn't exist on chain")]
    AccountDoesntExistOnChain,

    #[error("no account stored")]
    NoAccountStored,

    #[error("no device stored")]
    NoDeviceStored,

    #[error("an account is already stored")]
    ExistingAccount,

    #[error("no connectivity")]
    Offline,

    #[error("account is not set in decentralised mode")]
    AccountNotDecentralised,

    #[error("account is set in decentralised mode")]
    AccountDecentralised,

    #[error("account does not have sufficient funds")]
    InsufficientFunds,

    #[error("failed to obtain zk-nym: {0}")]
    ZkNymAcquisitionFailure(String),

    #[error("invalid passphrase: {0}")]
    InvalidMnemonic(String),

    #[error("invalid secret: {0}")]
    InvalidSecret(String),

    #[error("deeplink error: {0}")]
    DeeplinkError(String),
}

impl AccountCommandError {
    pub fn internal(message: impl ToString) -> Self {
        AccountCommandError::Internal(message.to_string())
    }

    pub fn storage(message: impl ToString) -> Self {
        AccountCommandError::Storage(message.to_string())
    }

    pub fn unexpected_response(message: impl std::fmt::Debug) -> Self {
        AccountCommandError::UnexpectedVpnApiResponse(format!("{message:?}"))
    }
}

#[cfg(feature = "nym-type-conversions")]
impl From<nym_validator_client::nyxd::error::NyxdError> for AccountCommandError {
    fn from(e: nym_validator_client::nyxd::error::NyxdError) -> Self {
        AccountCommandError::NyxdQueryFailure(e.to_string())
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum VpnApiError {
    #[error("timeout: {0}")]
    Timeout(String),

    #[error("status code: {code}, error: {msg}")]
    StatusCode { code: u16, msg: String },

    #[error(transparent)]
    Response(#[from] VpnApiErrorResponse),
}

impl VpnApiError {
    pub fn message(&self) -> String {
        match self {
            VpnApiError::Response(err) => err.message.clone(),
            VpnApiError::StatusCode { .. } => self.to_string(),
            VpnApiError::Timeout(_) => self.to_string(),
        }
    }

    pub fn message_id(&self) -> Option<String> {
        if let VpnApiError::Response(err) = self {
            err.message_id.clone()
        } else {
            None
        }
    }

    pub fn code_reference_id(&self) -> Option<String> {
        if let VpnApiError::Response(err) = self {
            err.code_reference_id.clone()
        } else {
            None
        }
    }
}

// That should disappear when reworking those errors
#[cfg(feature = "nym-type-conversions")]
impl TryFrom<nym_vpn_api_client::error::VpnApiClientError> for VpnApiError {
    type Error = nym_vpn_api_client::error::VpnApiClientError;

    fn try_from(err: nym_vpn_api_client::error::VpnApiClientError) -> Result<Self, Self::Error> {
        let err = match VpnApiErrorResponse::try_from(err) {
            Ok(err) => return Ok(Self::Response(err)),
            Err(err) => err,
        };

        if err
            .http_client_error()
            .is_some_and(nym_vpn_api_client::error::HttpClientError::is_timeout)
        {
            return Ok(Self::Timeout(err.to_string()));
        }

        match err
            .http_client_error()
            .and_then(nym_vpn_api_client::error::HttpClientError::status_code)
        {
            Some(code) => Ok(Self::StatusCode {
                code: code.into(),
                msg: err.to_string(),
            }),
            None => Err(err),
        }
    }
}

#[cfg(feature = "nym-type-conversions")]
impl From<nym_vpn_api_client::error::VpnApiClientError> for AccountCommandError {
    fn from(err: nym_vpn_api_client::error::VpnApiClientError) -> Self {
        use nym_vpn_api_client::response::NymErrorResponse;
        // TODO: Another example of losing information about the original error cause
        match NymErrorResponse::try_from(err) {
            Ok(err) => AccountCommandError::VpnApi(VpnApiError::Response(err.into())),
            Err(e) => AccountCommandError::Internal(e.to_string()),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("{message}, message_id: {message_id:?}, code_reference_id: {code_reference_id:?}")]
pub struct VpnApiErrorResponse {
    pub message: String,
    pub message_id: Option<String>,
    pub code_reference_id: Option<String>,
}

#[cfg(feature = "nym-type-conversions")]
impl TryFrom<nym_vpn_api_client::error::VpnApiClientError> for VpnApiErrorResponse {
    type Error = nym_vpn_api_client::error::VpnApiClientError;

    fn try_from(err: nym_vpn_api_client::error::VpnApiClientError) -> Result<Self, Self::Error> {
        Ok(VpnApiErrorResponse::from(
            nym_vpn_api_client::response::NymErrorResponse::try_from(err)?,
        ))
    }
}

#[cfg(feature = "nym-type-conversions")]
impl From<nym_vpn_api_client::response::NymErrorResponse> for VpnApiErrorResponse {
    fn from(err: nym_vpn_api_client::response::NymErrorResponse) -> Self {
        Self {
            message: err.message,
            message_id: err.message_id,
            code_reference_id: err.code_reference_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct VpnAccountSummary {
    #[cfg_attr(feature = "typescript-bindings", ts(as = "String"))]
    #[cfg_attr(feature = "serde", serde(with = "time::serde::iso8601::option"))]
    pub subscription_valid_until: Option<OffsetDateTime>,

    pub traffic_used_gb: u64,

    pub traffic_limit_gb: u64,

    #[cfg_attr(feature = "typescript-bindings", ts(as = "String"))]
    #[cfg_attr(feature = "serde", serde(with = "time::serde::iso8601::option"))]
    pub traffic_reset_time: Option<OffsetDateTime>,
}

impl VpnAccountSummary {
    pub fn new(
        subscription_expiry_time: Option<String>,
        traffic_used_gb: u64,
        traffic_limit_gb: u64,
        traffic_reset_time: Option<String>,
    ) -> Self {
        Self {
            subscription_valid_until: subscription_expiry_time
                .as_deref()
                .and_then(parse_api_timestamp),
            traffic_used_gb,
            traffic_limit_gb,
            traffic_reset_time: traffic_reset_time.as_deref().and_then(parse_api_timestamp),
        }
    }

    pub fn fair_usage_left(&self) -> bool {
        // A limit of 0 means the API has no reliable fair-usage figure for this
        // account (e.g. a transient fair-usage database outage), NOT that the
        // quota is exhausted. Treat it as "usage available" so an always-on
        // router is not torn down on a false positive. Genuine depletion is only
        // a positive limit that has been reached.
        self.traffic_limit_gb == 0 || self.traffic_used_gb < self.traffic_limit_gb
    }
}

/// Parse an RFC 3339 timestamp from the VPN API, tolerating the space-separated
/// variant some endpoints emit (`"2026-06-03 17:31:15Z"` vs the canonical
/// `"2026-06-03T17:15:15Z"`). A single malformed field must never fail the whole
/// account summary (the root cause of accounts silently appearing inactive), so
/// on error we log and fall back to `None`.
fn parse_api_timestamp(raw: &str) -> Option<OffsetDateTime> {
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    OffsetDateTime::parse(raw, rfc3339)
        .or_else(|_| OffsetDateTime::parse(&raw.replacen(' ', "T", 1), rfc3339))
        .map_err(|err| {
            tracing::warn!("Ignoring unparseable account-summary timestamp {raw:?}: {err}");
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fair_usage_left_treats_unknown_limit_as_available() {
        // limit == 0 is the API's "unknown / unavailable" sentinel — must not be
        // read as depleted (regression: false BandwidthExceeded teardown).
        assert!(VpnAccountSummary::new(None, 0, 0, None).fair_usage_left());
        assert!(VpnAccountSummary::new(None, 100, 0, None).fair_usage_left());
    }

    #[test]
    fn fair_usage_left_detects_real_depletion() {
        assert!(VpnAccountSummary::new(None, 5, 10, None).fair_usage_left());
        assert!(!VpnAccountSummary::new(None, 10, 10, None).fair_usage_left());
        assert!(!VpnAccountSummary::new(None, 11, 10, None).fair_usage_left());
    }

    #[test]
    fn parses_canonical_and_space_separated_timestamps() {
        assert!(parse_api_timestamp("2026-06-03T17:15:15Z").is_some());
        assert!(parse_api_timestamp("2026-06-03 17:15:15Z").is_some());
    }

    #[test]
    fn one_bad_timestamp_does_not_fail_the_summary() {
        let summary = VpnAccountSummary::new(
            Some("not-a-date".to_string()),
            1,
            10,
            Some("2026-06-03 17:15:15Z".to_string()),
        );
        assert!(summary.subscription_valid_until.is_none());
        assert!(summary.traffic_reset_time.is_some());
    }
}
