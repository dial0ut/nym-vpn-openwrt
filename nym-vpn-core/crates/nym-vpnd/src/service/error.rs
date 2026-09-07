// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use nym_vpn_api_client::error::VpnApiClientError;
use nym_vpn_lib::{MixnetError, tunnel_state_machine::Error as TunnelStateMachineError};
use nym_vpn_lib_types::GatewayType;

use super::config::ConfigSetupError;

#[derive(Debug, thiserror::Error)]
pub enum SetNetworkError {
    #[error("failed to read config")]
    ReadConfig {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to write config")]
    WriteConfig {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to set network: {0}")]
    NetworkNotFound(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AccountLinksError {
    #[error("account management not configured")]
    AccountManagementNotConfigured,

    #[error("failed to parse account management paths")]
    FailedToParseAccountLinks,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to create account controller")]
    CreateAccountController(#[source] nym_vpn_account_controller::Error),

    #[error("failed to create gateway client")]
    CreateGatewayClient(#[source] nym_vpn_lib::gateway_directory::Error),

    #[error("config setup error")]
    ConfigSetup(#[source] ConfigSetupError),

    #[error("state machine error")]
    StateMachine(#[source] TunnelStateMachineError),

    #[error("mixnet setup error")]
    MixnetSetup(#[from] MixnetError),

    #[error("failed to create api client")]
    CreateApiClient(#[source] VpnApiClientError),

    #[error("invalid environment: {0}")]
    InvalidEnvironment(&'static str),

    #[error("failed to convert API URLs")]
    ConvertApiUrls(#[source] VpnApiClientError),

    #[error("failed to start discovery refresh")]
    StartDiscoveryRefresh(#[source] nym_vpn_network_config::Error),
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum GlobalConfigError {
    #[error("failed to read config")]
    ReadConfig(String),
    #[error("failed to write config")]
    WriteConfig(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ListGatewaysError {
    #[error("failed to get gateways ({gw_type:?})")]
    GetGateways {
        gw_type: GatewayType,
        source: nym_vpn_lib::gateway_directory::Error,
    },

    #[error("failed to get filtered gateways ({gw_type:?})")]
    GetFilteredGateways {
        gw_type: GatewayType,
        source: nym_vpn_lib::gateway_directory::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayTestError {
    #[error("failed to get gateways ({gw_type:?})")]
    GetGateways {
        gw_type: nym_vpn_lib::gateway_directory::GatewayType,
        source: nym_vpn_lib::gateway_directory::Error,
    },

    #[error("invalid gateway id: {0}")]
    InvalidGatewayId(String),

    #[error("no gateway to test: nothing selected and no entry or exit point configured")]
    NoTargets,

    #[error("invalid gateway test request")]
    Params(#[source] nym_vpn_lib_types::GatewayTestParamsError),

    /// One run at a time: the kill-switch probe hatch is rate limited for a
    /// single run, so a second concurrent run would read as packet loss.
    #[error("a gateway test is already running; wait for it to finish")]
    AlreadyRunning,

    #[error("gateway test did not finish within {}s", .0.as_secs())]
    Timeout(std::time::Duration),

    #[error("failed to probe gateways")]
    Probe(#[source] nym_vpn_lib::gateway_probe::ProbeError),
}

impl GatewayTestError {
    /// The whole cause chain on one line, for gRPC messages and log lines:
    /// `Display` alone stops at "failed to probe gateways" and hides the
    /// EPERM/ENETUNREACH underneath.
    pub fn chain(&self) -> String {
        let mut s = self.to_string();
        let mut source = std::error::Error::source(self);
        while let Some(err) = source {
            s.push_str(": ");
            s.push_str(&err.to_string());
            source = err.source();
        }
        s
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
