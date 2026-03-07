// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use nym_vpn_proto::rpc_client::RpcClient;

use crate::boolean_option::BooleanOption;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Display current ad-blocking status
    Get,

    /// Enable or disable ad-blocking
    Set {
        /// enabled or disabled
        #[arg(value_parser = BooleanOption::custom_parser("enabled", "disabled"))]
        state: BooleanOption,
    },
}

impl Command {
    pub async fn execute(self, mut rpc_client: RpcClient) -> Result<()> {
        match self {
            Command::Get => {
                let config = rpc_client.get_config().await?;
                let status = if config.enable_ad_blocking {
                    "enabled"
                } else {
                    "disabled"
                };
                println!("Ad-blocking: {status}");
                Ok(())
            }
            Command::Set { state } => {
                rpc_client.set_enable_ad_blocking(*state).await?;
                Ok(())
            }
        }
    }
}
