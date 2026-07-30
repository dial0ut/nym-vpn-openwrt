// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{Result, anyhow};
use nym_vpn_lib_types::DnsUpstreamOwner;
use nym_vpn_proto::rpc_client::RpcClient;
use std::net::IpAddr;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Get Custom DNS servers
    Get,

    /// Enable Custom DNS
    Enable,

    /// Disable Custom DNS
    Disable,

    /// Set Custom DNS servers (space separated)
    Set { dns_servers: Vec<String> },

    /// Clear Custom DNS servers
    Clear,

    /// Get the Default DNS servers
    GetDefault,
}

impl Command {
    pub async fn execute(self, mut rpc_client: RpcClient) -> Result<()> {
        match self {
            Command::Get => {
                let config = rpc_client.get_config().await?;
                println!(
                    "Custom DNS: {} [{}]",
                    if config.enable_custom_dns {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                    config
                        .custom_dns
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                // The setting above is what was asked for; say so plainly when it
                // isn't what the resolver is actually doing. A daemon too old to
                // answer must not turn `dns get` into an error — stay quiet.
                let owner = rpc_client
                    .get_dns_upstream_owner()
                    .await
                    .unwrap_or(DnsUpstreamOwner::NotApplicable);
                if owner == DnsUpstreamOwner::User {
                    println!(
                        "\nNOT APPLIED: dnsmasq has 'noresolv' set, so you manage upstream DNS.\n\
                         The servers above are ignored; dnsmasq's own forwards (Network > DNS >\n\
                         Forwards in LuCI, 'uci show dhcp' server= entries) are what resolve, and\n\
                         they ride the tunnel while connected. Clear noresolv to let the VPN\n\
                         supply DNS instead."
                    );
                }
                Ok(())
            }
            Command::Enable => {
                rpc_client.set_enable_custom_dns(true).await?;
                Ok(())
            }
            Command::Disable => {
                rpc_client.set_enable_custom_dns(false).await?;
                Ok(())
            }
            Command::Set { dns_servers } => {
                let ip_addr_list = dns_servers
                    .iter()
                    .map(|s| {
                        s.parse()
                            .map_err(|e| anyhow!("Failed to parse '{s}' as an IP address: {e}",))
                    })
                    .collect::<Result<Vec<IpAddr>>>()?;
                rpc_client.set_custom_dns(ip_addr_list).await?;
                Ok(())
            }
            Command::Clear => {
                // You can also use `Set`, and specify no servers, but this is clearer.
                rpc_client.set_custom_dns(vec![]).await?;
                Ok(())
            }
            Command::GetDefault => {
                let default_dns = rpc_client.get_default_dns().await?;
                println!(
                    "Default DNS: {}",
                    default_dns
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                Ok(())
            }
        }
    }
}
