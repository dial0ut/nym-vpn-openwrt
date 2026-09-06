// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use nym_vpn_proto::rpc_client::RpcClient;

use crate::{
    boolean_option::BooleanOption,
    display_helpers::{LEWES_PROTOCOL_LINE, display_on_off, gateway_independence_summary},
};
use clap::builder::ValueParser;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// Display current tunnel configuration
    Get,

    /// Update tunnel configuration
    Set(Box<SetParams>),
}

#[derive(Debug, Clone, clap::Args)]
#[group(required = true, multiple = true)]
pub struct SetParams {
    /// Enable or disable IPv6
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    ipv6: Option<BooleanOption>,

    /// Enable or disable two-hop mode
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    two_hop: Option<BooleanOption>,

    /// Enable or disable netstack in two-hop mode
    /// Normally this is only used for testing purposes and should always be off
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    netstack: Option<BooleanOption>,

    /// Enable or disable the kill-switch (firewall + default route).
    /// Disable for PBR (Policy-Based Routing) compatibility.
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    killswitch: Option<BooleanOption>,

    /// Enable or disable legacy (inclusive) split tunneling. When enabled the
    /// default route into the tunnel is withheld so only PBR-selected traffic is
    /// routed in. Mutually exclusive with the kill-switch (forced off).
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    legacy_split_tunnel: Option<BooleanOption>,

    /// Enable or disable Stealth API connect: reach the Nym API through cover
    /// domains on every request instead of only after a direct request fails.
    /// Slower API calls, but works where the API is blocked. No reconnect needed.
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    stealth_api: Option<BooleanOption>,

    /// Require the entry and exit gateway to be independent: different node
    /// family, ASN and subnet. Switches all three criteria at once. When no
    /// independent pair exists the connect fails and asks to relax the
    /// criteria (see `connect-v2 --relax-independence`).
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    gateway_independence: Option<BooleanOption>,

    /// Remind the user when the selected entry and exit are not independent.
    #[arg(long, value_parser = clap::value_parser!(BooleanOption))]
    family_reminders: Option<BooleanOption>,

    /// Enable Circumvention Transport (CT) wrapping for the connection to the entry gateway in two hop wireguard mode.
    #[arg(long, alias = "ct", value_parser = clap::value_parser!(BooleanOption))]
    circumvention_transports: Option<BooleanOption>,

    /// Set the average delay for a loop cover packet (milliseconds)
    #[arg(
    long,
    value_name = "MILLISECONDS",
    value_parser = ValueParser::from(|s: &str| -> Result<u32, String> {
        s.parse().map_err(|_| format!("Invalid integer: {}", s))
    })
    )]
    loop_cover_stream_average_delay: Option<u32>,

    /// Set average packet delay at each mixnode (milliseconds)
    #[arg(
    long,
    value_name = "MILLISECONDS",
    value_parser = ValueParser::from(|s: &str| -> Result<u32, String> {
        s.parse().map_err(|_| format!("Invalid integer: {}", s))
    })
    )]
    average_packet_delay: Option<u32>,

    /// Set average real message sending delay (milliseconds)
    #[arg(
    long,
    value_name = "MILLISECONDS",
    value_parser = ValueParser::from(|s: &str| -> Result<u32, String> {
        s.parse().map_err(|_| format!("Invalid integer: {}", s))
    })
    )]
    message_sending_delay: Option<u32>,
    #[arg(
        long,
        help = "Disable Poisson process rate limiting for real traffic",
        value_parser = clap::value_parser!(BooleanOption),
    )]
    disable_real_traffic_poisson_rate: Option<BooleanOption>,
    #[arg(
        long,
        help = "Disable background loop cover (decoy) traffic",
        value_parser = clap::value_parser!(BooleanOption),
    )]
    disable_background_cover_traffic: Option<BooleanOption>,
}

impl Command {
    pub async fn execute(self, mut rpc_client: RpcClient) -> Result<()> {
        match self {
            Command::Get => {
                let config = rpc_client.get_config().await?;
                println!("IPv6: {}", display_on_off(!config.disable_ipv6));
                println!("Two-hop: {}", display_on_off(config.enable_two_hop));
                println!("{LEWES_PROTOCOL_LINE}");
                println!("Netstack: {}", display_on_off(config.netstack));
                println!(
                    "Circumvention transports: {}",
                    display_on_off(config.enable_bridges)
                );
                println!("Kill-switch: {}", display_on_off(config.killswitch));
                println!(
                    "Legacy-split-tunnel: {}",
                    display_on_off(config.legacy_split_tunnel)
                );
                // Fronting needs cover domains published by the network
                // environment; without them the setting has nothing to act on.
                let cover_domains = match rpc_client.get_info().await {
                    Ok(info) => info.has_api_cover_domains(),
                    Err(_) => true,
                };
                println!(
                    "Stealth API connect: {}{}",
                    display_on_off(config.stealth_api),
                    if cover_domains {
                        ""
                    } else {
                        " (no cover domains available)"
                    }
                );
                println!(
                    "Gateway independence: {}",
                    gateway_independence_summary(&config.gateway_independence)
                );
                println!(
                    "Family reminders: {}",
                    display_on_off(config.gateway_independence.enable_notifications)
                );
                if config.inbound_exemptions.is_empty() {
                    println!("Inbound exemptions: none");
                } else {
                    let list = config
                        .inbound_exemptions
                        .iter()
                        .map(|e| format!("{}/{}", e.proto, e.dport))
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("Inbound exemptions: {list}");
                }
                println!("Mixnet traffic configuration: {}", config.mixnet_traffic);

                Ok(())
            }
            Command::Set(params) => {
                if let Some(killswitch) = params.killswitch {
                    rpc_client.set_killswitch(*killswitch).await?;
                }

                if let Some(legacy_split_tunnel) = params.legacy_split_tunnel {
                    rpc_client
                        .set_legacy_split_tunnel(*legacy_split_tunnel)
                        .await?;
                }

                if let Some(stealth_api) = params.stealth_api {
                    rpc_client.set_stealth_api(*stealth_api).await?;
                }

                if let Some(gateway_independence) = params.gateway_independence {
                    rpc_client
                        .set_enable_gateway_independence(*gateway_independence)
                        .await?;
                }

                if let Some(family_reminders) = params.family_reminders {
                    rpc_client
                        .set_gateway_independence_notifications(*family_reminders)
                        .await?;
                }

                if let Some(two_hop) = params.two_hop {
                    rpc_client.set_enable_two_hop(*two_hop).await?;
                }

                if let Some(netstack) = params.netstack {
                    rpc_client.set_netstack(*netstack).await?;
                }

                if let Some(ipv6) = params.ipv6 {
                    rpc_client.set_disable_ipv6(!*ipv6).await?;
                }

                if let Some(enable_ct) = params.circumvention_transports {
                    rpc_client.set_enable_bridges(*enable_ct).await?;
                }

                if params.loop_cover_stream_average_delay.is_some()
                    || params.average_packet_delay.is_some()
                    || params.message_sending_delay.is_some()
                    || params.disable_real_traffic_poisson_rate.is_some()
                    || params.disable_background_cover_traffic.is_some()
                {
                    let mut config = rpc_client.get_config().await?;

                    if let Some(loop_delay) = params.loop_cover_stream_average_delay {
                        config
                            .mixnet_traffic
                            .poisson_parameter_for_loop_cover_stream = Some(loop_delay);
                    }

                    if let Some(average_packet_delay) = params.average_packet_delay {
                        config.mixnet_traffic.average_packet_delay = Some(average_packet_delay);
                    }

                    if let Some(message_sending_delay) = params.message_sending_delay {
                        config.mixnet_traffic.message_sending_average_delay =
                            Some(message_sending_delay);
                    }

                    if let Some(disable_poisson_rate) = params.disable_real_traffic_poisson_rate {
                        config.mixnet_traffic.disable_poisson_rate = *disable_poisson_rate;
                    }

                    if let Some(disable_background_cover_traffic) =
                        params.disable_background_cover_traffic
                    {
                        config.mixnet_traffic.disable_background_cover_traffic =
                            *disable_background_cover_traffic;
                    }

                    rpc_client
                        .set_mixnet_traffic_config(config.mixnet_traffic)
                        .await?;
                }

                Ok(())
            }
        }
    }
}
