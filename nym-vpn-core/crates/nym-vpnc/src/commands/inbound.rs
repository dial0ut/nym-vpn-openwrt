// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{Result, anyhow, bail};

use nym_vpn_lib_types::{InboundExemption, InboundExemptionProtocol};
use nym_vpn_proto::rpc_client::RpcClient;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Command {
    /// List configured inbound-service exemptions
    List,

    /// Add a new exemption (e.g. `tcp:443`, `udp:51820`)
    Add {
        /// Exemption in `<proto>:<port>` form
        spec: String,

        /// Optional human-readable label
        #[arg(long)]
        label: Option<String>,
    },

    /// Delete an exemption (e.g. `tcp:443`)
    Del {
        /// Exemption in `<proto>:<port>` form
        spec: String,
    },
}

impl Command {
    pub async fn execute(self, mut rpc_client: RpcClient) -> Result<()> {
        match self {
            Command::List => {
                let exemptions = rpc_client.get_inbound_exemptions().await?;
                if exemptions.is_empty() {
                    println!("No inbound exemptions configured.");
                } else {
                    for e in exemptions {
                        let label = e.label.as_deref().map(|s| format!(" — {s}")).unwrap_or_default();
                        println!("{}/{}{}", e.proto, e.dport, label);
                    }
                }
                Ok(())
            }
            Command::Add { spec, label } => {
                let new = parse_spec(&spec)?;
                let mut exemptions = rpc_client.get_inbound_exemptions().await?;
                if exemptions
                    .iter()
                    .any(|e| e.proto == new.proto && e.dport == new.dport)
                {
                    bail!("Exemption {}/{} already exists", new.proto, new.dport);
                }
                exemptions.push(InboundExemption {
                    proto: new.proto,
                    dport: new.dport,
                    label,
                });
                rpc_client.set_inbound_exemptions(exemptions).await?;
                println!("Added exemption {}/{}", new.proto, new.dport);
                Ok(())
            }
            Command::Del { spec } => {
                let target = parse_spec(&spec)?;
                let mut exemptions = rpc_client.get_inbound_exemptions().await?;
                let before = exemptions.len();
                exemptions.retain(|e| !(e.proto == target.proto && e.dport == target.dport));
                if exemptions.len() == before {
                    bail!("No matching exemption {}/{}", target.proto, target.dport);
                }
                rpc_client.set_inbound_exemptions(exemptions).await?;
                println!("Removed exemption {}/{}", target.proto, target.dport);
                Ok(())
            }
        }
    }
}

struct ParsedSpec {
    proto: InboundExemptionProtocol,
    dport: u16,
}

fn parse_spec(spec: &str) -> Result<ParsedSpec> {
    let (proto_str, port_str) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("Expected `<proto>:<port>`, got `{spec}`"))?;
    let proto = match proto_str.to_ascii_lowercase().as_str() {
        "tcp" => InboundExemptionProtocol::Tcp,
        "udp" => InboundExemptionProtocol::Udp,
        other => bail!("Unknown protocol `{other}` (expected tcp or udp)"),
    };
    let dport: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("Invalid port `{port_str}` (expected 1-65535)"))?;
    if dport == 0 {
        bail!("Port must be in the range 1-65535");
    }
    Ok(ParsedSpec { proto, dport })
}
