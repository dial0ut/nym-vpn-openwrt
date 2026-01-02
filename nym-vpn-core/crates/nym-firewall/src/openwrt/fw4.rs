// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! fw4 (nftables) backend for OpenWrt.
//!
//! This backend integrates with OpenWrt's fw4 firewall system by:
//! 1. Creating a separate `inet nym` table with lower priority than fw4
//! 2. Using nft -f for atomic rule application
//! 3. Using DROP for blocked traffic (immediate, fw4 never sees it)
//! 4. Using ACCEPT for allowed traffic (continues to fw4, which normally allows it)

use std::fmt::Write as FmtWrite;
use std::fs;
use std::net::IpAddr;
use std::process::Command;

use super::common::*;
use super::{Error, Result};
use crate::net::{AllowedEndpoint, TransportProtocol};
use crate::FirewallPolicy;

/// fw4/nftables firewall backend.
pub struct Fw4Firewall {
    fwmark: u32,
}

impl Fw4Firewall {
    pub fn new(fwmark: u32) -> Result<Self> {
        Ok(Fw4Firewall { fwmark })
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        tracing::debug!("Applying firewall policy via fw4/nftables backend");

        let rules = self.build_rules(&policy)?;
        fs::write(RULES_NFT_PATH, &rules)?;
        self.apply_nft()?;

        // Add fw4 integration rules for tunnel interfaces
        self.add_fw4_tunnel_rules(&policy)?;

        tracing::debug!("Firewall policy applied successfully");
        Ok(())
    }

    pub fn reset_policy(&mut self) -> Result<()> {
        tracing::debug!("Resetting firewall policy via fw4/nftables backend");

        // Remove fw4 integration rules for tunnel interfaces
        self.remove_fw4_tunnel_rules();

        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "nym"])
            .output();

        remove_file_if_exists(RULES_NFT_PATH)?;

        tracing::debug!("Firewall policy reset successfully");
        Ok(())
    }

    fn build_rules(&self, policy: &FirewallPolicy) -> Result<String> {
        let mut rules = String::new();

        writeln!(rules, "#!/usr/sbin/nft -f").unwrap();
        writeln!(rules).unwrap();
        // Create empty table first (idempotent), then delete, then recreate with rules
        // This avoids "No such file or directory" error on first run
        writeln!(rules, "table inet nym").unwrap();
        writeln!(rules, "delete table inet nym").unwrap();
        writeln!(rules).unwrap();
        writeln!(rules, "table inet nym {{").unwrap();

        self.build_input_chain(&mut rules, policy)?;
        self.build_output_chain(&mut rules, policy)?;
        self.build_forward_chain(&mut rules, policy)?;

        writeln!(rules, "}}").unwrap();

        Ok(rules)
    }

    fn build_input_chain(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        writeln!(rules, "    chain input {{").unwrap();
        writeln!(rules, "        type filter hook input priority filter - 10; policy accept;").unwrap();
        writeln!(rules).unwrap();

        // Base rules
        writeln!(rules, "        iifname \"lo\" accept").unwrap();
        writeln!(rules, "        ct state established,related accept").unwrap();
        writeln!(rules, "        udp sport 67 udp dport 68 accept").unwrap();
        writeln!(rules, "        udp sport 547 udp dport 546 accept").unwrap();
        writeln!(rules, "        icmpv6 type {{ nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect }} accept").unwrap();
        writeln!(rules).unwrap();

        // Policy rules
        self.add_input_policy_rules(rules, policy)?;

        writeln!(rules, "        counter drop").unwrap();
        writeln!(rules, "    }}").unwrap();
        writeln!(rules).unwrap();

        Ok(())
    }

    fn build_output_chain(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        writeln!(rules, "    chain output {{").unwrap();
        writeln!(rules, "        type filter hook output priority filter - 10; policy accept;").unwrap();
        writeln!(rules).unwrap();

        // Base rules
        writeln!(rules, "        oifname \"lo\" accept").unwrap();
        writeln!(rules, "        ct state established,related accept").unwrap();
        writeln!(rules, "        udp sport 68 udp dport 67 accept").unwrap();
        writeln!(rules, "        udp sport 546 udp dport 547 accept").unwrap();
        writeln!(rules, "        icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept").unwrap();
        writeln!(rules).unwrap();

        // Policy rules
        self.add_output_policy_rules(rules, policy)?;

        writeln!(rules, "        counter reject").unwrap();
        writeln!(rules, "    }}").unwrap();
        writeln!(rules).unwrap();

        Ok(())
    }

    fn build_forward_chain(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        writeln!(rules, "    chain forward {{").unwrap();
        writeln!(rules, "        type filter hook forward priority filter - 10; policy accept;").unwrap();
        writeln!(rules).unwrap();

        writeln!(rules, "        ct state established,related accept").unwrap();
        writeln!(rules).unwrap();

        self.add_forward_policy_rules(rules, policy)?;

        writeln!(rules, "        counter reject").unwrap();
        writeln!(rules, "    }}").unwrap();

        Ok(())
    }

    fn add_input_policy_rules(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        match policy {
            FirewallPolicy::Connecting {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                allowed_endpoints,
                ..
            } => {
                self.add_endpoint_input_rules(rules, peer_endpoints);
                self.add_endpoint_input_rules(rules, allowed_endpoints);

                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_input_rules(rules, *dns);
                }

                if let Some(tunnel) = tunnel {
                    for m in tunnel.inner_metadatas() {
                        writeln!(rules, "        iifname \"{}\" accept", m.interface).unwrap();
                    }
                }

                if *allow_lan {
                    self.add_lan_input_rules(rules);
                }
            }

            FirewallPolicy::Connected {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                ..
            } => {
                self.add_endpoint_input_rules(rules, peer_endpoints);

                for dns in dns_config.tunnel_config() {
                    self.add_dns_input_rules(rules, *dns);
                }
                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_input_rules(rules, *dns);
                }

                for m in tunnel.inner_metadatas() {
                    writeln!(rules, "        iifname \"{}\" accept", m.interface).unwrap();
                    if *allow_lan {
                        for ip in &m.ips {
                            let fam = if is_ipv4(ip) { "ip" } else { "ip6" };
                            writeln!(rules, "        iifname != \"{}\" {} daddr {} drop", m.interface, fam, format_ip(ip)).unwrap();
                        }
                    }
                }

                if *allow_lan {
                    self.add_lan_input_rules(rules);
                }
            }

            FirewallPolicy::Blocked { allow_lan, allowed_endpoints } => {
                self.add_endpoint_input_rules(rules, allowed_endpoints);
                if *allow_lan {
                    self.add_lan_input_rules(rules);
                }
            }
        }
        writeln!(rules).unwrap();
        Ok(())
    }

    fn add_output_policy_rules(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        match policy {
            FirewallPolicy::Connecting {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                allowed_endpoints,
                ..
            } => {
                self.add_endpoint_output_rules(rules, peer_endpoints);
                self.add_endpoint_output_rules(rules, allowed_endpoints);

                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_output_rules(rules, *dns);
                }

                // Add tunnel rules BEFORE blocking DNS
                // This ensures DNS traffic routed via tunnel interfaces is allowed
                if let Some(tunnel) = tunnel {
                    for m in tunnel.inner_metadatas() {
                        writeln!(rules, "        oifname \"{}\" accept", m.interface).unwrap();
                    }
                }

                // Block other DNS (only affects non-tunnel traffic now)
                self.add_block_dns_rules(rules);

                if *allow_lan {
                    self.add_lan_output_rules(rules);
                }
            }

            FirewallPolicy::Connected {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                ..
            } => {
                self.add_endpoint_output_rules(rules, peer_endpoints);

                for dns in dns_config.tunnel_config() {
                    self.add_dns_output_rules(rules, *dns);
                }
                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_output_rules(rules, *dns);
                }

                // Add tunnel rules BEFORE blocking DNS
                // This ensures DNS traffic routed via tunnel interfaces is allowed
                for m in tunnel.inner_metadatas() {
                    writeln!(rules, "        oifname \"{}\" accept", m.interface).unwrap();
                }

                // Block other DNS (only affects non-tunnel traffic now)
                self.add_block_dns_rules(rules);

                if *allow_lan {
                    self.add_lan_output_rules(rules);
                }
            }

            FirewallPolicy::Blocked { allow_lan, allowed_endpoints } => {
                self.add_endpoint_output_rules(rules, allowed_endpoints);
                self.add_block_dns_rules(rules);
                if *allow_lan {
                    self.add_lan_output_rules(rules);
                }
            }
        }
        writeln!(rules).unwrap();
        Ok(())
    }

    fn add_forward_policy_rules(&self, rules: &mut String, policy: &FirewallPolicy) -> Result<()> {
        match policy {
            FirewallPolicy::Connecting { tunnel, allow_lan, dns_config, .. } => {
                // Allow DNS to specific servers
                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_forward_rules(rules, *dns);
                }

                // Allow traffic to/from tunnel interfaces BEFORE blocking DNS
                if let Some(tunnel) = tunnel {
                    for m in tunnel.inner_metadatas() {
                        // Allow traffic TO tunnel
                        writeln!(rules, "        oifname \"{}\" accept", m.interface).unwrap();
                        // Allow traffic FROM tunnel
                        writeln!(rules, "        iifname \"{}\" accept", m.interface).unwrap();
                    }
                }

                // Explicitly block other DNS (kill-switch for DNS leaks)
                self.add_block_dns_rules(rules);

                if *allow_lan {
                    self.add_lan_forward_rules(rules);
                }
            }

            FirewallPolicy::Connected { tunnel, allow_lan, dns_config, .. } => {
                // Allow DNS to specific servers
                for dns in dns_config.tunnel_config() {
                    self.add_dns_forward_rules(rules, *dns);
                }

                // Allow traffic to/from tunnel interfaces BEFORE blocking DNS
                for m in tunnel.inner_metadatas() {
                    // Allow traffic TO tunnel (LAN -> Internet via VPN)
                    writeln!(rules, "        oifname \"{}\" accept", m.interface).unwrap();
                    // Allow traffic FROM tunnel (Internet -> LAN return traffic)
                    writeln!(rules, "        iifname \"{}\" accept", m.interface).unwrap();
                }

                // Explicitly block other DNS (kill-switch for DNS leaks)
                self.add_block_dns_rules(rules);

                if *allow_lan {
                    self.add_lan_forward_rules(rules);
                }
            }

            FirewallPolicy::Blocked { allow_lan, .. } => {
                // Block all DNS when in blocked state
                self.add_block_dns_rules(rules);

                if *allow_lan {
                    self.add_lan_forward_rules(rules);
                }
            }
        }
        writeln!(rules).unwrap();
        Ok(())
    }

    fn add_endpoint_input_rules(&self, rules: &mut String, endpoints: &[AllowedEndpoint]) {
        for ep in endpoints {
            let ip = ep.endpoint.address.ip();
            let port = ep.endpoint.address.port();
            let proto = match ep.endpoint.protocol {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Udp => "udp",
            };
            let fam = if is_ipv4(&ip) { "ip" } else { "ip6" };
            writeln!(rules, "        {} saddr {} {} sport {} accept", fam, format_ip(&ip), proto, port).unwrap();
        }
    }

    fn add_endpoint_output_rules(&self, rules: &mut String, endpoints: &[AllowedEndpoint]) {
        for ep in endpoints {
            let ip = ep.endpoint.address.ip();
            let port = ep.endpoint.address.port();
            let proto = match ep.endpoint.protocol {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Udp => "udp",
            };
            let fam = if is_ipv4(&ip) { "ip" } else { "ip6" };
            writeln!(rules, "        {} daddr {} {} dport {} accept", fam, format_ip(&ip), proto, port).unwrap();
        }
    }

    fn add_dns_input_rules(&self, rules: &mut String, dns: IpAddr) {
        let fam = if is_ipv4(&dns) { "ip" } else { "ip6" };
        let dns_str = format_ip(&dns);
        // Standard DNS (port 53)
        writeln!(rules, "        {} saddr {} udp sport 53 accept", fam, dns_str).unwrap();
        writeln!(rules, "        {} saddr {} tcp sport 53 accept", fam, dns_str).unwrap();
        // DNS-over-TLS (DoT, port 853)
        writeln!(rules, "        {} saddr {} tcp sport 853 accept", fam, dns_str).unwrap();
        // DNS-over-HTTPS (DoH, port 443)
        writeln!(rules, "        {} saddr {} tcp sport 443 accept", fam, dns_str).unwrap();
    }

    fn add_dns_output_rules(&self, rules: &mut String, dns: IpAddr) {
        let fam = if is_ipv4(&dns) { "ip" } else { "ip6" };
        let dns_str = format_ip(&dns);
        // Standard DNS (port 53)
        writeln!(rules, "        {} daddr {} udp dport 53 accept", fam, dns_str).unwrap();
        writeln!(rules, "        {} daddr {} tcp dport 53 accept", fam, dns_str).unwrap();
        // DNS-over-TLS (DoT, port 853)
        writeln!(rules, "        {} daddr {} tcp dport 853 accept", fam, dns_str).unwrap();
        // DNS-over-HTTPS (DoH, port 443)
        writeln!(rules, "        {} daddr {} tcp dport 443 accept", fam, dns_str).unwrap();
    }

    fn add_dns_forward_rules(&self, rules: &mut String, dns: IpAddr) {
        let fam = if is_ipv4(&dns) { "ip" } else { "ip6" };
        let dns_str = format_ip(&dns);
        // Standard DNS (port 53)
        writeln!(rules, "        {} daddr {} udp dport 53 accept", fam, dns_str).unwrap();
        writeln!(rules, "        {} daddr {} tcp dport 53 accept", fam, dns_str).unwrap();
        // DNS-over-TLS (DoT, port 853)
        writeln!(rules, "        {} daddr {} tcp dport 853 accept", fam, dns_str).unwrap();
        // DNS-over-HTTPS (DoH, port 443)
        writeln!(rules, "        {} daddr {} tcp dport 443 accept", fam, dns_str).unwrap();
    }

    fn add_block_dns_rules(&self, rules: &mut String) {
        writeln!(rules, "        udp dport 53 reject").unwrap();
        writeln!(rules, "        tcp dport 53 reject").unwrap();
    }

    fn add_lan_input_rules(&self, rules: &mut String) {
        writeln!(rules, "        ip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept").unwrap();
        writeln!(rules, "        ip6 saddr {{ fe80::/10, fc00::/7 }} accept").unwrap();
    }

    fn add_lan_output_rules(&self, rules: &mut String) {
        writeln!(rules, "        ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept").unwrap();
        writeln!(rules, "        ip6 daddr {{ fe80::/10, fc00::/7 }} accept").unwrap();
        writeln!(rules, "        ip daddr 224.0.0.0/4 accept").unwrap();
        writeln!(rules, "        ip6 daddr ff00::/8 accept").unwrap();
    }

    fn add_lan_forward_rules(&self, rules: &mut String) {
        writeln!(rules, "        ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept").unwrap();
        writeln!(rules, "        ip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept").unwrap();
    }

    fn apply_nft(&self) -> Result<()> {
        let output = Command::new("nft")
            .args(["-f", RULES_NFT_PATH])
            .output()
            .map_err(|e| Error::ApplyError(format!("Failed to run nft: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ApplyError(format!("nft -f failed: {}", stderr)));
        }

        Ok(())
    }

    /// Add rules to fw4's chains to integrate tunnel interfaces.
    ///
    /// fw4 uses zone-based forwarding and doesn't know about our tunnel interfaces.
    /// We need to add:
    /// 1. Masquerade rules to srcnat for tunnel interfaces
    /// 2. Forward rules to forward_lan to allow LAN<->tunnel traffic
    fn add_fw4_tunnel_rules(&self, policy: &FirewallPolicy) -> Result<()> {
        let interfaces = match policy {
            FirewallPolicy::Connecting { tunnel, .. } => {
                tunnel.as_ref().map(|t| {
                    t.inner_metadatas().iter().map(|m| m.interface.clone()).collect::<Vec<_>>()
                }).unwrap_or_default()
            }
            FirewallPolicy::Connected { tunnel, .. } => {
                tunnel.inner_metadatas().iter().map(|m| m.interface.clone()).collect()
            }
            FirewallPolicy::Blocked { .. } => Vec::new(),
        };

        for iface in &interfaces {
            // Add masquerade for tunnel interface
            // This NATs LAN client traffic going through the tunnel
            let _ = Command::new("nft")
                .args([
                    "add", "rule", "inet", "fw4", "srcnat",
                    "oifname", iface,
                    "counter", "masquerade",
                    "comment", "\"nym-vpn: masquerade tunnel traffic\""
                ])
                .output();

            // Add forward rules for LAN <-> tunnel
            // This allows fw4 to forward traffic between LAN zone and tunnel
            let _ = Command::new("nft")
                .args([
                    "add", "rule", "inet", "fw4", "forward_lan",
                    "oifname", iface, "accept",
                    "comment", "\"nym-vpn: forward LAN to tunnel\""
                ])
                .output();

            let _ = Command::new("nft")
                .args([
                    "add", "rule", "inet", "fw4", "forward_lan",
                    "iifname", iface, "accept",
                    "comment", "\"nym-vpn: forward tunnel to LAN\""
                ])
                .output();

            tracing::debug!("Added fw4 integration rules for interface {}", iface);
        }

        Ok(())
    }

    /// Remove tunnel rules from fw4's chains.
    fn remove_fw4_tunnel_rules(&self) {
        // Remove rules with our comment from fw4 chains
        // We use nft -a to get handles, then delete by handle
        for chain in ["srcnat", "forward_lan"] {
            if let Ok(output) = Command::new("nft")
                .args(["-a", "list", "chain", "inet", "fw4", chain])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Find lines with our comment and extract handles
                for line in stdout.lines() {
                    if line.contains("nym-vpn:") {
                        // Extract handle number from line like "... # handle 123"
                        if let Some(handle) = line.split("# handle ").last() {
                            let handle = handle.trim();
                            let _ = Command::new("nft")
                                .args(["delete", "rule", "inet", "fw4", chain, "handle", handle])
                                .output();
                        }
                    }
                }
            }
        }
    }
}

/// Configure UCI to use the fw4 include script.
/// The script itself is installed by the IPK package at FW4_INCLUDE_PATH.
pub fn install_include_script() -> Result<()> {
    // Verify the script exists (should be installed by package)
    if !std::path::Path::new(FW4_INCLUDE_PATH).exists() {
        tracing::warn!(
            "fw4 include script not found at {} - should be installed by package",
            FW4_INCLUDE_PATH
        );
    }

    // Add to UCI config if not already present
    install_uci_config()?;

    Ok(())
}

/// Install UCI firewall config for the include script.
fn install_uci_config() -> Result<()> {
    // Check if already configured
    let check = std::process::Command::new("uci")
        .args(["get", "firewall.nym_vpn"])
        .output();

    if check.map(|o| o.status.success()).unwrap_or(false) {
        tracing::debug!("UCI config already exists");
        return Ok(());
    }

    // Add the include configuration
    let commands = [
        ["set", "firewall.nym_vpn=include"],
        ["set", "firewall.nym_vpn.type=script"],
        ["set", &format!("firewall.nym_vpn.path={}", FW4_INCLUDE_PATH)],
        ["set", "firewall.nym_vpn.fw4_compatible=1"],
        ["set", "firewall.nym_vpn.enabled=1"],
    ];

    for args in &commands {
        let output = std::process::Command::new("uci")
            .args(*args)
            .output()
            .map_err(|e| Error::InstallError(format!("Failed to run uci: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::InstallError(format!("uci {} failed: {}", args[0], stderr)));
        }
    }

    // Commit changes
    let output = std::process::Command::new("uci")
        .args(["commit", "firewall"])
        .output()
        .map_err(|e| Error::InstallError(format!("Failed to commit UCI: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InstallError(format!("uci commit failed: {}", stderr)));
    }

    tracing::info!("Installed UCI firewall config for Nym VPN (fw4)");
    Ok(())
}
