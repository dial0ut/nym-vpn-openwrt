// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! fw3 (iptables) backend for OpenWrt.
//!
//! This backend integrates with OpenWrt's fw3 firewall system by:
//! 1. Writing rules to a file in iptables-restore format
//! 2. Applying rules atomically with a single iptables-restore call
//! 3. Hooking into fw3's *_rule chains (input_rule, output_rule, forwarding_rule)
//! 4. Using an include script for cleanup on fw3 restart
//!
//! This approach eliminates xtables lock contention by avoiding individual
//! iptables commands.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use super::common::{
    self, ensure_dir, format_ip, is_ipv6_enabled, remove_file_if_exists,
    FW3_HOOK_FORWARD, FW3_HOOK_INPUT, FW3_HOOK_OUTPUT, FW3_INCLUDE_PATH,
    LAN_NETWORKS_V4, LAN_NETWORKS_V6, MULTICAST_V4, MULTICAST_V6,
    NYM_FORWARD, NYM_INPUT, NYM_OUTPUT, RULES_V4_PATH, RULES_V6_PATH,
};
use super::{Error, Result};
use crate::net::{AllowedEndpoint, TransportProtocol, TunnelMetadata};
use crate::FirewallPolicy;

/// fw3/iptables firewall backend.
pub struct Fw3Firewall;

impl Fw3Firewall {
    pub fn new() -> Result<Self> {
        Ok(Fw3Firewall)
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        tracing::debug!("Applying firewall policy via fw3/iptables backend");

        // Build rules for IPv4
        let rules_v4 = self.build_rules(&policy, false)?;

        // Write and apply IPv4 rules
        fs::write(RULES_V4_PATH, &rules_v4)?;
        self.apply_restore(RULES_V4_PATH, false)?;
        self.setup_jumps(false)?;

        // Build and apply IPv6 rules if enabled
        if is_ipv6_enabled() {
            let rules_v6 = self.build_rules(&policy, true)?;
            fs::write(RULES_V6_PATH, &rules_v6)?;
            self.apply_restore(RULES_V6_PATH, true)?;
            self.setup_jumps(true)?;
        } else {
            tracing::info!("IPv6 disabled, skipping ip6tables rules");
            remove_file_if_exists(RULES_V6_PATH)?;
        }

        // Add masquerade rules for tunnel interfaces
        self.add_masquerade_rules(&policy)?;

        tracing::debug!("Firewall policy applied successfully");
        Ok(())
    }

    pub fn reset_policy(&mut self) -> Result<()> {
        tracing::debug!("Resetting firewall policy via fw3/iptables backend");

        // Remove masquerade rules for tunnel interfaces
        self.remove_masquerade_rules();

        // Remove jumps and clean up chains
        self.cleanup(false);
        if is_ipv6_enabled() {
            self.cleanup(true);
        }

        // Remove rules files
        remove_file_if_exists(RULES_V4_PATH)?;
        remove_file_if_exists(RULES_V6_PATH)?;

        tracing::debug!("Firewall policy reset successfully");
        Ok(())
    }

    /// Build iptables-restore format rules.
    fn build_rules(&self, policy: &FirewallPolicy, is_ipv6: bool) -> Result<String> {
        let mut rules = String::new();

        // Start filter table
        writeln!(rules, "*filter").unwrap();

        // Create our chains (idempotent - creates if not exists)
        writeln!(rules, ":{} - [0:0]", NYM_INPUT).unwrap();
        writeln!(rules, ":{} - [0:0]", NYM_OUTPUT).unwrap();
        writeln!(rules, ":{} - [0:0]", NYM_FORWARD).unwrap();

        // Flush our chains to remove old rules
        writeln!(rules, "-F {}", NYM_INPUT).unwrap();
        writeln!(rules, "-F {}", NYM_OUTPUT).unwrap();
        writeln!(rules, "-F {}", NYM_FORWARD).unwrap();

        // Add base rules
        self.add_loopback_rules(&mut rules);
        self.add_established_rules(&mut rules);
        self.add_dhcp_rules(&mut rules, is_ipv6);

        if is_ipv6 {
            self.add_ndp_rules(&mut rules);
        }

        // Allow mwan3 tracking pings so WAN interfaces stay up
        self.add_mwan3_rules(&mut rules, is_ipv6);

        // Add policy-specific rules
        self.add_policy_rules(&mut rules, policy, is_ipv6)?;

        // Commit
        writeln!(rules, "COMMIT").unwrap();

        Ok(rules)
    }

    /// Apply rules using iptables-restore.
    fn apply_restore(&self, path: &str, is_ipv6: bool) -> Result<()> {
        let cmd = if is_ipv6 { "ip6tables-restore" } else { "iptables-restore" };

        let output = Command::new(cmd)
            .args(["--noflush", "-w"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    let content = fs::read_to_string(path)?;
                    stdin.write_all(content.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| Error::ApplyError(format!("Failed to run {}: {}", cmd, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ApplyError(format!("{} failed: {}", cmd, stderr)));
        }

        Ok(())
    }

    /// Set up jump rules from fw3's *_rule chains to our chains.
    fn setup_jumps(&self, is_ipv6: bool) -> Result<()> {
        let ipt = if is_ipv6 { "ip6tables" } else { "iptables" };

        for (hook, target) in [
            (FW3_HOOK_INPUT, NYM_INPUT),
            (FW3_HOOK_OUTPUT, NYM_OUTPUT),
            (FW3_HOOK_FORWARD, NYM_FORWARD),
        ] {
            // Delete existing jump (ignore errors if not present)
            let _ = Command::new(ipt)
                .args(["-w", "-D", hook, "-j", target])
                .output();

            // Insert jump at position 1
            let output = Command::new(ipt)
                .args(["-w", "-I", hook, "1", "-j", target])
                .output()
                .map_err(|e| Error::ApplyError(format!("Failed to run {}: {}", ipt, e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::ApplyError(format!(
                    "Failed to insert jump rule {}->{}: {}",
                    hook, target, stderr
                )));
            }
        }

        Ok(())
    }

    /// Clean up our chains and jump rules.
    fn cleanup(&self, is_ipv6: bool) {
        let ipt = if is_ipv6 { "ip6tables" } else { "iptables" };

        // Remove jump rules
        for (hook, target) in [
            (FW3_HOOK_INPUT, NYM_INPUT),
            (FW3_HOOK_OUTPUT, NYM_OUTPUT),
            (FW3_HOOK_FORWARD, NYM_FORWARD),
        ] {
            let _ = Command::new(ipt).args(["-w", "-D", hook, "-j", target]).output();
        }

        // Flush and delete our chains
        for chain in [NYM_INPUT, NYM_OUTPUT, NYM_FORWARD] {
            let _ = Command::new(ipt).args(["-w", "-F", chain]).output();
            let _ = Command::new(ipt).args(["-w", "-X", chain]).output();
        }
    }

    // ========== Rule builders ==========

    fn add_loopback_rules(&self, rules: &mut String) {
        writeln!(rules, "-A {} -i lo -j ACCEPT", NYM_INPUT).unwrap();
        writeln!(rules, "-A {} -o lo -j ACCEPT", NYM_OUTPUT).unwrap();
    }

    fn add_established_rules(&self, rules: &mut String) {
        writeln!(
            rules,
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            NYM_INPUT
        ).unwrap();
        writeln!(
            rules,
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            NYM_OUTPUT
        ).unwrap();
        writeln!(
            rules,
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            NYM_FORWARD
        ).unwrap();
    }

    fn add_dhcp_rules(&self, rules: &mut String, is_ipv6: bool) {
        if is_ipv6 {
            // DHCPv6: router as client (getting WAN IPv6)
            writeln!(
                rules,
                "-A {} -p udp -s fe80::/10 --sport 546 --dport 547 -j ACCEPT",
                NYM_OUTPUT
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p udp -s fe80::/10 --sport 547 --dport 546 -j ACCEPT",
                NYM_INPUT
            ).unwrap();
            // DHCPv6: router as server (serving LAN clients)
            writeln!(
                rules,
                "-A {} -p udp --sport 547 --dport 546 -j ACCEPT",
                NYM_OUTPUT
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p udp --dport 547 -j ACCEPT",
                NYM_INPUT
            ).unwrap();
        } else {
            // DHCPv4 client (port 68) -> server (port 67)
            writeln!(
                rules,
                "-A {} -p udp --sport 68 --dport 67 -j ACCEPT",
                NYM_OUTPUT
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p udp --sport 67 --dport 68 -j ACCEPT",
                NYM_INPUT
            ).unwrap();
            // DHCP for LAN clients (router as DHCP server)
            writeln!(
                rules,
                "-A {} -p udp --sport 67 --dport 68 -j ACCEPT",
                NYM_OUTPUT
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p udp --sport 68 --dport 67 -j ACCEPT",
                NYM_INPUT
            ).unwrap();
        }
    }

    /// Allow ICMP pings to mwan3 tracking IPs.
    ///
    /// mwan3 pings these IPs to determine if WAN interfaces are alive.
    /// Without this, our kill-switch blocks the pings, mwan3 declares WAN down,
    /// and triggers a firewall reload cascade that kills VPN connections.
    fn add_mwan3_rules(&self, rules: &mut String, is_ipv6: bool) {
        let track_ips = common::get_mwan3_track_ips();
        let icmp_proto = if is_ipv6 { "icmpv6" } else { "icmp" };

        for ip in &track_ips {
            if is_ipv6 != common::is_ipv6(ip) {
                continue;
            }
            let ip_str = common::format_ip(ip);
            writeln!(
                rules,
                "-A {} -p {} -d {} -j ACCEPT",
                NYM_OUTPUT, icmp_proto, ip_str
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p {} -s {} -j ACCEPT",
                NYM_INPUT, icmp_proto, ip_str
            ).unwrap();
        }
    }

    fn add_ndp_rules(&self, rules: &mut String) {
        // Router Solicitation (type 133)
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT",
            NYM_OUTPUT
        ).unwrap();

        // Router Advertisement (type 134)
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT",
            NYM_INPUT
        ).unwrap();

        // Neighbor Solicitation (type 135)
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT",
            NYM_OUTPUT
        ).unwrap();
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT",
            NYM_INPUT
        ).unwrap();

        // Neighbor Advertisement (type 136)
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT",
            NYM_OUTPUT
        ).unwrap();
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT",
            NYM_INPUT
        ).unwrap();

        // Redirect (type 137)
        writeln!(
            rules,
            "-A {} -p icmpv6 --icmpv6-type redirect -j ACCEPT",
            NYM_INPUT
        ).unwrap();
    }

    fn add_policy_rules(
        &self,
        rules: &mut String,
        policy: &FirewallPolicy,
        is_ipv6: bool,
    ) -> Result<()> {
        let allow_lan = match policy {
            FirewallPolicy::Connecting {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                allowed_endpoints,
                ..
            } => {
                // Allow VPN peer endpoints
                for endpoint in peer_endpoints {
                    self.add_endpoint_rules(rules, endpoint, is_ipv6);
                }

                // Allow other endpoints (API servers, etc.)
                for endpoint in allowed_endpoints {
                    self.add_endpoint_rules(rules, endpoint, is_ipv6);
                }

                // Allow DNS servers
                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_rules(rules, *dns, None, is_ipv6);
                }

                // Add tunnel rules BEFORE blocking DNS
                // This ensures DNS traffic routed via tunnel interfaces is allowed
                if let Some(tunnel) = tunnel {
                    for metadata in tunnel.inner_metadatas() {
                        self.add_tunnel_rules(rules, &metadata.interface, is_ipv6);
                    }
                }

                // Block other DNS (only affects non-tunnel traffic now)
                self.add_block_dns_rules(rules, is_ipv6);

                *allow_lan
            }

            FirewallPolicy::Connected {
                peer_endpoints,
                tunnel,
                allow_lan,
                dns_config,
                ..
            } => {
                // Allow VPN peer endpoints
                for endpoint in peer_endpoints {
                    self.add_endpoint_rules(rules, endpoint, is_ipv6);
                }

                // Allow tunnel DNS
                for dns in dns_config.tunnel_config() {
                    for metadata in tunnel.inner_metadatas() {
                        self.add_dns_rules(rules, *dns, Some(&metadata.interface), is_ipv6);
                    }
                }

                // Allow non-tunnel DNS
                for dns in dns_config.non_tunnel_config() {
                    self.add_dns_rules(rules, *dns, None, is_ipv6);
                }

                // Add tunnel rules BEFORE blocking DNS
                // This ensures DNS traffic routed via tunnel interfaces is allowed
                // (critical for LAN clients whose DNS gets forwarded through the tunnel)
                for metadata in tunnel.inner_metadatas() {
                    self.add_tunnel_rules(rules, &metadata.interface, is_ipv6);

                    // CVE-2019-14899 protection
                    if *allow_lan {
                        self.add_tunnel_ip_protection(rules, metadata, is_ipv6);
                    }
                }

                // Block other DNS (only affects non-tunnel traffic now)
                self.add_block_dns_rules(rules, is_ipv6);

                *allow_lan
            }

            FirewallPolicy::Blocked {
                allow_lan,
                allowed_endpoints,
            } => {
                // Allow specific endpoints
                for endpoint in allowed_endpoints {
                    self.add_endpoint_rules(rules, endpoint, is_ipv6);
                }

                // Block all DNS
                self.add_block_dns_rules(rules, is_ipv6);

                *allow_lan
            }
        };

        // Add LAN rules if allowed
        if allow_lan {
            self.add_lan_rules(rules, is_ipv6);
        }

        // Final reject rules (catch-all)
        self.add_reject_rules(rules, is_ipv6);

        Ok(())
    }

    fn add_endpoint_rules(&self, rules: &mut String, endpoint: &AllowedEndpoint, is_ipv6: bool) {
        let ip = endpoint.endpoint.address.ip();

        // Skip if wrong IP version
        if is_ipv6 != common::is_ipv6(&ip) {
            return;
        }

        let port = endpoint.endpoint.address.port();
        let proto = match endpoint.endpoint.protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
        };

        // Allow outgoing to endpoint
        writeln!(
            rules,
            "-A {} -p {} -d {} --dport {} -j ACCEPT",
            NYM_OUTPUT, proto, format_ip(&ip), port
        ).unwrap();

        // Allow incoming from endpoint (for established, but explicit rule for clarity)
        writeln!(
            rules,
            "-A {} -p {} -s {} --sport {} -j ACCEPT",
            NYM_INPUT, proto, format_ip(&ip), port
        ).unwrap();
    }

    fn add_dns_rules(
        &self,
        rules: &mut String,
        dns: IpAddr,
        tunnel_iface: Option<&str>,
        is_ipv6: bool,
    ) {
        // Skip if wrong IP version
        if is_ipv6 != common::is_ipv6(&dns) {
            return;
        }

        let dns_str = format_ip(&dns);
        let out_iface = tunnel_iface.map(|i| format!("-o {} ", i)).unwrap_or_default();
        let in_iface = tunnel_iface.map(|i| format!("-i {} ", i)).unwrap_or_default();

        // UDP DNS (port 53)
        writeln!(
            rules,
            "-A {} {}-p udp -d {} --dport 53 -j ACCEPT",
            NYM_OUTPUT, out_iface, dns_str
        ).unwrap();
        writeln!(
            rules,
            "-A {} {}-p udp -s {} --sport 53 -j ACCEPT",
            NYM_INPUT, in_iface, dns_str
        ).unwrap();

        // TCP DNS (port 53)
        writeln!(
            rules,
            "-A {} {}-p tcp -d {} --dport 53 -j ACCEPT",
            NYM_OUTPUT, out_iface, dns_str
        ).unwrap();
        writeln!(
            rules,
            "-A {} {}-p tcp -s {} --sport 53 -j ACCEPT",
            NYM_INPUT, in_iface, dns_str
        ).unwrap();

        // DNS-over-TLS (DoT, port 853)
        writeln!(
            rules,
            "-A {} {}-p tcp -d {} --dport 853 -j ACCEPT",
            NYM_OUTPUT, out_iface, dns_str
        ).unwrap();
        writeln!(
            rules,
            "-A {} {}-p tcp -s {} --sport 853 -j ACCEPT",
            NYM_INPUT, in_iface, dns_str
        ).unwrap();

        // DNS-over-HTTPS (DoH, port 443)
        writeln!(
            rules,
            "-A {} {}-p tcp -d {} --dport 443 -j ACCEPT",
            NYM_OUTPUT, out_iface, dns_str
        ).unwrap();
        writeln!(
            rules,
            "-A {} {}-p tcp -s {} --sport 443 -j ACCEPT",
            NYM_INPUT, in_iface, dns_str
        ).unwrap();

        // Forward DNS for LAN clients (if not tunnel-specific)
        if tunnel_iface.is_none() {
            writeln!(
                rules,
                "-A {} -p udp -d {} --dport 53 -j ACCEPT",
                NYM_FORWARD, dns_str
            ).unwrap();
            writeln!(
                rules,
                "-A {} -p udp -s {} --sport 53 -j ACCEPT",
                NYM_FORWARD, dns_str
            ).unwrap();
        }
    }

    fn add_block_dns_rules(&self, rules: &mut String, is_ipv6: bool) {
        let reject = if is_ipv6 {
            "icmp6-port-unreachable"
        } else {
            "icmp-port-unreachable"
        };

        // Block DNS on OUTPUT
        writeln!(
            rules,
            "-A {} -p udp --dport 53 -j REJECT --reject-with {}",
            NYM_OUTPUT, reject
        ).unwrap();
        writeln!(
            rules,
            "-A {} -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
            NYM_OUTPUT
        ).unwrap();

        // Block DNS on FORWARD
        writeln!(
            rules,
            "-A {} -p udp --dport 53 -j REJECT --reject-with {}",
            NYM_FORWARD, reject
        ).unwrap();
        writeln!(
            rules,
            "-A {} -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
            NYM_FORWARD
        ).unwrap();
    }

    fn add_tunnel_rules(&self, rules: &mut String, interface: &str, _is_ipv6: bool) {
        // Allow all traffic on tunnel interface
        writeln!(
            rules,
            "-A {} -i {} -j ACCEPT",
            NYM_INPUT, interface
        ).unwrap();
        writeln!(
            rules,
            "-A {} -o {} -j ACCEPT",
            NYM_OUTPUT, interface
        ).unwrap();

        // Forward to/from tunnel
        writeln!(
            rules,
            "-A {} -o {} -j ACCEPT",
            NYM_FORWARD, interface
        ).unwrap();
        writeln!(
            rules,
            "-A {} -i {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            NYM_FORWARD, interface
        ).unwrap();
    }

    fn add_tunnel_ip_protection(&self, rules: &mut String, tunnel: &TunnelMetadata, is_ipv6: bool) {
        // CVE-2019-14899: Block traffic to tunnel IPs from non-tunnel interfaces
        for ip in &tunnel.ips {
            if is_ipv6 != common::is_ipv6(ip) {
                continue;
            }
            writeln!(
                rules,
                "-A {} ! -i {} -d {} -j DROP",
                NYM_INPUT, tunnel.interface, format_ip(ip)
            ).unwrap();
        }
    }

    fn add_lan_rules(&self, rules: &mut String, is_ipv6: bool) {
        let networks: Vec<&str> = if is_ipv6 {
            LAN_NETWORKS_V6.to_vec()
        } else {
            LAN_NETWORKS_V4.to_vec()
        };

        for net in networks {
            // Allow output to LAN
            writeln!(rules, "-A {} -d {} -j ACCEPT", NYM_OUTPUT, net).unwrap();
            // Allow input from LAN
            writeln!(rules, "-A {} -s {} -j ACCEPT", NYM_INPUT, net).unwrap();
            // Allow forward to/from LAN
            writeln!(rules, "-A {} -d {} -j ACCEPT", NYM_FORWARD, net).unwrap();
            writeln!(rules, "-A {} -s {} -j ACCEPT", NYM_FORWARD, net).unwrap();
        }

        // Multicast
        let mcast = if is_ipv6 { MULTICAST_V6 } else { MULTICAST_V4 };
        writeln!(rules, "-A {} -d {} -j ACCEPT", NYM_OUTPUT, mcast).unwrap();
    }

    fn add_reject_rules(&self, rules: &mut String, is_ipv6: bool) {
        let reject = if is_ipv6 {
            "icmp6-port-unreachable"
        } else {
            "icmp-port-unreachable"
        };

        // Reject all remaining traffic
        writeln!(
            rules,
            "-A {} -j REJECT --reject-with {}",
            NYM_OUTPUT, reject
        ).unwrap();
        writeln!(
            rules,
            "-A {} -j REJECT --reject-with {}",
            NYM_FORWARD, reject
        ).unwrap();
        // Note: We don't reject on INPUT - let fw3 handle that
        // This allows SSH and other management traffic through fw3's rules
    }

    /// Add masquerade rules for tunnel interfaces.
    ///
    /// This NATs LAN client traffic going through the tunnel so that
    /// return traffic can find its way back.
    fn add_masquerade_rules(&self, policy: &FirewallPolicy) -> Result<()> {
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
            // Add masquerade rule for this interface
            // iptables -t nat -A POSTROUTING -o <iface> -m comment --comment "nym-vpn" -j MASQUERADE
            let _ = Command::new("iptables")
                .args([
                    "-w",
                    "-t", "nat",
                    "-A", "POSTROUTING",
                    "-o", iface,
                    "-m", "comment", "--comment", "nym-vpn",
                    "-j", "MASQUERADE"
                ])
                .output();

            tracing::debug!("Added masquerade rule for interface {}", iface);
        }

        Ok(())
    }

    /// Remove masquerade rules for tunnel interfaces.
    fn remove_masquerade_rules(&self) {
        // List NAT POSTROUTING rules and remove ones with our comment
        if let Ok(output) = Command::new("iptables")
            .args(["-w", "-t", "nat", "-L", "POSTROUTING", "-n", "--line-numbers", "-v"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Collect line numbers to delete (in reverse order to avoid index shifting)
            let mut to_delete: Vec<u32> = Vec::new();
            for line in stdout.lines() {
                if line.contains("nym-vpn") {
                    // Line format: "1    ... /* nym-vpn */"
                    if let Some(num_str) = line.split_whitespace().next() {
                        if let Ok(num) = num_str.parse::<u32>() {
                            to_delete.push(num);
                        }
                    }
                }
            }
            // Delete in reverse order
            to_delete.sort();
            to_delete.reverse();
            for num in to_delete {
                let _ = Command::new("iptables")
                    .args(["-w", "-t", "nat", "-D", "POSTROUTING", &num.to_string()])
                    .output();
            }
        }
    }
}

/// Configure UCI to use the fw3 include script.
/// The script itself is installed by the IPK package at FW3_INCLUDE_PATH.
pub fn install_include_script() -> Result<()> {
    // Verify the script exists (should be installed by package)
    if !std::path::Path::new(FW3_INCLUDE_PATH).exists() {
        tracing::warn!(
            "fw3 include script not found at {} - should be installed by package",
            FW3_INCLUDE_PATH
        );
    }

    // Add to UCI config if not already present
    install_uci_config()?;

    Ok(())
}

/// Install UCI firewall config for the include script.
fn install_uci_config() -> Result<()> {
    // Check if already configured
    let check = Command::new("uci")
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
        ["set", &format!("firewall.nym_vpn.path={}", FW3_INCLUDE_PATH)],
        ["set", "firewall.nym_vpn.reload=1"],
        ["set", "firewall.nym_vpn.enabled=1"],
    ];

    for args in &commands {
        let output = Command::new("uci")
            .args(*args)
            .output()
            .map_err(|e| Error::InstallError(format!("Failed to run uci: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::InstallError(format!("uci {} failed: {}", args[0], stderr)));
        }
    }

    // Commit changes
    let output = Command::new("uci")
        .args(["commit", "firewall"])
        .output()
        .map_err(|e| Error::InstallError(format!("Failed to commit UCI: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InstallError(format!("uci commit failed: {}", stderr)));
    }

    tracing::info!("Installed UCI firewall config for Nym VPN");
    Ok(())
}
