// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt firewall integration.
//!
//! Provides backends that integrate with OpenWrt's firewall system — `fw3`
//! (iptables) on OpenWrt ≤21.02 and `fw4` (nftables) on OpenWrt ≥22.03.
//!
//! The shape of the module:
//! - [`policy`] compiles a [`FirewallPolicy`] into a backend-neutral
//!   [`rules::RuleSet`] — single source of truth for the kill-switch.
//! - [`render_nft`] and [`render_iptables`] translate the AST into the
//!   backend's wire syntax.
//! - [`fw3`] and [`fw4`] are thin backends that apply the rendered script
//!   and manage the small amount of backend-specific integration
//!   (masquerade, jumps from fw3/fw4's own chains).

mod common;
mod detect;
mod fw3;
mod fw4;
mod policy;
mod render_iptables;
mod render_nft;
mod rules;

pub use detect::{FirewallSystem, detect_system};

use crate::{FirewallArguments, FirewallPolicy};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to apply firewall rules: {0}")]
    ApplyError(String),

    #[error("failed to install include script: {0}")]
    InstallError(String),
}

/// OpenWrt firewall handle. Detects whether the host runs fw3 or fw4 once
/// at construction and dispatches every `apply` / `reset` to the matching
/// backend.
pub struct Firewall {
    system: FirewallSystem,
}

impl Firewall {
    /// Construct from the public [`FirewallArguments`]. The `fwmark` field
    /// is intentionally not plumbed through here: split-tunneling and
    /// fwmark-based filtering from the upstream desktop backend are not
    /// applicable on routers, so the firewall rules don't reference it.
    pub fn from_args(_args: FirewallArguments) -> Result<Self> {
        Self::new()
    }

    pub fn new() -> Result<Self> {
        let system = detect_system();
        tracing::info!("Detected OpenWrt firewall system: {:?}", system);
        Ok(Firewall { system })
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        let ruleset = policy::compile(&policy);
        match self.system {
            FirewallSystem::Fw3 => fw3::apply(&ruleset),
            FirewallSystem::Fw4 => fw4::apply(&ruleset),
            FirewallSystem::Unknown => {
                tracing::warn!("Unknown firewall system, falling back to fw3/iptables");
                fw3::apply(&ruleset)
            }
        }
    }

    pub fn reset_policy(&mut self) -> Result<()> {
        match self.system {
            FirewallSystem::Fw3 => fw3::reset(),
            FirewallSystem::Fw4 => fw4::reset(),
            FirewallSystem::Unknown => fw3::reset(),
        }
    }

    /// Install the OpenWrt include scripts so our chains survive an
    /// `/etc/init.d/firewall reload`. Called once during package install.
    pub fn install_include_scripts() -> Result<()> {
        match detect_system() {
            FirewallSystem::Fw3 => fw3::install_include_script(),
            FirewallSystem::Fw4 => fw4::install_include_script(),
            FirewallSystem::Unknown => {
                tracing::warn!("Unknown system, skipping include script installation");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod e2e_tests {
    //! End-to-end pipeline tests: build a `FirewallPolicy`, run it through
    //! `policy::compile` and both renderers, and assert on key invariants of
    //! the rendered output. These guard against drift between the renderers
    //! and policy compiler.

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use nym_dns::DnsConfig;

    use super::render_iptables::AddrFamily;
    use super::*;
    use crate::net::{
        AllowedClients, AllowedEndpoint, Endpoint, InboundExemption, TransportProtocol,
        TunnelInterface, TunnelMetadata,
    };

    fn ep(ip: [u8; 4], port: u16) -> AllowedEndpoint {
        AllowedEndpoint::new(
            Endpoint::from_socket_address(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
                TransportProtocol::Udp,
            ),
            AllowedClients::Root,
        )
    }

    fn tunnel(name: &str, ip: [u8; 4]) -> TunnelInterface {
        TunnelInterface::One(TunnelMetadata {
            interface: name.to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::from(ip))],
            ipv4_gateway: None,
            ipv6_gateway: None,
        })
    }

    fn dns(tunnel: &[IpAddr], non_tunnel: &[IpAddr]) -> nym_dns::ResolvedDnsConfig {
        DnsConfig::from_addresses(tunnel, non_tunnel).resolve(&[])
    }

    fn blocked_lan() -> FirewallPolicy {
        FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![ep([1, 2, 3, 4], 443)],
            dns_servers: vec!["8.8.8.8".parse().unwrap()],
        }
    }

    fn connected_lan() -> FirewallPolicy {
        FirewallPolicy::Connected {
            peer_endpoints: vec![ep([1, 2, 3, 4], 51820)],
            tunnel: tunnel("wg0", [10, 64, 0, 2]),
            allow_lan: true,
            dns_config: dns(
                &["10.64.0.1".parse().unwrap()],
                &["1.1.1.1".parse().unwrap()],
            ),
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
        }
    }

    #[test]
    fn blocked_nft_output_contains_kill_switch_essentials() {
        let rs = policy::compile(&blocked_lan());
        let script = render_nft::render(&rs);

        // Header / table.
        assert!(script.contains("table inet nym"));
        assert!(script.contains("delete table inet nym"));

        // Per-chain hook headers at filter -10.
        assert!(script.contains("priority filter - 10"));

        // Allowed endpoint shows up in OUTPUT.
        assert!(script.contains("ip daddr 1.2.3.4 udp dport 443 accept"));

        // DNS to 8.8.8.8 allowed; DNS to anywhere else blocked.
        assert!(script.contains("ip daddr 8.8.8.8 udp dport 53 accept"));
        assert!(script.contains("udp dport 53 reject"));
        assert!(script.contains("tcp dport 53 reject"));

        // NTP escape hatch present.
        assert!(script.contains("udp dport 123 limit rate 12/minute burst 8 packets accept"));

        // LAN allows.
        assert!(script.contains("ip saddr 10.0.0.0/8 accept"));
        assert!(script.contains("ip daddr 192.168.0.0/16 accept"));

        // Final reject in OUTPUT and FORWARD.
        let chunks: Vec<_> = script.split("chain ").collect();
        for (name, body) in chunks
            .iter()
            .filter_map(|c| c.split_once(" {"))
            .filter(|(n, _)| *n == "output" || *n == "forward")
        {
            assert!(body.contains("reject"), "{name} chain must reject");
        }
    }

    #[test]
    fn blocked_iptables_output_uses_reject_with() {
        let rs = policy::compile(&blocked_lan());
        let v4 = render_iptables::render(&rs, AddrFamily::V4);
        let v6 = render_iptables::render(&rs, AddrFamily::V6);

        // UDP DNS uses icmp port unreachable; TCP DNS uses tcp-reset.
        assert!(v4.contains("-p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable"));
        assert!(v4.contains("-p tcp --dport 53 -j REJECT --reject-with tcp-reset"));

        // v6 uses icmp6 variants.
        assert!(v6.contains("-j REJECT --reject-with icmp6-port-unreachable"));

        // Allowed endpoint in v4 only (it's an IPv4 address).
        assert!(v4.contains("-d 1.2.3.4 -p udp --dport 443 -j ACCEPT"));
        assert!(!v6.contains("-d 1.2.3.4"));

        // Both files end with COMMIT.
        assert!(v4.ends_with("COMMIT\n"));
        assert!(v6.ends_with("COMMIT\n"));
    }

    #[test]
    fn connected_lan_collects_tunnel_iface_and_emits_cve_drop() {
        let rs = policy::compile(&connected_lan());
        assert_eq!(rs.tunnel_interfaces, vec!["wg0".to_string()]);

        let nft = render_nft::render(&rs);
        // CVE-2019-14899 drop rule.
        assert!(nft.contains("iifname != \"wg0\" ip daddr 10.64.0.2 drop"));
        // Tunnel iface accepts on input/output/forward.
        assert!(nft.contains("iifname \"wg0\" accept"));
        assert!(nft.contains("oifname \"wg0\" accept"));
        // Tunnel DNS restricted to tunnel iface.
        assert!(nft.contains("oifname \"wg0\" ip daddr 10.64.0.1 udp dport 53 accept"));
        // Non-tunnel DNS — no iface restriction.
        assert!(nft.contains("ip daddr 1.1.1.1 udp dport 53 accept"));
        assert!(!nft.contains("oifname \"wg0\" ip daddr 1.1.1.1"));
    }

    #[test]
    fn smoke_render_with_exemptions_prints_output() {
        // Run with: cargo test -p nym-firewall smoke_render -- --nocapture
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![ep([1, 2, 3, 4], 51820)],
            tunnel: tunnel("nym0", [10, 64, 0, 2]),
            allow_lan: true,
            dns_config: dns(
                &["10.64.0.1".parse().unwrap()],
                &["1.1.1.1".parse().unwrap()],
            ),
            allowed_endpoints: vec![ep([198, 41, 192, 167], 7844)],
            inbound_exemptions: vec![
                InboundExemption::new(TransportProtocol::Tcp, 443)
                    .with_label("HTTPS reverse proxy"),
                InboundExemption::new(TransportProtocol::Udp, 51820),
            ],
        };

        let rs = policy::compile(&policy);
        let nft = render_nft::render(&rs);
        let v4 = render_iptables::render(&rs, render_iptables::AddrFamily::V4);

        // Also dump to /tmp for offline kernel-syntax validation against the
        // host's nft binary.
        let _ = std::fs::write("/tmp/nym_smoke.nft", &nft);
        let _ = std::fs::write("/tmp/nym_smoke.v4.rules", &v4);

        println!("\n--- POLICY DISPLAY ---\n{policy}");
        println!("\n--- NFT (inet nym) ---\n{nft}");
        println!("\n--- IPTABLES v4 ---\n{v4}");

        // Filter invariants: mark accept present in all chains before reject.
        // Mangle invariants depend on WAN detection (uci/ip route) which is
        // absent in CI — skip those here and verify only the filter side.
        assert!(nft.contains("meta mark 0x14e accept"));
        assert!(v4.contains("-m mark --mark 0x14e -j ACCEPT"));
        // CF edge endpoint from allowed_endpoints flows into Connected — the
        // test helper builds UDP endpoints, so we assert the UDP variant.
        assert!(nft.contains("ip daddr 198.41.192.167 udp dport 7844 accept"));
        // Mangle priority + chain ordering checks.
        assert!(nft.contains("type filter hook prerouting priority mangle - 10"));
        assert!(nft.contains("type filter hook output priority mangle - 10"));
        // mark restore precedes mark set in prerouting
        let pre_chain = nft
            .split("chain mangle_prerouting")
            .nth(1)
            .and_then(|s| s.split('}').next())
            .unwrap_or("");
        let restore_pos = pre_chain.find("meta mark set ct mark").unwrap();
        let set_pos = pre_chain.find("ct mark set 0x14e").unwrap();
        assert!(restore_pos < set_pos, "restore must come before set in mangle_prerouting");
    }

    #[test]
    fn drop_verdicts_only_appear_in_cve_protection() {
        // The only `drop` rules our policy emits are the CVE-2019-14899
        // guards: traffic to a tunnel IP from a non-tunnel interface.
        // Any other drop would be a bug — block by default should always be
        // `reject` so clients get a clean refusal.
        let rs = policy::compile(&connected_lan());
        let all_rules = rs
            .filter
            .input
            .rules
            .iter()
            .chain(rs.filter.output.rules.iter())
            .chain(rs.filter.forward.rules.iter());
        for rule in all_rules {
            if rule.verdict != rules::Verdict::Drop {
                continue;
            }
            assert!(
                rule.matches.iif_not.is_some() && rule.matches.daddr.is_some(),
                "unexpected drop rule: {rule:?}"
            );
        }
    }
}

