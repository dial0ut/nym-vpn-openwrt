// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt firewall integration.
//!
//! Provides backends that integrate with OpenWrt's firewall system — `fw3`
//! (iptables) on OpenWrt ≤21.02 and `fw4` (nftables) on OpenWrt ≥22.03.
//!
//! - [`policy`] compiles a [`FirewallPolicy`] into a backend-neutral
//!   [`rules::RuleSet`]; [`render_nft`] and [`render_iptables`] turn that
//!   into wire syntax; [`fw3`] and [`fw4`] apply it and own the
//!   backend-specific integration (masquerade, jumps from fw3/fw4 chains).
//! - [`boot_rules`] is the single definition of the emergency and boot-time
//!   rule sets; `build.rs` renders it into `scripts/fw-rules.sh`, which the
//!   shell includes source. Guarantees are tabulated in
//!   docs/architecture/killswitch-contract.md.

mod boot_rules;
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
}

/// OpenWrt firewall handle: detects fw3 vs fw4 at construction and dispatches
/// to that backend. An `Unknown` detection is re-probed on each apply.
pub struct Firewall {
    system: FirewallSystem,
}

impl Firewall {
    /// `fwmark` is deliberately ignored: fwmark-based split tunneling does
    /// not apply on routers.
    pub fn from_args(_args: FirewallArguments) -> Result<Self> {
        Self::new()
    }

    pub fn new() -> Result<Self> {
        let system = detect_system();
        tracing::info!("Detected OpenWrt firewall system: {:?}", system);
        Ok(Firewall { system })
    }

    /// `Unknown` means the firewall was not up at construction; re-probe.
    fn refresh_system_if_unknown(&mut self) {
        if self.system == FirewallSystem::Unknown {
            let redetected = detect_system();
            if redetected != FirewallSystem::Unknown {
                tracing::info!("Firewall system re-detected: {:?}", redetected);
                self.system = redetected;
            }
        }
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        self.refresh_system_if_unknown();
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

    /// Kill-switch disabled: install only masquerade + forward accepts and
    /// remove any blocking rules. Without the masquerade, forwarded LAN
    /// packets enter the tunnel un-NAT'd and the exit gateway drops them.
    pub fn apply_forwarding_only(&mut self, policy: FirewallPolicy) -> Result<()> {
        self.refresh_system_if_unknown();
        let ruleset = policy::compile(&policy);
        match self.system {
            FirewallSystem::Fw3 => fw3::apply_forwarding_only(&ruleset),
            FirewallSystem::Fw4 => fw4::apply_forwarding_only(&ruleset),
            FirewallSystem::Unknown => {
                tracing::warn!("Unknown firewall system, falling back to fw3/iptables");
                fw3::apply_forwarding_only(&ruleset)
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
}

#[cfg(test)]
mod e2e_tests {
    //! `FirewallPolicy` -> `policy::compile` -> both renderers, asserting on
    //! invariants of the rendered output.

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

        assert!(script.contains("table inet nym"));
        assert!(script.contains("delete table inet nym"));

        assert!(script.contains("priority filter - 10"));

        assert!(script.contains("meta skuid 0 ip daddr 1.2.3.4 udp dport 443 accept"));

        // Resolver accepts are root-only: dnsmasq relays LAN queries as router
        // OUTPUT, so an unscoped accept is a LAN leak.
        assert!(script.contains("meta skuid 0 ip daddr 8.8.8.8 udp dport 53 accept"));
        for line in script
            .lines()
            .filter(|l| l.contains("daddr 8.8.8.8") && l.contains("dport 53") && l.contains("accept"))
        {
            assert!(line.contains("meta skuid 0"), "unscoped resolver accept: {line}");
        }
        assert!(script.contains("udp dport 53 reject"));
        assert!(script.contains("tcp dport 53 reject"));

        // NTP hatch is never uid-scoped; sysntpd may not run as root.
        assert!(script.contains("udp dport 123 limit rate 12/minute burst 8 packets accept"));

        assert!(script.contains("meta skuid 0 udp dport 53 limit rate 30/minute burst 20 packets accept"));
        assert!(script.contains("meta skuid 0 tcp dport 53 limit rate 30/minute burst 20 packets accept"));

        assert!(script.contains("ip saddr 10.0.0.0/8 accept"));
        assert!(script.contains("ip daddr 192.168.0.0/16 accept"));

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

        assert!(v4.contains("-p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable"));
        assert!(v4.contains("-p tcp --dport 53 -j REJECT --reject-with tcp-reset"));

        assert!(v4.contains("-d 8.8.8.8 -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT"));
        assert!(v4.contains(
            "-p udp --dport 53 -m owner --uid-owner 0 -m limit --limit 30/minute --limit-burst 20 -j ACCEPT"
        ));

        assert!(v6.contains("-j REJECT --reject-with icmp6-port-unreachable"));

        assert!(v4.contains("-d 1.2.3.4 -p udp --dport 443 -m owner --uid-owner 0 -j ACCEPT"));
        assert!(!v6.contains("-d 1.2.3.4"));

        assert!(v4.ends_with("COMMIT\n"));
        assert!(v6.ends_with("COMMIT\n"));
    }

    #[test]
    fn connected_lan_collects_tunnel_iface_and_emits_cve_drop() {
        let rs = policy::compile(&connected_lan());
        assert_eq!(rs.tunnel_interfaces, vec!["wg0".to_string()]);

        let nft = render_nft::render(&rs);
        // CVE-2019-14899 guard.
        assert!(nft.contains("iifname != \"wg0\" ip daddr 10.64.0.2 drop"));
        assert!(nft.contains("iifname \"wg0\" accept"));
        assert!(nft.contains("oifname \"wg0\" accept"));
        assert!(nft.contains("oifname \"wg0\" ip daddr 10.64.0.1 udp dport 53 accept"));
        assert!(nft.contains("ip daddr 1.1.1.1 udp dport 53 accept"));
        assert!(!nft.contains("oifname \"wg0\" ip daddr 1.1.1.1"));
    }

    #[test]
    fn connecting_render_scopes_dns_hatch_to_root() {
        // Cold-boot NTP-pool resolution is daemon-owned (`clock_bootstrap` in
        // nym-vpn-lib), so the Connecting hatch needs no unscoped hole.
        let policy = FirewallPolicy::Connecting {
            peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
            tunnel: None,
            allow_lan: true,
            dns_config: dns(&[], &[]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: crate::net::AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: crate::net::AllowedTunnelTraffic::All,
            inbound_exemptions: vec![],
        };
        let rs = policy::compile(&policy);
        let nft = render_nft::render(&rs);
        let v4 = render_iptables::render(&rs, AddrFamily::V4);

        assert!(
            nft.contains("meta skuid 0 udp dport 53 limit rate 30/minute burst 20 packets accept")
        );
        assert!(v4.contains(
            "-p udp --dport 53 -m owner --uid-owner 0 -m limit --limit 30/minute --limit-burst 20 -j ACCEPT"
        ));
        for line in nft.lines() {
            if line.contains("dport 53") && line.ends_with("accept") {
                assert!(line.contains("skuid"), "unscoped 53 accept in nft: {line}");
            }
        }
        for line in v4.lines() {
            if line.contains("--dport 53") && line.contains("-j ACCEPT") {
                assert!(line.contains("--uid-owner"), "unscoped 53 accept in v4: {line}");
            }
        }
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

        // Mangle-side WAN rules need the WAN zone; uci/ubus are absent in CI.
        let wan = vec!["eth1".to_string()];
        let uplink = policy::Uplink {
            wan_devices: &wan,
            route_device: Box::new(|_| None),
        };
        let rs = policy::compile_with(&policy, &uplink);
        let nft = render_nft::render(&rs);
        let v4 = render_iptables::render(&rs, render_iptables::AddrFamily::V4);

        // Dumped for offline syntax validation against a host nft binary.
        let _ = std::fs::write("/tmp/nym_smoke.nft", &nft);
        let _ = std::fs::write("/tmp/nym_smoke.v4.rules", &v4);

        println!("\n--- POLICY DISPLAY ---\n{policy}");
        println!("\n--- NFT (inet nym) ---\n{nft}");
        println!("\n--- IPTABLES v4 ---\n{v4}");

        assert!(nft.contains("meta mark 0x14e accept"));
        assert!(v4.contains("-m mark --mark 0x14e -j ACCEPT"));
        assert!(nft.contains("meta skuid 0 ip daddr 198.41.192.167 udp dport 7844 accept"));
        assert!(nft.contains("type filter hook prerouting priority mangle - 10"));
        assert!(nft.contains("type filter hook output priority mangle - 10"));
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
    fn connected_forward_output_have_no_unqualified_established_accept() {
        let policy = connected_lan();
        let rs = policy::compile(&policy);
        let nft = render_nft::render(&rs);

        // An unqualified established accept in forward/output lets WAN-bound
        // established flows (esp. IPv6 on reconnect) leak past the kill-switch.
        for chain in ["chain forward", "chain output"] {
            let body = extract_chain(&nft, chain);
            for line in body.lines().map(str::trim) {
                if line == "ct state established,related accept" {
                    panic!("unqualified established accept in {chain}:\n{body}");
                }
            }
        }
        assert!(
            nft.contains("iifname \"wg0\" ct state established,related accept"),
            "expected tunnel-scoped established accept in forward chain:\n{nft}"
        );
    }

    fn extract_chain<'a>(nft: &'a str, header: &str) -> &'a str {
        let start = nft.find(header).expect("chain present");
        let after = &nft[start..];
        let brace = after.find('{').expect("chain body");
        let end = after[brace..].find('}').expect("chain close") + brace;
        &after[brace + 1..end]
    }

    #[test]
    fn drop_verdicts_only_appear_in_cve_protection() {
        // Only the CVE-2019-14899 guards may drop; everything else rejects so
        // clients get a clean refusal.
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

