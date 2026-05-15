// SPDX-License-Identifier: GPL-3.0-only

//! Compile a [`FirewallPolicy`] into a backend-neutral [`RuleSet`].
//!
//! This is the single source of truth for the OpenWrt kill-switch policy.
//! The two backends ([`super::fw3`], [`super::fw4`]) consume the resulting
//! [`RuleSet`] verbatim — they do not re-derive policy from `FirewallPolicy`.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::common;
use super::rules::*;
use crate::FirewallPolicy;
use crate::net::{AllowedEndpoint, TransportProtocol, TunnelMetadata};

/// LAN networks (RFC1918 private + IPv6 link-local + ULA).
const LAN_NETS_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const LAN_NETS_V6: &[&str] = &["fe80::/10", "fc00::/7"];
const MULTICAST_V4: &str = "224.0.0.0/4";
const MULTICAST_V6: &str = "ff00::/8";

const DHCPV4_CLIENT_PORT: u16 = 68;
const DHCPV4_SERVER_PORT: u16 = 67;
const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const DOH_PORT: u16 = 443;
const NTP_PORT: u16 = 123;

/// Rate limit for the NTP escape hatch in `Blocked`. Sized for sysntpd's
/// parallel startup round (~8 packets) and caps any exfil at ~500 B/min.
const NTP_RATE_PER_MIN: u32 = 12;
const NTP_BURST: u32 = 8;

/// Compile a [`FirewallPolicy`] into a backend-neutral [`RuleSet`].
pub fn compile(policy: &FirewallPolicy) -> RuleSet {
    let mut rs = RuleSet::default();

    base_rules(&mut rs);

    match policy {
        FirewallPolicy::Connecting {
            peer_endpoints,
            tunnel,
            allow_lan,
            dns_config,
            allowed_endpoints,
            ..
        } => {
            for ep in peer_endpoints {
                allow_endpoint(&mut rs, ep);
            }
            for ep in allowed_endpoints {
                allow_endpoint(&mut rs, ep);
            }
            for dns in dns_config.non_tunnel_config() {
                allow_dns_server(&mut rs, *dns, None);
            }
            // Tunnel interface rules must come before the DNS block so that
            // DNS routed through the tunnel isn't caught by the kill-switch.
            if let Some(tunnel) = tunnel {
                for m in tunnel.inner_metadatas() {
                    allow_tunnel(&mut rs, &m.interface);
                    rs.tunnel_interfaces.push(m.interface.clone());
                }
            }
            block_dns(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
        }

        FirewallPolicy::Connected {
            peer_endpoints,
            tunnel,
            allow_lan,
            dns_config,
            ..
        } => {
            for ep in peer_endpoints {
                allow_endpoint(&mut rs, ep);
            }
            // Tunnel-configured DNS: only egress via the tunnel interface.
            for dns in dns_config.tunnel_config() {
                for m in tunnel.inner_metadatas() {
                    allow_dns_server(&mut rs, *dns, Some(&m.interface));
                }
            }
            // Non-tunnel DNS: any interface (typically WAN-side resolvers).
            for dns in dns_config.non_tunnel_config() {
                allow_dns_server(&mut rs, *dns, None);
            }
            for m in tunnel.inner_metadatas() {
                allow_tunnel(&mut rs, &m.interface);
                rs.tunnel_interfaces.push(m.interface.clone());
                if *allow_lan {
                    cve_2019_14899_protection(&mut rs, m);
                }
            }
            block_dns(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
        }

        FirewallPolicy::Blocked {
            allow_lan,
            allowed_endpoints,
            dns_servers,
        } => {
            for ep in allowed_endpoints {
                allow_endpoint(&mut rs, ep);
            }
            for dns in dns_servers {
                allow_dns_server(&mut rs, *dns, None);
            }
            block_dns(&mut rs);
            ntp_escape_hatch(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
        }
    }

    final_reject(&mut rs);

    rs
}

// ---------- helpers ----------

fn base_rules(rs: &mut RuleSet) {
    // Loopback.
    rs.input.push(Rule::accept(Family::Inet).iif("lo"));
    rs.output.push(Rule::accept(Family::Inet).oif("lo"));

    // Established/related — covers return traffic on every chain.
    rs.input.push(Rule::accept(Family::Inet).ct_established());
    rs.output.push(Rule::accept(Family::Inet).ct_established());
    rs.forward.push(Rule::accept(Family::Inet).ct_established());

    // DHCPv4 — router as client and as server.
    rs.input.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_SERVER_PORT)
            .dport(DHCPV4_CLIENT_PORT),
    );
    rs.input.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .dport(DHCPV4_SERVER_PORT),
    );
    rs.output.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_CLIENT_PORT)
            .dport(DHCPV4_SERVER_PORT),
    );
    rs.output.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_SERVER_PORT)
            .dport(DHCPV4_CLIENT_PORT),
    );

    // DHCPv6 — router as client and as server.
    rs.input.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .sport(DHCPV6_SERVER_PORT)
            .dport(DHCPV6_CLIENT_PORT),
    );
    rs.input.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .dport(DHCPV6_SERVER_PORT),
    );
    rs.output.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .sport(DHCPV6_CLIENT_PORT)
            .dport(DHCPV6_SERVER_PORT),
    );
    rs.output.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .sport(DHCPV6_SERVER_PORT)
            .dport(DHCPV6_CLIENT_PORT),
    );

    // IPv6 NDP.
    for t in [
        IcmpV6Type::RouterAdvert,
        IcmpV6Type::NeighborSolicit,
        IcmpV6Type::NeighborAdvert,
        IcmpV6Type::Redirect,
    ] {
        rs.input.push(Rule::accept(Family::V6).icmpv6_type(t));
    }
    for t in [
        IcmpV6Type::RouterSolicit,
        IcmpV6Type::NeighborSolicit,
        IcmpV6Type::NeighborAdvert,
    ] {
        rs.output.push(Rule::accept(Family::V6).icmpv6_type(t));
    }

    // mwan3 tracking pings — keep WAN interfaces alive so mwan3 doesn't
    // declare WAN down and trigger a firewall reload cascade.
    for ip in common::get_mwan3_track_ips() {
        match ip {
            IpAddr::V4(_) => {
                rs.input.push(
                    Rule::accept(Family::V4)
                        .proto(Proto::Icmp)
                        .icmpv4_type(IcmpV4Type::EchoReply)
                        .saddr(ip),
                );
                rs.output.push(
                    Rule::accept(Family::V4)
                        .proto(Proto::Icmp)
                        .icmpv4_type(IcmpV4Type::EchoRequest)
                        .daddr(ip),
                );
            }
            IpAddr::V6(_) => {
                rs.input.push(
                    Rule::accept(Family::V6)
                        .proto(Proto::IcmpV6)
                        .icmpv6_type(IcmpV6Type::EchoReply)
                        .saddr(ip),
                );
                rs.output.push(
                    Rule::accept(Family::V6)
                        .proto(Proto::IcmpV6)
                        .icmpv6_type(IcmpV6Type::EchoRequest)
                        .daddr(ip),
                );
            }
        }
    }
}

fn allow_endpoint(rs: &mut RuleSet, ep: &AllowedEndpoint) {
    let ip = ep.endpoint.address.ip();
    let port = ep.endpoint.address.port();
    let proto = match ep.endpoint.protocol {
        TransportProtocol::Tcp => Proto::Tcp,
        TransportProtocol::Udp => Proto::Udp,
    };
    let family = family_of(&ip);
    rs.output.push(
        Rule::accept(family)
            .proto(proto)
            .daddr(ip)
            .dport(port),
    );
    rs.input.push(
        Rule::accept(family)
            .proto(proto)
            .saddr(ip)
            .sport(port),
    );
}

/// Allow DNS to a specific server. If `iface` is set, restrict to that
/// interface (used for tunnel-configured resolvers).
fn allow_dns_server(rs: &mut RuleSet, dns: IpAddr, iface: Option<&str>) {
    let family = family_of(&dns);

    // Standard DNS (UDP and TCP on 53), DoT (853/tcp), DoH (443/tcp).
    let pairs = [
        (Proto::Udp, DNS_PORT),
        (Proto::Tcp, DNS_PORT),
        (Proto::Tcp, DOT_PORT),
        (Proto::Tcp, DOH_PORT),
    ];
    for (proto, port) in pairs {
        let mut out = Rule::accept(family)
            .proto(proto)
            .daddr(dns)
            .dport(port);
        let mut inp = Rule::accept(family)
            .proto(proto)
            .saddr(dns)
            .sport(port);
        if let Some(iface) = iface {
            out = out.oif(iface);
            inp = inp.iif(iface);
        }
        rs.output.push(out);
        rs.input.push(inp);
    }

    // Forward DNS for LAN clients (only when not iface-restricted).
    if iface.is_none() {
        for proto in [Proto::Udp, Proto::Tcp] {
            rs.forward.push(
                Rule::accept(family)
                    .proto(proto)
                    .daddr(dns)
                    .dport(DNS_PORT),
            );
        }
    }
}

fn allow_tunnel(rs: &mut RuleSet, iface: &str) {
    rs.input.push(Rule::accept(Family::Inet).iif(iface));
    rs.output.push(Rule::accept(Family::Inet).oif(iface));
    // Forward LAN traffic out the tunnel. Return traffic is handled by the
    // ct established rule at the top of the forward chain.
    rs.forward.push(Rule::accept(Family::Inet).oif(iface));
}

/// CVE-2019-14899: an attacker on the local network can probe whether a host
/// has an in-tunnel connection by sending packets *to* the tunnel's IP via a
/// non-tunnel interface. Drop those.
fn cve_2019_14899_protection(rs: &mut RuleSet, tunnel: &TunnelMetadata) {
    for ip in &tunnel.ips {
        rs.input.push(
            Rule::drop_(family_of(ip))
                .iif_not(&tunnel.interface)
                .daddr(*ip),
        );
    }
}

fn block_dns(rs: &mut RuleSet) {
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.output
            .push(Rule::reject(Family::Inet).proto(proto).dport(DNS_PORT));
        rs.forward
            .push(Rule::reject(Family::Inet).proto(proto).dport(DNS_PORT));
    }
}

/// Rate-limited NTP escape hatch: a clockless router cold-boots with a stale
/// clock and would otherwise deadlock here, since TLS to the upstream API
/// fails cert validity until sysntpd can sync.
fn ntp_escape_hatch(rs: &mut RuleSet) {
    rs.output.push(
        Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(NTP_PORT)
            .rate_limit(NTP_RATE_PER_MIN, NTP_BURST),
    );
}

fn allow_lan_traffic(rs: &mut RuleSet) {
    for net in LAN_NETS_V4 {
        let n: IpNetwork = net.parse().expect("static LAN_NETS_V4 entry is valid");
        rs.input.push(Rule::accept(Family::V4).saddr(n));
        rs.output.push(Rule::accept(Family::V4).daddr(n));
        // Only daddr in forward — saddr would let a LAN client forward
        // straight out WAN between sessions, defeating the kill-switch.
        rs.forward.push(Rule::accept(Family::V4).daddr(n));
    }
    for net in LAN_NETS_V6 {
        let n: IpNetwork = net.parse().expect("static LAN_NETS_V6 entry is valid");
        rs.input.push(Rule::accept(Family::V6).saddr(n));
        rs.output.push(Rule::accept(Family::V6).daddr(n));
        rs.forward.push(Rule::accept(Family::V6).daddr(n));
    }
    let mcast4: IpNetwork = MULTICAST_V4.parse().unwrap();
    let mcast6: IpNetwork = MULTICAST_V6.parse().unwrap();
    rs.output.push(Rule::accept(Family::V4).daddr(mcast4));
    rs.output.push(Rule::accept(Family::V6).daddr(mcast6));
}

fn final_reject(rs: &mut RuleSet) {
    // INPUT is intentionally left to fall through to fw3/fw4's own input
    // chain so the router's own management traffic (SSH, LuCI) still works.
    rs.output.push(Rule::reject(Family::Inet));
    rs.forward.push(Rule::reject(Family::Inet));
}

fn family_of(ip: &IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use nym_dns::ResolvedDnsConfig;

    use super::*;
    use crate::net::{
        AllowedClients, AllowedEndpoint, AllowedTunnelTraffic, Endpoint, TransportProtocol,
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

    fn tunnel_iface(name: &str, ip: [u8; 4]) -> TunnelInterface {
        TunnelInterface::One(TunnelMetadata {
            interface: name.to_string(),
            ips: vec![IpAddr::V4(Ipv4Addr::from(ip))],
            ipv4_gateway: None,
            ipv6_gateway: None,
        })
    }

    fn dns_config(tunnel: &[IpAddr], non_tunnel: &[IpAddr]) -> ResolvedDnsConfig {
        use nym_dns::DnsConfig;
        DnsConfig::from_addresses(tunnel, non_tunnel).resolve(&[])
    }

    #[test]
    fn blocked_policy_terminates_in_reject() {
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec![],
        };
        let rs = compile(&policy);
        assert!(rs.output_terminates_in_block());
        assert!(rs.forward_terminates_in_block());
    }

    #[test]
    fn connecting_policy_terminates_in_reject() {
        let policy = FirewallPolicy::Connecting {
            peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
            tunnel: None,
            allow_lan: true,
            dns_config: dns_config(&[], &["8.8.8.8".parse().unwrap()]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
        };
        let rs = compile(&policy);
        assert!(rs.output_terminates_in_block());
        assert!(rs.forward_terminates_in_block());
        assert!(rs.tunnel_interfaces.is_empty());
    }

    #[test]
    fn connected_policy_collects_tunnel_interfaces() {
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: true,
            dns_config: dns_config(
                &["10.64.0.1".parse().unwrap()],
                &["1.1.1.1".parse().unwrap()],
            ),
        };
        let rs = compile(&policy);
        assert_eq!(rs.tunnel_interfaces, vec!["wg0".to_string()]);
        assert!(rs.output_terminates_in_block());
    }

    #[test]
    fn blocked_does_not_collect_tunnel_interfaces() {
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec![],
        };
        let rs = compile(&policy);
        assert!(rs.tunnel_interfaces.is_empty());
    }

    #[test]
    fn cve_2019_14899_protection_applied_only_in_connected_with_lan() {
        // Connected + allow_lan -> CVE rule present
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: true,
            dns_config: dns_config(&[], &[]),
        };
        let rs = compile(&policy);
        let has_cve = rs.input.rules.iter().any(|r| {
            r.matches.iif_not.as_deref() == Some("wg0")
                && matches!(r.matches.daddr, Some(AddrMatch::Ip(_)))
                && r.verdict == Verdict::Drop
        });
        assert!(has_cve, "CVE-2019-14899 drop rule missing in Connected+LAN");

        // Connected without allow_lan -> no CVE rule (no LAN traffic to defend against)
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
        };
        let rs = compile(&policy);
        let has_cve = rs
            .input
            .rules
            .iter()
            .any(|r| r.matches.iif_not.is_some() && r.verdict == Verdict::Drop);
        assert!(!has_cve, "CVE rule should be absent without allow_lan");
    }

    #[test]
    fn blocked_state_blocks_forward_lan_to_wan() {
        // The key kill-switch invariant: in Blocked state with allow_lan, a
        // LAN client must NOT be able to forward straight out the WAN.
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec![],
        };
        let rs = compile(&policy);
        // No forward rule should have an saddr LAN match (that would be the
        // historical leak). Only daddr LAN matches and ct established.
        for r in &rs.forward.rules {
            if let Some(AddrMatch::Net(net)) = &r.matches.saddr {
                panic!(
                    "Blocked policy must not have an saddr-LAN accept in forward chain: {:?}",
                    net
                );
            }
        }
    }
}
