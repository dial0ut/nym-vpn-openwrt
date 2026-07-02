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
use crate::net::{AllowedEndpoint, InboundExemption, TransportProtocol, TunnelMetadata};

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

/// Rate limit for the DNS escape hatch in `Blocked`/`Connecting`. The NTP
/// escape hatch is useless on its own because the router has to resolve the
/// NTP pool hostnames (`*.pool.ntp.org`) before it can reach a server, and
/// `block_dns` would otherwise reject that lookup. Sized for a cold-boot
/// resolution round (a handful of pool hostnames, A+AAAA, with retries) and
/// rate-capped so it can't degrade into a general DNS leak or exfil channel.
const DNS_RATE_PER_MIN: u32 = 30;
const DNS_BURST: u32 = 20;

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
            inbound_exemptions,
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
            exemption_filter_accepts(&mut rs, inbound_exemptions);
            bypass_mark_forward_accept(&mut rs);
            // DNS hatch must precede block_dns so the NTP-pool lookup the NTP
            // hatch depends on isn't rejected.
            dns_escape_hatch(&mut rs);
            block_dns(&mut rs);
            // A clockless router that boots straight into a connect attempt
            // needs NTP to reach a server before TLS to the API/gateway can
            // validate, otherwise it deadlocks in DeviceTimeDesynced. The
            // tunnel isn't up yet, so allow the same rate-limited escape hatch
            // as the Blocked state.
            ntp_escape_hatch(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
            exemption_mangle(&mut rs, inbound_exemptions);
        }

        FirewallPolicy::Connected {
            peer_endpoints,
            tunnel,
            allow_lan,
            dns_config,
            allowed_endpoints,
            inbound_exemptions,
        } => {
            for ep in peer_endpoints {
                allow_endpoint(&mut rs, ep);
            }
            for ep in allowed_endpoints {
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
            exemption_filter_accepts(&mut rs, inbound_exemptions);
            bypass_mark_forward_accept(&mut rs);
            block_dns(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
            exemption_mangle(&mut rs, inbound_exemptions);
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
            // DNS hatch must precede block_dns so the NTP-pool lookup the NTP
            // hatch depends on isn't rejected.
            dns_escape_hatch(&mut rs);
            block_dns(&mut rs);
            ntp_escape_hatch(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
            // Keep split-tunnel carve-outs alive while disconnected/reconnecting:
            // marked traffic egresses the WAN, everything else stays blocked.
            bypass_mark_forward_accept(&mut rs);
        }
    }

    final_reject(&mut rs);

    rs
}

// ---------- helpers ----------

fn base_rules(rs: &mut RuleSet) {
    // Loopback.
    rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
    rs.filter.output.push(Rule::accept(Family::Inet).oif("lo"));

    // Established/related — covers return traffic on every chain.
    rs.filter.input.push(Rule::accept(Family::Inet).ct_established());
    rs.filter.output.push(Rule::accept(Family::Inet).ct_established());
    rs.filter.forward.push(Rule::accept(Family::Inet).ct_established());

    // DHCPv4 — router as client and as server.
    rs.filter.input.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_SERVER_PORT)
            .dport(DHCPV4_CLIENT_PORT),
    );
    rs.filter.input.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .dport(DHCPV4_SERVER_PORT),
    );
    rs.filter.output.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_CLIENT_PORT)
            .dport(DHCPV4_SERVER_PORT),
    );
    rs.filter.output.push(
        Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .sport(DHCPV4_SERVER_PORT)
            .dport(DHCPV4_CLIENT_PORT),
    );

    // DHCPv6 — router as client and as server.
    rs.filter.input.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .sport(DHCPV6_SERVER_PORT)
            .dport(DHCPV6_CLIENT_PORT),
    );
    rs.filter.input.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .dport(DHCPV6_SERVER_PORT),
    );
    rs.filter.output.push(
        Rule::accept(Family::V6)
            .proto(Proto::Udp)
            .sport(DHCPV6_CLIENT_PORT)
            .dport(DHCPV6_SERVER_PORT),
    );
    rs.filter.output.push(
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
        rs.filter.input.push(Rule::accept(Family::V6).icmpv6_type(t));
    }
    for t in [
        IcmpV6Type::RouterSolicit,
        IcmpV6Type::NeighborSolicit,
        IcmpV6Type::NeighborAdvert,
    ] {
        rs.filter.output.push(Rule::accept(Family::V6).icmpv6_type(t));
    }

    // mwan3 tracking pings — keep WAN interfaces alive so mwan3 doesn't
    // declare WAN down and trigger a firewall reload cascade.
    for ip in common::get_mwan3_track_ips() {
        match ip {
            IpAddr::V4(_) => {
                rs.filter.input.push(
                    Rule::accept(Family::V4)
                        .proto(Proto::Icmp)
                        .icmpv4_type(IcmpV4Type::EchoReply)
                        .saddr(ip),
                );
                rs.filter.output.push(
                    Rule::accept(Family::V4)
                        .proto(Proto::Icmp)
                        .icmpv4_type(IcmpV4Type::EchoRequest)
                        .daddr(ip),
                );
            }
            IpAddr::V6(_) => {
                rs.filter.input.push(
                    Rule::accept(Family::V6)
                        .proto(Proto::IcmpV6)
                        .icmpv6_type(IcmpV6Type::EchoReply)
                        .saddr(ip),
                );
                rs.filter.output.push(
                    Rule::accept(Family::V6)
                        .proto(Proto::IcmpV6)
                        .icmpv6_type(IcmpV6Type::EchoRequest)
                        .daddr(ip),
                );
            }
        }
    }
}

/// Input/output filter accepts for the inbound-exemption mark. Slotted
/// **after** tunnel allows (so tunnel traffic still runs through normal filter
/// logic) and **before** `block_dns` (so a DNAT'd inbound DNS service on an
/// exempt port isn't rejected). Anchored on the mark alone — port matching
/// happened in the mangle prerouting chain, so by the time we see this we know
/// the packet belongs to an exempted flow. The **forward** accept is emitted
/// separately and unconditionally (see `bypass_mark_forward_accept`).
fn exemption_filter_accepts(rs: &mut RuleSet, exemptions: &[InboundExemption]) {
    if exemptions.is_empty() {
        return;
    }
    rs.filter.input.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
    rs.filter.output.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
}

/// Forward accept for the bypass fwmark (`0x14e`), emitted **unconditionally**
/// whenever a kill-switch policy is in force. This lets split-tunnel carve-outs
/// — and any admin-marked bypass (manual nft / PBR / inbound-service replies) —
/// egress the WAN while the kill-switch still rejects every other non-tunnel
/// forward. It mirrors the routing layer, which already honours `0x14e`
/// unconditionally (pri-90 ip rule). Safe because the mark is router-internal
/// netfilter metadata: a LAN client cannot set it on its own packets, so only
/// deliberate router rules ever carry it. This is what makes split tunneling
/// work with the kill-switch *on* — no leak window during reconnects.
fn bypass_mark_forward_accept(rs: &mut RuleSet) {
    rs.filter.forward.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
}

/// Mangle chain emission. `mangle_prerouting` restores the connmark for every
/// packet (so replies traversing the router carry the mark for `ip rule`) and
/// sets the connmark on the first packet of any matching inbound flow.
/// `mangle_output` restores the connmark for router-originated reply packets
/// so the post-mangle route reevaluation hits the fwmark rule.
fn exemption_mangle(rs: &mut RuleSet, exemptions: &[InboundExemption]) {
    if exemptions.is_empty() {
        return;
    }
    let Some(wan_iface) = common::detect_wan_iface() else {
        tracing::warn!(
            "Inbound exemptions configured but WAN interface could not be detected. \
             Exemption mangle rules will not be emitted; reply traffic will leak into the tunnel."
        );
        return;
    };

    // Restore comes first so replies on established flows pick up the mark.
    rs.mangle.prerouting.push(Rule::restore_mark(Family::Inet));
    // Set the connmark on the first packet of each exempted inbound flow.
    for ex in exemptions {
        let proto = match ex.proto {
            TransportProtocol::Tcp => Proto::Tcp,
            TransportProtocol::Udp => Proto::Udp,
        };
        rs.mangle.prerouting.push(
            Rule::set_ct_mark(Family::Inet, common::EXEMPT_FWMARK)
                .iif(&wan_iface)
                .proto(proto)
                .dport(ex.dport)
                .ct_new(),
        );
    }
    // Restore for locally-originated replies (router-hosted services).
    rs.mangle.output.push(Rule::restore_mark(Family::Inet));
}

fn allow_endpoint(rs: &mut RuleSet, ep: &AllowedEndpoint) {
    let ip = ep.endpoint.address.ip();
    let port = ep.endpoint.address.port();
    let proto = match ep.endpoint.protocol {
        TransportProtocol::Tcp => Proto::Tcp,
        TransportProtocol::Udp => Proto::Udp,
    };
    let family = family_of(&ip);
    rs.filter.output.push(
        Rule::accept(family)
            .proto(proto)
            .daddr(ip)
            .dport(port),
    );
    rs.filter.input.push(
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
        rs.filter.output.push(out);
        rs.filter.input.push(inp);
    }

    // Forward DNS for LAN clients (only when not iface-restricted).
    if iface.is_none() {
        for proto in [Proto::Udp, Proto::Tcp] {
            rs.filter.forward.push(
                Rule::accept(family)
                    .proto(proto)
                    .daddr(dns)
                    .dport(DNS_PORT),
            );
        }
    }
}

fn allow_tunnel(rs: &mut RuleSet, iface: &str) {
    rs.filter.input.push(Rule::accept(Family::Inet).iif(iface));
    rs.filter.output.push(Rule::accept(Family::Inet).oif(iface));
    // Forward LAN traffic out the tunnel. Return traffic is handled by the
    // ct established rule at the top of the forward chain.
    rs.filter.forward.push(Rule::accept(Family::Inet).oif(iface));
}

/// CVE-2019-14899: an attacker on the local network can probe whether a host
/// has an in-tunnel connection by sending packets *to* the tunnel's IP via a
/// non-tunnel interface. Drop those.
fn cve_2019_14899_protection(rs: &mut RuleSet, tunnel: &TunnelMetadata) {
    for ip in &tunnel.ips {
        rs.filter.input.push(
            Rule::drop_(family_of(ip))
                .iif_not(&tunnel.interface)
                .daddr(*ip),
        );
    }
}

fn block_dns(rs: &mut RuleSet) {
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.filter.output
            .push(Rule::reject(Family::Inet).proto(proto).dport(DNS_PORT));
        rs.filter.forward
            .push(Rule::reject(Family::Inet).proto(proto).dport(DNS_PORT));
    }
}

/// Rate-limited NTP escape hatch: a clockless router cold-boots with a stale
/// clock and would otherwise deadlock here, since TLS to the upstream API
/// fails cert validity until sysntpd can sync.
fn ntp_escape_hatch(rs: &mut RuleSet) {
    rs.filter.output.push(
        Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(NTP_PORT)
            .rate_limit(NTP_RATE_PER_MIN, NTP_BURST),
    );
}

/// Rate-limited DNS escape hatch: the NTP hatch needs the router's own resolver
/// to look up the NTP pool hostnames (and the API/gateway) before the tunnel is
/// up. Without this, `block_dns` rejects that lookup and the NTP hatch never
/// resolves a server — the cold-boot `DeviceTimeDesynced` deadlock the kill
/// switch is otherwise blamed for. OUTPUT-only (router-originated; LAN clients
/// stay fenced off via the forward-chain `block_dns` reject) and rate-capped so
/// it can't become a general DNS leak or exfil channel while disconnected.
fn dns_escape_hatch(rs: &mut RuleSet) {
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.filter.output.push(
            Rule::accept(Family::Inet)
                .proto(proto)
                .dport(DNS_PORT)
                .rate_limit(DNS_RATE_PER_MIN, DNS_BURST),
        );
    }
}

fn allow_lan_traffic(rs: &mut RuleSet) {
    for net in LAN_NETS_V4 {
        let n: IpNetwork = net.parse().expect("static LAN_NETS_V4 entry is valid");
        rs.filter.input.push(Rule::accept(Family::V4).saddr(n));
        rs.filter.output.push(Rule::accept(Family::V4).daddr(n));
        // Only daddr in forward — saddr would let a LAN client forward
        // straight out WAN between sessions, defeating the kill-switch.
        rs.filter.forward.push(Rule::accept(Family::V4).daddr(n));
    }
    for net in LAN_NETS_V6 {
        let n: IpNetwork = net.parse().expect("static LAN_NETS_V6 entry is valid");
        rs.filter.input.push(Rule::accept(Family::V6).saddr(n));
        rs.filter.output.push(Rule::accept(Family::V6).daddr(n));
        rs.filter.forward.push(Rule::accept(Family::V6).daddr(n));
    }
    let mcast4: IpNetwork = MULTICAST_V4.parse().unwrap();
    let mcast6: IpNetwork = MULTICAST_V6.parse().unwrap();
    rs.filter.output.push(Rule::accept(Family::V4).daddr(mcast4));
    rs.filter.output.push(Rule::accept(Family::V6).daddr(mcast6));
}

fn final_reject(rs: &mut RuleSet) {
    // INPUT is intentionally left to fall through to fw3/fw4's own input
    // chain so the router's own management traffic (SSH, LuCI) still works.
    rs.filter.output.push(Rule::reject(Family::Inet));
    rs.filter.forward.push(Rule::reject(Family::Inet));
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
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        assert!(rs.output_terminates_in_block());
        assert!(rs.forward_terminates_in_block());
        assert!(rs.tunnel_interfaces.is_empty());
    }

    #[test]
    fn connecting_policy_has_ntp_escape_hatch() {
        // A clockless router connecting with the kill-switch on must still be
        // able to reach NTP, or it deadlocks in DeviceTimeDesynced before TLS
        // to the API can validate.
        let policy = FirewallPolicy::Connecting {
            peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
            tunnel: None,
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let has_ntp = rs
            .filter
            .output
            .rules
            .iter()
            .any(|r| r.matches.dport == Some(NTP_PORT) && r.verdict == Verdict::Accept);
        assert!(has_ntp, "Connecting policy is missing the NTP escape hatch");
    }

    #[test]
    fn blocked_and_connecting_emit_dns_escape_hatch_before_block() {
        // The NTP hatch is useless unless the router can resolve the NTP pool
        // hostnames first, so a rate-limited DNS accept must sit in OUTPUT
        // ahead of the block_dns reject. Verify for both states.
        let connecting = FirewallPolicy::Connecting {
            peer_endpoints: vec![],
            tunnel: None,
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
            inbound_exemptions: vec![],
        };
        let blocked = FirewallPolicy::Blocked {
            allow_lan: false,
            allowed_endpoints: vec![],
            dns_servers: vec![],
        };
        for policy in [connecting, blocked] {
            let rs = compile(&policy);
            let out = &rs.filter.output.rules;
            let hatch = out.iter().position(|r| {
                r.matches.dport == Some(DNS_PORT)
                    && r.matches.rate_limit.is_some()
                    && r.verdict == Verdict::Accept
            });
            let reject = out
                .iter()
                .position(|r| r.matches.dport == Some(DNS_PORT) && r.verdict == Verdict::Reject);
            assert!(hatch.is_some(), "missing rate-limited DNS escape hatch");
            assert!(reject.is_some(), "missing block_dns reject");
            assert!(
                hatch.unwrap() < reject.unwrap(),
                "DNS hatch must precede block_dns reject"
            );
            // The hatch is router-only: no forward-chain DNS accept should leak
            // LAN client resolution out the WAN while disconnected.
            assert!(
                !rs.filter
                    .forward
                    .rules
                    .iter()
                    .any(|r| r.matches.dport == Some(DNS_PORT) && r.verdict == Verdict::Accept),
                "DNS hatch must not open the forward chain"
            );
        }
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
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
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
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let has_cve = rs.filter.input.rules.iter().any(|r| {
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
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let has_cve = rs
            .filter
            .input
            .rules
            .iter()
            .any(|r| r.matches.iif_not.is_some() && r.verdict == Verdict::Drop);
        assert!(!has_cve, "CVE rule should be absent without allow_lan");
    }

    #[test]
    fn connected_emits_allowed_endpoints() {
        // The folded outbound-allow-list patch: Connected now passes its
        // allowed_endpoints through the same allow_endpoint() helper as
        // Connecting did.
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![ep([198, 41, 192, 167], 7844)],
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let has_endpoint_accept = rs.filter.output.rules.iter().any(|r| {
            matches!(r.matches.daddr, Some(AddrMatch::Ip(IpAddr::V4(ip))) if ip.octets() == [198, 41, 192, 167])
                && r.matches.dport == Some(7844)
                && r.verdict == Verdict::Accept
        });
        assert!(has_endpoint_accept, "allowed_endpoints not emitted in OUTPUT");
    }

    #[test]
    fn exemptions_do_not_emit_mangle_when_empty() {
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: true,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        assert!(rs.mangle.is_empty(), "no mangle rules expected without exemptions");
        let has_mark_accept = rs
            .filter
            .output
            .rules
            .iter()
            .any(|r| r.matches.mark.is_some());
        assert!(!has_mark_accept, "no mark accepts expected without exemptions");
    }

    #[test]
    fn exemptions_emit_filter_mark_accepts_before_final_reject() {
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            inbound_exemptions: vec![
                InboundExemption::new(TransportProtocol::Tcp, 443),
                InboundExemption::new(TransportProtocol::Udp, 51820),
            ],
        };
        let rs = compile(&policy);

        for chain in [&rs.filter.input, &rs.filter.output, &rs.filter.forward] {
            let mark_pos = chain
                .rules
                .iter()
                .position(|r| r.matches.mark == Some(common::EXEMPT_FWMARK));
            assert!(mark_pos.is_some(), "expected mark accept in chain");
            let last = chain.rules.last().expect("non-empty chain");
            // mark accept must precede the final reject in OUTPUT/FORWARD.
            if matches!(last.verdict, Verdict::Reject) {
                assert!(mark_pos.unwrap() < chain.rules.len() - 1);
            }
        }
    }

    // Build each kill-switch policy variant with NO inbound exemptions, so any
    // forward mark accept comes solely from `bypass_mark_forward_accept`.
    fn killswitch_states_without_exemptions() -> Vec<(&'static str, FirewallPolicy)> {
        vec![
            (
                "connecting",
                FirewallPolicy::Connecting {
                    peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
                    tunnel: None,
                    allow_lan: true,
                    dns_config: dns_config(&[], &["8.8.8.8".parse().unwrap()]),
                    allowed_endpoints: vec![],
                    allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
                    allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
                    inbound_exemptions: vec![],
                },
            ),
            (
                "connected",
                FirewallPolicy::Connected {
                    peer_endpoints: vec![],
                    tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
                    allow_lan: true,
                    dns_config: dns_config(&[], &[]),
                    allowed_endpoints: vec![],
                    inbound_exemptions: vec![],
                },
            ),
            (
                "blocked",
                FirewallPolicy::Blocked {
                    allow_lan: true,
                    allowed_endpoints: vec![],
                    dns_servers: vec![],
                },
            ),
        ]
    }

    #[test]
    fn bypass_mark_accepted_in_forward_without_exemptions() {
        // The split-tunnel-coexistence invariant: every kill-switch state accepts
        // the bypass fwmark in FORWARD even with zero inbound exemptions, and that
        // accept precedes the terminal reject. This is what lets carve-outs egress
        // the WAN with the kill-switch on, including mid-reconnect (Connecting /
        // Blocked).
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            let pos = rs
                .filter
                .forward
                .rules
                .iter()
                .position(|r| r.matches.mark == Some(common::EXEMPT_FWMARK));
            assert!(pos.is_some(), "{name}: missing bypass-mark forward accept");
            assert!(
                rs.forward_terminates_in_block(),
                "{name}: forward must still terminate in reject"
            );
            assert!(
                pos.unwrap() < rs.filter.forward.rules.len() - 1,
                "{name}: bypass-mark accept must precede the final reject"
            );
        }
    }

    #[test]
    fn unmarked_lan_to_wan_still_rejected_with_bypass_accept() {
        // Safety backstop: making the bypass accept unconditional must NOT open a
        // hole for unmarked traffic. The only new forward accept is mark-gated;
        // no unmarked/saddr-LAN forward accept may be introduced, and forward
        // still ends in reject — so non-excluded LAN clients stay blocked
        // (no leak during reconnects).
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            assert!(
                rs.forward_terminates_in_block(),
                "{name}: forward chain must terminate in reject"
            );
            for r in &rs.filter.forward.rules {
                if matches!(r.verdict, Verdict::Accept) && r.matches.mark != Some(common::EXEMPT_FWMARK) {
                    // The only unmarked forward accepts allowed are ct-established
                    // (return traffic) and daddr-LAN (into-LAN). An saddr-LAN or
                    // bare accept would be the leak.
                    assert!(
                        r.matches.saddr.is_none(),
                        "{name}: unexpected saddr-matched forward accept (potential leak): {r:?}"
                    );
                }
            }
        }
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
        for r in &rs.filter.forward.rules {
            if let Some(AddrMatch::Net(net)) = &r.matches.saddr {
                panic!(
                    "Blocked policy must not have an saddr-LAN accept in forward chain: {:?}",
                    net
                );
            }
        }
    }
}
