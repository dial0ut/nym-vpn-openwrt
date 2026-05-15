// SPDX-License-Identifier: GPL-3.0-only

//! Render a [`RuleSet`] into iptables-restore format, separately for IPv4
//! and IPv6.

use std::fmt::Write;

use super::rules::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    V4,
    V6,
}

pub const CHAIN_INPUT: &str = "NYM_INPUT";
pub const CHAIN_OUTPUT: &str = "NYM_OUTPUT";
pub const CHAIN_FORWARD: &str = "NYM_FORWARD";

/// Render the [`RuleSet`] for one address family as an iptables-restore
/// script body.
pub fn render(rs: &RuleSet, family: AddrFamily) -> String {
    let mut out = String::new();
    writeln!(out, "*filter").unwrap();
    // Declare our chains (create-if-missing with zeroed counters).
    writeln!(out, ":{CHAIN_INPUT} - [0:0]").unwrap();
    writeln!(out, ":{CHAIN_OUTPUT} - [0:0]").unwrap();
    writeln!(out, ":{CHAIN_FORWARD} - [0:0]").unwrap();
    // Flush so a re-apply starts from a known state.
    writeln!(out, "-F {CHAIN_INPUT}").unwrap();
    writeln!(out, "-F {CHAIN_OUTPUT}").unwrap();
    writeln!(out, "-F {CHAIN_FORWARD}").unwrap();

    render_chain(&mut out, CHAIN_INPUT, &rs.input, family);
    render_chain(&mut out, CHAIN_OUTPUT, &rs.output, family);
    render_chain(&mut out, CHAIN_FORWARD, &rs.forward, family);

    writeln!(out, "COMMIT").unwrap();
    out
}

fn render_chain(out: &mut String, chain: &str, c: &Chain, family: AddrFamily) {
    for rule in &c.rules {
        if !family_matches(rule.family, family) {
            continue;
        }
        writeln!(out, "-A {chain} {}", render_rule(rule, family)).unwrap();
    }
}

fn family_matches(rule_family: Family, target: AddrFamily) -> bool {
    matches!(
        (rule_family, target),
        (Family::V4, AddrFamily::V4) | (Family::V6, AddrFamily::V6) | (Family::Inet, _)
    )
}

fn render_rule(rule: &Rule, family: AddrFamily) -> String {
    let mut parts: Vec<String> = Vec::new();
    let m = &rule.matches;

    if let Some(iface) = &m.iif {
        parts.push(format!("-i {iface}"));
    }
    if let Some(iface) = &m.oif {
        parts.push(format!("-o {iface}"));
    }
    if let Some(iface) = &m.iif_not {
        parts.push(format!("! -i {iface}"));
    }
    if let Some(saddr) = &m.saddr {
        parts.push(format!("-s {}", render_addr(saddr)));
    }
    if let Some(daddr) = &m.daddr {
        parts.push(format!("-d {}", render_addr(daddr)));
    }
    if let Some(proto) = m.proto {
        parts.push(format!("-p {}", proto_str(proto)));
    }
    if let Some(t) = m.icmpv4_type {
        parts.push(format!("--icmp-type {}", icmpv4_name(t)));
    }
    if let Some(t) = m.icmpv6_type {
        parts.push(format!("--icmpv6-type {}", icmpv6_name(t)));
    }
    if let Some(sport) = m.sport {
        parts.push(format!("--sport {sport}"));
    }
    if let Some(dport) = m.dport {
        parts.push(format!("--dport {dport}"));
    }
    if let Some(ct) = m.ct_state {
        match ct {
            CtState::EstablishedRelated => {
                parts.push("-m conntrack --ctstate ESTABLISHED,RELATED".into())
            }
        }
    }
    if let Some(rl) = m.rate_limit {
        parts.push(format!(
            "-m limit --limit {}/minute --limit-burst {}",
            rl.per_minute, rl.burst
        ));
    }

    match rule.verdict {
        Verdict::Accept => parts.push("-j ACCEPT".into()),
        Verdict::Drop => parts.push("-j DROP".into()),
        Verdict::Reject => parts.push(format!("-j REJECT --reject-with {}", reject_with(rule, family))),
    }
    parts.join(" ")
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => "icmp",
        Proto::IcmpV6 => "icmpv6",
    }
}

fn render_addr(addr: &AddrMatch) -> String {
    match addr {
        AddrMatch::Ip(ip) => ip.to_string(),
        AddrMatch::Net(net) => net.to_string(),
    }
}

fn icmpv4_name(t: IcmpV4Type) -> &'static str {
    match t {
        IcmpV4Type::EchoRequest => "echo-request",
        IcmpV4Type::EchoReply => "echo-reply",
    }
}

fn icmpv6_name(t: IcmpV6Type) -> &'static str {
    match t {
        IcmpV6Type::RouterSolicit => "router-solicitation",
        IcmpV6Type::RouterAdvert => "router-advertisement",
        IcmpV6Type::NeighborSolicit => "neighbour-solicitation",
        IcmpV6Type::NeighborAdvert => "neighbour-advertisement",
        IcmpV6Type::Redirect => "redirect",
        IcmpV6Type::EchoRequest => "echo-request",
        IcmpV6Type::EchoReply => "echo-reply",
    }
}

/// Pick the right REJECT method per family/proto. Without a `--reject-with`
/// flag iptables would default to icmp-port-unreachable on v4 / icmp6 on v6,
/// but for TCP we want tcp-reset so clients see a clean refusal.
fn reject_with(rule: &Rule, family: AddrFamily) -> &'static str {
    if rule.matches.proto == Some(Proto::Tcp) {
        return "tcp-reset";
    }
    match family {
        AddrFamily::V4 => "icmp-port-unreachable",
        AddrFamily::V6 => "icmp6-port-unreachable",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn renders_loopback_accept() {
        let rule = Rule::accept(Family::Inet).iif("lo");
        assert_eq!(render_rule(&rule, AddrFamily::V4), "-i lo -j ACCEPT");
    }

    #[test]
    fn renders_ct_established() {
        let rule = Rule::accept(Family::Inet).ct_established();
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        );
    }

    #[test]
    fn renders_dhcpv4_client() {
        let rule = Rule::accept(Family::V4).proto(Proto::Udp).sport(68).dport(67);
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "-p udp --sport 68 --dport 67 -j ACCEPT"
        );
    }

    #[test]
    fn renders_cve_2019_14899_drop() {
        let rule = Rule::drop_(Family::V4)
            .iif_not("wg0")
            .daddr(IpAddr::V4(Ipv4Addr::new(10, 64, 0, 2)));
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "! -i wg0 -d 10.64.0.2 -j DROP"
        );
    }

    #[test]
    fn renders_dns_block_udp_v4() {
        let rule = Rule::reject(Family::Inet).proto(Proto::Udp).dport(53);
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "-p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable"
        );
    }

    #[test]
    fn renders_dns_block_tcp_uses_tcp_reset() {
        let rule = Rule::reject(Family::Inet).proto(Proto::Tcp).dport(53);
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "-p tcp --dport 53 -j REJECT --reject-with tcp-reset"
        );
    }

    #[test]
    fn renders_final_reject_v6_uses_icmp6() {
        let rule = Rule::reject(Family::Inet);
        assert_eq!(
            render_rule(&rule, AddrFamily::V6),
            "-j REJECT --reject-with icmp6-port-unreachable"
        );
    }

    #[test]
    fn renders_ntp_rate_limit() {
        let rule = Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(123)
            .rate_limit(12, 8);
        assert_eq!(
            render_rule(&rule, AddrFamily::V4),
            "-p udp --dport 123 -m limit --limit 12/minute --limit-burst 8 -j ACCEPT"
        );
    }

    #[test]
    fn skips_v6_only_rules_in_v4_render() {
        let mut rs = RuleSet::default();
        rs.input.push(Rule::accept(Family::V6).icmpv6_type(IcmpV6Type::RouterAdvert));
        rs.input.push(Rule::accept(Family::V4).proto(Proto::Udp).dport(67));
        rs.output.push(Rule::reject(Family::Inet));
        rs.forward.push(Rule::reject(Family::Inet));
        let v4 = render(&rs, AddrFamily::V4);
        assert!(!v4.contains("icmpv6"));
        assert!(v4.contains("--dport 67"));
    }

    #[test]
    fn skips_v4_only_rules_in_v6_render() {
        let mut rs = RuleSet::default();
        rs.input.push(Rule::accept(Family::V6).icmpv6_type(IcmpV6Type::RouterAdvert));
        rs.input.push(Rule::accept(Family::V4).proto(Proto::Udp).dport(67));
        rs.output.push(Rule::reject(Family::Inet));
        rs.forward.push(Rule::reject(Family::Inet));
        let v6 = render(&rs, AddrFamily::V6);
        assert!(v6.contains("icmpv6"));
        assert!(!v6.contains("--dport 67"));
    }

    #[test]
    fn render_emits_filter_table_with_chains() {
        let rs = RuleSet::default();
        let v4 = render(&rs, AddrFamily::V4);
        assert!(v4.starts_with("*filter\n"));
        assert!(v4.contains(":NYM_INPUT - [0:0]"));
        assert!(v4.contains(":NYM_OUTPUT - [0:0]"));
        assert!(v4.contains(":NYM_FORWARD - [0:0]"));
        assert!(v4.contains("-F NYM_INPUT"));
        assert!(v4.ends_with("COMMIT\n"));
    }
}
