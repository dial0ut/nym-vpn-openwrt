// SPDX-License-Identifier: GPL-3.0-only

//! Render a [`RuleSet`] into an nft script string for `table inet nym`.

use std::fmt::Write;

use super::rules::*;

/// Priority of our chains relative to fw4's: we run first so blocks are
/// final and fw4 never sees that traffic.
const PRIORITY_OFFSET: i32 = -10;

/// Render the [`RuleSet`] as an `nft -f` script.
pub fn render(rs: &RuleSet) -> String {
    let mut out = String::new();
    writeln!(out, "#!/usr/sbin/nft -f").unwrap();
    writeln!(out).unwrap();
    // Idempotent create-then-replace dance: `delete table` errors if the
    // table doesn't exist, so we create-then-delete-then-create.
    writeln!(out, "table inet nym").unwrap();
    writeln!(out, "delete table inet nym").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "table inet nym {{").unwrap();

    render_chain(&mut out, "input", "input", &rs.input);
    render_chain(&mut out, "output", "output", &rs.output);
    render_chain(&mut out, "forward", "forward", &rs.forward);

    writeln!(out, "}}").unwrap();
    out
}

fn render_chain(out: &mut String, chain_name: &str, hook: &str, chain: &Chain) {
    writeln!(out, "    chain {chain_name} {{").unwrap();
    writeln!(
        out,
        "        type filter hook {hook} priority filter {sign} {abs}; policy accept;",
        sign = if PRIORITY_OFFSET < 0 { "-" } else { "+" },
        abs = PRIORITY_OFFSET.unsigned_abs(),
    )
    .unwrap();
    for rule in &chain.rules {
        writeln!(out, "        {}", render_rule(rule)).unwrap();
    }
    writeln!(out, "    }}").unwrap();
}

fn render_rule(rule: &Rule) -> String {
    let mut parts: Vec<String> = Vec::new();
    let m = &rule.matches;

    if let Some(iface) = &m.iif {
        parts.push(format!("iifname \"{iface}\""));
    }
    if let Some(iface) = &m.oif {
        parts.push(format!("oifname \"{iface}\""));
    }
    if let Some(iface) = &m.iif_not {
        parts.push(format!("iifname != \"{iface}\""));
    }
    if let Some(ct) = m.ct_state {
        match ct {
            CtState::EstablishedRelated => parts.push("ct state established,related".into()),
        }
    }
    if let Some(saddr) = &m.saddr {
        parts.push(format!("{} saddr {}", addr_family(rule.family), render_addr(saddr)));
    }
    if let Some(daddr) = &m.daddr {
        parts.push(format!("{} daddr {}", addr_family(rule.family), render_addr(daddr)));
    }
    if let Some(t) = m.icmpv4_type {
        parts.push(format!("icmp type {}", icmpv4_name(t)));
    }
    if let Some(t) = m.icmpv6_type {
        parts.push(format!("icmpv6 type {}", icmpv6_name(t)));
    }
    match m.proto {
        Some(Proto::Tcp) => {
            if let Some(sport) = m.sport {
                parts.push(format!("tcp sport {sport}"));
            }
            if let Some(dport) = m.dport {
                parts.push(format!("tcp dport {dport}"));
            }
            if m.sport.is_none() && m.dport.is_none() {
                parts.push("meta l4proto tcp".into());
            }
        }
        Some(Proto::Udp) => {
            if let Some(sport) = m.sport {
                parts.push(format!("udp sport {sport}"));
            }
            if let Some(dport) = m.dport {
                parts.push(format!("udp dport {dport}"));
            }
            if m.sport.is_none() && m.dport.is_none() {
                parts.push("meta l4proto udp".into());
            }
        }
        // Icmp / IcmpV6 are already implied by the icmp(v6) type match above.
        Some(Proto::Icmp) | Some(Proto::IcmpV6) | None => {}
    }
    if let Some(rl) = m.rate_limit {
        parts.push(format!(
            "limit rate {}/minute burst {} packets",
            rl.per_minute, rl.burst
        ));
    }

    let verdict = match rule.verdict {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
        Verdict::Reject => "reject",
    };
    parts.push(verdict.into());
    parts.join(" ")
}

fn addr_family(family: Family) -> &'static str {
    match family {
        Family::V4 => "ip",
        Family::V6 => "ip6",
        // `inet` family chains accept both; if we got here, the caller is
        // passing an address with no explicit family. Treat as ipv4 — but
        // policy.rs always sets V4/V6 explicitly when there's an address.
        Family::Inet => "ip",
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
        IcmpV6Type::RouterSolicit => "nd-router-solicit",
        IcmpV6Type::RouterAdvert => "nd-router-advert",
        IcmpV6Type::NeighborSolicit => "nd-neighbor-solicit",
        IcmpV6Type::NeighborAdvert => "nd-neighbor-advert",
        IcmpV6Type::Redirect => "nd-redirect",
        IcmpV6Type::EchoRequest => "echo-request",
        IcmpV6Type::EchoReply => "echo-reply",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn renders_loopback_accept() {
        let rule = Rule::accept(Family::Inet).iif("lo");
        assert_eq!(render_rule(&rule), "iifname \"lo\" accept");
    }

    #[test]
    fn renders_ct_established() {
        let rule = Rule::accept(Family::Inet).ct_established();
        assert_eq!(render_rule(&rule), "ct state established,related accept");
    }

    #[test]
    fn renders_dhcpv4_client() {
        let rule = Rule::accept(Family::V4).proto(Proto::Udp).sport(68).dport(67);
        assert_eq!(render_rule(&rule), "udp sport 68 udp dport 67 accept");
    }

    #[test]
    fn renders_cve_2019_14899_drop() {
        let rule = Rule::drop_(Family::V4)
            .iif_not("wg0")
            .daddr(IpAddr::V4(Ipv4Addr::new(10, 64, 0, 2)));
        assert_eq!(
            render_rule(&rule),
            "iifname != \"wg0\" ip daddr 10.64.0.2 drop"
        );
    }

    #[test]
    fn renders_dns_block_udp() {
        let rule = Rule::reject(Family::Inet).proto(Proto::Udp).dport(53);
        assert_eq!(render_rule(&rule), "udp dport 53 reject");
    }

    #[test]
    fn renders_final_reject() {
        let rule = Rule::reject(Family::Inet);
        assert_eq!(render_rule(&rule), "reject");
    }

    #[test]
    fn renders_ntp_rate_limit() {
        let rule = Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(123)
            .rate_limit(12, 8);
        assert_eq!(
            render_rule(&rule),
            "udp dport 123 limit rate 12/minute burst 8 packets accept"
        );
    }

    #[test]
    fn renders_endpoint_output() {
        let rule = Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .daddr(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .dport(443);
        assert_eq!(
            render_rule(&rule),
            "ip daddr 1.2.3.4 udp dport 443 accept"
        );
    }

    #[test]
    fn renders_icmpv6_nd() {
        let rule = Rule::accept(Family::V6).icmpv6_type(IcmpV6Type::RouterAdvert);
        assert_eq!(render_rule(&rule), "icmpv6 type nd-router-advert accept");
    }

    #[test]
    fn render_emits_full_table() {
        let mut rs = RuleSet::default();
        rs.input.push(Rule::accept(Family::Inet).iif("lo"));
        rs.output.push(Rule::reject(Family::Inet));
        rs.forward.push(Rule::reject(Family::Inet));
        let script = render(&rs);
        assert!(script.contains("table inet nym"));
        assert!(script.contains("chain input"));
        assert!(script.contains("chain output"));
        assert!(script.contains("chain forward"));
        assert!(script.contains("priority filter - 10"));
        assert!(script.contains("iifname \"lo\" accept"));
    }
}
