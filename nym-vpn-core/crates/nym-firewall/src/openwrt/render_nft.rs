// SPDX-License-Identifier: GPL-3.0-only

//! Render a [`RuleSet`] into an nft script string for `table inet nym`.

use std::fmt::Write;

use super::rules::*;

/// Priority of our filter chains relative to fw4's: we run first so blocks
/// are final and fw4 never sees that traffic.
const FILTER_PRIORITY_OFFSET: i32 = -10;

/// Priority of our mangle chains. Sits at `mangle - 10` so it runs before
/// any other mangle hook (and crucially before fw4's dstnat at `dstnat`).
/// `mangle` is -150 in nftables, so this resolves to -160.
const MANGLE_PRIORITY_OFFSET: i32 = -10;

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

    if !rs.mangle.is_empty() {
        render_mangle_chain(&mut out, "mangle_prerouting", "prerouting", &rs.mangle.prerouting);
        render_mangle_chain(&mut out, "mangle_output", "output", &rs.mangle.output);
    }
    render_chain(&mut out, "input", "input", &rs.filter.input);
    render_chain(&mut out, "output", "output", &rs.filter.output);
    render_chain(&mut out, "forward", "forward", &rs.filter.forward);

    writeln!(out, "}}").unwrap();
    out
}

fn render_chain(out: &mut String, chain_name: &str, hook: &str, chain: &Chain) {
    debug_assert!(
        hook == "output" || chain.rules.iter().all(|r| r.matches.skuid.is_none()),
        "skuid match emitted on non-output hook {hook}"
    );
    writeln!(out, "    chain {chain_name} {{").unwrap();
    writeln!(
        out,
        "        type filter hook {hook} priority filter {sign} {abs}; policy accept;",
        sign = if FILTER_PRIORITY_OFFSET < 0 { "-" } else { "+" },
        abs = FILTER_PRIORITY_OFFSET.unsigned_abs(),
    )
    .unwrap();
    for rule in &chain.rules {
        writeln!(out, "        {}", render_rule(rule)).unwrap();
    }
    writeln!(out, "    }}").unwrap();
}

fn render_mangle_chain(out: &mut String, chain_name: &str, hook: &str, chain: &Chain) {
    debug_assert!(
        hook == "output" || chain.rules.iter().all(|r| r.matches.skuid.is_none()),
        "skuid match emitted on non-output hook {hook}"
    );
    writeln!(out, "    chain {chain_name} {{").unwrap();
    writeln!(
        out,
        "        type filter hook {hook} priority mangle {sign} {abs};",
        sign = if MANGLE_PRIORITY_OFFSET < 0 { "-" } else { "+" },
        abs = MANGLE_PRIORITY_OFFSET.unsigned_abs(),
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
            CtState::New => parts.push("ct state new".into()),
        }
    }
    if let Some(mark) = m.mark {
        parts.push(format!("meta mark {mark:#x}"));
    }
    if let Some(ct_mark) = m.ct_mark {
        parts.push(format!("ct mark {ct_mark:#x}"));
    }
    if let Some(uid) = m.skuid {
        parts.push(format!("meta skuid {uid}"));
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

    let verdict: String = match rule.verdict {
        Verdict::Accept => "accept".into(),
        Verdict::Drop => "drop".into(),
        Verdict::Reject => "reject".into(),
        Verdict::SetCtMark(n) => format!("ct mark set {n:#x}"),
        Verdict::RestoreMark => "meta mark set ct mark".into(),
    };
    parts.push(verdict);
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
    fn renders_set_ct_mark_on_new_inbound() {
        let rule = Rule::set_ct_mark(Family::Inet, 0x14e)
            .iif("wan")
            .proto(Proto::Tcp)
            .dport(443)
            .ct_new();
        assert_eq!(
            render_rule(&rule),
            "iifname \"wan\" ct state new tcp dport 443 ct mark set 0x14e"
        );
    }

    #[test]
    fn renders_restore_mark() {
        let rule = Rule::restore_mark(Family::Inet);
        assert_eq!(render_rule(&rule), "meta mark set ct mark");
    }

    #[test]
    fn renders_ct_mark_scoped_restore() {
        let rule = Rule::restore_mark(Family::Inet).ct_mark_eq(0x14e);
        assert_eq!(render_rule(&rule), "ct mark 0x14e meta mark set ct mark");
    }

    #[test]
    fn renders_meta_mark_match_accept() {
        let rule = Rule::accept(Family::Inet).mark_eq(0x14e);
        assert_eq!(render_rule(&rule), "meta mark 0x14e accept");
    }

    #[test]
    fn renders_skuid_scoped_dns_hatch() {
        let rule = Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(53)
            .rate_limit(30, 20)
            .skuid(0);
        assert_eq!(
            render_rule(&rule),
            "meta skuid 0 udp dport 53 limit rate 30/minute burst 20 packets accept"
        );
    }

    #[test]
    fn renders_skuid_scoped_resolver_accept() {
        let rule = Rule::accept(Family::V4)
            .proto(Proto::Udp)
            .daddr(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
            .dport(53)
            .skuid(0);
        assert_eq!(
            render_rule(&rule),
            "meta skuid 0 ip daddr 9.9.9.9 udp dport 53 accept"
        );
    }

    #[test]
    fn renders_icmpv6_nd() {
        let rule = Rule::accept(Family::V6).icmpv6_type(IcmpV6Type::RouterAdvert);
        assert_eq!(render_rule(&rule), "icmpv6 type nd-router-advert accept");
    }

    #[test]
    fn render_omits_mangle_chains_when_empty() {
        let mut rs = RuleSet::default();
        rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
        rs.filter.output.push(Rule::reject(Family::Inet));
        rs.filter.forward.push(Rule::reject(Family::Inet));
        let script = render(&rs);
        assert!(!script.contains("mangle_prerouting"));
        assert!(!script.contains("mangle_output"));
        assert!(!script.contains("priority mangle"));
    }

    #[test]
    fn render_emits_mangle_chains_when_non_empty() {
        let mut rs = RuleSet::default();
        rs.mangle.prerouting.push(Rule::restore_mark(Family::Inet));
        rs.mangle.prerouting.push(
            Rule::set_ct_mark(Family::Inet, 0x14e)
                .iif("wan")
                .proto(Proto::Tcp)
                .dport(443)
                .ct_new(),
        );
        rs.mangle.output.push(Rule::restore_mark(Family::Inet));
        rs.filter.output.push(Rule::reject(Family::Inet));
        rs.filter.forward.push(Rule::reject(Family::Inet));
        let script = render(&rs);
        assert!(script.contains("chain mangle_prerouting"));
        assert!(script.contains("chain mangle_output"));
        assert!(script.contains("type filter hook prerouting priority mangle - 10"));
        assert!(script.contains("type filter hook output priority mangle - 10"));
        assert!(script.contains("meta mark set ct mark"));
        assert!(script.contains("iifname \"wan\" ct state new tcp dport 443 ct mark set 0x14e"));
    }

    #[test]
    fn render_emits_full_table() {
        let mut rs = RuleSet::default();
        rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
        rs.filter.output.push(Rule::reject(Family::Inet));
        rs.filter.forward.push(Rule::reject(Family::Inet));
        let script = render(&rs);
        assert!(script.contains("table inet nym"));
        assert!(script.contains("chain input"));
        assert!(script.contains("chain output"));
        assert!(script.contains("chain forward"));
        assert!(script.contains("priority filter - 10"));
        assert!(script.contains("iifname \"lo\" accept"));
    }
}
