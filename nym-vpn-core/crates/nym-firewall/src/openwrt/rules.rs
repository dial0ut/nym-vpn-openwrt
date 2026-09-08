// SPDX-License-Identifier: GPL-3.0-only

//! Backend-neutral firewall rule AST shared by both renderers.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
    /// Emitted in both iptables files and without an nft family qualifier.
    Inet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    /// Non-terminal `ct mark set`.
    SetCtMark(u32),
    /// Non-terminal `meta mark set ct mark`, for `ip rule fwmark` routing.
    RestoreMark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtState {
    EstablishedRelated,
    New,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpV4Type {
    EchoRequest,
    EchoReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpV6Type {
    RouterSolicit,
    RouterAdvert,
    NeighborSolicit,
    NeighborAdvert,
    Redirect,
    EchoRequest,
    EchoReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub per_minute: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrMatch {
    Ip(IpAddr),
    Net(IpNetwork),
}

impl From<IpAddr> for AddrMatch {
    fn from(ip: IpAddr) -> Self {
        AddrMatch::Ip(ip)
    }
}

impl From<IpNetwork> for AddrMatch {
    fn from(net: IpNetwork) -> Self {
        AddrMatch::Net(net)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub iif_not: Option<String>,
    pub saddr: Option<AddrMatch>,
    pub daddr: Option<AddrMatch>,
    pub proto: Option<Proto>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub ct_state: Option<CtState>,
    pub icmpv4_type: Option<IcmpV4Type>,
    pub icmpv6_type: Option<IcmpV6Type>,
    pub rate_limit: Option<RateLimit>,
    /// Packet (meta) mark.
    pub mark: Option<u32>,
    /// Conntrack mark; `-m connmark` ships in iptables-mod-conntrack-extra.
    pub ct_mark: Option<u32>,
    /// Owning socket uid. OUTPUT only: iptables rejects it on other chains.
    pub skuid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub family: Family,
    pub matches: Match,
    pub verdict: Verdict,
}

impl Rule {
    pub fn new(family: Family, verdict: Verdict) -> Self {
        Self {
            family,
            matches: Match::default(),
            verdict,
        }
    }

    pub fn accept(family: Family) -> Self {
        Self::new(family, Verdict::Accept)
    }
    pub fn drop_(family: Family) -> Self {
        Self::new(family, Verdict::Drop)
    }
    pub fn reject(family: Family) -> Self {
        Self::new(family, Verdict::Reject)
    }

    pub fn iif(mut self, iface: impl Into<String>) -> Self {
        self.matches.iif = Some(iface.into());
        self
    }
    pub fn oif(mut self, iface: impl Into<String>) -> Self {
        self.matches.oif = Some(iface.into());
        self
    }
    pub fn iif_not(mut self, iface: impl Into<String>) -> Self {
        self.matches.iif_not = Some(iface.into());
        self
    }
    pub fn saddr(mut self, addr: impl Into<AddrMatch>) -> Self {
        self.matches.saddr = Some(addr.into());
        self
    }
    pub fn daddr(mut self, addr: impl Into<AddrMatch>) -> Self {
        self.matches.daddr = Some(addr.into());
        self
    }
    pub fn proto(mut self, proto: Proto) -> Self {
        self.matches.proto = Some(proto);
        self
    }
    pub fn sport(mut self, port: u16) -> Self {
        self.matches.sport = Some(port);
        self
    }
    pub fn dport(mut self, port: u16) -> Self {
        self.matches.dport = Some(port);
        self
    }
    pub fn ct_established(mut self) -> Self {
        self.matches.ct_state = Some(CtState::EstablishedRelated);
        self
    }
    pub fn ct_new(mut self) -> Self {
        self.matches.ct_state = Some(CtState::New);
        self
    }
    pub fn mark_eq(mut self, mark: u32) -> Self {
        self.matches.mark = Some(mark);
        self
    }
    pub fn ct_mark_eq(mut self, mark: u32) -> Self {
        self.matches.ct_mark = Some(mark);
        self
    }
    /// OUTPUT only; see [`Match::skuid`].
    pub fn skuid(mut self, uid: u32) -> Self {
        self.matches.skuid = Some(uid);
        self
    }
    pub fn set_ct_mark(family: Family, mark: u32) -> Self {
        Self::new(family, Verdict::SetCtMark(mark))
    }
    pub fn restore_mark(family: Family) -> Self {
        Self::new(family, Verdict::RestoreMark)
    }
    /// Sets the protocol too: iptables-restore rejects `--icmp-type`
    /// without `-p icmp` on the same line.
    pub fn icmpv4_type(mut self, t: IcmpV4Type) -> Self {
        self.matches.proto = Some(Proto::Icmp);
        self.matches.icmpv4_type = Some(t);
        self
    }
    /// See [`Self::icmpv4_type`].
    pub fn icmpv6_type(mut self, t: IcmpV6Type) -> Self {
        self.matches.proto = Some(Proto::IcmpV6);
        self.matches.icmpv6_type = Some(t);
        self
    }
    pub fn rate_limit(mut self, per_minute: u32, burst: u32) -> Self {
        self.matches.rate_limit = Some(RateLimit { per_minute, burst });
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn push(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterRules {
    pub input: Chain,
    pub output: Chain,
    pub forward: Chain,
}

/// Renderers emit nothing for the mangle table when both chains are empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MangleRules {
    pub prerouting: Chain,
    pub output: Chain,
}

impl MangleRules {
    pub fn is_empty(&self) -> bool {
        self.prerouting.is_empty() && self.output.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub filter: FilterRules,
    pub mangle: MangleRules,
    /// Interfaces needing masquerade/forward integration; empty in `Blocked`.
    pub tunnel_interfaces: Vec<String>,
}

impl RuleSet {
    pub fn has_skuid(&self) -> bool {
        self.all_chains().any(|c| c.rules.iter().any(|r| r.matches.skuid.is_some()))
    }

    /// fw3 fallback without `-m owner`: the scoped exceptions are dropped,
    /// never widened into unscoped accepts.
    pub fn without_skuid_rules(&self) -> RuleSet {
        let mut rs = self.clone();
        let chains = [
            &mut rs.filter.input,
            &mut rs.filter.output,
            &mut rs.filter.forward,
            &mut rs.mangle.prerouting,
            &mut rs.mangle.output,
        ];
        for chain in chains {
            chain.rules.retain(|rule| rule.matches.skuid.is_none());
        }
        rs
    }

    /// fw3 fallback without the `CONNMARK` target. The filter-side mark
    /// accepts stay: `-m mark` is a separate extension, inert while unset.
    pub fn without_mangle_rules(&self) -> RuleSet {
        let mut rs = self.clone();
        rs.mangle = MangleRules::default();
        rs
    }

    fn all_chains(&self) -> impl Iterator<Item = &Chain> {
        [
            &self.filter.input,
            &self.filter.output,
            &self.filter.forward,
            &self.mangle.prerouting,
            &self.mangle.output,
        ]
        .into_iter()
    }

    #[cfg(test)]
    pub fn output_terminates_in_block(&self) -> bool {
        matches!(
            self.filter.output.rules.last().map(|r| r.verdict),
            Some(Verdict::Reject) | Some(Verdict::Drop)
        )
    }

    #[cfg(test)]
    pub fn forward_terminates_in_block(&self) -> bool {
        matches!(
            self.filter.forward.rules.last().map(|r| r.verdict),
            Some(Verdict::Reject) | Some(Verdict::Drop)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_mangle_rules_strips_only_mangle() {
        let mut rs = RuleSet::default();
        rs.mangle.prerouting.push(Rule::restore_mark(Family::Inet));
        rs.mangle.output.push(Rule::restore_mark(Family::Inet));
        rs.filter.input.push(Rule::accept(Family::Inet).mark_eq(0x14e));

        let stripped = rs.without_mangle_rules();
        assert!(stripped.mangle.is_empty());
        assert_eq!(stripped.filter, rs.filter);
    }

    #[test]
    fn without_skuid_rules_removes_scoped_exceptions() {
        let mut rs = RuleSet::default();
        rs.filter.output.push(Rule::accept(Family::Inet).proto(Proto::Udp).dport(53).skuid(0));
        rs.filter.output.push(Rule::reject(Family::Inet));
        rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
        assert!(rs.has_skuid());

        let stripped = rs.without_skuid_rules();
        assert!(!stripped.has_skuid());
        assert_eq!(stripped.filter.output.rules.len(), 1);
        assert_eq!(stripped.filter.output.rules[0].verdict, Verdict::Reject);
        assert_eq!(stripped.filter.input, rs.filter.input);
    }
}
