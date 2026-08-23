// SPDX-License-Identifier: GPL-3.0-only

//! Backend-neutral firewall rule AST.
//!
//! A single representation that both the iptables-restore and nft renderers
//! emit from. Keeps policy logic in one place ([`super::policy`]) and the
//! two backends as thin syntactic translations.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

/// Address family a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4-only. iptables: emit only in the v4 file. nft: emit with `ip` qualifier.
    V4,
    /// IPv6-only. iptables: emit only in the v6 file. nft: emit with `ip6` qualifier.
    V6,
    /// Family-agnostic (e.g. loopback, ct state). iptables: emit in both files. nft:
    /// emit without an address-family qualifier.
    Inet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    /// Non-terminal: set the conntrack mark. Used by the inbound-exemption
    /// path in the mangle prerouting chain.
    SetCtMark(u32),
    /// Non-terminal: copy `ct mark` onto the packet mark so it can be used
    /// for `ip rule fwmark` routing decisions. Used in mangle prerouting
    /// (forwarded replies) and mangle output (router-originated replies).
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
    /// New connection. Used to gate `ct mark set` on the very first packet
    /// of an inbound-exempted flow, so subsequent packets don't redo the work.
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
    /// `iifname != "X"` / `! -i X` — used for CVE-2019-14899 protection.
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
    /// Match on packet (meta) mark. nft: `meta mark <N>`; iptables: `-m mark --mark <N>`.
    pub mark: Option<u32>,
    /// Match on the conntrack mark. nft: `ct mark <N>`; iptables:
    /// `-m connmark --mark <N>` (ships with the CONNMARK target in
    /// iptables-mod-conntrack-extra). Used to scope mark restores to
    /// exempted flows only — an unconditioned restore overwrites the
    /// daemon's own SO_MARK (0x14d) with the zero ct mark of its flows,
    /// knocking its packets off the VPN policy routes.
    pub ct_mark: Option<u32>,
    /// Match on the owning socket's uid. nft: `meta skuid <N>`; iptables:
    /// `-m owner --uid-owner <N>`. OUTPUT-chain only: input/forward packets
    /// have no local socket, so the match never fires there (nft) or is
    /// rejected outright by the kernel (iptables).
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
    /// Match on the owning socket's uid. Only valid on OUTPUT-chain rules —
    /// see [`Match::skuid`].
    pub fn skuid(mut self, uid: u32) -> Self {
        self.matches.skuid = Some(uid);
        self
    }
    /// Build a non-terminal `ct mark set <N>` rule (mangle prerouting).
    pub fn set_ct_mark(family: Family, mark: u32) -> Self {
        Self::new(family, Verdict::SetCtMark(mark))
    }
    /// Build a non-terminal `meta mark set ct mark` rule (mangle prerouting/output).
    pub fn restore_mark(family: Family) -> Self {
        Self::new(family, Verdict::RestoreMark)
    }
    /// An ICMP type match implies the ICMP protocol — set it here so no
    /// backend has to guess. nft doesn't need the proto (`icmp type` carries
    /// it), but iptables-restore rejects `--icmp-type` without `-p icmp` on
    /// the line, and a builder that constructs proto-less ICMP rules shipped
    /// that exact bug to every fw3 router from v1.27.0 to v1.33.1.
    pub fn icmpv4_type(mut self, t: IcmpV4Type) -> Self {
        self.matches.proto = Some(Proto::Icmp);
        self.matches.icmpv4_type = Some(t);
        self
    }
    /// See [`Self::icmpv4_type`]: implies `Proto::IcmpV6`.
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

/// Per-direction list of rules; renderers walk these in order.
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

/// Filter-table chains: kill-switch policy with terminal accept/reject/drop
/// verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterRules {
    pub input: Chain,
    pub output: Chain,
    pub forward: Chain,
}

/// Mangle-table chains: mark setting and conntrack-mark restoration. Renderers
/// emit nothing when both chains are empty, so existing all-filter policies
/// produce byte-identical output.
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

/// The full compiled policy: filter chains, mangle chains (for inbound
/// service exemption), and the list of tunnel interfaces that need
/// backend-specific NAT/forward integration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub filter: FilterRules,
    pub mangle: MangleRules,
    /// Tunnel interfaces that need masquerade (fw3 + fw4) and forward_lan
    /// integration (fw4). Empty in `Blocked` policies.
    pub tunnel_interfaces: Vec<String>,
}

impl RuleSet {
    /// True if any rule carries a socket-uid match.
    pub fn has_skuid(&self) -> bool {
        self.all_chains().any(|c| c.rules.iter().any(|r| r.matches.skuid.is_some()))
    }

    /// A copy with socket-uid-scoped exception rules removed. This is the
    /// secure fw3 fallback when `-m owner` is unavailable: daemon reconnect
    /// DNS may fail, but an unscoped DNS accept is never installed.
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

    /// A copy with the mangle chains emptied. This is the fw3 fallback when
    /// the iptables `CONNMARK` target is unavailable: every mangle rule we
    /// emit is a CONNMARK set/restore, and one unparseable rule fails the
    /// whole restore — taking the entire kill-switch (and the tunnel) down
    /// with it. Inbound exemptions stop working; nothing else degrades. The
    /// filter-side mark accepts stay: `-m mark` is a separate extension and
    /// they are inert while nothing sets the mark.
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

    /// True if every rule that lacks a verdict-bearing match (the catch-all
    /// final rules in OUTPUT and FORWARD) is `Reject` or `Drop`. Used by
    /// tests to verify the kill-switch invariant.
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
        // Filter-side mark accepts survive — `-m mark` is a separate
        // extension and inert while nothing sets the mark.
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
        // The scoped exception is removed, while unrelated rules are untouched.
        assert_eq!(stripped.filter.output.rules.len(), 1);
        assert_eq!(stripped.filter.output.rules[0].verdict, Verdict::Reject);
        assert_eq!(stripped.filter.input, rs.filter.input);
    }
}
