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
    pub fn icmpv4_type(mut self, t: IcmpV4Type) -> Self {
        self.matches.icmpv4_type = Some(t);
        self
    }
    pub fn icmpv6_type(mut self, t: IcmpV6Type) -> Self {
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
}

/// The full compiled policy: three filter chains plus the list of tunnel
/// interfaces that need backend-specific NAT/forward integration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub input: Chain,
    pub output: Chain,
    pub forward: Chain,
    /// Tunnel interfaces that need masquerade (fw3 + fw4) and forward_lan
    /// integration (fw4). Empty in `Blocked` policies.
    pub tunnel_interfaces: Vec<String>,
}

impl RuleSet {
    /// True if every rule that lacks a verdict-bearing match (the catch-all
    /// final rules in OUTPUT and FORWARD) is `Reject` or `Drop`. Used by
    /// tests to verify the kill-switch invariant.
    #[cfg(test)]
    pub fn output_terminates_in_block(&self) -> bool {
        matches!(
            self.output.rules.last().map(|r| r.verdict),
            Some(Verdict::Reject) | Some(Verdict::Drop)
        )
    }

    #[cfg(test)]
    pub fn forward_terminates_in_block(&self) -> bool {
        matches!(
            self.forward.rules.last().map(|r| r.verdict),
            Some(Verdict::Reject) | Some(Verdict::Drop)
        )
    }
}
