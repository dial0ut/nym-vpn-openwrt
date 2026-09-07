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
use crate::net::{
    AllowedClients, AllowedEndpoint, InboundExemption, TransportProtocol, TunnelMetadata,
};

// LAN networks (RFC1918 private + IPv6 link-local + ULA) and multicast:
// defined once in boot_rules, which the boot-time block and the shell
// includes derive from as well.
use super::boot_rules::{LAN_NETS_V4, LAN_NETS_V6, MULTICAST_V4, MULTICAST_V6};

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
/// escape hatch is useless on its own because the daemon has to resolve the
/// NTP pool hostnames (`*.pool.ntp.org`) before it can reach a server, and
/// `block_dns` would otherwise reject that lookup. The daemon owns that
/// cold-boot resolution (plain UDP/53 as root — see `clock_bootstrap` in
/// nym-vpn-lib), so the hatch is always root-scoped. Sized for a cold-boot
/// resolution round (a handful of pool hostnames, A+AAAA, with retries) and
/// rate-capped so it can't degrade into a general DNS leak or exfil channel.
const DNS_RATE_PER_MIN: u32 = 30;
const DNS_BURST: u32 = 20;

/// Rate limit for the gateway probe hatch. `nym-vpnc gateway test` probes at
/// most 8 gateways at a time, 5 packets/s each (see `gateway_probe` in
/// nym-vpn-lib), so a well-behaved daemon stays under 2400/minute; the cap
/// only bites if something loops.
const PROBE_RATE_PER_MIN: u32 = 3000;
const PROBE_BURST: u32 = 100;

/// Explicitly describes which principals may use a DNS exception. Keeping this
/// at the policy boundary prevents a destination-only accept from accidentally
/// becoming a LAN relay bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsAccess {
    /// The daemon/bootstrap process only.
    Daemon,
    /// Router and forwarded LAN clients.
    RouterAndLan,
}

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
            // Daemon-only, like Blocked: the daemon resolves in-process as
            // root, and mid-connect is precisely when dnsmasq must not relay
            // LAN queries out the WAN.
            for dns in dns_config.non_tunnel_config() {
                allow_dns_server_daemon_only(&mut rs, *dns);
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
            // hatch depends on isn't rejected. Root-scoped: the cold-boot
            // pool lookup is daemon-owned (plain UDP/53 as root, see
            // `clock_bootstrap` in nym-vpn-lib) — it no longer rides
            // sysntpd -> dnsmasq, so nothing outside the daemon is entitled
            // to DNS while the kill switch is enforcing.
            dns_escape_hatch(&mut rs);
            block_dns(&mut rs);
            // A clockless router that boots straight into a connect attempt
            // needs NTP to reach a server before TLS to the API/gateway can
            // validate, otherwise it deadlocks in DeviceTimeDesynced. The
            // daemon's SNTP bootstrap goes out through this hatch; it's the
            // same rate-limited hatch as the Blocked state.
            ntp_escape_hatch(&mut rs);
            probe_escape_hatch(&mut rs);
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
            // Gateway probes must reach the gateways directly, not through
            // the tunnel, so they need a WAN-side accept here too.
            probe_escape_hatch(&mut rs);
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
            // Daemon-only (root-scoped): these are the daemon's own resolvers,
            // which it queries in-process (hickory, DoT/DoH) as uid 0. No
            // forward accept, and the output accepts are uid-scoped, because
            // "router-originated" is not the same as "daemon-originated":
            // dnsmasq relays LAN clients' queries as its own OUTPUT packets,
            // which leaked every LAN lookup to these public resolvers while
            // the kill switch claimed to block DNS (packet-capture confirmed).
            // dnsmasq runs as user `dnsmasq`, so uid-0 scoping fails it closed
            // while the daemon's reconnect bootstrap still passes.
            for dns in dns_servers {
                allow_dns_server_daemon_only(&mut rs, *dns);
            }
            // Must precede block_dns: an excluded client with hardcoded DNS
            // (Chromecasts, consoles) forwards port 53, and the reject is
            // terminal. Carve-outs are meant to survive exactly this state.
            bypass_mark_forward_accept(&mut rs);
            // DNS hatch must precede block_dns so the NTP-pool lookup the NTP
            // hatch depends on isn't rejected. Root-scoped like everywhere
            // else: dnsmasq (uid `dnsmasq`) gets no escape hatch — an
            // unscoped one re-opens the LAN relay leak.
            dns_escape_hatch(&mut rs);
            block_dns(&mut rs);
            ntp_escape_hatch(&mut rs);
            probe_escape_hatch(&mut rs);
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
    rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
    rs.filter.output.push(Rule::accept(Family::Inet).oif("lo"));

    // Established/related on INPUT only — this is return traffic *to* the
    // router, not egress, so it is not a kill-switch bypass. Output/forward
    // established accepts are scoped to the tunnel interface in allow_tunnel;
    // a blanket accept there let WAN-bound established flows (notably IPv6
    // during reconnects) leak past the kill-switch.
    rs.filter.input.push(Rule::accept(Family::Inet).ct_established());

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
                        .icmpv4_type(IcmpV4Type::EchoReply)
                        .saddr(ip),
                );
                rs.filter.output.push(
                    Rule::accept(Family::V4)
                        .icmpv4_type(IcmpV4Type::EchoRequest)
                        .daddr(ip),
                );
            }
            IpAddr::V6(_) => {
                rs.filter.input.push(
                    Rule::accept(Family::V6)
                        .icmpv6_type(IcmpV6Type::EchoReply)
                        .saddr(ip),
                );
                rs.filter.output.push(
                    Rule::accept(Family::V6)
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
    exemption_mangle_rules(rs, exemptions, &wan_iface);
}

fn exemption_mangle_rules(rs: &mut RuleSet, exemptions: &[InboundExemption], wan_iface: &str) {
    // Every restore is scoped to `ct mark == EXEMPT_FWMARK`: only exempted
    // flows may have their packet mark rewritten. An unconditioned
    // `meta mark set ct mark` runs on EVERY packet, and for the daemon's own
    // flows (ct mark 0) it OVERWRITES the socket's tunnel fwmark (0x14d)
    // with zero — the mangle-stage reroute then pulls the daemon's probes
    // and handshakes off the VPN policy routes and connecting fails
    // (HW-reproduced on fw3: every connect attempt died on its ICMP probe).
    // It also stops us stomping marks other systems (mwan3, qos) set.
    let restore = || Rule::restore_mark(Family::Inet).ct_mark_eq(common::EXEMPT_FWMARK);

    // Restore comes first so replies on established flows pick up the mark.
    rs.mangle.prerouting.push(restore());
    // Set the connmark on the first packet of each exempted inbound flow.
    for ex in exemptions {
        let proto = match ex.proto {
            TransportProtocol::Tcp => Proto::Tcp,
            TransportProtocol::Udp => Proto::Udp,
        };
        rs.mangle.prerouting.push(
            Rule::set_ct_mark(Family::Inet, common::EXEMPT_FWMARK)
                .iif(wan_iface)
                .proto(proto)
                .dport(ex.dport)
                .ct_new(),
        );
    }
    // Restore again AFTER the set rules: `ct mark set` writes only the
    // conntrack mark, so the flow-creating packet itself still carries meta
    // mark 0 — and the filter accepts match the meta mark. Without this the
    // first packet of every exempted flow falls through to the terminal
    // reject, which also prevents conntrack confirmation, destroying the
    // freshly-marked entry: retransmissions repeat identically and the flow
    // never establishes.
    rs.mangle.prerouting.push(restore());
    // Restore for locally-originated replies (router-hosted services).
    rs.mangle.output.push(restore());
}

fn allow_endpoint(rs: &mut RuleSet, ep: &AllowedEndpoint) {
    let ip = ep.endpoint.address.ip();
    let port = ep.endpoint.address.port();
    let proto = match ep.endpoint.protocol {
        TransportProtocol::Tcp => Proto::Tcp,
        TransportProtocol::Udp => Proto::Udp,
    };
    let family = family_of(&ip);
    let mut out = Rule::accept(family)
        .proto(proto)
        .daddr(ip)
        .dport(port);
    // Honor the `AllowedClients` contract: `Root`-marked endpoints (API,
    // gateway control while blocked/connecting) are the daemon's own — scope
    // the output accept to uid 0 like the daemon-only DNS exceptions, so no
    // other router-local process can use the hole. Input stays unscoped:
    // inbound packets carry no local socket owner, and without the scoped
    // output rule no reply traffic exists anyway.
    if ep.clients == AllowedClients::Root {
        out = out.skuid(crate::ROOT_UID);
    }
    rs.filter.output.push(out);
    rs.filter.input.push(
        Rule::accept(family)
            .proto(proto)
            .saddr(ip)
            .sport(port),
    );
}

/// Allow the **daemon's own** lookups to a server. For the `Blocked` and
/// `Connecting` states, where the servers are the daemon's in-process
/// (hickory DoT/DoH) resolvers and only the daemon — uid 0 — needs to
/// resolve. A plain "router-only" (unscoped output) accept is NOT enough:
/// dnsmasq re-originates LAN clients' queries as router OUTPUT packets,
/// which turned these accepts into a LAN-wide plaintext DNS leak while
/// disconnected.
fn allow_dns_server_daemon_only(rs: &mut RuleSet, dns: IpAddr) {
    allow_dns_server_inner(rs, dns, None, DnsAccess::Daemon);
}

/// Allow DNS to a specific server. If `iface` is set, restrict to that
/// interface (used for tunnel-configured resolvers). LAN clients are permitted
/// to reach it too when not iface-restricted.
fn allow_dns_server(rs: &mut RuleSet, dns: IpAddr, iface: Option<&str>) {
    allow_dns_server_inner(rs, dns, iface, DnsAccess::RouterAndLan);
}

fn allow_dns_server_inner(
    rs: &mut RuleSet,
    dns: IpAddr,
    iface: Option<&str>,
    clients: DnsAccess,
) {
    let family = family_of(&dns);
    let output_skuid = match clients {
        DnsAccess::Daemon => Some(crate::ROOT_UID),
        DnsAccess::RouterAndLan => None,
    };
    let allow_forward = matches!(clients, DnsAccess::RouterAndLan);

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
        // Input stays unscoped: inbound packets have no local socket owner,
        // and without the scoped output rule no reply traffic exists anyway.
        let mut inp = Rule::accept(family)
            .proto(proto)
            .saddr(dns)
            .sport(port);
        if let Some(iface) = iface {
            out = out.oif(iface);
            inp = inp.iif(iface);
        }
        if let Some(uid) = output_skuid {
            out = out.skuid(uid);
        }
        rs.filter.output.push(out);
        rs.filter.input.push(inp);
    }

    // Forward DNS for LAN clients (only when not iface-restricted).
    if allow_forward && iface.is_none() {
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
    // LAN -> tunnel (new + established). The exit never initiates into the LAN,
    // so the return direction is scoped to established/related entering FROM
    // the tunnel. This replaces the old blanket forward established accept,
    // which also matched WAN egress and leaked on tunnel teardown.
    rs.filter.forward.push(Rule::accept(Family::Inet).oif(iface));
    rs.filter.forward.push(Rule::accept(Family::Inet).iif(iface).ct_established());
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

/// Rate-limited DNS escape hatch: the daemon needs to resolve the NTP pool
/// hostnames (and the API/gateway) before the tunnel is up. Without this,
/// `block_dns` rejects that lookup and the NTP hatch never resolves a server
/// — the cold-boot `DeviceTimeDesynced` deadlock the kill switch is
/// otherwise blamed for.
///
/// Always root-scoped. OUTPUT-only is NOT a LAN fence on its own: dnsmasq
/// re-originates LAN clients' queries as router OUTPUT packets, so an
/// unscoped hatch trickles LAN hostnames out the WAN. The cold-boot pool
/// lookup no longer needs an unscoped hole either — the daemon resolves the
/// pool itself over plain UDP/53 as root (`clock_bootstrap` in nym-vpn-lib)
/// instead of riding sysntpd -> dnsmasq -> upstream.
fn dns_escape_hatch(rs: &mut RuleSet) {
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.filter.output.push(
            Rule::accept(Family::Inet)
                .proto(proto)
                .dport(DNS_PORT)
                .rate_limit(DNS_RATE_PER_MIN, DNS_BURST)
                .skuid(crate::ROOT_UID),
        );
    }
}

/// ICMP echo hatch for the daemon's gateway latency probes (`nym-vpnc gateway
/// test`). The probes have to leave via the real WAN whether or not a tunnel
/// is up, so the daemon puts the tunnel fwmark on the probe socket — the same
/// mark the WireGuard transport carries — and the routing layer sends marked
/// packets to the main table. This accepts those marked echo requests; the
/// replies come back through the established/related INPUT accept.
///
/// Keyed on the mark, not uid 0: on OpenWrt nearly every process is root, so
/// a uid-scoped ICMP accept would let any router-local `ping` (mwan3,
/// watchdog scripts, an admin shell) out past the kill switch, whereas only a
/// CAP_NET_ADMIN process that deliberately sets `0x14d` ever carries the
/// mark. Echo-request only and rate-limited, so it cannot turn into a general
/// egress path.
fn probe_escape_hatch(rs: &mut RuleSet) {
    rs.filter.output.push(
        Rule::accept(Family::V4)
            .icmpv4_type(IcmpV4Type::EchoRequest)
            .mark_eq(crate::TUNNEL_FWMARK)
            .rate_limit(PROBE_RATE_PER_MIN, PROBE_BURST),
    );
    rs.filter.output.push(
        Rule::accept(Family::V6)
            .icmpv6_type(IcmpV6Type::EchoRequest)
            .mark_eq(crate::TUNNEL_FWMARK)
            .rate_limit(PROBE_RATE_PER_MIN, PROBE_BURST),
    );
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
    fn root_endpoints_are_uid_scoped_in_output() {
        // `AllowedClients::Root` is a contract: only the daemon (uid 0) may
        // use the hole. The output accept must carry the uid scope, exactly
        // like the daemon-only DNS exceptions.
        let policy = FirewallPolicy::Blocked {
            allow_lan: false,
            allowed_endpoints: vec![ep([1, 2, 3, 4], 443)], // ep() marks Root
            dns_servers: vec![],
        };
        let rs = compile(&policy);
        let out = rs
            .filter
            .output
            .rules
            .iter()
            .find(|r| r.matches.dport == Some(443) && r.matches.daddr.is_some())
            .expect("endpoint accept present");
        assert_eq!(out.matches.skuid, Some(0), "Root endpoint must be uid-scoped");

        // `All`-marked endpoints (Connected peer endpoints) stay unscoped.
        let all_ep = AllowedEndpoint::new(
            Endpoint::from_socket_address(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 51820),
                TransportProtocol::Udp,
            ),
            AllowedClients::All,
        );
        let policy = FirewallPolicy::Connected {
            peer_endpoints: vec![all_ep],
            tunnel: tunnel_iface("wg0", [10, 64, 0, 2]),
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let out = rs
            .filter
            .output
            .rules
            .iter()
            .find(|r| r.matches.dport == Some(51820))
            .expect("peer endpoint accept present");
        assert_eq!(out.matches.skuid, None, "All endpoint must stay unscoped");
    }

    #[test]
    fn exemption_mangle_restores_meta_mark_after_set() {
        // `ct mark set` writes only the conntrack mark; the filter accepts
        // match the packet (meta) mark. A restore AFTER the set rules is what
        // marks the flow-creating packet itself — without it the first packet
        // is rejected, conntrack never confirms the entry, and the exempted
        // flow can never establish.
        let mut rs = RuleSet::default();
        let exemptions = vec![
            InboundExemption::new(TransportProtocol::Tcp, 443),
            InboundExemption::new(TransportProtocol::Udp, 51820),
        ];
        exemption_mangle_rules(&mut rs, &exemptions, "eth1");

        let pre = &rs.mangle.prerouting.rules;
        let first_set = pre
            .iter()
            .position(|r| matches!(r.verdict, Verdict::SetCtMark(_)))
            .expect("set rules present");
        let last_set = pre
            .iter()
            .rposition(|r| matches!(r.verdict, Verdict::SetCtMark(_)))
            .expect("set rules present");
        let first_restore = pre
            .iter()
            .position(|r| matches!(r.verdict, Verdict::RestoreMark))
            .expect("restore present");
        let last_restore = pre
            .iter()
            .rposition(|r| matches!(r.verdict, Verdict::RestoreMark))
            .expect("restore present");
        // One restore before the sets (replies on established flows) ...
        assert!(first_restore < first_set);
        // ... and one after (the first packet of a fresh exempted flow).
        assert!(last_restore > last_set);
        // Router-hosted replies still get their output-chain restore.
        assert!(
            rs.mangle
                .output
                .rules
                .iter()
                .any(|r| matches!(r.verdict, Verdict::RestoreMark))
        );
        // Every restore must be scoped to the exempt ct mark: an
        // unconditioned restore zeroes the daemon's socket fwmark (0x14d)
        // on its own flows and reroutes its probes off the VPN policy
        // routes — connect attempts then fail on their ICMP probe.
        for chain in [&rs.mangle.prerouting, &rs.mangle.output] {
            for rule in chain
                .rules
                .iter()
                .filter(|r| matches!(r.verdict, Verdict::RestoreMark))
            {
                assert_eq!(
                    rule.matches.ct_mark,
                    Some(common::EXEMPT_FWMARK),
                    "unscoped mark restore: {rule:?}"
                );
            }
        }
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
        // The probe hatch matches the tunnel fwmark in every state; only the
        // exemption mark must be absent here.
        let has_mark_accept = rs
            .filter
            .output
            .rules
            .iter()
            .any(|r| r.matches.mark == Some(common::EXEMPT_FWMARK));
        assert!(!has_mark_accept, "no exemption mark accepts expected without exemptions");
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
            // Preceding the *final* reject is not enough: block_dns pushes its
            // own terminal port-53 rejects into FORWARD, and an excluded client
            // with hardcoded DNS is forwarded traffic. If those land first the
            // carve-out silently loses DNS in that state — which is exactly what
            // used to happen in Blocked.
            if let Some(dns_reject) = rs.filter.forward.rules.iter().position(|r| {
                r.verdict == Verdict::Reject && r.matches.dport == Some(DNS_PORT)
            }) {
                assert!(
                    pos.unwrap() < dns_reject,
                    "{name}: bypass-mark accept must precede the port-53 reject, \
                     else excluded clients with hardcoded DNS lose resolution"
                );
            }
        }
    }

    /// In Blocked the DNS accepts exist so the *daemon* can resolve enough to
    /// reconnect, and that only needs output/input. A forward accept would let a
    /// LAN client with hardcoded DNS query those public resolvers out the WAN
    /// while every other destination is blocked — leaking what it is looking up
    /// in exchange for addresses it cannot reach.
    #[test]
    fn blocked_dns_accepts_are_not_forwarded() {
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        };
        let rs = compile(&policy);

        assert!(
            rs.filter
                .output
                .rules
                .iter()
                .any(|r| r.verdict == Verdict::Accept && r.matches.dport == Some(DNS_PORT)),
            "the daemon's own lookups must still be allowed in OUTPUT"
        );
        assert!(
            !rs.filter
                .forward
                .rules
                .iter()
                .any(|r| r.verdict == Verdict::Accept && r.matches.dport == Some(DNS_PORT)),
            "LAN clients must not be forwarded to the daemon's resolvers while blocked"
        );
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

    /// The dnsmasq-relay leak: dnsmasq re-originates LAN clients' queries as
    /// router OUTPUT packets, so "router-only" DNS accepts are LAN-reachable
    /// unless uid-scoped. Every Blocked OUTPUT accept that dnsmasq could use —
    /// any-destination port 53 (the escape hatch) or any port to a resolver
    /// address (53/853/443) — must be scoped to root, the daemon. Accepts to
    /// non-resolver allowed endpoints are out of scope even on port 443:
    /// dnsmasq speaks neither DoT nor DoH, and the endpoint list is
    /// daemon-controlled, not client-influenced. Input accepts must stay
    /// unscoped (inbound packets have no socket owner).
    #[test]
    fn blocked_dns_exceptions_are_root_scoped() {
        let resolvers: Vec<IpAddr> =
            vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()];
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            // An API endpoint on 443 must NOT trip the resolver-scoping sweep.
            allowed_endpoints: vec![ep([1, 2, 3, 4], 443)],
            dns_servers: resolvers.clone(),
        };
        let rs = compile(&policy);

        let is_resolver_daddr = |r: &Rule| {
            matches!(&r.matches.daddr, Some(AddrMatch::Ip(ip)) if resolvers.contains(ip))
        };
        let scoped: Vec<_> = rs
            .filter
            .output
            .rules
            .iter()
            .filter(|r| {
                r.verdict == Verdict::Accept
                    && (is_resolver_daddr(r)
                        || (r.matches.dport == Some(DNS_PORT) && r.matches.daddr.is_none()))
            })
            .collect();
        // 2 resolvers x 4 proto/port pairs + 2 escape-hatch rules.
        assert_eq!(scoped.len(), 10, "unexpected resolver-accept count: {scoped:#?}");
        for r in &scoped {
            assert_eq!(
                r.matches.skuid,
                Some(crate::ROOT_UID),
                "unscoped DNS-capable OUTPUT accept in Blocked (dnsmasq relay leak): {r:?}"
            );
        }

        // The 443 endpoint accept exists and is not swept up in the scoping.
        assert!(
            rs.filter.output.rules.iter().any(|r| {
                r.verdict == Verdict::Accept
                    && r.matches.dport == Some(443)
                    && matches!(&r.matches.daddr, Some(AddrMatch::Ip(IpAddr::V4(ip))) if ip.octets() == [1, 2, 3, 4])
            }),
            "allowed endpoint on 443 missing from Blocked OUTPUT"
        );

        for r in &rs.filter.input.rules {
            assert_eq!(r.matches.skuid, None, "input rules must not carry skuid: {r:?}");
        }
    }

    /// The Connecting DNS hatch is root-scoped like Blocked's. The cold-boot
    /// NTP-pool lookup that used to justify an unscoped hatch is daemon-owned
    /// now (plain UDP/53 as root, `clock_bootstrap` in nym-vpn-lib), so a
    /// reappearing unscoped hatch would be a plain LAN relay leak on every
    /// reconnect — the exact hole this scoping closed.
    #[test]
    fn connecting_dns_hatch_is_root_scoped() {
        let policy = FirewallPolicy::Connecting {
            peer_endpoints: vec![],
            tunnel: None,
            allow_lan: false,
            dns_config: dns_config(&[], &[]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
            inbound_exemptions: vec![],
        };
        let rs = compile(&policy);
        let hatch: Vec<_> = rs
            .filter
            .output
            .rules
            .iter()
            .filter(|r| {
                r.verdict == Verdict::Accept
                    && r.matches.dport == Some(DNS_PORT)
                    && r.matches.rate_limit.is_some()
            })
            .collect();
        assert!(!hatch.is_empty(), "Connecting is missing the DNS escape hatch");
        for r in hatch {
            assert_eq!(
                r.matches.skuid,
                Some(crate::ROOT_UID),
                "Connecting DNS hatch must be root-scoped: {r:?}"
            );
        }
    }

    /// The kill-switch DNS invariant: while the tunnel is not up (Blocked,
    /// Connecting), every DNS-capable OUTPUT accept — any accept on port 53
    /// or 853 — is scoped to the daemon (root), and FORWARD carries no
    /// port-53 accepts at all. The split-tunnel carve-out matches on the
    /// bypass mark, not on a port, so it doesn't appear here. Connected is
    /// exempt: with the tunnel up, LAN DNS follows the tunnel policy.
    #[test]
    fn no_unscoped_dns_output_while_tunnel_down() {
        for (name, policy) in killswitch_states_without_exemptions() {
            if name == "connected" {
                continue;
            }
            let rs = compile(&policy);
            for r in &rs.filter.output.rules {
                if r.verdict == Verdict::Accept
                    && matches!(r.matches.dport, Some(DNS_PORT) | Some(DOT_PORT))
                {
                    assert_eq!(
                        r.matches.skuid,
                        Some(crate::ROOT_UID),
                        "{name}: unscoped DNS-capable OUTPUT accept: {r:?}"
                    );
                }
            }
            for r in &rs.filter.forward.rules {
                assert!(
                    !(r.verdict == Verdict::Accept && r.matches.dport == Some(DNS_PORT)),
                    "{name}: FORWARD accept on port 53: {r:?}"
                );
            }
        }
    }

    /// The gateway probe hatch (`nym-vpnc gateway test`) must exist in every
    /// kill-switch state, be keyed on the daemon's tunnel fwmark rather than
    /// uid 0, admit echo requests only, be rate limited, and precede the
    /// terminal reject.
    #[test]
    fn probe_hatch_in_every_state_is_mark_scoped_echo_request_only() {
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            let rules = &rs.filter.output.rules;
            let hatch: Vec<_> = rules
                .iter()
                .filter(|r| r.matches.mark == Some(crate::TUNNEL_FWMARK))
                .collect();
            assert_eq!(hatch.len(), 2, "{name}: expected a v4 and a v6 probe hatch");
            for r in &hatch {
                assert_eq!(r.verdict, Verdict::Accept, "{name}: {r:?}");
                assert!(
                    r.matches.rate_limit.is_some(),
                    "{name}: hatch must be rate limited: {r:?}"
                );
                assert_eq!(
                    r.matches.skuid, None,
                    "{name}: hatch is mark-scoped, not uid-scoped: {r:?}"
                );
                let echo_request = match r.family {
                    Family::V4 => r.matches.icmpv4_type == Some(IcmpV4Type::EchoRequest),
                    Family::V6 => r.matches.icmpv6_type == Some(IcmpV6Type::EchoRequest),
                    Family::Inet => false,
                };
                assert!(
                    echo_request,
                    "{name}: hatch must match echo-request only: {r:?}"
                );
            }
            let last_hatch = rules
                .iter()
                .rposition(|r| r.matches.mark == Some(crate::TUNNEL_FWMARK))
                .expect("hatch present");
            let final_reject = rules
                .iter()
                .position(|r| r.verdict == Verdict::Reject && r.matches == Match::default())
                .expect("final reject present");
            assert!(
                last_hatch < final_reject,
                "{name}: probe hatch must precede the final reject"
            );
        }
    }

    /// No kill-switch state may accept an unscoped echo request in OUTPUT:
    /// every echo-request accept is either the mark-scoped probe hatch or an
    /// mwan3 tracking rule pinned to a destination.
    #[test]
    fn no_unscoped_icmp_echo_output_accept() {
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            for r in &rs.filter.output.rules {
                let is_echo_request = r.matches.icmpv4_type == Some(IcmpV4Type::EchoRequest)
                    || r.matches.icmpv6_type == Some(IcmpV6Type::EchoRequest);
                if r.verdict == Verdict::Accept && is_echo_request {
                    assert!(
                        r.matches.mark.is_some() || r.matches.daddr.is_some(),
                        "{name}: unscoped echo-request accept: {r:?}"
                    );
                }
            }
        }
    }

    /// skuid is only meaningful on OUTPUT (and would fail the iptables restore
    /// on any other chain). Sweep every state: no input/forward/mangle rule
    /// may carry it, and Connected must not carry it anywhere.
    #[test]
    fn skuid_only_ever_in_output_chain() {
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            for (chain_name, chain) in [
                ("input", &rs.filter.input),
                ("forward", &rs.filter.forward),
                ("mangle_prerouting", &rs.mangle.prerouting),
                ("mangle_output", &rs.mangle.output),
            ] {
                for r in &chain.rules {
                    assert_eq!(
                        r.matches.skuid, None,
                        "{name}: skuid match in {chain_name} chain: {r:?}"
                    );
                }
            }
            if name == "connected" {
                for r in &rs.filter.output.rules {
                    assert_eq!(r.matches.skuid, None, "Connected must have no skuid rules: {r:?}");
                }
            }
        }
    }
}
