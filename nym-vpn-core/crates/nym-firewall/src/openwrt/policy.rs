// SPDX-License-Identifier: GPL-3.0-only

//! Compile a [`FirewallPolicy`] into a backend-neutral [`RuleSet`]; the
//! backends consume it verbatim.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::common;
use super::rules::*;
use crate::FirewallPolicy;
use crate::net::{
    AllowedClients, AllowedEndpoint, InboundExemption, TransportProtocol, TunnelMetadata,
};

use super::boot_rules::{LAN_NETS_V4, LAN_NETS_V6, MULTICAST_V4, MULTICAST_V6};

const DHCPV4_CLIENT_PORT: u16 = 68;
const DHCPV4_SERVER_PORT: u16 = 67;
const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const DOH_PORT: u16 = 443;
const NTP_PORT: u16 = 123;

/// Sized for sysntpd's parallel startup round; caps exfil at ~500 B/min.
const NTP_RATE_PER_MIN: u32 = 12;
const NTP_BURST: u32 = 8;

/// Sized for one cold-boot NTP-pool resolution round (A+AAAA with retries).
const DNS_RATE_PER_MIN: u32 = 30;
const DNS_BURST: u32 = 20;

/// `gateway test` probes at most 8 gateways at 5 packets/s each (<2400/min);
/// the cap only bites if something loops.
const PROBE_RATE_PER_MIN: u32 = 3000;
const PROBE_BURST: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsAccess {
    /// uid 0 only.
    Daemon,
    /// Router and forwarded LAN clients.
    RouterAndLan,
}

/// What the private-DNS accepts and the exemption mangle rules need to know
/// about the uplink. Tests inject it; [`compile`] probes the system.
pub(crate) struct Uplink<'a> {
    /// L3 devices of every WAN zone ([`common::wan_zone_devices`]). Empty
    /// means unknown, and everything keyed on it fails closed.
    pub wan_devices: &'a [String],
    /// Device an address is routed out on ([`common::route_device`]).
    pub route_device: Box<dyn Fn(IpAddr) -> Option<String> + 'a>,
}

/// The WAN zone is probed only when a private custom DNS server or an
/// inbound exemption needs it.
pub fn compile(policy: &FirewallPolicy) -> RuleSet {
    let wan_devices = if policy_has_private_dns(policy) || policy_has_exemptions(policy) {
        common::wan_zone_devices()
    } else {
        Vec::new()
    };
    compile_with(
        policy,
        &Uplink {
            wan_devices: &wan_devices,
            route_device: Box::new(common::route_device),
        },
    )
}

/// Loopback excluded: a resolver on the router is reached over `lo`, which
/// the base rules accept anyway.
fn is_private_dns(ip: &IpAddr) -> bool {
    nym_firewall_config::is_local_address(ip) && !ip.is_loopback()
}

fn policy_has_private_dns(policy: &FirewallPolicy) -> bool {
    match policy {
        FirewallPolicy::Connecting { dns_config, .. }
        | FirewallPolicy::Connected { dns_config, .. } => {
            dns_config.non_tunnel_config().iter().any(is_private_dns)
        }
        FirewallPolicy::Blocked { dns_servers, .. } => dns_servers.iter().any(is_private_dns),
    }
}

fn policy_has_exemptions(policy: &FirewallPolicy) -> bool {
    match policy {
        FirewallPolicy::Connecting {
            inbound_exemptions, ..
        }
        | FirewallPolicy::Connected {
            inbound_exemptions, ..
        } => !inbound_exemptions.is_empty(),
        FirewallPolicy::Blocked { .. } => false,
    }
}

/// A private custom DNS server whose device cannot be pinned falls back to
/// the tunnel-only or daemon-only treatment of its state.
pub(crate) fn compile_with(policy: &FirewallPolicy, uplink: &Uplink<'_>) -> RuleSet {
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
            let tunnel_ifaces: Vec<&str> = tunnel
                .iter()
                .flat_map(|t| t.inner_metadatas())
                .map(|m| m.interface.as_str())
                .collect();
            for dns in dns_config.non_tunnel_config() {
                if !allow_private_dns_server(&mut rs, *dns, uplink, &tunnel_ifaces) {
                    allow_dns_server_daemon_only(&mut rs, *dns);
                }
            }
            // Tunnel accepts before block_dns, or tunnel-routed DNS is rejected.
            if let Some(tunnel) = tunnel {
                for m in tunnel.inner_metadatas() {
                    allow_tunnel(&mut rs, &m.interface);
                    rs.tunnel_interfaces.push(m.interface.clone());
                }
            }
            exemption_filter_accepts(&mut rs, inbound_exemptions);
            bypass_mark_forward_accept(&mut rs);
            // Hatch before block_dns: the NTP-pool lookup must not be rejected.
            dns_escape_hatch(&mut rs);
            block_dns(&mut rs);
            ntp_escape_hatch(&mut rs);
            probe_escape_hatch(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
            exemption_mangle(&mut rs, inbound_exemptions, uplink.wan_devices);
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
            for dns in dns_config.tunnel_config() {
                for m in tunnel.inner_metadatas() {
                    allow_dns_server(&mut rs, *dns, Some(&m.interface));
                }
            }
            // A private resolver whose device cannot be pinned is tunnel-only
            // (fail closed); public non-tunnel resolvers keep their
            // any-interface accept.
            let tunnel_ifaces: Vec<&str> = tunnel
                .inner_metadatas()
                .into_iter()
                .map(|m| m.interface.as_str())
                .collect();
            for dns in dns_config.non_tunnel_config() {
                if allow_private_dns_server(&mut rs, *dns, uplink, &tunnel_ifaces) {
                    continue;
                }
                if is_private_dns(dns) {
                    for m in tunnel.inner_metadatas() {
                        allow_dns_server(&mut rs, *dns, Some(&m.interface));
                    }
                } else {
                    allow_dns_server(&mut rs, *dns, None);
                }
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
            // Gateway probes go out the WAN even while connected.
            probe_escape_hatch(&mut rs);
            if *allow_lan {
                allow_lan_traffic(&mut rs);
            }
            exemption_mangle(&mut rs, inbound_exemptions, uplink.wan_devices);
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
                if !allow_private_dns_server(&mut rs, *dns, uplink, &[]) {
                    allow_dns_server_daemon_only(&mut rs, *dns);
                }
            }
            // Before block_dns: an excluded client with hardcoded DNS forwards
            // port 53, and the reject is terminal.
            bypass_mark_forward_accept(&mut rs);
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

fn base_rules(rs: &mut RuleSet) {
    rs.filter.input.push(Rule::accept(Family::Inet).iif("lo"));
    rs.filter.output.push(Rule::accept(Family::Inet).oif("lo"));

    // INPUT only: a blanket output/forward established accept let WAN-bound
    // flows (notably IPv6 on reconnect) leak past the kill-switch.
    rs.filter.input.push(Rule::accept(Family::Inet).ct_established());

    // DHCPv4, router as client and as server.
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

    // DHCPv6, both roles.
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

/// Slotted after the tunnel allows and before `block_dns` (a DNAT'd inbound
/// DNS service on an exempt port must not be rejected). Port matching already
/// happened in mangle prerouting, so the mark alone suffices.
fn exemption_filter_accepts(rs: &mut RuleSet, exemptions: &[InboundExemption]) {
    if exemptions.is_empty() {
        return;
    }
    rs.filter.input.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
    rs.filter.output.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
}

/// Unconditional in every kill-switch state, mirroring the pri-90 `ip rule`
/// for `0x14e`: split-tunnel carve-outs egress the WAN with the kill-switch
/// on. Safe because a LAN client cannot set a netfilter mark on its packets.
fn bypass_mark_forward_accept(rs: &mut RuleSet) {
    rs.filter.forward.push(Rule::accept(Family::Inet).mark_eq(common::EXEMPT_FWMARK));
}

fn exemption_mangle(rs: &mut RuleSet, exemptions: &[InboundExemption], wan_devices: &[String]) {
    if exemptions.is_empty() {
        return;
    }
    if wan_devices.is_empty() {
        tracing::warn!(
            "Inbound exemptions configured but no WAN zone device could be determined. \
             Exemption mangle rules will not be emitted; reply traffic will leak into the tunnel."
        );
        return;
    }
    exemption_mangle_rules(rs, exemptions, wan_devices);
}

/// One set rule per (WAN device, exemption): a flow arriving on any uplink,
/// mwan3's `wanb` included, gets its replies pinned to that uplink.
fn exemption_mangle_rules(
    rs: &mut RuleSet,
    exemptions: &[InboundExemption],
    wan_devices: &[String],
) {
    // Scoped to the exempt ct mark: an unconditioned `meta mark set ct mark`
    // overwrites the daemon's socket fwmark (0x14d) with zero on its own
    // flows and reroutes its probes off the VPN policy routes.
    let restore = || Rule::restore_mark(Family::Inet).ct_mark_eq(common::EXEMPT_FWMARK);

    rs.mangle.prerouting.push(restore());
    for wan in wan_devices {
        for ex in exemptions {
            let proto = match ex.proto {
                TransportProtocol::Tcp => Proto::Tcp,
                TransportProtocol::Udp => Proto::Udp,
            };
            rs.mangle.prerouting.push(
                Rule::set_ct_mark(Family::Inet, common::EXEMPT_FWMARK)
                    .iif(wan.as_str())
                    .proto(proto)
                    .dport(ex.dport)
                    .ct_new(),
            );
        }
    }
    // Restore again after the sets: `ct mark set` leaves the flow-creating
    // packet's meta mark at 0, so it would hit the terminal reject and the
    // unconfirmed conntrack entry would be destroyed.
    rs.mangle.prerouting.push(restore());
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
    // Input stays unscoped: inbound packets carry no socket owner.
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

/// uid-0 scoped: an unscoped "router-only" accept is a LAN leak, because
/// dnsmasq re-originates LAN clients' queries as router OUTPUT packets.
fn allow_dns_server_daemon_only(rs: &mut RuleSet, dns: IpAddr) {
    allow_dns_server_inner(rs, dns, None, DnsAccess::Daemon);
}

/// `iface` pins the accept to one interface (tunnel resolvers); LAN clients
/// are forwarded only when unpinned.
fn allow_dns_server(rs: &mut RuleSet, dns: IpAddr, iface: Option<&str>) {
    allow_dns_server_inner(rs, dns, iface, DnsAccess::RouterAndLan);
}

/// Private custom resolver (a LAN Pi-hole), pinned to the device it is routed
/// on. "Private" is not "LAN": behind another router the upstream is
/// 192.168.x.1, so the rule is positive (a device name) rather than "not the
/// WAN", which iptables cannot express for several WANs. Unscoped by uid on
/// purpose (dnsmasq is not root). Returns `false` and emits nothing when the
/// address is not private or [`private_dns_device`] refuses.
fn allow_private_dns_server(
    rs: &mut RuleSet,
    dns: IpAddr,
    uplink: &Uplink<'_>,
    tunnel_ifaces: &[&str],
) -> bool {
    if !is_private_dns(&dns) {
        return false;
    }
    let Some(dev) = private_dns_device(dns, uplink, tunnel_ifaces) else {
        return false;
    };
    let family = family_of(&dns);
    let pairs = [
        (Proto::Udp, DNS_PORT),
        (Proto::Tcp, DNS_PORT),
        (Proto::Tcp, DOT_PORT),
        (Proto::Tcp, DOH_PORT),
    ];
    for (proto, port) in pairs {
        rs.filter.output.push(
            Rule::accept(family)
                .proto(proto)
                .daddr(dns)
                .dport(port)
                .oif(dev.as_str()),
        );
        rs.filter.input.push(
            Rule::accept(family)
                .proto(proto)
                .saddr(dns)
                .sport(port)
                .iif(dev.as_str()),
        );
    }
    // Multi-LAN: same-segment clients never traverse the router.
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.filter.forward.push(
            Rule::accept(family)
                .proto(proto)
                .daddr(dns)
                .dport(DNS_PORT)
                .oif(dev.as_str()),
        );
    }
    true
}

/// Fail closed (the state's tunnel-only or daemon-only treatment) unless the
/// WAN zone is known and the resolver's route leaves on a device that is
/// neither a WAN nor the tunnel. The tunnel is the route of any private
/// address without a connected route once the VPN default route is up.
fn private_dns_device(dns: IpAddr, uplink: &Uplink<'_>, tunnel_ifaces: &[&str]) -> Option<String> {
    let fallback = "admitting it through the tunnel only (fail closed)";
    if uplink.wan_devices.is_empty() {
        tracing::warn!(
            "Private custom DNS server {dns} configured but no WAN zone device could be \
             determined; {fallback}"
        );
        return None;
    }
    let Some(dev) = (uplink.route_device)(dns) else {
        tracing::warn!("Private custom DNS server {dns} has no route; {fallback}");
        return None;
    };
    if uplink.wan_devices.contains(&dev) {
        tracing::warn!("Private custom DNS server {dns} is routed via WAN device {dev}; {fallback}");
        return None;
    }
    if tunnel_ifaces.contains(&dev.as_str()) {
        tracing::warn!(
            "Private custom DNS server {dns} has no route outside the tunnel ({dev}); {fallback}"
        );
        return None;
    }
    Some(dev)
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
        // Input stays unscoped: inbound packets have no socket owner.
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
    // Return direction is established-only: the exit never initiates into
    // the LAN, and a blanket established accept also matched WAN egress.
    rs.filter.forward.push(Rule::accept(Family::Inet).oif(iface));
    rs.filter.forward.push(Rule::accept(Family::Inet).iif(iface).ct_established());
}

/// CVE-2019-14899: drop packets to the tunnel IP arriving on a non-tunnel
/// interface, which a LAN attacker uses to probe in-tunnel connections.
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

/// A clockless router would otherwise deadlock: TLS to the API fails cert
/// validity until the clock syncs.
fn ntp_escape_hatch(rs: &mut RuleSet) {
    rs.filter.output.push(
        Rule::accept(Family::Inet)
            .proto(Proto::Udp)
            .dport(NTP_PORT)
            .rate_limit(NTP_RATE_PER_MIN, NTP_BURST),
    );
}

/// Lets the daemon resolve the NTP pool before the tunnel is up. Root-scoped:
/// an unscoped OUTPUT hatch is a LAN leak via dnsmasq's relayed queries; the
/// daemon resolves the pool itself as root (`clock_bootstrap` in nym-vpn-lib).
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

/// Gateway latency probes carry the tunnel fwmark so they route via the WAN.
/// Keyed on the mark, not uid 0: nearly every OpenWrt process is root, so a
/// uid-scoped ICMP accept would let any local `ping` past the kill switch.
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
        // daddr only: an saddr accept would forward LAN clients straight out WAN.
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
    // INPUT falls through to fw3/fw4 so management traffic keeps working.
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
        let mut rs = RuleSet::default();
        let exemptions = vec![
            InboundExemption::new(TransportProtocol::Tcp, 443),
            InboundExemption::new(TransportProtocol::Udp, 51820),
        ];
        exemption_mangle_rules(&mut rs, &exemptions, &["eth1".to_string()]);

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
        assert!(first_restore < first_set);
        assert!(last_restore > last_set);
        assert!(
            rs.mangle
                .output
                .rules
                .iter()
                .any(|r| matches!(r.verdict, Verdict::RestoreMark))
        );
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
        // The probe hatch carries the tunnel fwmark in every state.
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
        let wan = vec!["eth1".to_string()];
        let rs = compile_with(&policy, &uplink(&wan, None));

        for chain in [&rs.filter.input, &rs.filter.output, &rs.filter.forward] {
            let mark_pos = chain
                .rules
                .iter()
                .position(|r| r.matches.mark == Some(common::EXEMPT_FWMARK));
            assert!(mark_pos.is_some(), "expected mark accept in chain");
            let last = chain.rules.last().expect("non-empty chain");
            if matches!(last.verdict, Verdict::Reject) {
                assert!(mark_pos.unwrap() < chain.rules.len() - 1);
            }
        }
    }

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
            // block_dns pushes its own terminal port-53 rejects into FORWARD.
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
        for (name, policy) in killswitch_states_without_exemptions() {
            let rs = compile(&policy);
            assert!(
                rs.forward_terminates_in_block(),
                "{name}: forward chain must terminate in reject"
            );
            for r in &rs.filter.forward.rules {
                if matches!(r.verdict, Verdict::Accept) && r.matches.mark != Some(common::EXEMPT_FWMARK) {
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
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec![],
        };
        let rs = compile(&policy);
        for r in &rs.filter.forward.rules {
            if let Some(AddrMatch::Net(net)) = &r.matches.saddr {
                panic!(
                    "Blocked policy must not have an saddr-LAN accept in forward chain: {:?}",
                    net
                );
            }
        }
    }

    /// Non-resolver endpoints on 443 are out of scope: dnsmasq speaks neither
    /// DoT nor DoH, and the endpoint list is daemon-controlled.
    #[test]
    fn blocked_dns_exceptions_are_root_scoped() {
        let resolvers: Vec<IpAddr> =
            vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()];
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
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

    /// Connected is exempt: with the tunnel up, LAN DNS follows the tunnel policy.
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

    /// Every echo-request accept is the mark-scoped probe hatch or an mwan3
    /// tracking rule pinned to a destination.
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

    /// skuid fails the iptables restore on any chain but OUTPUT.
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

    fn accepts_to(rs: &RuleSet, dns: IpAddr) -> Vec<&Rule> {
        rs.filter
            .output
            .rules
            .iter()
            .filter(|r| {
                r.verdict == Verdict::Accept
                    && matches!(&r.matches.daddr, Some(AddrMatch::Ip(ip)) if *ip == dns)
            })
            .collect()
    }

    fn block_dns_at(rs: &RuleSet) -> usize {
        rs.filter
            .output
            .rules
            .iter()
            .position(|r| {
                r.verdict == Verdict::Reject
                    && r.matches.dport == Some(DNS_PORT)
                    && r.matches.daddr.is_none()
            })
            .expect("block_dns present")
    }

    fn states_with_private_dns(pihole: IpAddr) -> Vec<(&'static str, FirewallPolicy)> {
        vec![
            (
                "blocked",
                FirewallPolicy::Blocked {
                    allow_lan: true,
                    allowed_endpoints: vec![],
                    dns_servers: vec!["9.9.9.9".parse().unwrap(), pihole],
                },
            ),
            (
                "connecting",
                FirewallPolicy::Connecting {
                    peer_endpoints: vec![ep([1, 2, 3, 4], 443)],
                    tunnel: None,
                    allow_lan: true,
                    dns_config: dns_config(&[], &["9.9.9.9".parse().unwrap(), pihole]),
                    allowed_endpoints: vec![],
                    allowed_entry_tunnel_traffic: AllowedTunnelTraffic::All,
                    allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
                    inbound_exemptions: vec![],
                },
            ),
            (
                "connected",
                FirewallPolicy::Connected {
                    peer_endpoints: vec![ep([1, 2, 3, 4], 51820)],
                    tunnel: tunnel_iface("nym0", [10, 64, 0, 2]),
                    allow_lan: true,
                    dns_config: dns_config(&["9.9.9.9".parse().unwrap()], &[pihole]),
                    allowed_endpoints: vec![],
                    inbound_exemptions: vec![],
                },
            ),
        ]
    }

    /// Two WAN devices (mwan3: DHCP `wan` on eth1, PPPoE `wanb`) and a fixed
    /// answer for every route lookup.
    fn uplink<'a>(wan_devices: &'a [String], route: Option<&str>) -> Uplink<'a> {
        let route = route.map(str::to_string);
        Uplink {
            wan_devices,
            route_device: Box::new(move |_| route.clone()),
        }
    }

    fn multi_wan() -> Vec<String> {
        vec!["eth1".to_string(), "pppoe-wanb".to_string()]
    }

    fn pihole_forward_accepts(rs: &RuleSet, pihole: IpAddr) -> Vec<&Rule> {
        rs.filter
            .forward
            .rules
            .iter()
            .filter(|r| {
                r.verdict == Verdict::Accept
                    && matches!(&r.matches.daddr, Some(AddrMatch::Ip(ip)) if *ip == pihole)
            })
            .collect()
    }

    #[test]
    fn private_custom_dns_is_pinned_to_its_route_device_in_every_state() {
        let pihole: IpAddr = "10.0.0.2".parse().unwrap();
        let wan = multi_wan();
        for (name, policy) in states_with_private_dns(pihole) {
            let rs = compile_with(&policy, &uplink(&wan, Some("br-lan")));

            let out = accepts_to(&rs, pihole);
            assert_eq!(out.len(), 4, "{name}: udp/53, tcp/53, DoT, DoH");
            for r in &out {
                assert_eq!(r.matches.oif.as_deref(), Some("br-lan"), "{name}");
                assert!(r.matches.skuid.is_none(), "{name}: dnsmasq is not root");
            }
            let inp: Vec<_> = rs
                .filter
                .input
                .rules
                .iter()
                .filter(|r| matches!(&r.matches.saddr, Some(AddrMatch::Ip(ip)) if *ip == pihole))
                .collect();
            assert_eq!(inp.len(), 4, "{name}");
            for r in &inp {
                assert_eq!(r.matches.iif.as_deref(), Some("br-lan"), "{name}");
            }
            let first = rs
                .filter
                .output
                .rules
                .iter()
                .position(|r| matches!(&r.matches.daddr, Some(AddrMatch::Ip(ip)) if *ip == pihole))
                .unwrap();
            assert!(
                first < block_dns_at(&rs),
                "{name}: accept precedes block_dns"
            );

            let fwd = pihole_forward_accepts(&rs, pihole);
            assert_eq!(
                fwd.len(),
                2,
                "{name}: LAN clients may reach it, udp and tcp"
            );
            for r in &fwd {
                assert_eq!(r.matches.oif.as_deref(), Some("br-lan"), "{name}");
            }

            let nft = super::super::render_nft::render(&rs);
            assert!(
                nft.lines().any(|l| {
                    l.contains("oifname \"br-lan\"")
                        && l.contains("ip daddr 10.0.0.2")
                        && l.contains("udp dport 53")
                        && l.trim_end().ends_with("accept")
                }),
                "{name}: nft render\n{nft}"
            );
            assert!(
                !nft.contains("oifname !="),
                "{name}: no negated device match"
            );
            let v4 = super::super::render_iptables::render(
                &rs,
                super::super::render_iptables::AddrFamily::V4,
            );
            assert!(
                v4.lines().any(|l| {
                    l.contains("-o br-lan")
                        && l.contains("-d 10.0.0.2")
                        && l.contains("--dport 53")
                        && l.contains("-j ACCEPT")
                }),
                "{name}: iptables render\n{v4}"
            );
            assert!(!v4.contains("! -o"), "{name}: no negated device match");

            let quad9: IpAddr = "9.9.9.9".parse().unwrap();
            for r in accepts_to(&rs, quad9) {
                match name {
                    "connected" => assert_eq!(r.matches.oif.as_deref(), Some("nym0")),
                    _ => {
                        assert!(r.matches.oif.is_none(), "{name}: public resolver untouched");
                        assert_eq!(r.matches.skuid, Some(crate::ROOT_UID));
                    }
                }
            }
        }
    }

    fn assert_private_dns_fails_closed(name: &str, rs: &RuleSet, pihole: IpAddr) {
        let out = accepts_to(rs, pihole);
        assert!(!out.is_empty(), "{name}");
        for r in &out {
            match name {
                "connected" => assert_eq!(r.matches.oif.as_deref(), Some("nym0"), "{name}"),
                _ => {
                    assert!(r.matches.oif.is_none(), "{name}");
                    assert_eq!(r.matches.skuid, Some(crate::ROOT_UID), "{name}");
                }
            }
        }
        assert!(
            pihole_forward_accepts(rs, pihole).is_empty(),
            "{name}: no forward accept"
        );
    }

    #[test]
    fn private_custom_dns_routed_via_a_wan_device_is_not_admitted() {
        // The upstream router behind another NAT: 192.168.1.1 out the second
        // WAN. Every WAN device counts, not only the one named `wan`.
        let upstream: IpAddr = "192.168.1.1".parse().unwrap();
        let wan = multi_wan();
        for (name, policy) in states_with_private_dns(upstream) {
            let rs = compile_with(&policy, &uplink(&wan, Some("pppoe-wanb")));
            assert_private_dns_fails_closed(name, &rs, upstream);
        }
    }

    #[test]
    fn private_custom_dns_routed_via_the_tunnel_is_not_admitted() {
        // No connected route: once the VPN default route is up the lookup
        // lands on the tunnel, which is not "a non-WAN interface".
        let pihole: IpAddr = "10.0.0.2".parse().unwrap();
        let wan = multi_wan();
        let (name, policy) = states_with_private_dns(pihole)
            .into_iter()
            .find(|(name, _)| *name == "connected")
            .unwrap();
        let rs = compile_with(&policy, &uplink(&wan, Some("nym0")));
        assert_private_dns_fails_closed(name, &rs, pihole);
    }

    #[test]
    fn private_custom_dns_falls_back_when_the_wan_or_route_is_unknown() {
        let pihole: IpAddr = "10.0.0.2".parse().unwrap();
        let wan = multi_wan();
        let no_wan: Vec<String> = Vec::new();
        for (name, policy) in states_with_private_dns(pihole) {
            let rs = compile_with(&policy, &uplink(&no_wan, Some("br-lan")));
            assert_private_dns_fails_closed(name, &rs, pihole);
            let rs = compile_with(&policy, &uplink(&wan, None));
            assert_private_dns_fails_closed(name, &rs, pihole);
        }
    }

    #[test]
    fn private_custom_dns_ipv6_ula_is_pinned_to_its_route_device() {
        let ula: IpAddr = "fd00::53".parse().unwrap();
        let policy = FirewallPolicy::Blocked {
            allow_lan: true,
            allowed_endpoints: vec![],
            dns_servers: vec![ula],
        };
        let wan = multi_wan();
        let rs = compile_with(&policy, &uplink(&wan, Some("br-lan")));
        let out = accepts_to(&rs, ula);
        assert_eq!(out.len(), 4);
        for r in &out {
            assert_eq!(r.family, Family::V6);
            assert_eq!(r.matches.oif.as_deref(), Some("br-lan"));
        }
        let nft = super::super::render_nft::render(&rs);
        assert!(nft.contains("oifname \"br-lan\" ip6 daddr fd00::53 udp dport 53 accept"));
    }

    #[test]
    fn exemption_mangle_marks_inbound_flows_on_every_wan_device() {
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
        let wan = multi_wan();
        let rs = compile_with(&policy, &uplink(&wan, None));
        let sets: Vec<_> = rs
            .mangle
            .prerouting
            .rules
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::SetCtMark(_)))
            .collect();
        assert_eq!(sets.len(), 4, "two exemptions on two WAN devices");
        for dev in ["eth1", "pppoe-wanb"] {
            for port in [443, 51820] {
                assert!(
                    sets.iter().any(|r| {
                        r.matches.iif.as_deref() == Some(dev) && r.matches.dport == Some(port)
                    }),
                    "missing set rule for {dev}:{port}"
                );
            }
        }
        let nft = super::super::render_nft::render(&rs);
        assert!(
            nft.contains("iifname \"pppoe-wanb\" ct state new tcp dport 443 ct mark set 0x14e"),
            "{nft}"
        );

        let rs = compile_with(&policy, &uplink(&[], None));
        assert!(rs.mangle.is_empty(), "unknown WAN zone: no mangle rules");
    }

    #[test]
    fn private_dns_classification() {
        let yes = [
            "10.0.0.2",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
        ];
        let no = ["100.64.0.1", "8.8.8.8", "127.0.0.1", "::1", "2620:fe::fe"];
        for ip in yes {
            assert!(is_private_dns(&ip.parse().unwrap()), "{ip} is private");
        }
        for ip in no {
            assert!(!is_private_dns(&ip.parse().unwrap()), "{ip} is not private");
        }
    }
}
