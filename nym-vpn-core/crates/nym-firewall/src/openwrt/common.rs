// SPDX-License-Identifier: GPL-3.0-only

//! Constants and runtime probes shared between the fw3 and fw4 backends.

use std::net::IpAddr;
use std::path::Path;

/// Persisted fw3 state, consumed by `fw3-include.sh` to re-apply the
/// kill-switch after an fw3 reload wipes the iptables tables. The paths are
/// part of the contract with that script and with the package prerm — keep
/// them in sync when renaming.
pub const FW3_RULES_V4_PATH: &str = "/tmp/nym-firewall-v4.rules";
pub const FW3_RULES_V6_PATH: &str = "/tmp/nym-firewall-v6.rules";
/// Tunnel interface list (one name per line) for masquerade restore. Shared
/// naming with the fw4 include script, which reads it as an optional hint.
pub const IFACES_PATH: &str = "/tmp/nym-firewall.ifaces";

/// fw3 hook chains — user chains in the `filter` table that survive a fw3
/// reload. Our chains are jumped to from the front of these.
pub const FW3_HOOK_INPUT: &str = "input_rule";
pub const FW3_HOOK_OUTPUT: &str = "output_rule";
pub const FW3_HOOK_FORWARD: &str = "forwarding_rule";

/// Firewall mark used for inbound-exemption reply pinning. Distinct from the
/// tunnel fwmark (`0x14d`). Carried in `ct mark` for the connection lifetime
/// and restored onto packet mark so reply traffic hits `ip rule fwmark` and
/// routes via the real WAN instead of the tunnel.
pub const EXEMPT_FWMARK: u32 = 0x14e;

/// Detect the active WAN interface name. Used to anchor inbound-exemption
/// rules so we only mark new flows arriving from the WAN side.
///
/// The name we need is the **L3 device** packets actually ingress on. For a
/// plain DHCP/static WAN that equals `network.wan.device`, but for tunnelled
/// WAN protocols (PPPoE, L2TP, …) the L3 device is a virtual netdev such as
/// `pppoe-wan`, while `network.wan.device` is the *underlying* ethernet/bridge.
/// Anchoring the `iif` match on the wrong one silently drops every inbound
/// mark, so the exemption never fires.
///
/// Strategy (most authoritative first):
/// 1. `ubus call network.interface.wan status` → `l3_device`. Correct for
///    both tunnelled and plain WANs, and independent of the current default
///    route (which points into the VPN tunnel once connected).
/// 2. Read `uci get network.wan.device` — right for plain DHCP/static WANs.
/// 3. Parse `ip -o route get 1.1.1.1` for the `dev <name>` token. Last resort:
///    may return the tunnel device if the VPN default route is already up.
///
/// Returns `None` only if all three fail (very unusual on a router).
pub fn detect_wan_iface() -> Option<String> {
    if let Ok(output) = std::process::Command::new("ubus")
        .args(["call", "network.interface.wan", "status"])
        .output()
        && output.status.success()
        && let Some(dev) =
            parse_ubus_l3_device(&String::from_utf8_lossy(&output.stdout))
    {
        return Some(dev);
    }

    if let Ok(output) = std::process::Command::new("uci")
        .args(["get", "network.wan.device"])
        .output()
        && output.status.success()
    {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }

    if let Ok(output) = std::process::Command::new("ip")
        .args(["-o", "route", "get", "1.1.1.1"])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut iter = stdout.split_whitespace();
        while let Some(tok) = iter.next() {
            if tok == "dev"
                && let Some(name) = iter.next()
            {
                return Some(name.to_string());
            }
        }
    }

    None
}

/// Extract the `l3_device` string from `ubus call network.interface.wan status`
/// JSON output. Kept as a tiny hand-rolled extractor so the crate needn't pull
/// in a JSON parser for one field; interface names never contain quotes or
/// escapes, so this is sufficient. Returns `None` if the field is absent or
/// empty (e.g. WAN link down).
fn parse_ubus_l3_device(json: &str) -> Option<String> {
    let needle = "\"l3_device\"";
    let after_key = &json[json.find(needle)? + needle.len()..];
    let after_colon = &after_key[after_key.find(':')? + 1..];
    let open = after_colon.find('"')?;
    let value = &after_colon[open + 1..];
    let close = value.find('"')?;
    let dev = &value[..close];
    if dev.is_empty() {
        None
    } else {
        Some(dev.to_string())
    }
}

/// Whether the kernel's IPv6 stack is up and, if so, whether `ip6tables`
/// can actually filter it. The distinction matters for fail-closed behavior:
/// "kernel IPv6 off" legitimately needs no v6 rules, while "kernel IPv6 on
/// but ip6tables broken" means v6 traffic flows and CANNOT be firewalled —
/// treating that as "disabled" would install a v4-only kill-switch with a
/// silent IPv6 bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Status {
    /// IPv6 is disabled in (or absent from) the kernel: nothing to filter.
    Disabled,
    /// IPv6 is up and `ip6tables` works.
    Enabled,
    /// IPv6 is up but `ip6tables` is missing or broken (no binary, no
    /// kernel module): v6 traffic flows unfiltered.
    Unusable,
}

/// Probe the kernel IPv6 stack and the `ip6tables` toolchain.
pub fn ipv6_status() -> Ipv6Status {
    if !Path::new("/proc/sys/net/ipv6").exists() {
        return Ipv6Status::Disabled;
    }
    if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        && content.trim() == "1"
    {
        return Ipv6Status::Disabled;
    }
    // Smoke-test ip6tables: present-but-broken (missing ip6_tables kernel
    // module) exits non-zero, and a missing binary fails the spawn.
    match std::process::Command::new("ip6tables").args(["-L", "-n"]).output() {
        Ok(output) if output.status.success() => Ipv6Status::Enabled,
        _ => Ipv6Status::Unusable,
    }
}

/// Read mwan3 tracking IPs from UCI config.
///
/// mwan3 pings these IPs to determine WAN liveness. If our kill-switch
/// blocks them, mwan3 declares WAN down and triggers a firewall reload
/// cascade that kills VPN connections — so we always allow them.
pub fn get_mwan3_track_ips() -> Vec<IpAddr> {
    let output = match std::process::Command::new("uci").args(["show", "mwan3"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    for line in stdout.lines() {
        // Lines look like: mwan3.wan.track_ip='1.1.1.1' '8.8.8.8' ...
        if !line.contains(".track_ip=") {
            continue;
        }
        let Some(value) = line.split('=').nth(1) else {
            continue;
        };
        for token in value.split_whitespace() {
            let ip_str = token.trim_matches('\'');
            if let Ok(ip) = ip_str.parse::<IpAddr>()
                && !ips.contains(&ip)
            {
                ips.push(ip);
            }
        }
    }

    if !ips.is_empty() {
        tracing::debug!("Found mwan3 tracking IPs: {:?}", ips);
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l3_device_pppoe_returns_virtual_netdev() {
        // The regression case: a PPPoE WAN. `device` is the underlying
        // ethernet ("wan"), but inbound packets ingress on `pppoe-wan`.
        let json = r#"{"up":true,"l3_device":"pppoe-wan","device":"wan","proto":"pppoe"}"#;
        assert_eq!(parse_ubus_l3_device(json).as_deref(), Some("pppoe-wan"));
    }

    #[test]
    fn l3_device_dhcp_equals_ethernet() {
        let json = r#"{"up":true,"device":"eth1","l3_device":"eth1","proto":"dhcp"}"#;
        assert_eq!(parse_ubus_l3_device(json).as_deref(), Some("eth1"));
    }

    #[test]
    fn l3_device_absent_is_none() {
        // WAN link down: status omits l3_device.
        let json = r#"{"up":false,"pending":false,"available":true}"#;
        assert_eq!(parse_ubus_l3_device(json), None);
    }

    #[test]
    fn l3_device_empty_is_none() {
        let json = r#"{"up":false,"l3_device":"","device":"wan"}"#;
        assert_eq!(parse_ubus_l3_device(json), None);
    }

    #[test]
    fn l3_device_real_pretty_printed_ubus_output() {
        // Exact shape emitted by `ubus call network.interface.wan status` on
        // OpenWrt 25.12 (tab indent, space after the colon), captured from a
        // live router. Guards against the compact-JSON tests masking a real
        // formatting mismatch.
        let json = "{\n\t\"up\": true,\n\t\"pending\": false,\n\t\"available\": true,\n\t\"l3_device\": \"eth0\",\n\t\"proto\": \"static\",\n\t\"device\": \"eth0\"\n}\n";
        assert_eq!(parse_ubus_l3_device(json).as_deref(), Some("eth0"));
    }
}
