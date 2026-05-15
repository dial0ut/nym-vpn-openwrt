// SPDX-License-Identifier: GPL-3.0-only

//! Constants and runtime probes shared between the fw3 and fw4 backends.

use std::net::IpAddr;
use std::path::Path;

/// Include script paths (installed by the IPK package).
pub const FW3_INCLUDE_PATH: &str = "/usr/share/nym-vpn/fw3-include.sh";
pub const FW4_INCLUDE_PATH: &str = "/usr/share/nym-vpn/fw4-include.sh";

/// fw3 hook chains — user chains in the `filter` table that survive a fw3
/// reload. Our chains are jumped to from the front of these.
pub const FW3_HOOK_INPUT: &str = "input_rule";
pub const FW3_HOOK_OUTPUT: &str = "output_rule";
pub const FW3_HOOK_FORWARD: &str = "forwarding_rule";

/// Check whether IPv6 is enabled in the kernel and `ip6tables` is usable.
pub fn is_ipv6_enabled() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        && content.trim() == "1"
    {
        return false;
    }
    if !Path::new("/proc/sys/net/ipv6").exists() {
        return false;
    }
    // Final probe: some systems have IPv6 enabled in sysctl but ip6tables is
    // missing or broken (no kernel module). Smoke-test it.
    if let Ok(output) = std::process::Command::new("ip6tables")
        .args(["-L", "-n"])
        .output()
    {
        return output.status.success();
    }
    true
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
