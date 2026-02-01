// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Common utilities shared between fw3 and fw4 backends.

use std::net::IpAddr;
use std::path::Path;

/// File paths for firewall rules.
pub const RULES_V4_PATH: &str = "/tmp/nym-firewall-v4.rules";
pub const RULES_V6_PATH: &str = "/tmp/nym-firewall-v6.rules";
pub const RULES_NFT_PATH: &str = "/tmp/nym-firewall.nft";

/// Include script paths (installed by the IPK package).
#[expect(dead_code, reason = "Used by install_include_script in fw3.rs and fw4.rs")]
pub const FW3_INCLUDE_PATH: &str = "/usr/share/nym-vpn/fw3-include.sh";
#[expect(dead_code, reason = "Used by install_include_script in fw3.rs and fw4.rs")]
pub const FW4_INCLUDE_PATH: &str = "/usr/share/nym-vpn/fw4-include.sh";

/// Chain names for our custom chains.
pub const NYM_INPUT: &str = "NYM_INPUT";
pub const NYM_OUTPUT: &str = "NYM_OUTPUT";
pub const NYM_FORWARD: &str = "NYM_FORWARD";

/// fw3 hook chains (user chains that survive reload).
pub const FW3_HOOK_INPUT: &str = "input_rule";
pub const FW3_HOOK_OUTPUT: &str = "output_rule";
pub const FW3_HOOK_FORWARD: &str = "forwarding_rule";

/// LAN networks (RFC1918 private addresses).
pub const LAN_NETWORKS_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

/// LAN networks for IPv6 (link-local and ULA).
pub const LAN_NETWORKS_V6: &[&str] = &[
    "fe80::/10",  // Link-local
    "fc00::/7",   // Unique local addresses
];

/// Multicast networks.
pub const MULTICAST_V4: &str = "224.0.0.0/4";
pub const MULTICAST_V6: &str = "ff00::/8";

/// Check if IPv6 is enabled in the kernel.
pub fn is_ipv6_enabled() -> bool {
    // Check if IPv6 is disabled via sysctl
    if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        if content.trim() == "1" {
            return false;
        }
    }

    // Also check if the IPv6 module is loaded at all
    if !Path::new("/proc/sys/net/ipv6").exists() {
        return false;
    }

    // Additional check: try to see if ip6tables works
    // On some systems IPv6 might be "enabled" but ip6tables fails
    if let Ok(output) = std::process::Command::new("ip6tables")
        .args(["-L", "-n"])
        .output()
    {
        return output.status.success();
    }

    true
}

/// Format an IP address for use in firewall rules.
pub fn format_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    }
}

/// Check if an IP is IPv4.
pub fn is_ipv4(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(_))
}

/// Check if an IP is IPv6.
pub fn is_ipv6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_))
}

/// Remove a file if it exists.
pub fn remove_file_if_exists(path: &str) -> std::io::Result<()> {
    if Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
