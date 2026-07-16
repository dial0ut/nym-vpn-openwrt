// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt firewall system detection.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

/// The detected OpenWrt firewall system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallSystem {
    /// fw3 - iptables-based firewall (OpenWrt ≤21.02)
    Fw3,
    /// fw4 - nftables-based firewall (OpenWrt ≥22.03)
    Fw4,
    /// Unknown or non-OpenWrt system
    Unknown,
}

static DETECTED_SYSTEM: OnceLock<FirewallSystem> = OnceLock::new();

/// Detect which firewall system is in use. A definitive result (fw3/fw4) is
/// cached for the process lifetime; an `Unknown` result is NOT cached, so a
/// later call re-probes once the firewall has actually come up (e.g. after a
/// firewall restart or slow boot). This prevents a transient early `Unknown`
/// from permanently disabling the kill-switch.
pub fn detect_system() -> FirewallSystem {
    if let Some(&cached) = DETECTED_SYSTEM.get() {
        return cached;
    }
    let detected = detect_uncached();
    if detected != FirewallSystem::Unknown {
        let _ = DETECTED_SYSTEM.set(detected);
    }
    detected
}

/// Test-only view of the cache (None until a definitive result is stored).
#[cfg(test)]
fn cached_system() -> Option<FirewallSystem> {
    DETECTED_SYSTEM.get().copied()
}

fn detect_uncached() -> FirewallSystem {
    if !is_openwrt() {
        tracing::debug!("Not running on OpenWrt");
        return FirewallSystem::Unknown;
    }

    // Check for fw4 first (newer)
    if is_fw4_available() {
        tracing::debug!("Detected fw4 (nftables-based firewall)");
        return FirewallSystem::Fw4;
    }

    // Check for fw3
    if is_fw3_available() {
        tracing::debug!("Detected fw3 (iptables-based firewall)");
        return FirewallSystem::Fw3;
    }

    tracing::warn!("OpenWrt detected but no known firewall system found");
    FirewallSystem::Unknown
}

/// Check if we're running on OpenWrt.
fn is_openwrt() -> bool {
    Path::new("/etc/openwrt_release").exists()
}

/// Check if fw4 is available and active.
fn is_fw4_available() -> bool {
    // Check if fw4 binary exists
    if !Path::new("/sbin/fw4").exists() && !Path::new("/usr/sbin/fw4").exists() {
        return false;
    }

    // Check if nft is available
    let nft_ok = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !nft_ok {
        return false;
    }

    // Check if fw4 table exists (indicates fw4 is active)
    let fw4_active = Command::new("nft")
        .args(["list", "table", "inet", "fw4"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    fw4_active
}

/// Check if fw3 is available and active.
fn is_fw3_available() -> bool {
    // Check if fw3 binary exists
    if !Path::new("/sbin/fw3").exists() && !Path::new("/usr/sbin/fw3").exists() {
        return false;
    }

    // Check if iptables is available
    let ipt_ok = Command::new("iptables")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !ipt_ok {
        return false;
    }

    // Check if fw3's chains exist (indicates fw3 is active)
    // fw3 creates zone chains like zone_lan_input
    let fw3_active = Command::new("iptables")
        .args(["-L", "input_rule", "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    fw3_active
}

/// Get the OpenWrt version string if available.
pub fn get_openwrt_version() -> Option<String> {
    std::fs::read_to_string("/etc/openwrt_release")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("DISTRIB_RELEASE="))
                .map(|line| {
                    line.trim_start_matches("DISTRIB_RELEASE=")
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string()
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openwrt_detection() {
        // This test will behave differently on OpenWrt vs other systems
        let system = detect_system();
        println!("Detected system: {:?}", system);
    }

    #[test]
    fn unknown_is_not_cached() {
        // Two calls that both resolve Unknown (non-OpenWrt CI host) must each
        // re-probe rather than freeze the first Unknown forever. We assert the
        // cache only ever holds a definitive value.
        let _ = detect_system();
        let _ = detect_system();
        if let Some(cached) = cached_system() {
            assert_ne!(
                cached,
                FirewallSystem::Unknown,
                "Unknown must never be cached"
            );
        }
    }
}
