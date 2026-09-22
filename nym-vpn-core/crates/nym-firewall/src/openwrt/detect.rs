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
    let detected = detect_with(&SystemProbe);
    match detected {
        FirewallSystem::Fw4 => tracing::debug!("Detected fw4 (nftables-based firewall)"),
        FirewallSystem::Fw3 => tracing::debug!("Detected fw3 (iptables-based firewall)"),
        FirewallSystem::Unknown => {
            tracing::warn!("No OpenWrt firewall system found")
        }
    }
    detected
}

/// What detection asks of the system; tests inject it.
trait Probe {
    fn is_openwrt(&self) -> bool;
    /// `inet fw4` is loaded.
    fn fw4_live(&self) -> bool;
    /// fw3's `input_rule` chain exists.
    fn fw3_live(&self) -> bool;
    /// `/etc/init.d/firewall`, if readable.
    fn firewall_init_script(&self) -> Option<String>;
    fn file_exists(&self, path: &str) -> bool;
}

/// The order of `nym_fw_backend` in `fw-boot-guard.sh`, which picks the
/// include: live state first (a vendor image may ship both stacks), then the
/// firewall init script, which still names fw4 when its ruleset failed to
/// load (a bad user rule), then binary presence. `inet nym` does not need
/// `inet fw4`, so a router whose fw4 failed still gets its kill-switch.
fn detect_with(probe: &dyn Probe) -> FirewallSystem {
    if !probe.is_openwrt() {
        return FirewallSystem::Unknown;
    }
    if probe.fw4_live() {
        return FirewallSystem::Fw4;
    }
    if probe.fw3_live() {
        return FirewallSystem::Fw3;
    }
    if let Some(script) = probe.firewall_init_script() {
        let names = |word: &str| {
            script
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token == word)
        };
        if names("fw4") {
            return FirewallSystem::Fw4;
        }
        if names("fw3") {
            return FirewallSystem::Fw3;
        }
    }
    let exists = |paths: &[&str]| paths.iter().any(|p| probe.file_exists(p));
    if exists(&["/sbin/fw4", "/usr/sbin/fw4"]) {
        return FirewallSystem::Fw4;
    }
    if exists(&["/sbin/fw3", "/usr/sbin/fw3"]) {
        return FirewallSystem::Fw3;
    }
    FirewallSystem::Unknown
}

struct SystemProbe;

impl Probe for SystemProbe {
    fn is_openwrt(&self) -> bool {
        Path::new("/etc/openwrt_release").exists()
    }

    fn fw4_live(&self) -> bool {
        succeeds("nft", &["list", "table", "inet", "fw4"])
    }

    fn fw3_live(&self) -> bool {
        succeeds("iptables", &["-L", "input_rule", "-n"])
    }

    fn firewall_init_script(&self) -> Option<String> {
        std::fs::read_to_string("/etc/init.d/firewall").ok()
    }

    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
}

fn succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

    #[derive(Default)]
    struct FakeProbe {
        openwrt: bool,
        fw4_live: bool,
        fw3_live: bool,
        init: Option<&'static str>,
        files: Vec<&'static str>,
    }

    impl Probe for FakeProbe {
        fn is_openwrt(&self) -> bool {
            self.openwrt
        }
        fn fw4_live(&self) -> bool {
            self.fw4_live
        }
        fn fw3_live(&self) -> bool {
            self.fw3_live
        }
        fn firewall_init_script(&self) -> Option<String> {
            self.init.map(str::to_string)
        }
        fn file_exists(&self, path: &str) -> bool {
            self.files.contains(&path)
        }
    }

    fn openwrt() -> FakeProbe {
        FakeProbe {
            openwrt: true,
            ..Default::default()
        }
    }

    const FW4_INIT: &str = "#!/bin/sh /etc/rc.common\nSTART=19\nboot() { fw4 -q start; }";
    const FW3_INIT: &str = "#!/bin/sh /etc/rc.common\nSTART=19\nstart_service() { fw3 start; }";

    #[test]
    fn live_state_wins() {
        let both_binaries = vec!["/sbin/fw3", "/sbin/fw4"];
        let probe = FakeProbe {
            fw3_live: true,
            init: Some(FW4_INIT),
            files: both_binaries.clone(),
            ..openwrt()
        };
        assert_eq!(detect_with(&probe), FirewallSystem::Fw3);
        let probe = FakeProbe {
            fw4_live: true,
            fw3_live: true,
            files: both_binaries,
            ..openwrt()
        };
        assert_eq!(detect_with(&probe), FirewallSystem::Fw4);
    }

    /// The regression: fw4 whose ruleset failed to load is still fw4, not
    /// an unknown system handed to the iptables backend.
    #[test]
    fn fw4_that_failed_to_load_is_still_fw4() {
        let probe = FakeProbe {
            init: Some(FW4_INIT),
            files: vec!["/sbin/fw4"],
            ..openwrt()
        };
        assert_eq!(detect_with(&probe), FirewallSystem::Fw4);
        let no_init = FakeProbe {
            files: vec!["/sbin/fw4"],
            ..openwrt()
        };
        assert_eq!(detect_with(&no_init), FirewallSystem::Fw4);
    }

    #[test]
    fn init_script_names_the_framework() {
        let probe = FakeProbe {
            init: Some(FW3_INIT),
            files: vec!["/sbin/fw4"],
            ..openwrt()
        };
        assert_eq!(detect_with(&probe), FirewallSystem::Fw3);
        // A word match: "fw4" inside another token names nothing.
        let probe = FakeProbe {
            init: Some("start_service() { myfw4tool; }"),
            files: vec!["/sbin/fw3"],
            ..openwrt()
        };
        assert_eq!(detect_with(&probe), FirewallSystem::Fw3);
    }

    #[test]
    fn nothing_known_is_unknown() {
        assert_eq!(detect_with(&openwrt()), FirewallSystem::Unknown);
        let not_openwrt = FakeProbe {
            fw4_live: true,
            ..Default::default()
        };
        assert_eq!(detect_with(&not_openwrt), FirewallSystem::Unknown);
    }

    /// Same order as the shell that picks the include, so the daemon and the
    /// include never disagree about the backend.
    #[test]
    fn order_matches_nym_fw_backend() {
        let script = include_str!("../../scripts/fw-boot-guard.sh");
        let body = script
            .split("nym_fw_backend() {")
            .nth(1)
            .and_then(|s| s.split("\n}").next())
            .expect("nym_fw_backend in fw-boot-guard.sh");
        let probes = [
            "nft list table inet fw4",
            "iptables -L input_rule -n",
            "grep -q -w fw4 /etc/init.d/firewall",
            "grep -q -w fw3 /etc/init.d/firewall",
            "[ -x /sbin/fw4 ]",
        ];
        let positions: Vec<usize> = probes
            .iter()
            .map(|p| body.find(p).unwrap_or_else(|| panic!("{p} missing from:\n{body}")))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{body}");
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
