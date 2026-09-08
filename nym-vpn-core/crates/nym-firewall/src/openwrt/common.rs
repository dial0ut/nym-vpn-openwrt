// SPDX-License-Identifier: GPL-3.0-only

//! Constants and runtime probes shared between the fw3 and fw4 backends.

use std::net::IpAddr;
use std::path::Path;

use super::{Error, Result};

/// Root-only runtime state shared with the includes, init script and package
/// hooks. Under `/var/run` (root-owned tmpfs, cleared on reboot), not the
/// world-writable `/tmp`: the includes run as root and act on what they find
/// here, so nothing unprivileged may plant files in it. The scripts derive
/// their paths from `NYM_RUNTIME_DIR`, which the tests pin to this constant.
pub const RUNTIME_DIR: &str = "/var/run/nym-firewall";

/// Persisted fw3 state, replayed by `fw3-include.sh` after an fw3 restart
/// flushes the tables (a reload leaves foreign chains alone). File names are
/// a contract with that script and `prerm`.
pub const FW3_RULES_V4_PATH: &str = "/var/run/nym-firewall/v4.rules";
pub const FW3_RULES_V6_PATH: &str = "/var/run/nym-firewall/v6.rules";
/// Present for the whole of an fw3 state transition; the include installs
/// the emergency block instead of reading half-written state while it exists.
/// A crash leaves it behind on purpose.
pub const FW3_TRANSITION_PATH: &str = "/var/run/nym-firewall/transition";
/// `flock(2)` file serializing every writer of fw3 state (backend, include,
/// init-script stop). The transition marker alone races: the include could
/// test it, lose the CPU while the daemon lifted its block, then install an
/// emergency block nobody removes. Never deleted while installed.
pub const FW3_LOCK_PATH: &str = "/var/run/nym-firewall/lock";
/// Tunnel interface list (one per line) for masquerade restore; the fw4
/// include reads it as an optional hint.
pub const IFACES_PATH: &str = "/var/run/nym-firewall/ifaces";
/// Reserved: nothing writes it (fw4 pipes to `nft -f -`). Named so the
/// include's forward-compatible read stays inside the trusted directory.
#[allow(dead_code)]
pub const FW4_POLICY_PATH: &str = "/var/run/nym-firewall/policy.nft";
/// Written by the init script on explicit `stop`, read by `fw-boot-guard.sh`
/// to skip the boot block. The daemon never touches it.
#[allow(dead_code)]
pub const STOP_MARKER_PATH: &str = "/var/run/nym-firewall/stopped";

/// Create [`RUNTIME_DIR`] 0700 if missing and refuse to proceed unless it is
/// a real directory (not a symlink), root-owned, with no group/other bits.
pub fn ensure_runtime_dir() -> Result<()> {
    ensure_runtime_dir_at(Path::new(RUNTIME_DIR), 0)
}

/// [`ensure_runtime_dir`] parameterised so tests can run unprivileged.
pub fn ensure_runtime_dir_at(dir: &Path, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let refuse = |what: String| {
        Error::ApplyError(format!(
            "firewall runtime directory {}: {what}; refusing to apply a policy on top of it",
            dir.display()
        ))
    };

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(refuse(format!("cannot create: {e}"))),
    }

    // symlink_metadata so a planted symlink is seen as one.
    let meta = std::fs::symlink_metadata(dir).map_err(|e| refuse(format!("cannot stat: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(refuse("is a symlink".into()));
    }
    if !meta.is_dir() {
        return Err(refuse("is not a directory".into()));
    }
    if meta.uid() != expected_uid {
        return Err(refuse(format!(
            "owned by uid {}, expected {expected_uid}",
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(refuse(format!(
            "mode {mode:o} grants group/other access, expected 0700"
        )));
    }
    Ok(())
}

/// Chain and table names shared with the shell includes. Defined in
/// [`super::boot_rules`], whose generated `fw-rules.sh` carries the same
/// values to the scripts; the other runtime paths above are pinned by tests.
pub use super::boot_rules::{FW3_HOOK_FORWARD, FW3_HOOK_INPUT, FW3_HOOK_OUTPUT, FW4_BOOT_TABLE};

/// Inbound-exemption reply mark (distinct from the tunnel fwmark `0x14d`),
/// carried in `ct mark` and restored so replies route via the real WAN.
pub const EXEMPT_FWMARK: u32 = 0x14e;

/// The WAN L3 device packets actually ingress on. For PPPoE/L2TP that is
/// `pppoe-wan`, not `network.wan.device` (the underlying ethernet), so ubus
/// `l3_device` is tried first; `ip route get` last, since the default route
/// points into the tunnel once connected.
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

/// Hand-rolled to avoid a JSON dependency for one field; interface names
/// never contain quotes or escapes.
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

/// `Unusable` (IPv6 up, `ip6tables` broken) must not be treated as
/// `Disabled`: that would install a v4-only kill-switch with an IPv6 bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Status {
    Disabled,
    Enabled,
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
    // A missing ip6_tables kernel module exits non-zero; no binary fails the spawn.
    match std::process::Command::new("ip6tables").args(["-L", "-n"]).output() {
        Ok(output) if output.status.success() => Ipv6Status::Enabled,
        _ => Ipv6Status::Unusable,
    }
}

/// mwan3's liveness ping targets. Blocking them makes mwan3 declare WAN down
/// and trigger a firewall reload cascade, so they are always allowed.
pub fn get_mwan3_track_ips() -> Vec<IpAddr> {
    let output = match std::process::Command::new("uci").args(["show", "mwan3"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    for line in stdout.lines() {
        // mwan3.wan.track_ip='1.1.1.1' '8.8.8.8'
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
        // Captured verbatim from OpenWrt 25.12 (tab indent, space after colon).
        let json = "{\n\t\"up\": true,\n\t\"pending\": false,\n\t\"available\": true,\n\t\"l3_device\": \"eth0\",\n\t\"proto\": \"static\",\n\t\"device\": \"eth0\"\n}\n";
        assert_eq!(parse_ubus_l3_device(json).as_deref(), Some("eth0"));
    }

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("nym-firewall-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        root
    }

    fn my_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn runtime_dir_is_created_private_when_missing() {
        use std::os::unix::fs::MetadataExt;
        let root = tmp_root("rtdir-create");
        let dir = root.join("state");
        ensure_runtime_dir_at(&dir, my_uid()).unwrap();
        let meta = std::fs::metadata(&dir).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
        ensure_runtime_dir_at(&dir, my_uid()).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dir_rejects_a_symlink() {
        let root = tmp_root("rtdir-symlink");
        let target = root.join("elsewhere");
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&target)
                .unwrap();
        }
        let dir = root.join("state");
        std::os::unix::fs::symlink(&target, &dir).unwrap();
        let err = ensure_runtime_dir_at(&dir, my_uid())
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dir_rejects_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp_root("rtdir-mode");
        let dir = root.join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_runtime_dir_at(&dir, my_uid())
            .unwrap_err()
            .to_string();
        assert!(err.contains("group/other"), "{err}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dir_rejects_a_foreign_owner() {
        // Cannot chown unprivileged, so ask for an owner the directory is not.
        let root = tmp_root("rtdir-owner");
        let dir = root.join("state");
        let err = ensure_runtime_dir_at(&dir, my_uid().wrapping_add(1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by uid"), "{err}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dir_rejects_a_plain_file() {
        let root = tmp_root("rtdir-file");
        let dir = root.join("state");
        std::fs::write(&dir, b"").unwrap();
        let err = ensure_runtime_dir_at(&dir, my_uid())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a directory"), "{err}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_runtime_path_lives_in_the_runtime_dir() {
        for path in [
            FW3_RULES_V4_PATH,
            FW3_RULES_V6_PATH,
            FW3_TRANSITION_PATH,
            FW3_LOCK_PATH,
            IFACES_PATH,
            FW4_POLICY_PATH,
            STOP_MARKER_PATH,
        ] {
            let rest = path
                .strip_prefix(RUNTIME_DIR)
                .unwrap_or_else(|| panic!("{path} is outside {RUNTIME_DIR}"));
            assert!(rest.starts_with('/') && !rest[1..].contains('/'), "{path}");
        }
        assert!(
            !RUNTIME_DIR.starts_with("/tmp/"),
            "runtime state must not live in /tmp"
        );
    }
}
