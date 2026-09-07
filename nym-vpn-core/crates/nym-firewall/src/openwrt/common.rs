// SPDX-License-Identifier: GPL-3.0-only

//! Constants and runtime probes shared between the fw3 and fw4 backends.

use std::net::IpAddr;
use std::path::Path;

use super::{Error, Result};

/// Root-owned private directory for every piece of kill-switch runtime
/// state shared between the daemon, the firewall includes (`fw3-include.sh`,
/// `fw4-include.sh`, `fw-boot-guard.sh`), the init script and the package
/// hooks. It lives under `/var/run` (OpenWrt: a root-owned, 0755 tmpfs
/// directory that exists before the firewall starts, so a reboot clears it)
/// rather than `/tmp`, which is world-writable: the includes run as root and
/// act on what they find here — a rules file is fed to `iptables-restore`,
/// the stop marker suppresses the boot-time block — so an unprivileged
/// local process must not be able to plant any of it. Only root can create
/// entries in `/var/run`; [`ensure_runtime_dir`] additionally refuses to use
/// the directory unless it is a real directory owned by uid 0 with no
/// group/other permission bits, and the scripts perform the same check
/// before trusting a file in it. The path is a contract with those scripts:
/// each derives its file names from one `NYM_RUNTIME_DIR` variable whose
/// default the tests pin to this constant.
pub const RUNTIME_DIR: &str = "/var/run/nym-firewall";

/// Persisted fw3 state, consumed by `fw3-include.sh` to re-apply the
/// kill-switch after an fw3 restart has flushed the iptables tables (an fw3
/// *reload* leaves foreign chains alone; the include then only reconciles).
/// The file names are part of the contract with that script and with the
/// package prerm — keep them in sync when renaming.
pub const FW3_RULES_V4_PATH: &str = "/var/run/nym-firewall/v4.rules";
pub const FW3_RULES_V6_PATH: &str = "/var/run/nym-firewall/v6.rules";
/// Present for the full duration of any fw3 state transition. The reload
/// include treats its presence as an instruction to install an emergency
/// OUTPUT/FORWARD block instead of reading or cleaning partially-updated
/// persisted state. A crash deliberately leaves it behind; a later successful
/// apply/reset or an explicit daemon stop removes it.
pub const FW3_TRANSITION_PATH: &str = "/var/run/nym-firewall/transition";
/// Advisory `flock(2)` file serializing every writer of fw3 state: this
/// backend's apply/forwarding-only/reset, `fw3-include.sh` (run by fw3 on
/// every reload) and the init script's stop-time teardown. The transition
/// marker alone cannot exclude a concurrent include: it could test the marker,
/// lose the CPU while the daemon finished and lifted its block, then install
/// an emergency block nobody removes. Each writer holds the lock for its whole
/// mutation, so the include observes fw3 state only between complete
/// transitions. Never deleted while the package is installed.
pub const FW3_LOCK_PATH: &str = "/var/run/nym-firewall/lock";
/// Tunnel interface list (one name per line) for masquerade restore. Shared
/// naming with the fw4 include script, which reads it as an optional hint.
pub const IFACES_PATH: &str = "/var/run/nym-firewall/ifaces";
/// Optional saved nftables policy the fw4 include would replay. The fw4
/// backend does not write it today (it pipes its ruleset to `nft -f -`); the
/// name is reserved so the include's forward-compatible read stays inside
/// the trusted directory instead of taking an `nft -f` input from `/tmp`.
/// Consumed by the shell side only; the tests pin the script to it.
#[allow(dead_code)]
pub const FW4_POLICY_PATH: &str = "/var/run/nym-firewall/policy.nft";
/// Stop marker written by the init script on an explicit `stop` and read by
/// `fw-boot-guard.sh`: while present, no boot-time block is installed
/// because the administrator asked for the network back and no daemon is
/// coming to lift one. The daemon never touches it; the constant exists so
/// the tests can pin the scripts to the same name.
#[allow(dead_code)]
pub const STOP_MARKER_PATH: &str = "/var/run/nym-firewall/stopped";

/// Make sure [`RUNTIME_DIR`] exists and can be trusted, failing closed
/// otherwise. Creates it 0700 when missing; then requires a real directory
/// (not a symlink), owned by root, with no group/other permission bits.
/// Anything else means the state files in it could have been planted or
/// read by an unprivileged process, and no policy is applied on top of that.
pub fn ensure_runtime_dir() -> Result<()> {
    ensure_runtime_dir_at(Path::new(RUNTIME_DIR), 0)
}

/// [`ensure_runtime_dir`] for an arbitrary path and expected owner uid, so
/// the checks can be exercised in tests as an unprivileged user.
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

    // symlink_metadata: a symlink planted at this path must be seen as a
    // symlink, not as whatever it points at.
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

/// nftables table holding the boot-time kill-switch block. `fw4-include.sh`
/// installs it at firewall start when the kill-switch is armed
/// (`fw-boot-guard.sh`: on in the daemon's saved settings, daemon enabled at
/// boot, not stopped by the administrator) and no `inet nym` table exists yet
/// — the window between network-up and this daemon's first policy. The fw4
/// backend deletes it as the last step of every apply and reset; the init
/// script and package prerm delete it on explicit stop and removal. The name
/// is a contract with those scripts. fw3 needs no counterpart: its include
/// reuses the `NYM_EMERGENCY_*` chains, which the fw3 backend already lifts.
pub const FW4_BOOT_TABLE: &str = "nym_boot";

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
        // Idempotent on the directory it just created.
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
        // Cannot chown to another user without privileges, so ask for an
        // owner the directory is not: the check must fail the same way it
        // would for a directory root did not create.
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
