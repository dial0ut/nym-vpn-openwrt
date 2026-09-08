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

/// The firewall zone `uci-defaults/luci-app-nym-vpn` declares for the tunnel
/// devices (`nym+`): masquerade, MSS clamp and the `lan -> nym` forwarding
/// are fw3/fw4's own from then on. It masquerades, so [`wan_zone_devices`]
/// has to know it is not an uplink.
pub const NYM_ZONE: &str = "nym";

/// Inbound-exemption reply mark (distinct from the tunnel fwmark `0x14d`),
/// carried in `ct mark` and restored so replies route via the real WAN.
pub const EXEMPT_FWMARK: u32 = 0x14e;

/// L3 devices of every WAN zone: `uci show firewall` zones with `name='wan'`
/// or `masq='1'` (except our own [`NYM_ZONE`], which masquerades into the
/// tunnel), their `network` members resolved through `ubus call
/// network.interface dump` to `l3_device` (`pppoe-wan`, not the underlying
/// ethernet; `device` when the interface is down), plus raw `device` members.
/// Empty when either tool fails; callers fail closed on that. A zone, not a
/// route: `ip route get` points into the tunnel once connected.
pub fn wan_zone_devices() -> Vec<String> {
    let Some(uci) = run_stdout("uci", &["show", "firewall"]) else {
        return Vec::new();
    };
    let Some(dump) = run_stdout("ubus", &["call", "network.interface", "dump"]) else {
        return Vec::new();
    };
    resolve_wan_devices(&uci, &dump)
}

fn resolve_wan_devices(uci_show: &str, dump: &str) -> Vec<String> {
    let (networks, mut devices) = wan_zone_members(uci_show);
    let l3 = interface_l3_devices(dump);
    for network in networks {
        if let Some((_, dev)) = l3.iter().find(|(name, _)| *name == network)
            && !devices.contains(dev)
        {
            devices.push(dev.clone());
        }
    }
    devices
}

/// Device the kernel routes `ip` out on right now (`ip -o route get`): while
/// connected an address without a more specific route resolves to the
/// tunnel. `None` when unreachable.
pub fn route_device(ip: IpAddr) -> Option<String> {
    let out = run_stdout("ip", &["-o", "route", "get", &ip.to_string()])?;
    parse_route_get_device(&out)
}

fn run_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_route_get_device(route_get: &str) -> Option<String> {
    let mut iter = route_get.split_whitespace();
    while let Some(tok) = iter.next() {
        if tok == "dev" {
            return iter.next().map(str::to_string);
        }
    }
    None
}

/// `(network members, device members)` of the WAN zones in `uci show
/// firewall` output. Sections may be anonymous (`@zone[1]`) or named; list
/// values are space-separated, quoted on current uci and bare on 18.06.
fn wan_zone_members(uci_show: &str) -> (Vec<String>, Vec<String>) {
    #[derive(Default)]
    struct Section {
        is_zone: bool,
        name: String,
        masq: bool,
        networks: Vec<String>,
        devices: Vec<String>,
    }
    let unquote = |v: &str| v.trim().trim_matches('\'').to_string();
    let list = |v: &str| {
        v.split_whitespace()
            .map(unquote)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    };

    let mut sections: Vec<(String, Section)> = Vec::new();
    for line in uci_show.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(key) = key.strip_prefix("firewall.") else {
            continue;
        };
        let (id, option) = match key.split_once('.') {
            Some((id, option)) => (id, Some(option)),
            None => (key, None),
        };
        let idx = match sections.iter().position(|(s, _)| s == id) {
            Some(i) => i,
            None => {
                sections.push((id.to_string(), Section::default()));
                sections.len() - 1
            }
        };
        let section = &mut sections[idx].1;
        match option {
            None => section.is_zone = unquote(value) == "zone",
            Some("name") => section.name = unquote(value),
            Some("masq") => section.masq = unquote(value) == "1",
            Some("network") => section.networks = list(value),
            Some("device") => section.devices = list(value),
            Some(_) => {}
        }
    }

    let mut networks = Vec::new();
    let mut devices = Vec::new();
    for (_, s) in sections {
        if !s.is_zone || s.name == NYM_ZONE || !(s.name == "wan" || s.masq) {
            continue;
        }
        for n in s.networks {
            if !networks.contains(&n) {
                networks.push(n);
            }
        }
        for d in s.devices {
            if !devices.contains(&d) {
                devices.push(d);
            }
        }
    }
    (networks, devices)
}

/// `(interface, l3_device or device)` per entry of `ubus call
/// network.interface dump`. Hand-rolled to avoid a JSON dependency: names
/// never contain quotes or escapes, and the array key `"interface": [` is
/// skipped because its value is not a string.
fn interface_l3_devices(dump: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut segments = dump.split("\"interface\"");
    segments.next();
    for segment in segments {
        let Some(name) = string_after_colon(segment) else {
            continue;
        };
        let dev = json_string_field(segment, "l3_device")
            .or_else(|| json_string_field(segment, "device"));
        if let Some(dev) = dev {
            out.push((name.to_string(), dev.to_string()));
        }
    }
    out
}

fn json_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    string_after_colon(&json[json.find(&needle)? + needle.len()..])
}

/// `: "value"` at the start of `s` (whitespace tolerant); `None` for any
/// other value shape or an empty string.
fn string_after_colon(s: &str) -> Option<&str> {
    let s = s.trim_start().strip_prefix(':')?.trim_start();
    let value = s.strip_prefix('"')?;
    let close = value.find('"')?;
    let value = &value[..close];
    (!value.is_empty()).then_some(value)
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

    const UCI_FIREWALL_MULTI_WAN: &str = "\
firewall.@defaults[0]=defaults
firewall.@defaults[0].input='REJECT'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[0].network='lan' 'guest'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].input='REJECT'
firewall.@zone[1].masq='1'
firewall.@zone[1].mtu_fix='1'
firewall.@zone[1].network='wan' 'wanb'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.nym_zone=zone
firewall.nym_zone.name='nym'
firewall.nym_zone.device='nym+'
firewall.nym_zone.masq='1'
firewall.nym_zone.mtu_fix='1'
firewall.nym_lan_fwd=forwarding
firewall.nym_lan_fwd.src='lan'
firewall.nym_lan_fwd.dest='nym'
";

    /// Shape of `ubus call network.interface dump` on OpenWrt 25.12 (tab
    /// indent, space after the colon), cut to the fields that matter. `wanb`
    /// is PPPoE, so its `device` is the underlying ethernet.
    const UBUS_DUMP_MULTI_WAN: &str = "{
\t\"interface\": [
\t\t{
\t\t\t\"interface\": \"loopback\",
\t\t\t\"up\": true,
\t\t\t\"l3_device\": \"lo\",
\t\t\t\"proto\": \"static\",
\t\t\t\"device\": \"lo\",
\t\t\t\"data\": {
\t\t\t}
\t\t},
\t\t{
\t\t\t\"interface\": \"lan\",
\t\t\t\"up\": true,
\t\t\t\"l3_device\": \"br-lan\",
\t\t\t\"proto\": \"static\",
\t\t\t\"device\": \"br-lan\",
\t\t\t\"ipv4-address\": [
\t\t\t\t{
\t\t\t\t\t\"address\": \"10.0.0.1\",
\t\t\t\t\t\"mask\": 24
\t\t\t\t}
\t\t\t]
\t\t},
\t\t{
\t\t\t\"interface\": \"wan\",
\t\t\t\"up\": true,
\t\t\t\"l3_device\": \"eth1\",
\t\t\t\"proto\": \"dhcp\",
\t\t\t\"device\": \"eth1\",
\t\t\t\"route\": [
\t\t\t\t{
\t\t\t\t\t\"target\": \"0.0.0.0\",
\t\t\t\t\t\"nexthop\": \"203.0.113.1\"
\t\t\t\t}
\t\t\t]
\t\t},
\t\t{
\t\t\t\"interface\": \"wanb\",
\t\t\t\"up\": true,
\t\t\t\"l3_device\": \"pppoe-wanb\",
\t\t\t\"proto\": \"pppoe\",
\t\t\t\"device\": \"eth2\"
\t\t},
\t\t{
\t\t\t\"interface\": \"wan6\",
\t\t\t\"up\": false,
\t\t\t\"pending\": false,
\t\t\t\"available\": true,
\t\t\t\"proto\": \"dhcpv6\",
\t\t\t\"device\": \"eth1\"
\t\t}
\t]
}
";

    /// The `nym` zone masquerades like an uplink but is the tunnel; its
    /// `nym+` device must never count as a WAN device.
    #[test]
    fn wan_zone_collects_every_network_of_the_wan_zone() {
        let (networks, devices) = wan_zone_members(UCI_FIREWALL_MULTI_WAN);
        assert_eq!(networks, ["wan", "wanb"]);
        assert!(devices.is_empty(), "the nym zone's device is not an uplink");
    }

    #[test]
    fn wan_zone_matches_masq_zones_named_sections_and_bare_lists() {
        // A second masquerading uplink zone under another name; 18.06 uci
        // prints list values unquoted; a raw `device` member; a non-zone
        // section named "wan".
        let uci = "\
firewall.lanzone=zone
firewall.lanzone.name=lan
firewall.lanzone.network=lan
firewall.wanzone=zone
firewall.wanzone.name=wan
firewall.wanzone.network=wan
firewall.lte=zone
firewall.lte.name=mobile
firewall.lte.masq=1
firewall.lte.network=wwan
firewall.lte.device=usb0
firewall.@rule[0]=rule
firewall.@rule[0].name=wan
firewall.@rule[0].network=lan
";
        let (networks, devices) = wan_zone_members(uci);
        assert_eq!(networks, ["wan", "wwan"]);
        assert_eq!(devices, ["usb0"]);
    }

    #[test]
    fn dump_resolves_l3_device_with_device_fallback() {
        let l3 = interface_l3_devices(UBUS_DUMP_MULTI_WAN);
        let get = |name: &str| l3.iter().find(|(n, _)| n == name).map(|(_, d)| d.as_str());
        assert_eq!(get("lan"), Some("br-lan"));
        assert_eq!(get("wan"), Some("eth1"));
        assert_eq!(
            get("wanb"),
            Some("pppoe-wanb"),
            "PPPoE: the virtual netdev, not eth2"
        );
        assert_eq!(
            get("wan6"),
            Some("eth1"),
            "down interface: `device` fallback"
        );
        assert_eq!(get("loopback"), Some("lo"));
        assert_eq!(l3.len(), 5);
    }

    #[test]
    fn wan_devices_from_fixtures() {
        assert_eq!(
            resolve_wan_devices(UCI_FIREWALL_MULTI_WAN, UBUS_DUMP_MULTI_WAN),
            ["eth1", "pppoe-wanb"]
        );
        // `wan6` shares eth1 with `wan`: no duplicate.
        let uci = "firewall.@zone[1]=zone\nfirewall.@zone[1].name='wan'\n\
                   firewall.@zone[1].network='wan' 'wan6'\n";
        assert_eq!(resolve_wan_devices(uci, UBUS_DUMP_MULTI_WAN), ["eth1"]);
        assert!(resolve_wan_devices("", UBUS_DUMP_MULTI_WAN).is_empty());
        assert!(resolve_wan_devices(UCI_FIREWALL_MULTI_WAN, "").is_empty());
    }

    #[test]
    fn string_field_absent_or_empty_is_none() {
        assert_eq!(json_string_field(r#"{"up":false}"#, "l3_device"), None);
        assert_eq!(
            json_string_field(r#"{"l3_device":"","device":"wan"}"#, "l3_device"),
            None
        );
        assert_eq!(
            json_string_field(r#"{"l3_device":"pppoe-wan"}"#, "l3_device"),
            Some("pppoe-wan")
        );
        // `"l3_device"` must not satisfy a lookup of `"device"`.
        assert_eq!(
            json_string_field(r#"{"l3_device":"pppoe-wan","device":"eth1"}"#, "device"),
            Some("eth1")
        );
    }

    #[test]
    fn route_get_device_token() {
        assert_eq!(
            parse_route_get_device("10.0.0.2 dev br-lan src 10.0.0.1 uid 0 \\    cache \n")
                .as_deref(),
            Some("br-lan")
        );
        assert_eq!(
            parse_route_get_device(
                "1.1.1.1 via 10.64.0.1 dev nym0 src 10.64.0.2 uid 0 \\    cache \n"
            )
            .as_deref(),
            Some("nym0")
        );
        assert_eq!(parse_route_get_device(""), None);
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
