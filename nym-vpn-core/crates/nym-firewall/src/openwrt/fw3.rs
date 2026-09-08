// SPDX-License-Identifier: GPL-3.0-only

//! fw3 (iptables) backend: kill-switch rules in owned `NYM_*` chains that
//! fw3's `*_rule` hook chains jump to first, applied atomically with
//! `iptables-restore --noflush`.
//!
//! `fw3 reload` deletes only fw3's own tagged rules and skips the `*_rule`
//! chains, so our chains and jumps survive it; the include then only
//! reconciles. `fw3 restart`/`stop` flush every table and run the includes
//! last, which is what the persisted restore scripts are for. The window
//! between that flush and the include is fw3's own; nothing here closes it.

use std::fs::File;
use std::io::Write as IoWrite;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use super::boot_rules::{self, EMERGENCY_FORWARD_CHAIN, EMERGENCY_OUTPUT_CHAIN};
use super::common::{
    FW3_HOOK_FORWARD, FW3_HOOK_INPUT, FW3_HOOK_OUTPUT, FW3_LOCK_PATH, FW3_RULES_V4_PATH,
    FW3_RULES_V6_PATH, FW3_TRANSITION_PATH, IFACES_PATH, Ipv6Status, ensure_runtime_dir,
    ipv6_status,
};
use super::render_iptables::{
    self, AddrFamily, CHAIN_FORWARD, CHAIN_INPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING,
    CHAIN_OUTPUT,
};
use super::rules::RuleSet;
use super::{Error, Result};

/// Chain we own in the iptables `nat` table; POSTROUTING jumps to it.
const NAT_CHAIN: &str = "NYM_POSTROUTING";

/// LAN<->tunnel forwarding plane (fw3 analogue of fw4's `nym_forward_lan`).
/// Needed with the kill-switch off too: tun devices belong to no fw3 zone,
/// so fw3's forward policy rejects LAN flows without explicit accepts. Also
/// carries the TCP MSS clamp for the 1340-MTU tunnel.
const FORWARD_LAN_CHAIN: &str = "NYM_FORWARD_LAN";

/// Fail-closed transition: lock, publish the transition marker, install the
/// emergency block for any family not yet hooked (a crash between chain
/// creation and hook insertion would otherwise leave it open), build the
/// live chains, persist state, remove the marker, re-activate if a flush
/// raced us, lift the block. The marker covers crashes (left behind on
/// purpose), the lock covers concurrency with the include and init script.
pub fn apply(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying firewall policy via fw3/iptables backend");
    ensure_runtime_dir()?;
    let _lock = lock_fw3_state()?;

    let with_v6 = match ipv6_status() {
        Ipv6Status::Enabled => true,
        Ipv6Status::Disabled => {
            tracing::info!("IPv6 disabled in the kernel, skipping ip6tables rules");
            false
        }
        Ipv6Status::Unusable => {
            return Err(Error::ApplyError(
                "IPv6 is enabled in the kernel but ip6tables is unusable; refusing to \
                 install an IPv4-only kill-switch (IPv6 traffic would bypass it). \
                 Install ip6tables and kmod-ip6tables, or disable IPv6."
                    .into(),
            ));
        }
    };

    begin_transition()?;

    // Per family: IPv6 can become enabled long after IPv4 was first hooked.
    for family in [AddrFamily::V4, AddrFamily::V6] {
        if family == AddrFamily::V6 && !with_v6 {
            continue;
        }
        if !jumps_present(family) {
            tracing::info!(
                "First fw3 policy activation for {}; installing emergency block while chains are built",
                ipt_cmd(family)
            );
            install_emergency_block(family)?;
        }
    }

    // The persisted scripts are the post-fallback (owner/CONNMARK) ones.
    let v4_script = apply_family(rs, AddrFamily::V4)?;
    let v6_script = if with_v6 {
        Some(apply_family(rs, AddrFamily::V6)?)
    } else {
        None
    };

    persist_state(&v4_script, v6_script.as_deref(), &rs.tunnel_interfaces)?;
    finish_transition()?;

    // Missing jumps mean an fw3 restart flushed the tables underneath us (a
    // reload leaves them); converge from the persisted scripts.
    if !jumps_present(AddrFamily::V4) {
        tracing::info!(
            "Firewall tables were flushed during the policy apply; re-activating IPv4 rules"
        );
        activate_family_script(&v4_script, AddrFamily::V4)?;
    }
    if let Some(script) = &v6_script
        && !jumps_present(AddrFamily::V6)
    {
        tracing::info!(
            "Firewall tables were flushed during the policy apply; re-activating IPv6 rules"
        );
        activate_family_script(script, AddrFamily::V6)?;
    }

    if rs.tunnel_interfaces.is_empty() {
        remove_masquerade_rules();
        remove_forwarding_rules();
    } else {
        add_masquerade_rules(&rs.tunnel_interfaces)?;
        add_forwarding_rules(&rs.tunnel_interfaces)?;
    }

    remove_emergency_blocks(with_v6)?;

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Exclusive fw3 state lock, released on guard drop. Never hold it across
/// an `.await`.
fn lock_fw3_state() -> Result<Flock<File>> {
    lock_state_file(FW3_LOCK_PATH)
}

fn lock_state_file(path: &str) -> Result<Flock<File>> {
    // O_NOFOLLOW: a planted symlink must not be opened elsewhere as root.
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            Error::ApplyError(format!(
                "open fw3 state lock {path}: {e}; refusing to change live firewall state"
            ))
        })?;
    let file = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => return Ok(lock),
        Err((file, Errno::EWOULDBLOCK)) => file,
        Err((_, e)) => {
            return Err(Error::ApplyError(format!("lock fw3 state {path}: {e}")));
        }
    };
    tracing::debug!("fw3 state lock {path} is held by another writer; waiting");
    let waited = Instant::now();
    let lock = Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, e)| Error::ApplyError(format!("lock fw3 state {path}: {e}")))?;
    tracing::debug!(
        "fw3 state lock {path} acquired after {:?}",
        waited.elapsed()
    );
    Ok(lock)
}

fn begin_transition() -> Result<()> {
    write_transition_marker(FW3_TRANSITION_PATH)
}

fn finish_transition() -> Result<()> {
    remove_state_file(FW3_TRANSITION_PATH)
}

fn write_transition_marker(path: &str) -> Result<()> {
    write_state_file(path, "fw3 state transition in progress\n").map_err(|e| {
        Error::ApplyError(format!(
            "create fw3 transition marker: {e}; refusing to change live firewall state"
        ))
    })
}

fn install_emergency_block(family: AddrFamily) -> Result<()> {
    run_restore(&emergency_script(family), family)
}

/// The daemon only ever installs the transition set; the boot set is the
/// include's, and this backend lifts it.
fn emergency_script(family: AddrFamily) -> String {
    boot_rules::iptables_emergency_rules(boot_family(family), boot_rules::Mode::Transition)
}

fn boot_family(family: AddrFamily) -> boot_rules::Family {
    match family {
        AddrFamily::V4 => boot_rules::Family::V4,
        AddrFamily::V6 => boot_rules::Family::V6,
    }
}

/// An fw3 restart recreates the `*_rule` chains empty (a reload keeps them),
/// so a missing jump means the tables were flushed underneath the apply.
fn jumps_present(family: AddrFamily) -> bool {
    let ipt = ipt_cmd(family);
    JUMPS.iter().all(|(hook, target)| {
        Command::new(ipt)
            .args(["-w", "-C", hook, "-j", target])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn activate_family_script(script: &str, family: AddrFamily) -> Result<()> {
    run_restore(script, family)?;
    setup_jumps(family)?;
    if script.lines().any(|line| line == "*mangle") {
        setup_mangle_jumps(family)
    } else {
        cleanup_mangle(family);
        Ok(())
    }
}

/// Failure here fails the apply: never report a working connection while
/// the emergency blackhole is still active.
fn remove_emergency_block(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, chain) in [
        (FW3_HOOK_OUTPUT, EMERGENCY_OUTPUT_CHAIN),
        (FW3_HOOK_FORWARD, EMERGENCY_FORWARD_CHAIN),
    ] {
        if !chain_exists(ipt, chain)? {
            continue;
        }
        tracing::info!("Removing emergency {ipt} block left by a firewall reload ({chain})");
        loop {
            let output = Command::new(ipt)
                .args(["-w", "-D", hook, "-j", chain])
                .output()
                .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
            if !output.status.success() {
                break;
            }
        }
        let still_present = Command::new(ipt)
            .args(["-w", "-C", hook, "-j", chain])
            .output()
            .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?
            .status
            .success();
        if still_present {
            return Err(Error::ApplyError(format!(
                "failed to remove emergency jump {hook} -> {chain} from {ipt}"
            )));
        }

        // The include may be lifting the same chains concurrently; a chain
        // already gone is the outcome we wanted.
        for op in ["-F", "-X"] {
            if let Err(e) = run_ipt(ipt, &["-w", op, chain]) {
                if chain_exists(ipt, chain)? {
                    return Err(e);
                }
                break;
            }
        }
    }
    Ok(())
}

fn chain_exists(ipt: &str, chain: &str) -> Result<bool> {
    Command::new(ipt)
        .args(["-w", "-L", chain, "-n"])
        .output()
        .map(|o| o.status.success())
        .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))
}

fn remove_emergency_blocks(with_v6: bool) -> Result<()> {
    remove_emergency_block(AddrFamily::V4)?;
    if with_v6 {
        remove_emergency_block(AddrFamily::V6)?;
    } else {
        // Without IPv6, ip6tables may be uninspectable; best-effort.
        let _ = remove_emergency_block(AddrFamily::V6);
    }
    Ok(())
}

/// Returns the restore script that was actually applied, for persistence.
fn apply_family(rs: &RuleSet, family: AddrFamily) -> Result<String> {
    // libxt_CONNMARK ships in iptables-mod-conntrack-extra, which stock
    // images lack; one unparseable mangle rule would fail the whole restore.
    let stripped;
    let rs = if !rs.mangle.is_empty() && !connmark_target_available(family) {
        let ipt = ipt_cmd(family);
        tracing::error!(
            "{ipt} CONNMARK target unavailable; omitting inbound-exemption \
             mangle rules. The kill switch remains active but exempted \
             inbound services will not work. Install \
             iptables-mod-conntrack-extra and kmod-ipt-conntrack-extra."
        );
        stripped = rs.without_mangle_rules();
        &stripped
    } else {
        rs
    };

    let script = apply_filter(rs, family)?;
    setup_jumps(family)?;
    if !rs.mangle.is_empty() {
        setup_mangle_jumps(family)?;
    } else {
        cleanup_mangle(family);
    }
    Ok(script)
}

/// Probed with a real append to a scratch chain: iptables exits 0 for
/// unknown targets under `--help`.
fn connmark_target_available(family: AddrFamily) -> bool {
    let ipt = ipt_cmd(family);
    const PROBE: &str = "NYM_CONNMARK_PROBE";
    let _ = Command::new(ipt)
        .args(["-w", "-t", "mangle", "-N", PROBE])
        .output();
    let ok = Command::new(ipt)
        .args(["-w", "-t", "mangle", "-A", PROBE, "-j", "CONNMARK", "--restore-mark"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    let _ = Command::new(ipt)
        .args(["-w", "-t", "mangle", "-F", PROBE])
        .output();
    let _ = Command::new(ipt)
        .args(["-w", "-t", "mangle", "-X", PROBE])
        .output();
    ok
}

/// Persist for `fw3-include.sh` to replay after an fw3 restart. Failure
/// fails the apply: success without it leaves a hole at the next restart.
fn persist_state(v4_script: &str, v6_script: Option<&str>, interfaces: &[String]) -> Result<()> {
    write_state_file(FW3_RULES_V4_PATH, v4_script)?;
    match v6_script {
        Some(script) => write_state_file(FW3_RULES_V6_PATH, script)?,
        None => remove_state_file(FW3_RULES_V6_PATH)?,
    }
    persist_ifaces(interfaces)
}

fn persist_ifaces(interfaces: &[String]) -> Result<()> {
    if interfaces.is_empty() {
        remove_state_file(IFACES_PATH)
    } else {
        let mut buf = interfaces.join("\n");
        buf.push('\n');
        write_state_file(IFACES_PATH, &buf)
    }
}

/// Temp file + rename so a racing reload never sees a half-written script.
/// `O_EXCL | O_NOFOLLOW` on the temp name: a planted file or symlink fails
/// the open instead of being followed as root.
fn write_state_file(path: &str, contents: &str) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "{path}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    write_state_file_via(path, &tmp, contents)
}

fn write_state_file_via(path: &str, tmp: &str, contents: &str) -> Result<()> {
    let written = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)
        .and_then(|mut f| {
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        Error::ApplyError(format!(
            "persist firewall state to {path}: {e}; refusing to report a policy \
             that would disappear on firewall restart"
        ))
    })
}

fn remove_state_file(path: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::ApplyError(format!(
            "remove persisted firewall state {path}: {e}; stale policy could be resurrected on reload"
        ))),
    }
}

fn clear_persisted_state() -> Result<()> {
    remove_state_file(FW3_RULES_V4_PATH)?;
    remove_state_file(FW3_RULES_V6_PATH)?;
    remove_state_file(IFACES_PATH)
}

/// Kill-switch off: forwarding plane only, blocking chains removed.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw3/iptables");
    ensure_runtime_dir()?;
    let _lock = lock_fw3_state()?;

    let with_v6 = ipv6_status() == Ipv6Status::Enabled;
    begin_transition()?;

    // Persisted blocking state goes before the live firewall opens; the
    // marker keeps a racing reload from reading the absent v4 file as "open".
    remove_state_file(FW3_RULES_V4_PATH)?;
    remove_state_file(FW3_RULES_V6_PATH)?;
    persist_ifaces(&rs.tunnel_interfaces)?;

    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    cleanup_filter(AddrFamily::V6);
    cleanup_mangle(AddrFamily::V6);

    if rs.tunnel_interfaces.is_empty() {
        remove_masquerade_rules();
        remove_forwarding_rules();
    } else {
        add_masquerade_rules(&rs.tunnel_interfaces)?;
        add_forwarding_rules(&rs.tunnel_interfaces)?;
    }

    finish_transition()?;
    remove_emergency_blocks(with_v6)?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Tear down the jumps and our chains. Best-effort throughout.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw3/iptables backend");
    ensure_runtime_dir()?;
    let _lock = lock_fw3_state()?;

    let with_v6 = ipv6_status() == Ipv6Status::Enabled;
    begin_transition()?;

    clear_persisted_state()?;

    remove_masquerade_rules();
    remove_forwarding_rules();
    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    cleanup_filter(AddrFamily::V6);
    cleanup_mangle(AddrFamily::V6);

    finish_transition()?;
    remove_emergency_blocks(with_v6)?;

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Without the `owner` match the daemon-only exceptions are dropped rather
/// than widened into unscoped accepts.
fn apply_filter(rs: &RuleSet, family: AddrFamily) -> Result<String> {
    let stripped;
    let rs = if rs.has_skuid() && !owner_match_available(family) {
        let ipt = ipt_cmd(family);
        tracing::error!(
            "{ipt} owner match unavailable; omitting daemon-only exceptions \
             (DNS and API endpoints). The kill switch remains active but the \
             daemon cannot resolve DNS or reach the API, so connecting will \
             fail until the extension is installed. Install iptables-mod-extra \
             and kmod-ipt-extra, or disable the kill switch."
        );
        stripped = rs.without_skuid_rules();
        &stripped
    } else {
        rs
    };

    let script = render_iptables::render(rs, family);
    run_restore(&script, family)?;
    Ok(script)
}

fn owner_match_available(family: AddrFamily) -> bool {
    let ipt = ipt_cmd(family);
    Command::new(ipt)
        .args(["-m", "owner", "--help"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_restore(script: &str, family: AddrFamily) -> Result<()> {
    let cmd = match family {
        AddrFamily::V4 => "iptables-restore",
        AddrFamily::V6 => "ip6tables-restore",
    };

    let mut child = Command::new(cmd)
        .args(["--noflush", "-w"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::ApplyError(format!("spawn {cmd}: {e}")))?;

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())
        .map_err(|e| Error::ApplyError(format!("write {cmd} stdin: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| Error::ApplyError(format!("wait {cmd}: {e}")))?;

    if !output.status.success() {
        return Err(Error::ApplyError(format!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Each jump must lead its hook chain (only other Nym jumps ahead of it), or
/// a foreign rule at position 1 could accept past the kill-switch. A jump in
/// a valid position is left alone; delete + re-insert would unhook briefly.
fn setup_jumps(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, target) in JUMPS {
        ensure_jump(ipt, hook, target, JumpPosition::Leading)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JumpPosition {
    /// Rule 1 exactly: the MSS clamp must run before the kill-switch chain
    /// accepts tunnel-bound flows.
    First,
    /// Only jumps to our own `NYM_*` chains may precede it.
    Leading,
}

/// Rule specs of a chain with the `-A <hook> ` prefix stripped, in order.
fn list_hook_rules(ipt: &str, hook: &str) -> Result<Vec<String>> {
    let output = Command::new(ipt)
        .args(["-w", "-S", hook])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
    if !output.status.success() {
        return Err(Error::ApplyError(format!(
            "{ipt} -S {hook} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let prefix = format!("-A {hook} ");
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix(&prefix).map(str::to_string))
        .collect())
}

fn jump_position_ok(rules: &[String], jump: &str, position: JumpPosition) -> bool {
    match rules.iter().position(|r| r == jump) {
        Some(0) => true,
        Some(i) => {
            position == JumpPosition::Leading && rules[..i].iter().all(|r| r.starts_with("-j NYM_"))
        }
        None => false,
    }
}

fn ensure_jump(ipt: &str, hook: &str, target: &str, position: JumpPosition) -> Result<()> {
    let jump = format!("-j {target}");
    let mut rules = list_hook_rules(ipt, hook)?;
    if !jump_position_ok(&rules, &jump, position) {
        run_ipt(ipt, &["-w", "-I", hook, "1", "-j", target])?;
        rules = list_hook_rules(ipt, hook)?;
    }
    // Highest rule number first so the remaining numbers stay valid.
    let first = rules.iter().position(|r| r == &jump).unwrap_or(0);
    for (idx, rule) in rules.iter().enumerate().skip(first + 1).rev() {
        if rule == &jump {
            let num = (idx + 1).to_string();
            run_ipt(ipt, &["-w", "-D", hook, &num])?;
        }
    }
    Ok(())
}

fn cleanup_filter(family: AddrFamily) {
    let ipt = ipt_cmd(family);

    for (hook, target) in JUMPS {
        let _ = Command::new(ipt)
            .args(["-w", "-D", hook, "-j", target])
            .output();
    }
    for chain in [CHAIN_INPUT, CHAIN_OUTPUT, CHAIN_FORWARD] {
        let _ = Command::new(ipt).args(["-w", "-F", chain]).output();
        let _ = Command::new(ipt).args(["-w", "-X", chain]).output();
    }
}

const JUMPS: [(&str, &str); 3] = [
    (FW3_HOOK_INPUT, CHAIN_INPUT),
    (FW3_HOOK_OUTPUT, CHAIN_OUTPUT),
    (FW3_HOOK_FORWARD, CHAIN_FORWARD),
];

/// fw3 has no `*_rule` chains in mangle; jump from the built-ins directly.
const MANGLE_JUMPS: [(&str, &str); 2] = [
    ("PREROUTING", CHAIN_MANGLE_PREROUTING),
    ("OUTPUT", CHAIN_MANGLE_OUTPUT),
];

/// Presence only, not position: a foreign rule ahead of a mangle jump can
/// only leave a flow unmarked (blocked), never bypass.
fn setup_mangle_jumps(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, target) in MANGLE_JUMPS {
        if jump_present(ipt, &["-t", "mangle"], hook, target)? {
            continue;
        }
        let output = Command::new(ipt)
            .args(["-w", "-t", "mangle", "-I", hook, "1", "-j", target])
            .output()
            .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
        if !output.status.success() {
            return Err(Error::ApplyError(format!(
                "{ipt} -t mangle -I {hook} -j {target} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }
    Ok(())
}

/// A missing hook chain (firewall stopped) reads as absent; only a failed
/// spawn is an error.
fn jump_present(ipt: &str, table: &[&str], hook: &str, target: &str) -> Result<bool> {
    let mut args = vec!["-w"];
    args.extend_from_slice(table);
    args.extend_from_slice(&["-C", hook, "-j", target]);
    Ok(Command::new(ipt)
        .args(&args)
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?
        .status
        .success())
}

fn cleanup_mangle(family: AddrFamily) {
    let ipt = ipt_cmd(family);
    for (hook, target) in MANGLE_JUMPS {
        let _ = Command::new(ipt)
            .args(["-w", "-t", "mangle", "-D", hook, "-j", target])
            .output();
    }
    for chain in [CHAIN_MANGLE_PREROUTING, CHAIN_MANGLE_OUTPUT] {
        let _ = Command::new(ipt)
            .args(["-w", "-t", "mangle", "-F", chain])
            .output();
        let _ = Command::new(ipt)
            .args(["-w", "-t", "mangle", "-X", chain])
            .output();
    }
}

fn ipt_cmd(family: AddrFamily) -> &'static str {
    match family {
        AddrFamily::V4 => "iptables",
        AddrFamily::V6 => "ip6tables",
    }
}

fn add_masquerade_rules(interfaces: &[String]) -> Result<()> {
    let output = Command::new("iptables")
        .args(["-w", "-t", "nat", "-N", NAT_CHAIN])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn iptables: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already exists") {
            return Err(Error::ApplyError(format!(
                "iptables -t nat -N {NAT_CHAIN} failed: {}",
                stderr.trim()
            )));
        }
    }

    let output = Command::new("iptables")
        .args(["-w", "-t", "nat", "-F", NAT_CHAIN])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn iptables: {e}")))?;
    if !output.status.success() {
        return Err(Error::ApplyError(format!(
            "iptables -t nat -F {NAT_CHAIN} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    for iface in interfaces {
        let output = Command::new("iptables")
            .args([
                "-w", "-t", "nat", "-A", NAT_CHAIN, "-o", iface, "-j", "MASQUERADE",
            ])
            .output()
            .map_err(|e| Error::ApplyError(format!("spawn iptables: {e}")))?;
        if !output.status.success() {
            return Err(Error::ApplyError(format!(
                "iptables -t nat -A {NAT_CHAIN} -o {iface}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        tracing::debug!("Populated {NAT_CHAIN} for interface {iface}");
    }

    let jump_present = Command::new("iptables")
        .args(["-w", "-t", "nat", "-C", "POSTROUTING", "-j", NAT_CHAIN])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !jump_present {
        let output = Command::new("iptables")
            .args(["-w", "-t", "nat", "-A", "POSTROUTING", "-j", NAT_CHAIN])
            .output()
            .map_err(|e| Error::ApplyError(format!("spawn iptables: {e}")))?;
        if !output.status.success() {
            return Err(Error::ApplyError(format!(
                "iptables -t nat -A POSTROUTING -j {NAT_CHAIN}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }

    Ok(())
}

/// IPv6 is best-effort: the kernel may lack it, and these are additive accepts.
fn add_forwarding_rules(interfaces: &[String]) -> Result<()> {
    add_forwarding_rules_family("iptables", interfaces)?;
    if let Err(e) = add_forwarding_rules_family("ip6tables", interfaces) {
        tracing::debug!("ip6tables forwarding plane (non-fatal): {e}");
    }
    Ok(())
}

fn add_forwarding_rules_family(ipt: &str, interfaces: &[String]) -> Result<()> {
    let output = Command::new(ipt)
        .args(["-w", "-N", FORWARD_LAN_CHAIN])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("exists") {
            return Err(Error::ApplyError(format!(
                "{ipt} -N {FORWARD_LAN_CHAIN} failed: {}",
                stderr.trim()
            )));
        }
    }

    run_ipt(ipt, &["-w", "-F", FORWARD_LAN_CHAIN])?;

    for iface in interfaces {
        // MSS clamp must precede the accepts.
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-o", iface, "-p", "tcp", "--tcp-flags",
            "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-i", iface, "-p", "tcp", "--tcp-flags",
            "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
        run_ipt(ipt, &["-w", "-A", FORWARD_LAN_CHAIN, "-o", iface, "-j", "ACCEPT"])?;
        // Established only: the exit never initiates into the LAN.
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-i", iface, "-m", "conntrack", "--ctstate",
            "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])?;
        tracing::debug!("Populated {FORWARD_LAN_CHAIN} ({ipt}) for interface {iface}");
    }
    ensure_jump(ipt, FW3_HOOK_FORWARD, FORWARD_LAN_CHAIN, JumpPosition::First)
}

fn remove_forwarding_rules() {
    for ipt in ["iptables", "ip6tables"] {
        let _ = Command::new(ipt)
            .args(["-w", "-D", FW3_HOOK_FORWARD, "-j", FORWARD_LAN_CHAIN])
            .output();
        let _ = Command::new(ipt)
            .args(["-w", "-F", FORWARD_LAN_CHAIN])
            .output();
        let _ = Command::new(ipt)
            .args(["-w", "-X", FORWARD_LAN_CHAIN])
            .output();
    }
}

fn run_ipt(ipt: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(ipt)
        .args(args)
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ApplyError(format!(
            "{ipt} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn remove_masquerade_rules() {
    // -D removes one match per call; loop for stale duplicates.
    loop {
        let removed = Command::new("iptables")
            .args(["-w", "-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !removed {
            break;
        }
    }
    let _ = Command::new("iptables")
        .args(["-w", "-t", "nat", "-F", NAT_CHAIN])
        .output();
    let _ = Command::new("iptables")
        .args(["-w", "-t", "nat", "-X", NAT_CHAIN])
        .output();
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::common::{RUNTIME_DIR, STOP_MARKER_PATH};
    use super::*;

    #[test]
    fn jump_position_rules() {
        let r = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let j = "-j NYM_OUTPUT";
        assert!(jump_position_ok(&r(&[j]), j, JumpPosition::Leading));
        assert!(jump_position_ok(&r(&[j, "-j ACCEPT"]), j, JumpPosition::First));
        assert!(jump_position_ok(&r(&["-j NYM_EMERGENCY_OUT", j]), j, JumpPosition::Leading));
        assert!(!jump_position_ok(&r(&["-j NYM_EMERGENCY_OUT", j]), j, JumpPosition::First));
        assert!(!jump_position_ok(&r(&["-j ACCEPT", j]), j, JumpPosition::Leading));
        assert!(!jump_position_ok(&r(&["-p tcp -j NYM_OUTPUT", j]), j, JumpPosition::Leading));
        assert!(!jump_position_ok(&r(&[]), j, JumpPosition::Leading));
    }

    #[test]
    fn emergency_script_keeps_reply_traffic_and_never_touches_input() {
        for family in [AddrFamily::V4, AddrFamily::V6] {
            let script = emergency_script(family);
            assert!(script.contains("--ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT"));
            assert!(script.contains("-A NYM_EMERGENCY_OUT -j DROP"));
            assert!(script.contains("-I output_rule 1 -j NYM_EMERGENCY_OUT"));
            assert!(script.contains("-I forwarding_rule 1 -j NYM_EMERGENCY_FWD"));
            assert!(!script.contains("input_rule"));
        }
        assert!(emergency_script(AddrFamily::V6).contains("-p icmpv6 --icmpv6-type neighbour-solicitation"));
        assert!(!emergency_script(AddrFamily::V4).contains("icmpv6"));
    }

    /// Rule content itself is tested in `boot_rules`.
    #[test]
    fn include_script_installs_the_generated_rule_sets() {
        const INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");
        let lines: Vec<&str> = INCLUDE.lines().map(str::trim).collect();
        let has = |needle: &str| lines.contains(&needle);

        assert!(has(". \"$NYM_SHARE_DIR/fw-rules.sh\""), "must source fw-rules.sh");
        assert!(has("EMERGENCY_OUT=\"$NYM_EMERGENCY_OUT\""));
        assert!(has("EMERGENCY_FWD=\"$NYM_EMERGENCY_FWD\""));
        assert!(
            lines.iter().any(|l| l.contains("nym_emergency_rules_v4"))
                && lines.iter().any(|l| l.contains("nym_emergency_rules_v6")),
            "emergency_block must use the generated rule functions"
        );
        for line in &lines {
            if line.starts_with('#') {
                continue;
            }
            assert!(
                !line.contains("-A $EMERGENCY_OUT") && !line.contains("-A $EMERGENCY_FWD"),
                "fw3-include.sh must not carry emergency rule text: {line}"
            );
            assert!(
                !line.contains("10.0.0.0/8") && !line.contains("fe80::/10"),
                "fw3-include.sh must not carry LAN network lists: {line}"
            );
        }
    }

    /// Both helpers ship in every package (build-ipk.sh / build-apk.sh fail
    /// without them), so the include no longer carries stand-in definitions
    /// for a missing one: it logs CRITICAL and exits, installing nothing.
    #[test]
    fn include_script_refuses_to_run_without_its_helpers() {
        const INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");
        const GUARD: &str = include_str!("../../scripts/fw-boot-guard.sh");
        let lines: Vec<&str> = INCLUDE.lines().map(str::trim).collect();

        for helper in ["fw-boot-guard.sh", "fw-rules.sh"] {
            let check = format!("[ -r \"$NYM_SHARE_DIR/{helper}\" ] || {{");
            let at = lines
                .iter()
                .position(|l| *l == check)
                .unwrap_or_else(|| panic!("fw3-include.sh must test for {helper}"));
            assert!(
                lines[at + 1].contains("CRITICAL") && lines[at + 2] == "exit 1",
                "a missing {helper} must log CRITICAL and exit"
            );
            let source = format!(". \"$NYM_SHARE_DIR/{helper}\"");
            assert!(lines.iter().skip(at).any(|l| *l == source));
        }
        for line in &lines {
            assert!(
                !line.contains("nym_runtime_dir_prepare() {")
                    && !line.contains("nym_boot_block_wanted() {")
                    && !line.contains("nym_emergency_rules_v4() {")
                    && !line.contains("nym_boot_block_nft() {"),
                "fw3-include.sh must not define a stand-in for a helper function: {line}"
            );
        }
        assert!(
            GUARD.lines().any(|l| l == "nym_fw_backend() {"),
            "the backend detector lives in the guard"
        );
    }

    #[test]
    fn include_script_takes_the_shared_state_lock() {
        const INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");
        let lines: Vec<&str> = INCLUDE.lines().map(str::trim).collect();

        let lock = format!(
            "LOCK_FILE=\"$NYM_RUNTIME_DIR{}\"",
            FW3_LOCK_PATH.strip_prefix(RUNTIME_DIR).unwrap()
        );
        assert!(
            lines.contains(&lock.as_str()),
            "fw3-include.sh must define {lock}"
        );
        assert!(lines.contains(&"exec 9>\"$LOCK_FILE\""));
        assert!(lines.iter().any(|l| l.starts_with("flock 9")));
        assert!(lines.iter().any(|l| l.contains("NYM_FW_LOCKED")));
        let lock_at = lines.iter().position(|l| l.starts_with("flock 9")).unwrap();
        let main_at = lines.iter().position(|l| *l == "main \"$@\"").unwrap();
        assert!(lock_at < main_at);
        // Stop intent wins over persisted state, so a stop whose teardown
        // could not take the lock is completed by the next run.
        let stop_at = lines
            .iter()
            .position(|l| *l == "if have_state \"$NYM_VPND_STOPPED\"; then")
            .expect("main must check the stop marker");
        let restore_at = lines
            .iter()
            .position(|l| *l == "if have_state \"$RULES_V4\"; then")
            .expect("main must restore from the rules file");
        assert!(stop_at < restore_at);
        let install_at = lines
            .iter()
            .position(|l| l.contains("installing the boot-time emergency block"))
            .unwrap();
        let recheck_at = lines
            .iter()
            .position(|l| l.contains("lifting the emergency block"))
            .expect("fallback must re-check and lift");
        assert!(install_at < recheck_at);
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("running unlocked") || l.contains("include unlocked")),
            "fw3-include.sh must not fall back to running unlocked"
        );
        let fallback_at = lines
            .iter()
            .position(|l| *l == "run_without_lock() {")
            .expect("fw3-include.sh must define run_without_lock");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("CRITICAL") && l.contains("without the state lock")),
            "the lockless path must log CRITICAL"
        );
        assert!(
            fallback_at < lock_at,
            "fallback is defined before it is needed"
        );
    }

    #[test]
    fn state_lock_excludes_while_held_and_releases_on_drop() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nym-firewall-lock-test-{}-{nonce}",
            std::process::id()
        ));
        let path = path.to_str().unwrap();

        let held = lock_state_file(path).unwrap();
        let other = File::options().write(true).open(path).unwrap();
        let contended = Flock::lock(other, FlockArg::LockExclusiveNonblock);
        assert!(matches!(contended, Err((_, Errno::EWOULDBLOCK))));

        drop(held);
        let reacquired = lock_state_file(path);
        assert!(
            reacquired.is_ok(),
            "lock must be free once the guard is dropped"
        );
        drop(reacquired);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn scripts_derive_every_state_path_from_the_runtime_dir() {
        const INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");
        const GUARD: &str = include_str!("../../scripts/fw-boot-guard.sh");
        let default = format!("NYM_RUNTIME_DIR=\"${{NYM_RUNTIME_DIR:-{RUNTIME_DIR}}}\"");
        for (name, script) in [("fw3-include.sh", INCLUDE), ("fw-boot-guard.sh", GUARD)] {
            assert!(
                script.lines().map(str::trim).any(|l| l == default),
                "{name} must define {default}"
            );
            for line in script.lines() {
                assert!(
                    !line.contains("/tmp/nym-") && !line.contains("/tmp/run/nym"),
                    "{name} must not name a runtime file directly: {line}"
                );
            }
        }
        let file = |full: &str| full.strip_prefix(RUNTIME_DIR).unwrap().to_owned();
        for expected in [
            format!("RULES_V4=\"$NYM_RUNTIME_DIR{}\"", file(FW3_RULES_V4_PATH)),
            format!("RULES_V6=\"$NYM_RUNTIME_DIR{}\"", file(FW3_RULES_V6_PATH)),
            format!("IFACES_FILE=\"$NYM_RUNTIME_DIR{}\"", file(IFACES_PATH)),
            format!(
                "TRANSITION_FILE=\"$NYM_RUNTIME_DIR{}\"",
                file(FW3_TRANSITION_PATH)
            ),
        ] {
            assert!(
                INCLUDE.lines().map(str::trim).any(|l| l == expected),
                "fw3-include.sh must define {expected}"
            );
        }
        let stopped = format!(
            "NYM_VPND_STOPPED=\"${{NYM_VPND_STOPPED:-$NYM_RUNTIME_DIR{}}}\"",
            file(STOP_MARKER_PATH)
        );
        assert!(
            GUARD.lines().map(str::trim).any(|l| l == stopped),
            "fw-boot-guard.sh must define {stopped}"
        );
        assert!(INCLUDE.contains("nym_runtime_dir_prepare"));
        assert!(GUARD.contains("nym_runtime_dir_trusted"));
        for line in INCLUDE.lines() {
            for var in ["RULES_V4", "RULES_V6", "IFACES_FILE", "TRANSITION_FILE"] {
                assert!(
                    !line.contains(&format!("[ -f \"${var}\""))
                        && !line.contains(&format!("[ ! -f \"${var}\"")),
                    "fw3-include.sh must test state files through have_state: {line}"
                );
            }
        }
    }

    /// The guard decides the boot block from the daemon's settings file, so
    /// it must read `killswitch` exactly as the daemon does: an absent file,
    /// an absent key and an explicit value each land on the same answer. The
    /// daemon side cannot be linked from here, so its verdicts are literals:
    /// a missing file is `nym_vpn_lib_types::VpnServiceConfig::default()`
    /// and a missing key `nym-vpnd`'s `config::v8::default_killswitch`, both
    /// on. Exercises the guard's text-scan path (no `jsonfilter` off OpenWrt).
    #[cfg(unix)]
    #[test]
    fn boot_guard_reads_killswitch_like_the_daemon() {
        use std::os::unix::fs::PermissionsExt;

        const GUARD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fw-boot-guard.sh");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nym-firewall-boot-guard-{}-{nonce}",
            std::process::id()
        ));
        let rc_dir = dir.join("rc.d");
        std::fs::create_dir_all(&rc_dir).unwrap();
        // An enabled daemon: the guard wants an executable S-link.
        let init = dir.join("nym-vpnd.init");
        std::fs::write(&init, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&init, rc_dir.join("S90nym-vpnd")).unwrap();

        let v8 = |killswitch_line: &str| {
            format!(
                "{{\n  \"version\": \"v8\",\n  \"allow_lan\": true,\n{killswitch_line}  \"legacy_split_tunnel\": false,\n  \"inbound_exemptions\": [],\n  \"stealth_api\": false\n}}\n"
            )
        };
        let cases = [
            ("absent-file", None, "absent", true),
            ("true", Some(v8("  \"killswitch\": true,\n")), "true", true),
            (
                "false",
                Some(v8("  \"killswitch\": false,\n")),
                "false",
                false,
            ),
            ("no-key", Some(v8("")), "absent", true),
        ];
        for (name, content, read_as, daemon_killswitch) in cases {
            let config = dir.join(format!("{name}.json"));
            if let Some(content) = content {
                std::fs::write(&config, content).unwrap();
            }
            let run = |body: &str| {
                let out = Command::new("sh")
                    .arg("-c")
                    .arg(format!(". \"$1\"; {body}"))
                    .arg("sh")
                    .arg(GUARD)
                    .env("NYM_VPND_CONFIG", &config)
                    .env("NYM_RC_DIR", &rc_dir)
                    .env("NYM_RUNTIME_DIR", dir.join("missing-runtime-dir"))
                    .output()
                    .unwrap();
                (
                    out.status.success(),
                    String::from_utf8(out.stdout).unwrap().trim().to_owned(),
                )
            };
            let (ok, value) = run("nym_config_bool killswitch");
            assert!(ok, "{name}: nym_config_bool must succeed");
            assert_eq!(value, read_as, "{name}: nym_config_bool killswitch");
            let (block_wanted, reason) =
                run("nym_boot_block_wanted; rc=$?; echo \"$NYM_BOOT_REASON\"; exit $rc");
            assert_eq!(
                block_wanted, daemon_killswitch,
                "{name}: the guard's verdict ({reason}) must match what nym-vpnd loads"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_file_write_refuses_a_planted_temp_path() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "nym-firewall-plant-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let target = root.join("v4.rules");
        let tmp = root.join("v4.rules.planted.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        let result = write_state_file_via(
            target.to_str().unwrap(),
            tmp.to_str().unwrap(),
            "*filter\nCOMMIT\n",
        );
        assert!(result.is_err(), "must not write through a planted symlink");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(!target.exists());

        // The failed write unlinks the symlink itself, not its target.
        assert!(!tmp.exists() && std::fs::symlink_metadata(&tmp).is_err());
        std::fs::write(&tmp, "planted").unwrap();
        assert!(
            write_state_file_via(target.to_str().unwrap(), tmp.to_str().unwrap(), "x").is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistence_write_failure_is_reported() {
        let result = write_state_file("/proc/nym-firewall-test.rules", "*filter\nCOMMIT\n");
        assert!(result.is_err(), "unwritable state path must fail policy persistence");
    }

    #[test]
    fn transition_marker_is_explicitly_cleared_only_on_success() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nym-firewall-transition-test-{}-{nonce}",
            std::process::id()
        ));
        let path = path.to_str().unwrap();

        write_transition_marker(path).unwrap();
        assert!(std::path::Path::new(path).exists());
        remove_state_file(path).unwrap();
        assert!(!std::path::Path::new(path).exists());
    }
}
