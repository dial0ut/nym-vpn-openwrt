// SPDX-License-Identifier: GPL-3.0-only

//! fw3 (iptables) backend for OpenWrt.
//!
//! Hosts kill-switch rules in three owned chains (`NYM_INPUT`,
//! `NYM_OUTPUT`, `NYM_FORWARD`) which fw3's hook chains
//! (`input_rule`, `output_rule`, `forwarding_rule`) jump to first.
//!
//! Atomic application via `iptables-restore --noflush`. Masquerade lives in
//! its own chain (`NYM_POSTROUTING` in the `nat` table) so re-applies
//! flush + repopulate without touching anyone else's NAT rules.

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::{
    FW3_HOOK_FORWARD, FW3_HOOK_INPUT, FW3_HOOK_OUTPUT, FW3_RULES_V4_PATH, FW3_RULES_V6_PATH,
    IFACES_PATH, Ipv6Status, ipv6_status,
};
use super::render_iptables::{
    self, AddrFamily, CHAIN_FORWARD, CHAIN_INPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING,
    CHAIN_OUTPUT,
};
use super::rules::RuleSet;
use super::{Error, Result};

/// Chain we own in the iptables `nat` table; POSTROUTING jumps to it.
const NAT_CHAIN: &str = "NYM_POSTROUTING";

/// Apply the [`RuleSet`] to fw3. Order is deliberate: install the kill-switch
/// chains first (fail-closed) before touching the nat table for masquerade.
pub fn apply(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying firewall policy via fw3/iptables backend");

    // Fail closed on a half-firewallable host: if the kernel routes IPv6 but
    // ip6tables can't filter it, an IPv4-only ruleset would just be a
    // kill-switch with a silent v6 bypass.
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

    let v4_script = apply_family(rs, AddrFamily::V4)?;
    let v6_script = if with_v6 {
        Some(apply_family(rs, AddrFamily::V6)?)
    } else {
        None
    };

    add_masquerade_rules(&rs.tunnel_interfaces)?;

    persist_state(&v4_script, v6_script.as_deref(), &rs.tunnel_interfaces);

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Apply the filter (and mangle, when present) plane for one address family
/// and return the rendered restore script that was applied, for persistence.
fn apply_family(rs: &RuleSet, family: AddrFamily) -> Result<String> {
    // Degrade rather than die when the CONNMARK target can't be parsed
    // (libxt_CONNMARK ships in iptables-mod-conntrack-extra, which stock
    // images lack): one unparseable mangle rule fails the entire restore,
    // which would tear the tunnel down over an optional feature. Mirrors
    // the owner-match fallback in apply_filter.
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

/// Whether the iptables `CONNMARK` target extension can be loaded. Probed by
/// appending a real CONNMARK rule to a scratch chain — `--help`-style probes
/// are useless here (iptables exits 0 for unknown targets with `--help`),
/// and only an actual append exercises the same parse path as the restore.
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

/// Persist the applied ruleset for `fw3-include.sh`. Unlike fw4 — whose
/// `inet nym` table survives a firewall reload untouched — fw3 wipes the
/// shared iptables tables on every reload, chains and all. The include
/// script re-applies these files afterwards, so a reload is transparent
/// exactly like it is on fw4. Best-effort: an unwritable /tmp shouldn't
/// fail the live apply, but it does degrade reload survival, so log loudly.
fn persist_state(v4_script: &str, v6_script: Option<&str>, interfaces: &[String]) {
    write_state_file(FW3_RULES_V4_PATH, v4_script);
    match v6_script {
        Some(script) => write_state_file(FW3_RULES_V6_PATH, script),
        None => remove_state_file(FW3_RULES_V6_PATH),
    }
    persist_ifaces(interfaces);
}

/// Persist (or clear) the tunnel interface list for masquerade restore.
fn persist_ifaces(interfaces: &[String]) {
    if interfaces.is_empty() {
        remove_state_file(IFACES_PATH);
    } else {
        let mut buf = interfaces.join("\n");
        buf.push('\n');
        write_state_file(IFACES_PATH, &buf);
    }
}

/// Write via temp file + rename so a firewall reload racing this apply never
/// sees a half-written restore script.
fn write_state_file(path: &str, contents: &str) {
    let tmp = format!("{path}.tmp");
    let result = std::fs::write(&tmp, contents).and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = result {
        tracing::error!(
            "Failed to persist firewall state to {path}: {e}; \
             the kill-switch will not survive a firewall reload"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}

fn remove_state_file(path: &str) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("Failed to remove firewall state file {path}: {e}");
    }
}

/// Remove all persisted state so the include script's cleanup branch runs on
/// the next firewall reload instead of resurrecting stale rules.
fn clear_persisted_state() {
    remove_state_file(FW3_RULES_V4_PATH);
    remove_state_file(FW3_RULES_V6_PATH);
    remove_state_file(IFACES_PATH);
}

/// Install only the LAN↔tunnel forwarding plane (masquerade), dropping any
/// kill-switch blocking chains. Used when the kill-switch is off: routing into
/// the tunnel is unconditional, so forwarded LAN traffic must still be NAT'd to
/// the tunnel source address, but nothing is fenced off from the WAN.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw3/iptables");

    // Lift any blocking left over from a previous kill-switch-on state.
    // Cleanup is best-effort for both families — no ipv6_status() gate, the
    // commands fail harmlessly when ip6tables is absent.
    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    cleanup_filter(AddrFamily::V6);
    cleanup_mangle(AddrFamily::V6);

    add_masquerade_rules(&rs.tunnel_interfaces)?;

    // No blocking ruleset to resurrect after a reload, but the include
    // script still needs the interface list to restore masquerade.
    remove_state_file(FW3_RULES_V4_PATH);
    remove_state_file(FW3_RULES_V6_PATH);
    persist_ifaces(&rs.tunnel_interfaces);

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Tear down the jumps and our chains. Best-effort throughout.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw3/iptables backend");

    remove_masquerade_rules();
    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    cleanup_filter(AddrFamily::V6);
    cleanup_mangle(AddrFamily::V6);

    clear_persisted_state();

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Apply a ruleset only when the iptables `owner` match is available.
///
/// If it is unavailable, remove the daemon-only exceptions entirely. This
/// preserves the kill switch without silently turning them into unscoped
/// accepts; reconnect DNS may fail until the extension is installed.
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

/// Insert jumps from fw3's `*_rule` chains into ours at position 1.
/// Idempotent: any existing jump to our chain is removed first.
fn setup_jumps(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, target) in JUMPS {
        // Remove any pre-existing jump (best-effort; fails if absent).
        let _ = Command::new(ipt)
            .args(["-w", "-D", hook, "-j", target])
            .output();
        // Insert at position 1 so our rules run before any fw3-managed ones.
        let output = Command::new(ipt)
            .args(["-w", "-I", hook, "1", "-j", target])
            .output()
            .map_err(|e| Error::ApplyError(format!("spawn {ipt}: {e}")))?;
        if !output.status.success() {
            return Err(Error::ApplyError(format!(
                "{ipt} -I {hook} -j {target} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
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

/// Jumps in the `mangle` table. Unlike the filter table, there are no fw3
/// `*_rule` chains in mangle — we jump directly from the built-in PREROUTING
/// and OUTPUT hooks.
const MANGLE_JUMPS: [(&str, &str); 2] = [
    ("PREROUTING", CHAIN_MANGLE_PREROUTING),
    ("OUTPUT", CHAIN_MANGLE_OUTPUT),
];

/// Insert jumps from the mangle table's built-in chains into ours at position 1.
/// Idempotent: any existing jump is removed first.
fn setup_mangle_jumps(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, target) in MANGLE_JUMPS {
        let _ = Command::new(ipt)
            .args(["-w", "-t", "mangle", "-D", hook, "-j", target])
            .output();
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

/// Add masquerade rules in our own chain in the iptables `nat` table.
/// POSTROUTING jumps to it; we flush + repopulate so the rules track the
/// current tunnel interface list without touching anyone else's NAT rules.
fn add_masquerade_rules(interfaces: &[String]) -> Result<()> {
    // -N errors with "Chain already exists" on re-runs; treat as success.
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

    // -C returns 0 if the rule exists, non-zero otherwise.
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

fn remove_masquerade_rules() {
    // -D removes one matching rule per call; loop until exhausted to handle
    // any stale duplicates that may have accumulated.
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
