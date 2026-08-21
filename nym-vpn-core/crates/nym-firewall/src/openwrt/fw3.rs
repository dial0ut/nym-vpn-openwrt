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

use super::common::{FW3_HOOK_FORWARD, FW3_HOOK_INPUT, FW3_HOOK_OUTPUT, FW3_INCLUDE_PATH, is_ipv6_enabled};
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

    apply_filter(rs, AddrFamily::V4)?;
    setup_jumps(AddrFamily::V4)?;
    if !rs.mangle.is_empty() {
        setup_mangle_jumps(AddrFamily::V4)?;
    } else {
        cleanup_mangle(AddrFamily::V4);
    }

    if is_ipv6_enabled() {
        apply_filter(rs, AddrFamily::V6)?;
        setup_jumps(AddrFamily::V6)?;
        if !rs.mangle.is_empty() {
            setup_mangle_jumps(AddrFamily::V6)?;
        } else {
            cleanup_mangle(AddrFamily::V6);
        }
    } else {
        tracing::info!("IPv6 disabled, skipping ip6tables rules");
    }

    add_masquerade_rules(&rs.tunnel_interfaces)?;

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Install only the LAN↔tunnel forwarding plane (masquerade), dropping any
/// kill-switch blocking chains. Used when the kill-switch is off: routing into
/// the tunnel is unconditional, so forwarded LAN traffic must still be NAT'd to
/// the tunnel source address, but nothing is fenced off from the WAN.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw3/iptables");

    // Lift any blocking left over from a previous kill-switch-on state.
    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    if is_ipv6_enabled() {
        cleanup_filter(AddrFamily::V6);
        cleanup_mangle(AddrFamily::V6);
    }

    add_masquerade_rules(&rs.tunnel_interfaces)?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Tear down the jumps and our chains. Best-effort throughout.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw3/iptables backend");

    remove_masquerade_rules();
    cleanup_filter(AddrFamily::V4);
    cleanup_mangle(AddrFamily::V4);
    if is_ipv6_enabled() {
        cleanup_filter(AddrFamily::V6);
        cleanup_mangle(AddrFamily::V6);
    }

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Apply a ruleset only when the iptables `owner` match is available.
///
/// If it is unavailable, remove the daemon-only exceptions entirely. This
/// preserves the kill switch without silently turning them into unscoped
/// accepts; reconnect DNS may fail until the extension is installed.
fn apply_filter(rs: &RuleSet, family: AddrFamily) -> Result<()> {
    let stripped;
    let rs = if rs.has_skuid() && !owner_match_available(family) {
        let ipt = ipt_cmd(family);
        tracing::error!(
            "{ipt} owner match unavailable; omitting daemon-only DNS exceptions. \
             The kill switch remains active but the daemon cannot resolve DNS, \
             so connecting will fail until the extension is installed. Install \
             iptables-mod-extra and kmod-ipt-extra, or disable the kill switch."
        );
        stripped = rs.without_skuid_rules();
        &stripped
    } else {
        rs
    };

    let script = render_iptables::render(rs, family);
    run_restore(&script, family)
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

/// Configure UCI to use the fw3 include script. The script itself is
/// installed by the IPK package at [`FW3_INCLUDE_PATH`].
pub fn install_include_script() -> Result<()> {
    if !std::path::Path::new(FW3_INCLUDE_PATH).exists() {
        tracing::warn!(
            "fw3 include script not found at {FW3_INCLUDE_PATH} \
             - should be installed by package"
        );
    }
    install_uci_config()
}

fn install_uci_config() -> Result<()> {
    let check = Command::new("uci")
        .args(["get", "firewall.nym_vpn"])
        .output();
    if check.map(|o| o.status.success()).unwrap_or(false) {
        tracing::debug!("UCI firewall.nym_vpn config already exists");
        return Ok(());
    }

    let path_setting = format!("firewall.nym_vpn.path={FW3_INCLUDE_PATH}");
    let commands: &[&[&str]] = &[
        &["set", "firewall.nym_vpn=include"],
        &["set", "firewall.nym_vpn.type=script"],
        &["set", &path_setting],
        &["set", "firewall.nym_vpn.reload=1"],
        &["set", "firewall.nym_vpn.enabled=1"],
        &["commit", "firewall"],
    ];

    for args in commands {
        let output = Command::new("uci")
            .args(*args)
            .output()
            .map_err(|e| Error::InstallError(format!("spawn uci: {e}")))?;
        if !output.status.success() {
            return Err(Error::InstallError(format!(
                "uci {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }
    tracing::info!("Installed UCI firewall config for Nym VPN (fw3)");
    Ok(())
}
