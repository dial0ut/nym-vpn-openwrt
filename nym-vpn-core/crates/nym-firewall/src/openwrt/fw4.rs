// SPDX-License-Identifier: GPL-3.0-only

//! fw4 (nftables) backend for OpenWrt.
//!
//! Hosts kill-switch rules in its own `inet nym` table (priority `filter -10`
//! so it runs before fw4) and integrates with fw4 via two owned chains in
//! `inet fw4`:
//!
//! - `nym_postrouting` — jumped to from `srcnat`, holds the masquerade
//!   rules for tunnel interfaces.
//! - `nym_forward_lan` — jumped to from `forward_lan`, holds the accepts
//!   that let fw4 forward traffic between LAN and the tunnel.
//!
//! Owning the chains means re-applies are atomic: flush + repopulate, no
//! risk of stomping on user rules in fw4's own chains.

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::FW4_INCLUDE_PATH;
use super::render_nft;
use super::rules::RuleSet;
use super::{Error, Result};

/// Chain in `inet fw4` that hosts our masquerade rules.
const NAT_CHAIN: &str = "nym_postrouting";
/// Chain in `inet fw4` that hosts our LAN↔tunnel forward accepts.
const FORWARD_CHAIN: &str = "nym_forward_lan";
/// fw4's parent chains we jump into.
const FW4_SRCNAT: &str = "srcnat";
const FW4_FORWARD_LAN: &str = "forward_lan";

/// Apply the [`RuleSet`] to fw4. Order is deliberate: install the kill-switch
/// table first (fail-closed) before touching fw4's chains for masquerade.
pub fn apply(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying firewall policy via fw4/nftables backend");

    let script = render_nft::render(rs);
    run_nft_script(&script)?;

    integrate_with_fw4(&rs.tunnel_interfaces)?;

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Install only the LAN↔tunnel forwarding plane (masquerade + forward accepts),
/// dropping any kill-switch blocking table. Used when the kill-switch is off:
/// routing into the tunnel is unconditional, so the tunnel must still NAT and
/// forward LAN traffic, but nothing is fenced off from the WAN.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw4/nftables");

    // Lift any blocking left over from a previous kill-switch-on state.
    delete_nym_table();

    integrate_with_fw4(&rs.tunnel_interfaces)?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Remove our kill-switch table and integration chains. Best-effort: any
/// step that fails because state is already absent is logged and ignored.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw4/nftables backend");

    remove_integration();
    delete_nym_table();

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Delete the `inet nym` kill-switch table. Best-effort; ignores absence.
fn delete_nym_table() {
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "nym"])
        .output();
    if let Ok(o) = output
        && !o.status.success()
    {
        tracing::debug!(
            "nft delete table inet nym (non-fatal): {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::ApplyError(format!("spawn nft: {e}")))?;

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(script.as_bytes())
        .map_err(|e| Error::ApplyError(format!("write nft stdin: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| Error::ApplyError(format!("wait nft: {e}")))?;

    if !output.status.success() {
        return Err(Error::ApplyError(format!(
            "nft -f failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Install our chains + jumps in `inet fw4` and populate them with one
/// masquerade and one forward-accept rule per tunnel interface.
fn integrate_with_fw4(interfaces: &[String]) -> Result<()> {
    ensure_chain(NAT_CHAIN)?;
    ensure_chain(FORWARD_CHAIN)?;
    flush_chain(NAT_CHAIN)?;
    flush_chain(FORWARD_CHAIN)?;

    for iface in interfaces {
        add_rule(&[
            "add", "rule", "inet", "fw4", NAT_CHAIN, "oifname", iface, "counter", "masquerade",
        ])?;
        // Clamp TCP MSS to the path MTU for flows entering/leaving the tunnel.
        // The 2-hop WG tun runs at 1340 bytes; without clamping, LAN clients
        // negotiate MSS 1460 against their own 1500 link and full-size segments
        // blackhole whenever ICMP frag-needed is lost (PMTU blackhole: pages
        // hang, bulk transfers limp). `rt mtu` uses the packet's route MTU, so
        // this is inert for the 1500-MTU mixnet tun. Must precede the accepts.
        add_rule(&[
            "add", "rule", "inet", "fw4", FORWARD_CHAIN, "oifname", iface, "tcp", "flags",
            "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu",
        ])?;
        add_rule(&[
            "add", "rule", "inet", "fw4", FORWARD_CHAIN, "iifname", iface, "tcp", "flags",
            "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu",
        ])?;
        add_rule(&[
            "add", "rule", "inet", "fw4", FORWARD_CHAIN, "oifname", iface, "accept",
        ])?;
        // Allow return traffic from tunnel to LAN (the ct established rule
        // in our table covers traffic the router originated; this lets the
        // forwarded LAN flows resume after the kill-switch state changes).
        add_rule(&[
            "add", "rule", "inet", "fw4", FORWARD_CHAIN, "iifname", iface, "ct", "state",
            "established,related", "accept",
        ])?;
        tracing::debug!("Populated fw4 nym chains for interface {iface}");
    }

    ensure_jump(FW4_SRCNAT, NAT_CHAIN)?;
    ensure_jump(FW4_FORWARD_LAN, FORWARD_CHAIN)?;
    Ok(())
}

/// Remove jumps from fw4's chains, then delete our chains. Best-effort.
fn remove_integration() {
    remove_jumps(FW4_SRCNAT, NAT_CHAIN);
    remove_jumps(FW4_FORWARD_LAN, FORWARD_CHAIN);

    for chain in [NAT_CHAIN, FORWARD_CHAIN] {
        let output = Command::new("nft")
            .args(["delete", "chain", "inet", "fw4", chain])
            .output();
        if let Ok(o) = output
            && !o.status.success()
        {
            tracing::debug!(
                "nft delete chain {chain} (non-fatal): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }
}

fn ensure_chain(name: &str) -> Result<()> {
    // `nft add chain` is idempotent if the chain spec is identical, but
    // gives a non-zero exit + "File exists" stderr if it already exists.
    // Treat both as success; only "real" errors (no fw4 table, no nft
    // binary) should fail us here.
    let output = Command::new("nft")
        .args(["add", "chain", "inet", "fw4", name])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn nft add chain: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") || stderr.contains("exists") {
        return Ok(());
    }
    Err(Error::ApplyError(format!(
        "nft add chain {name} failed: {}",
        stderr.trim()
    )))
}

fn flush_chain(name: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["flush", "chain", "inet", "fw4", name])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn nft flush chain: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ApplyError(format!(
            "nft flush chain {name} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn add_rule(args: &[&str]) -> Result<()> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn nft add rule: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ApplyError(format!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Add a `jump <target>` rule to a fw4 chain unless one is already present.
/// We match structurally on `jump <name>`, so a user rule that merely
/// mentions our chain name in a comment can never collide with ours.
fn ensure_jump(parent: &str, target: &str) -> Result<()> {
    let listing = Command::new("nft")
        .args(["list", "chain", "inet", "fw4", parent])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn nft list chain {parent}: {e}")))?;
    if !listing.status.success() {
        return Err(Error::ApplyError(format!(
            "nft list chain {parent} failed: {}",
            String::from_utf8_lossy(&listing.stderr).trim()
        )));
    }
    let needle = format!("jump {target}");
    if String::from_utf8_lossy(&listing.stdout).contains(&needle) {
        return Ok(());
    }
    add_rule(&["add", "rule", "inet", "fw4", parent, "jump", target])
}

/// Remove every `jump <target>` rule from `parent`. Best-effort.
fn remove_jumps(parent: &str, target: &str) {
    let listing = match Command::new("nft")
        .args(["-a", "list", "chain", "inet", "fw4", parent])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            tracing::debug!(
                "nft list chain {parent} (non-fatal): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return;
        }
        Err(e) => {
            tracing::debug!("spawn nft list chain {parent}: {e}");
            return;
        }
    };
    let needle = format!("jump {target}");
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        if !line.contains(&needle) {
            continue;
        }
        let Some(handle) = line.split("# handle ").last() else {
            continue;
        };
        let result = Command::new("nft")
            .args([
                "delete",
                "rule",
                "inet",
                "fw4",
                parent,
                "handle",
                handle.trim(),
            ])
            .output();
        if let Ok(o) = result
            && !o.status.success()
        {
            tracing::debug!(
                "nft delete jump rule (non-fatal): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }
}

/// Configure UCI to use the fw4 include script. The script itself is
/// installed by the IPK package at [`FW4_INCLUDE_PATH`].
pub fn install_include_script() -> Result<()> {
    if !std::path::Path::new(FW4_INCLUDE_PATH).exists() {
        tracing::warn!(
            "fw4 include script not found at {FW4_INCLUDE_PATH} \
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

    // Register as a side-effecting script include: fw4 runs it after building
    // its table on every start/reload, so our script can re-add the masquerade
    // and forward jumps inside `inet fw4` that the reload wiped. Note: NOT
    // `fw4_compatible` — that flag makes fw4 capture the script's stdout as nft
    // syntax during ruleset assembly (when `inet fw4` doesn't exist yet), which
    // is wrong for a script that issues `nft add rule inet fw4 ...` side effects.
    // This matches the proven pattern used by stock OpenWrt/GL.iNet script
    // includes. (`reload` is an fw3-ism fw4 warns about and ignores — omit it.)
    let path_setting = format!("firewall.nym_vpn.path={FW4_INCLUDE_PATH}");
    let commands: &[&[&str]] = &[
        &["set", "firewall.nym_vpn=include"],
        &["set", "firewall.nym_vpn.type=script"],
        &["set", &path_setting],
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
    tracing::info!("Installed UCI firewall config for Nym VPN (fw4)");
    Ok(())
}
