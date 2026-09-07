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
//!
//! A third table, `inet nym_boot`, is not ours to create: the fw4 include
//! script installs it at firewall start to cover the window before this
//! daemon's first policy (see [`FW4_BOOT_TABLE`]). Every apply and reset
//! lifts it last, once the live state has converged.
//!
//! This backend keeps no persisted state of its own, but every entry point
//! first makes sure the shared runtime directory
//! ([`RUNTIME_DIR`](super::common::RUNTIME_DIR)) exists
//! and is private to root: the init script's stop marker and the include's
//! optional hints live there, and the include trusts them only from a
//! directory that passes the same checks.

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::{FW4_BOOT_TABLE, ensure_runtime_dir};
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
/// table first (fail-closed) before touching fw4's chains for masquerade, and
/// lift the boot-time block only once both are in place.
pub fn apply(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying firewall policy via fw4/nftables backend");
    ensure_runtime_dir()?;

    let script = render_nft::render(rs);
    run_nft_script(&script)?;

    integrate_with_fw4(&rs.tunnel_interfaces)?;

    remove_boot_block()?;

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Install only the LAN↔tunnel forwarding plane (masquerade + forward accepts),
/// dropping any kill-switch blocking table. Used when the kill-switch is off:
/// routing into the tunnel is unconditional, so the tunnel must still NAT and
/// forward LAN traffic, but nothing is fenced off from the WAN.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw4/nftables");
    ensure_runtime_dir()?;

    // Lift any blocking left over from a previous kill-switch-on state.
    delete_nym_table();

    integrate_with_fw4(&rs.tunnel_interfaces)?;

    // Kill-switch off means no boot-time block either; the include reads
    // the same setting and would remove it on the next reload, but the user
    // asked for an open firewall now.
    remove_boot_block()?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Remove our kill-switch table and integration chains. Best-effort: any
/// step that fails because state is already absent is logged and ignored.
/// The one exception is a boot-time block that exists and cannot be removed
/// — that is reported, since it would leave WAN egress blackholed.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw4/nftables backend");
    ensure_runtime_dir()?;

    remove_integration();
    delete_nym_table();
    remove_boot_block()?;

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Lift the boot-time kill-switch block the fw4 include installs at firewall
/// start (`inet nym_boot`, see [`FW4_BOOT_TABLE`]). Called last in every
/// apply and reset so it goes only once the live state has converged. Cheap
/// when absent: one existence probe. A block that exists and cannot be
/// removed fails the operation rather than reporting a working connection
/// while WAN egress is still blackholed. The include may be lifting it
/// concurrently (it re-checks after installing), so "gone by the time we
/// delete it" is success.
fn remove_boot_block() -> Result<()> {
    if !table_exists(FW4_BOOT_TABLE)? {
        return Ok(());
    }
    tracing::info!("Removing boot-time kill-switch block (inet {FW4_BOOT_TABLE})");
    let output = Command::new("nft")
        .args(["delete", "table", "inet", FW4_BOOT_TABLE])
        .output()
        .map_err(|e| Error::ApplyError(format!("spawn nft delete table: {e}")))?;
    if output.status.success() || !table_exists(FW4_BOOT_TABLE)? {
        return Ok(());
    }
    Err(Error::ApplyError(format!(
        "nft delete table inet {FW4_BOOT_TABLE} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn table_exists(name: &str) -> Result<bool> {
    Command::new("nft")
        .args(["list", "table", "inet", name])
        .output()
        .map(|o| o.status.success())
        .map_err(|e| Error::ApplyError(format!("spawn nft list table {name}: {e}")))
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

#[cfg(test)]
mod tests {
    use super::super::common::{FW4_POLICY_PATH, IFACES_PATH, RUNTIME_DIR};
    use super::*;

    /// The include script that installs the boot-time block this backend
    /// lifts. Scanned line by line so a rename on either side fails here
    /// instead of leaving a table nobody deletes.
    const INCLUDE: &str = include_str!("../../scripts/fw4-include.sh");

    fn lines() -> impl Iterator<Item = &'static str> {
        INCLUDE.lines().map(str::trim)
    }

    #[test]
    fn include_script_names_the_same_tables() {
        // The boot table name comes from the generated fragment, which
        // boot_rules renders from FW4_BOOT_TABLE.
        assert!(
            lines().any(|l| l == "BOOT_TABLE=\"$NYM_BOOT_TABLE\""),
            "fw4-include.sh must take the boot table name from fw-rules.sh"
        );
        assert!(
            super::super::boot_rules::shell_fragment()
                .contains(&format!("NYM_BOOT_TABLE=\"{FW4_BOOT_TABLE}\"")),
        );
        assert!(lines().any(|l| l == "NYM_TABLE=\"nym\""));
    }

    /// The include installs the boot block from the generated fragment,
    /// never from nft text of its own. Rule content is tested in
    /// `boot_rules`.
    #[test]
    fn include_script_installs_the_generated_boot_block() {
        assert!(
            lines().any(|l| l == ". \"$NYM_SHARE_DIR/fw-rules.sh\""),
            "must source fw-rules.sh"
        );
        assert!(
            lines().any(|l| l == "nym_boot_block_nft | nft -f -"),
            "install_boot_block must pipe the generated table into nft"
        );
        for line in lines() {
            if line.starts_with('#') {
                continue;
            }
            assert!(
                !line.contains("hook output") && !line.contains("hook forward"),
                "fw4-include.sh must not carry boot block rule text: {line}"
            );
            assert!(
                !line.contains("10.0.0.0/8") && !line.contains("fe80::/10"),
                "fw4-include.sh must not carry LAN network lists: {line}"
            );
        }
    }

    /// The include's optional hint files live in the runtime directory and
    /// are only read once it has been verified.
    #[test]
    fn include_script_reads_hints_from_the_runtime_dir_only() {
        let default = format!("NYM_RUNTIME_DIR=\"${{NYM_RUNTIME_DIR:-{RUNTIME_DIR}}}\"");
        assert!(
            lines().any(|l| l == default),
            "fw4-include.sh must define {default}"
        );
        let file = |full: &str| full.strip_prefix(RUNTIME_DIR).unwrap().to_owned();
        for expected in [
            format!("RULES_NFT=\"$NYM_RUNTIME_DIR{}\"", file(FW4_POLICY_PATH)),
            format!("IFACES_FILE=\"$NYM_RUNTIME_DIR{}\"", file(IFACES_PATH)),
        ] {
            assert!(
                lines().any(|l| l == expected),
                "fw4-include.sh must define {expected}"
            );
        }
        assert!(INCLUDE.contains("nym_runtime_dir_trusted"));
        for line in lines() {
            assert!(
                !line.contains("/tmp/nym"),
                "no runtime file outside the directory: {line}"
            );
            for var in ["RULES_NFT", "IFACES_FILE"] {
                assert!(
                    !line.contains(&format!("[ -f \"${var}\""))
                        && !line.contains(&format!("[ ! -f \"${var}\"")),
                    "hints must be tested through have_state: {line}"
                );
            }
        }
    }

    #[test]
    fn include_script_only_ever_deletes_the_boot_table() {
        // `inet nym` is the daemon's; the include may probe it, never drop it.
        for line in lines().filter(|l| l.contains("delete table inet")) {
            assert!(
                line.contains("$BOOT_TABLE"),
                "include must not delete a table other than the boot block: {line}"
            );
        }
    }
}
