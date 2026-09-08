// SPDX-License-Identifier: GPL-3.0-only

//! fw4 (nftables) backend: kill-switch rules in an own `inet nym` table at
//! `filter - 10` (ahead of fw4), plus two owned chains inside `inet fw4`
//! (`nym_postrouting` from `srcnat`, `nym_forward_lan` from `forward_lan`).
//! `inet nym_boot` is the include's to create; every apply and reset lifts
//! it last. No persisted state, but the runtime directory is still verified
//! because the include trusts hints there only from a directory that passes.

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::{FW4_BOOT_TABLE, ensure_runtime_dir};
use super::render_nft;
use super::rules::RuleSet;
use super::{Error, Result};

const NAT_CHAIN: &str = "nym_postrouting";
const FORWARD_CHAIN: &str = "nym_forward_lan";
const FW4_SRCNAT: &str = "srcnat";
const FW4_FORWARD_LAN: &str = "forward_lan";

/// Kill-switch table first, then fw4 integration, then lift the boot block.
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

/// Kill-switch off: forwarding plane only, blocking table removed.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw4/nftables");
    ensure_runtime_dir()?;

    delete_nym_table();

    integrate_with_fw4(&rs.tunnel_interfaces)?;

    remove_boot_block()?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Best-effort, except a boot block that exists and cannot be removed: that
/// would leave WAN egress blackholed, so it is reported.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw4/nftables backend");
    ensure_runtime_dir()?;

    remove_integration();
    delete_nym_table();
    remove_boot_block()?;

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// Called last so the block goes only once live state has converged. The
/// include may be lifting it concurrently, so "already gone" is success.
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

fn integrate_with_fw4(interfaces: &[String]) -> Result<()> {
    ensure_chain(NAT_CHAIN)?;
    ensure_chain(FORWARD_CHAIN)?;
    flush_chain(NAT_CHAIN)?;
    flush_chain(FORWARD_CHAIN)?;

    for iface in interfaces {
        add_rule(&[
            "add", "rule", "inet", "fw4", NAT_CHAIN, "oifname", iface, "counter", "masquerade",
        ])?;
        // MSS clamp: the 1340-MTU WG tun blackholes full-size segments when
        // ICMP frag-needed is lost. `rt mtu` is inert for the 1500-MTU mixnet
        // tun. Must precede the accepts.
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
        // Return traffic to the LAN; `inet nym` only covers router-originated flows.
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
    // `nft add chain` exits non-zero with "File exists" on some versions.
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

    /// A rename on either side must fail here, not leave a table nobody deletes.
    const INCLUDE: &str = include_str!("../../scripts/fw4-include.sh");

    fn lines() -> impl Iterator<Item = &'static str> {
        INCLUDE.lines().map(str::trim)
    }

    #[test]
    fn include_script_names_the_same_tables() {
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

    /// Rule content is tested in `boot_rules`.
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
        for line in lines().filter(|l| l.contains("delete table inet")) {
            assert!(
                line.contains("$BOOT_TABLE"),
                "include must not delete a table other than the boot block: {line}"
            );
        }
    }
}
