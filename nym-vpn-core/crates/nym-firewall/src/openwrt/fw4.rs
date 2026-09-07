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

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::FW4_BOOT_TABLE;
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
    use super::*;

    /// The include script that installs the boot-time block this backend
    /// lifts. Scanned line by line so a rename on either side fails here
    /// instead of leaving a table nobody deletes.
    const INCLUDE: &str = include_str!("../../scripts/fw4-include.sh");

    fn lines() -> impl Iterator<Item = &'static str> {
        INCLUDE.lines().map(str::trim)
    }

    /// The nft heredoc between the boot table header and the closing EOF.
    fn boot_block_body() -> Vec<&'static str> {
        let start = INCLUDE
            .find("table inet $BOOT_TABLE {")
            .expect("include defines the boot table body");
        let body = &INCLUDE[start..];
        let end = body.find("\nEOF").expect("heredoc terminator");
        body[..end].lines().map(str::trim).collect()
    }

    #[test]
    fn include_script_names_the_same_tables() {
        let boot = format!("BOOT_TABLE=\"{FW4_BOOT_TABLE}\"");
        assert!(lines().any(|l| l == boot), "fw4-include.sh must define {boot}");
        assert!(lines().any(|l| l == "NYM_TABLE=\"nym\""));
    }

    #[test]
    fn boot_block_keeps_the_router_reachable_and_ends_in_drop() {
        let body = boot_block_body();
        for must in [
            "oifname \"lo\" accept",
            "ct state established,related ct direction reply accept",
            "udp sport 68 udp dport 67 accept",
            "udp sport 67 udp dport 68 accept",
            "udp sport 546 udp dport 547 accept",
            "udp sport 547 udp dport 546 accept",
            "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
            "ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept",
        ] {
            assert!(body.contains(&must), "boot block must keep: {must}");
        }
        // LAN destinations pass in both egress chains; nothing else does.
        let lan = "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
        assert_eq!(body.iter().filter(|l| l.starts_with(lan)).count(), 2);
        assert_eq!(body.iter().filter(|l| **l == "drop").count(), 2);
        // Only the two egress hooks, ahead of the daemon's own table.
        assert_eq!(body.iter().filter(|l| l.contains("priority filter - 20")).count(), 2);
        assert!(body.iter().any(|l| l.contains("hook output")));
        assert!(body.iter().any(|l| l.contains("hook forward")));
        assert!(!body.iter().any(|l| l.contains("hook input")));
    }

    /// Same ordering rule as the daemon's policy (`block_dns` before
    /// `allow_lan_traffic`): a private destination is not a LAN interface,
    /// so DNS must be rejected before the LAN accepts in both egress chains
    /// or a double-NAT router leaks plaintext lookups to its upstream during
    /// the boot window. The reject must still follow the loopback and
    /// reply-direction accepts so the router's own dnsmasq keeps answering.
    #[test]
    fn boot_block_rejects_dns_before_the_lan_accepts() {
        let body = boot_block_body();
        let chain_starts: Vec<usize> = body
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with("chain "))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(chain_starts.len(), 2, "output and forward chains");

        for (n, &start) in chain_starts.iter().enumerate() {
            let end = chain_starts.get(n + 1).copied().unwrap_or(body.len());
            let chain = &body[start..end];
            let pos = |needle: &str| {
                chain
                    .iter()
                    .position(|l| l.starts_with(needle))
                    .unwrap_or_else(|| panic!("{}: missing {needle}", chain[0]))
            };
            let udp = pos("udp dport 53 reject");
            let tcp = pos("tcp dport 53 reject");
            let lan = pos("ip daddr {");
            let lan6 = pos("ip6 daddr {");
            assert!(
                udp < lan && tcp < lan,
                "{}: DNS reject must precede the LAN accept",
                chain[0]
            );
            assert!(
                udp < lan6 && tcp < lan6,
                "{}: DNS reject must precede the ULA accept",
                chain[0]
            );
            if chain[0].starts_with("chain output") {
                assert!(
                    pos("oifname \"lo\" accept") < udp,
                    "loopback must stay ahead of the DNS reject"
                );
                assert!(
                    pos("ct state established,related ct direction reply accept") < udp,
                    "reply-direction accept must stay ahead of the DNS reject"
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
