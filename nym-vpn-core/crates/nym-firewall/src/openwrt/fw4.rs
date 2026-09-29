// SPDX-License-Identifier: GPL-3.0-only

//! fw4 (nftables) backend: kill-switch rules in an own `inet nym` table at
//! `filter - 10` (ahead of fw4). Nothing of ours lives inside `inet fw4`:
//! masquerade, MSS clamp and LAN-to-tunnel forwarding come from the `nym`
//! zone `uci-defaults` declares (`common::NYM_ZONE`), which fw4 renders on
//! every reload. `inet nym_boot` is the include's to create; every apply
//! and reset lifts it, as the last statements of its one `nft -f`
//! transaction. No persisted state, but the runtime directory is still
//! verified because the include trusts hints there only from a directory
//! that passes.

use std::io::Write as IoWrite;
use std::process::{Command, Stdio};

use super::common::{FW4_BOOT_TABLE, ensure_runtime_dir};
use super::render_nft::{self, NYM_TABLE};
use super::rules::RuleSet;
use super::{Error, Result};

/// One transaction: the kill-switch table, then the boot block's removal.
/// Whether a block was there is not known without another `nft` run, so
/// its removal is not logged; the include logs installing it.
pub fn apply(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying firewall policy via fw4/nftables backend");
    ensure_runtime_dir()?;

    run_nft_script(&apply_script(rs))?;

    tracing::debug!("Firewall policy applied successfully");
    Ok(())
}

/// Also what the kill-switch-off path runs: with no blocking wanted there
/// is nothing left for the daemon to keep in nftables. One transaction: a
/// failure leaves both tables as they were and is reported, so a reset is
/// never claimed while `inet nym` still blocks.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw4/nftables backend");
    ensure_runtime_dir()?;

    run_nft_script(&reset_script())?;

    tracing::debug!("Firewall policy reset successfully");
    Ok(())
}

/// The boot block's removal comes last, inside the transaction, so it goes
/// only together with the policy that replaces it and a policy the kernel
/// refuses leaves it standing. Create-then-delete is a no-op on a missing
/// table, so the include lifting it concurrently is harmless: `nft`
/// transactions are serialized, and each sees the other's result whole.
fn apply_script(rs: &RuleSet) -> String {
    let mut script = render_nft::render(rs);
    script.push_str(&render_nft::delete_table(FW4_BOOT_TABLE));
    script
}

fn reset_script() -> String {
    [NYM_TABLE, FW4_BOOT_TABLE]
        .map(render_nft::delete_table)
        .concat()
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

#[cfg(test)]
mod tests {
    use super::super::common::{FW4_POLICY_PATH, RUNTIME_DIR};
    use super::*;

    const FW3_INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");

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
        let nym = format!("NYM_TABLE=\"{NYM_TABLE}\"");
        assert!(lines().any(|l| l == nym));
    }

    fn empty_policy() -> RuleSet {
        use super::super::rules::{Family, Rule};
        let mut rs = RuleSet::default();
        rs.filter.output.push(Rule::reject(Family::Inet));
        rs.filter.forward.push(Rule::reject(Family::Inet));
        rs
    }

    fn statements(script: &str) -> Vec<&str> {
        script
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    /// The boot block may go only with the policy that replaces it: same
    /// transaction, after the whole of `inet nym`.
    #[test]
    fn apply_lifts_the_boot_block_last_in_the_same_transaction() {
        let script = apply_script(&empty_policy());
        let all = statements(&script);
        let n = all.len();
        assert_eq!(
            all[n - 2..],
            [
                format!("table inet {FW4_BOOT_TABLE}"),
                format!("delete table inet {FW4_BOOT_TABLE}")
            ]
        );
        let policy_end = all.iter().rposition(|l| *l == "}").unwrap();
        let policy_start = all
            .iter()
            .position(|l| *l == format!("table inet {NYM_TABLE} {{"))
            .unwrap();
        assert!(policy_start < policy_end && policy_end == n - 3, "{script}");
        assert_eq!(
            all.iter().filter(|l| l.contains(FW4_BOOT_TABLE)).count(),
            2,
            "{script}"
        );
    }

    #[test]
    fn reset_deletes_both_tables_in_one_transaction_boot_block_last() {
        assert_eq!(
            statements(&reset_script()),
            [
                format!("table inet {NYM_TABLE}"),
                format!("delete table inet {NYM_TABLE}"),
                format!("table inet {FW4_BOOT_TABLE}"),
                format!("delete table inet {FW4_BOOT_TABLE}"),
            ]
        );
    }

    /// Every delete is preceded by a create of the same table, so a missing
    /// table cannot fail the transaction, and none is foreign.
    #[test]
    fn daemon_scripts_only_delete_their_own_tables_idempotently() {
        for script in [apply_script(&empty_policy()), reset_script()] {
            let all = statements(&script);
            for (i, line) in all.iter().enumerate() {
                let Some(table) = line.strip_prefix("delete table inet ") else {
                    continue;
                };
                assert!(table == NYM_TABLE || table == FW4_BOOT_TABLE, "{line}");
                assert_eq!(all[i - 1], format!("table inet {table}"), "{script}");
            }
        }
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

    /// Mirrors the fw3 test: no stand-in definitions for a missing helper.
    #[test]
    fn include_script_refuses_to_run_without_its_helpers() {
        let all: Vec<&str> = lines().collect();
        for helper in ["fw-boot-guard.sh", "fw-rules.sh"] {
            let check = format!("[ -r \"$NYM_SHARE_DIR/{helper}\" ] || {{");
            let at = all
                .iter()
                .position(|l| *l == check)
                .unwrap_or_else(|| panic!("fw4-include.sh must test for {helper}"));
            assert!(
                all[at + 1].contains("CRITICAL") && all[at + 2] == "exit 1",
                "a missing {helper} must log CRITICAL and exit"
            );
            let source = format!(". \"$NYM_SHARE_DIR/{helper}\"");
            assert!(all.iter().skip(at).any(|l| *l == source));
        }
        for line in &all {
            assert!(
                !line.contains("nym_runtime_dir_trusted() {")
                    && !line.contains("nym_boot_block_wanted() {")
                    && !line.contains("nym_boot_block_nft() {"),
                "fw4-include.sh must not define a stand-in for a helper function: {line}"
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
        let expected = format!("RULES_NFT=\"$NYM_RUNTIME_DIR{}\"", file(FW4_POLICY_PATH));
        assert!(
            lines().any(|l| l == expected),
            "fw4-include.sh must define {expected}"
        );
        assert!(INCLUDE.contains("nym_runtime_dir_trusted"));
        for line in lines() {
            assert!(
                !line.contains("/tmp/nym"),
                "no runtime file outside the directory: {line}"
            );
            assert!(
                !line.contains("[ -f \"$RULES_NFT\"") && !line.contains("[ ! -f \"$RULES_NFT\""),
                "hints must be tested through have_state: {line}"
            );
        }
    }

    /// The tunnel plane (masquerade, MSS clamp, LAN-to-tunnel accepts) is
    /// fw3/fw4's own, from the `nym` zone in /etc/config/firewall. Neither
    /// include may carry a second implementation of it.
    #[test]
    fn includes_carry_no_tunnel_plane() {
        for (name, script) in [("fw3-include.sh", FW3_INCLUDE), ("fw4-include.sh", INCLUDE)] {
            for line in script
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
            {
                for needle in ["MASQUERADE", "masquerade", "TCPMSS", "rt mtu", "ifaces"] {
                    assert!(
                        !line.contains(needle),
                        "{name} must not implement the tunnel plane ({needle}): {line}"
                    );
                }
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
