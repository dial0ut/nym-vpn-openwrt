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
    FW3_TRANSITION_PATH, IFACES_PATH, Ipv6Status, ipv6_status,
};
use super::render_iptables::{
    self, AddrFamily, CHAIN_FORWARD, CHAIN_INPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING,
    CHAIN_OUTPUT,
};
use super::rules::RuleSet;
use super::{Error, Result};

/// Chain we own in the iptables `nat` table; POSTROUTING jumps to it.
const NAT_CHAIN: &str = "NYM_POSTROUTING";

/// Chain we own in the `filter` table holding the LAN↔tunnel forwarding
/// plane — the fw3 analogue of fw4's `nym_forward_lan` inside `inet fw4`.
/// Needed whenever a tunnel is up, kill-switch on or off: the tun devices
/// belong to no fw3 zone, so without explicit accepts fw3's global forward
/// policy rejects every forwarded LAN flow the moment our kill-switch
/// chains are absent. Also carries the TCP MSS clamp — the 1340-MTU 2-hop
/// tunnel blackholes full-size segments whenever ICMP frag-needed is lost.
const FORWARD_LAN_CHAIN: &str = "NYM_FORWARD_LAN";

/// Dedicated fail-closed chains. The fw3 include script installs them when a
/// firewall reload runs while a transition marker exists, when it cannot
/// restore the persisted policy, and — with a boot rule set that also lets
/// the router come up and stay manageable from the LAN — at boot, before
/// this daemon has applied any policy (see fw-boot-guard.sh). The daemon
/// installs them only for the *first* activation (no hook jumps in place
/// yet, so nothing is protecting traffic while the chains are built) and
/// tears them down once the live state has converged, which also lifts the
/// include's boot-time block — a re-apply of a live policy never blackholes
/// traffic. Names and rule shape are a contract with fw3-include.sh and
/// scripts/ipk/prerm.
const EMERGENCY_OUTPUT_CHAIN: &str = "NYM_EMERGENCY_OUT";
const EMERGENCY_FORWARD_CHAIN: &str = "NYM_EMERGENCY_FWD";

/// Apply the [`RuleSet`] to fw3 using a fail-closed transition protocol:
///
/// 1. publish the transition marker; for each family whose hook jumps are
///    not in place yet (first activation, or IPv6 newly enabled) also
///    install that family's emergency block so a crash between chain
///    creation and hook insertion cannot leave its traffic open;
/// 2. build the desired live chains (each `*-restore` is atomic per table,
///    and hook jumps are only inserted when absent or preceded by a foreign
///    rule, so a live policy is replaced without a window) and persist the
///    complete v4/v6/interface state;
/// 3. remove the marker (the persisted v4 file is now the reload activation
///    marker);
/// 4. if a firewall reload raced the transition — it wiped our chains and
///    the include installed the emergency block instead of reading
///    half-written state — re-activate from the same scripts the include
///    would now read, then lift the block.
///
/// Any error or daemon crash before completion deliberately leaves the
/// marker behind, so reloads stay fail-closed until a later successful
/// apply/reset or an explicit service stop.
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

    begin_transition()?;

    // First activation of a family: nothing is hooked yet for it, so the
    // marker alone would not block anything if we crashed between creating
    // the chains and hooking them. Block first; the tail of this function
    // lifts it again. Decided per family — IPv6 can become enabled long
    // after IPv4 was first protected and then needs the block on its own.
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

    // Activation also resolves the effective scripts (owner/CONNMARK
    // fallbacks), which is what gets persisted for the include to replay.
    let v4_script = apply_family(rs, AddrFamily::V4)?;
    let v6_script = if with_v6 {
        Some(apply_family(rs, AddrFamily::V6)?)
    } else {
        None
    };

    // The transition marker prevents the include from consuming this
    // multi-file state until every file is complete.
    persist_state(&v4_script, v6_script.as_deref(), &rs.tunnel_interfaces)?;
    finish_transition()?;

    // A reload that ran while the marker existed recreated fw3's hook chains
    // empty, which is how we detect it. Re-activate from the persisted
    // scripts so both paths converge on the same state.
    if !jumps_present(AddrFamily::V4) {
        tracing::info!("Firewall reload raced the policy apply; re-activating IPv4 rules");
        activate_family_script(&v4_script, AddrFamily::V4)?;
    }
    if let Some(script) = &v6_script
        && !jumps_present(AddrFamily::V6)
    {
        tracing::info!("Firewall reload raced the policy apply; re-activating IPv6 rules");
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

fn begin_transition() -> Result<()> {
    write_transition_marker(FW3_TRANSITION_PATH)
}

fn finish_transition() -> Result<()> {
    remove_state_file(FW3_TRANSITION_PATH)
}

fn write_transition_marker(path: &str) -> Result<()> {
    std::fs::write(path, b"fw3 state transition in progress\n").map_err(|e| {
        Error::ApplyError(format!(
            "create fw3 transition marker {path}: {e}; refusing to change live firewall state"
        ))
    })
}

/// Install the emergency block: dedicated OUTPUT/FORWARD drop chains hooked
/// at position 1, in one atomic restore. Identical in shape to the include
/// script's block. INPUT is untouched, and — because fw3 runs `output_rule`
/// BEFORE its own established-accept — reply-direction packets are let out
/// so SSH/LuCI sessions to the router survive; router-originated flows are
/// in the ORIGINAL direction and stay blocked. Duplicate jumps from a crashed
/// earlier attempt are harmless and removed exhaustively afterwards.
fn install_emergency_block(family: AddrFamily) -> Result<()> {
    run_restore(&emergency_script(family), family)
}

fn emergency_script(family: AddrFamily) -> String {
    let nd = match family {
        AddrFamily::V4 => "",
        AddrFamily::V6 => {
            "-A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT\n\
             -A NYM_EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT\n"
        }
    };
    format!(
        "*filter\n\
         :{EMERGENCY_OUTPUT_CHAIN} - [0:0]\n\
         :{EMERGENCY_FORWARD_CHAIN} - [0:0]\n\
         -F {EMERGENCY_OUTPUT_CHAIN}\n\
         -F {EMERGENCY_FORWARD_CHAIN}\n\
         -A {EMERGENCY_OUTPUT_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT\n\
         {nd}\
         -A {EMERGENCY_OUTPUT_CHAIN} -j DROP\n\
         -A {EMERGENCY_FORWARD_CHAIN} -j DROP\n\
         -I {FW3_HOOK_OUTPUT} 1 -j {EMERGENCY_OUTPUT_CHAIN}\n\
         -I {FW3_HOOK_FORWARD} 1 -j {EMERGENCY_FORWARD_CHAIN}\n\
         COMMIT\n"
    )
}

/// Whether every hook jump into our filter chains is in place. fw3 recreates
/// its `*_rule` hook chains empty on every reload, so a missing jump after
/// the transition marker was removed means a reload raced the apply.
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

/// Activate a previously-rendered family script and reconcile its hook
/// jumps. Used to converge with a firewall reload that raced the apply.
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

/// Remove every emergency jump and then its chain, if the include left one
/// behind. Cheap when nothing is there (one existence probe per chain).
/// Failure leaves traffic blocked and makes the policy application fail
/// rather than claiming a functional connection while the emergency
/// blackhole is still active.
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

        // The include may be lifting the same chains concurrently — it
        // re-checks after installing its boot-time block — so a chain that
        // is gone by the time we flush or delete it is the outcome we wanted.
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
        // IPv6 is absent, so stale ip6tables emergency state is irrelevant and
        // may be impossible to inspect. Clean it best-effort.
        let _ = remove_emergency_block(AddrFamily::V6);
    }
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
/// exactly like it is on fw4. Persistence is part of successful policy
/// application: reporting success without it would create a known leak on
/// the next firewall reload.
fn persist_state(v4_script: &str, v6_script: Option<&str>, interfaces: &[String]) -> Result<()> {
    write_state_file(FW3_RULES_V4_PATH, v4_script)?;
    match v6_script {
        Some(script) => write_state_file(FW3_RULES_V6_PATH, script)?,
        None => remove_state_file(FW3_RULES_V6_PATH)?,
    }
    persist_ifaces(interfaces)
}

/// Persist (or clear) the tunnel interface list for masquerade restore.
fn persist_ifaces(interfaces: &[String]) -> Result<()> {
    if interfaces.is_empty() {
        remove_state_file(IFACES_PATH)
    } else {
        let mut buf = interfaces.join("\n");
        buf.push('\n');
        write_state_file(IFACES_PATH, &buf)
    }
}

/// Write via temp file + rename so a firewall reload racing this apply never
/// sees a half-written restore script.
fn write_state_file(path: &str, contents: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, contents)
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::ApplyError(format!(
                "persist firewall state to {path}: {e}; refusing to report a policy \
                 that would disappear on firewall reload"
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

/// Remove all persisted state so the include script's cleanup branch runs on
/// the next firewall reload instead of resurrecting stale rules.
fn clear_persisted_state() -> Result<()> {
    remove_state_file(FW3_RULES_V4_PATH)?;
    remove_state_file(FW3_RULES_V6_PATH)?;
    remove_state_file(IFACES_PATH)
}

/// Install only the LAN↔tunnel forwarding plane (masquerade), dropping any
/// kill-switch blocking chains. Used when the kill-switch is off: routing into
/// the tunnel is unconditional, so forwarded LAN traffic must still be NAT'd to
/// the tunnel source address, but nothing is fenced off from the WAN.
pub fn apply_forwarding_only(rs: &RuleSet) -> Result<()> {
    tracing::debug!("Applying tunnel forwarding plane (kill-switch off) via fw3/iptables");

    let with_v6 = ipv6_status() == Ipv6Status::Enabled;
    begin_transition()?;

    // Remove persisted blocking state before opening the live firewall. While
    // the marker exists, a racing reload installs the emergency block rather
    // than interpreting the absent v4 file as permission to clean/open.
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

    // Publish the non-blocking state, then lift any emergency block a reload
    // installed meanwhile. A reload after marker removal sees no v4
    // activation file and performs the same cleanup, so disabling cannot
    // resurrect stale blocking policy.
    finish_transition()?;
    remove_emergency_blocks(with_v6)?;

    tracing::debug!("Tunnel forwarding plane applied successfully");
    Ok(())
}

/// Tear down the jumps and our chains. Best-effort throughout.
pub fn reset() -> Result<()> {
    tracing::debug!("Resetting firewall policy via fw3/iptables backend");

    let with_v6 = ipv6_status() == Ipv6Status::Enabled;
    begin_transition()?;

    // Clear persisted state while reloads are marker-gated. Once the marker
    // is removed, both the include and this path agree that no policy should
    // be resurrected.
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

/// Hook our filter chains from fw3's `*_rule` chains. Each jump must lead
/// its hook chain: nothing but other Nym jumps may run before it, or a
/// foreign rule (another include, `firewall.user`) inserted at position 1
/// could accept traffic past the kill-switch. A jump already in a valid
/// position is left alone — deleting and re-inserting would leave our chains
/// unhooked for a moment on every re-apply. Otherwise it is inserted at
/// position 1 first and any stale later occurrence removed afterwards, so
/// there is never a moment without the jump.
fn setup_jumps(family: AddrFamily) -> Result<()> {
    let ipt = ipt_cmd(family);
    for (hook, target) in JUMPS {
        ensure_jump(ipt, hook, target, JumpPosition::Leading)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JumpPosition {
    /// Must be rule 1 exactly (the LAN forwarding plane, whose MSS clamp
    /// must run before the kill-switch chain accepts tunnel-bound flows).
    First,
    /// Only jumps to our own `NYM_*` chains may precede it.
    Leading,
}

/// Rule specs (`-A <hook> ...` with the prefix stripped) of a filter chain,
/// in rule-number order.
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
    // Remove stale duplicates after the leading one, highest rule number
    // first so the numbers of the remaining ones stay valid.
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

/// Jumps in the `mangle` table. Unlike the filter table, there are no fw3
/// `*_rule` chains in mangle — we jump directly from the built-in PREROUTING
/// and OUTPUT hooks.
const MANGLE_JUMPS: [(&str, &str); 2] = [
    ("PREROUTING", CHAIN_MANGLE_PREROUTING),
    ("OUTPUT", CHAIN_MANGLE_OUTPUT),
];

/// Insert jumps from the mangle table's built-in chains into ours at position 1.
/// Idempotent: any existing jump is removed first.
/// Mangle jumps are only checked for presence, not position: they exist to
/// mark exempted inbound flows, so a foreign rule running first can only
/// leave a flow unmarked (blocked) — fail-closed, never a bypass.
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

/// `iptables -C`: true when the jump rule exists. A missing hook chain
/// (firewall stopped) reads as absent; only a failure to run iptables at all
/// is an error.
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

/// Populate [`FORWARD_LAN_CHAIN`] with per-interface MSS clamps and forward
/// accepts, and jump to it from fw3's `forwarding_rule` hook. Mirrors
/// `integrate_with_fw4`: owned chain, flush + repopulate, jump re-inserted
/// at position 1. IPv4 failures are hard errors; IPv6 is best-effort (the
/// kernel may not have v6 at all, and these rules are additive accepts).
fn add_forwarding_rules(interfaces: &[String]) -> Result<()> {
    add_forwarding_rules_family("iptables", interfaces)?;
    if let Err(e) = add_forwarding_rules_family("ip6tables", interfaces) {
        tracing::debug!("ip6tables forwarding plane (non-fatal): {e}");
    }
    Ok(())
}

fn add_forwarding_rules_family(ipt: &str, interfaces: &[String]) -> Result<()> {
    // -N errors with "Chain already exists" on re-runs; treat as success.
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
        // Clamp TCP MSS to the path MTU for flows entering/leaving the
        // tunnel (see the fw4 backend for the full rationale). Must precede
        // the accepts.
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-o", iface, "-p", "tcp", "--tcp-flags",
            "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-i", iface, "-p", "tcp", "--tcp-flags",
            "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
        run_ipt(ipt, &["-w", "-A", FORWARD_LAN_CHAIN, "-o", iface, "-j", "ACCEPT"])?;
        // Return traffic from tunnel to LAN, scoped to established flows —
        // the exit never initiates into the LAN.
        run_ipt(ipt, &[
            "-w", "-A", FORWARD_LAN_CHAIN, "-i", iface, "-m", "conntrack", "--ctstate",
            "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])?;
        tracing::debug!("Populated {FORWARD_LAN_CHAIN} ({ipt}) for interface {iface}");
    }
    // Must be rule 1: its MSS clamp has to run before NYM_FORWARD accepts
    // tunnel-bound flows. Re-asserted without a delete/insert gap.
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn jump_position_rules() {
        let r = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let j = "-j NYM_OUTPUT";
        assert!(jump_position_ok(&r(&[j]), j, JumpPosition::Leading));
        assert!(jump_position_ok(&r(&[j, "-j ACCEPT"]), j, JumpPosition::First));
        // Our own chains may precede in Leading mode, but not in First mode.
        assert!(jump_position_ok(&r(&["-j NYM_EMERGENCY_OUT", j]), j, JumpPosition::Leading));
        assert!(!jump_position_ok(&r(&["-j NYM_EMERGENCY_OUT", j]), j, JumpPosition::First));
        // A foreign rule ahead of the jump is never acceptable.
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

    /// The include installs its boot-time block in the same chains this
    /// backend lifts. Scan the script so a rename on either side fails here
    /// instead of leaving chains nobody removes, and pin the allowances the
    /// boot rule set must keep so a crash-looping daemon never locks the
    /// administrator out of the LAN.
    #[test]
    fn include_script_shares_the_emergency_chains_and_boot_rules_keep_lan_alive() {
        const INCLUDE: &str = include_str!("../../scripts/fw3-include.sh");
        let lines: Vec<&str> = INCLUDE.lines().map(str::trim).collect();

        let out = format!("EMERGENCY_OUT=\"{EMERGENCY_OUTPUT_CHAIN}\"");
        let fwd = format!("EMERGENCY_FWD=\"{EMERGENCY_FORWARD_CHAIN}\"");
        assert!(lines.contains(&out.as_str()), "fw3-include.sh must define {out}");
        assert!(lines.contains(&fwd.as_str()), "fw3-include.sh must define {fwd}");

        for must in [
            "-A $EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT",
            "echo \"-A $EMERGENCY_OUT -o lo -j ACCEPT\"",
            "-A $EMERGENCY_OUT -p udp --sport 68 --dport 67 -j ACCEPT",
            "-A $EMERGENCY_OUT -p udp --sport 67 --dport 68 -j ACCEPT",
            "-A $EMERGENCY_OUT -p udp --sport 546 --dport 547 -j ACCEPT",
            "-A $EMERGENCY_OUT -p udp --sport 547 --dport 546 -j ACCEPT",
            "-A $EMERGENCY_OUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT",
            "echo \"-A $EMERGENCY_OUT -d $net -j ACCEPT\"",
            "echo \"-A $EMERGENCY_FWD -d $net -j ACCEPT\"",
            "LAN_NETS_V4=\"10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16\"",
            "LAN_NETS_V6=\"fe80::/10 fc00::/7\"",
            "-A $EMERGENCY_OUT -j DROP",
            "-A $EMERGENCY_FWD -j DROP",
        ] {
            assert!(lines.contains(&must), "fw3-include.sh boot block must carry: {must}");
        }
        // INPUT stays fw3's: no emergency rule ever targets input_rule.
        assert!(!lines.iter().any(|l| {
            !l.starts_with('#') && l.contains("EMERGENCY") && l.contains("HOOK_INPUT")
        }));
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
