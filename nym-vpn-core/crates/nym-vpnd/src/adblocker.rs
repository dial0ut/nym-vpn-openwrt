// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt dnsmasq-based ad-blocking.
//!
//! Downloads a blocklist and converts it to dnsmasq `local=` directives that
//! resolve blocked domains to NXDOMAIN immediately without upstream forwarding.
//! The blocklist is written to `/tmp/dnsmasq.d/nym-adblock.conf` and dnsmasq is
//! restarted to pick up the changes.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::fs;
use tokio::process::Command;

const DNSMASQ_CONF_DIR: &str = "/tmp/dnsmasq.d";
const DNSMASQ_CONF_FILE: &str = "/tmp/dnsmasq.d/nym-adblock.conf";

/// Hagezi Multi Normal blocklist — good balance of coverage vs false positives.
const BLOCKLIST_URL: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/multi.txt";

/// Download the blocklist and install it into dnsmasq.
pub async fn apply_adblock() -> Result<(), AdblockError> {
    tracing::info!("Applying ad-blocking via dnsmasq");

    // Download blocklist
    let body = download_blocklist().await?;

    // Parse hosts file into domain list, convert to dnsmasq format
    let conf = hosts_to_dnsmasq(&body);

    // Ensure dnsmasq.d directory exists
    fs::create_dir_all(DNSMASQ_CONF_DIR)
        .await
        .map_err(|e| AdblockError::Io("create dnsmasq.d dir", e))?;

    // Write the config file
    fs::write(DNSMASQ_CONF_FILE, conf.as_bytes())
        .await
        .map_err(|e| AdblockError::Io("write dnsmasq conf", e))?;

    tracing::info!("Wrote ad-block config to {DNSMASQ_CONF_FILE}");

    // Ensure dnsmasq is configured to read from our conf directory
    ensure_dnsmasq_confdir().await?;

    // Intercept LAN DNS so all clients go through dnsmasq
    install_dns_redirect().await?;

    restart_dnsmasq().await?;

    Ok(())
}

/// Remove the dnsmasq ad-block config and restart dnsmasq.
pub async fn remove_adblock() -> Result<(), AdblockError> {
    tracing::info!("Removing ad-blocking config");

    // Remove DNS redirect rules
    remove_dns_redirect().await?;

    if Path::new(DNSMASQ_CONF_FILE).exists() {
        fs::remove_file(DNSMASQ_CONF_FILE)
            .await
            .map_err(|e| AdblockError::Io("remove dnsmasq conf", e))?;

        restart_dnsmasq().await?;
    }

    Ok(())
}

/// Bumped on every explicit enable/disable so a pending background restore
/// can tell it has been superseded by a user action. Usize, not u64: the
/// 32-bit tier-3 targets (mips, armv5te) have no `AtomicU64` in std, and
/// only equality is ever compared so width doesn't matter.
static TOGGLE_GENERATION: AtomicUsize = AtomicUsize::new(0);

/// Must be called from the explicit enable/disable path (not from restore):
/// supersedes any background restore still retrying its download.
pub fn note_explicit_toggle() {
    TOGGLE_GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// Re-apply ad-blocking on startup if it was previously enabled.
///
/// The kill-switch keeps its blocked policy loaded while disconnected, so a
/// blocklist download at daemon startup is *expected* to fail (instant curl
/// exit 7). Two-tier recovery: after a daemon restart the converted list in
/// /tmp is still installed and dnsmasq is already serving it, so only the
/// redirect rules are re-asserted — no download, no dnsmasq restart. After a
/// reboot (/tmp empty) the download is retried in the background with
/// backoff; it succeeds once a tunnel is up or the kill-switch is off.
pub async fn restore_if_enabled(config: &nym_vpn_lib_types::VpnServiceConfig) {
    if !config.enable_ad_blocking {
        return;
    }

    if Path::new(DNSMASQ_CONF_FILE).exists() {
        tracing::info!("Ad-block list already installed; re-asserting DNS redirect only");
        if let Err(e) = install_dns_redirect().await {
            tracing::warn!("Failed to re-assert ad-block DNS redirect: {e}");
        }
        return;
    }

    tokio::spawn(async {
        let generation = TOGGLE_GENERATION.load(Ordering::Relaxed);
        let mut delay = std::time::Duration::from_secs(15);
        let mut first = true;
        loop {
            match apply_adblock().await {
                Ok(()) => return,
                Err(e) if first => {
                    first = false;
                    tracing::warn!("Ad-block restore failed (will keep retrying): {e}");
                }
                Err(e) => tracing::debug!("Ad-block restore retry failed: {e}"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(std::time::Duration::from_secs(300));
            if TOGGLE_GENERATION.load(Ordering::Relaxed) != generation {
                tracing::debug!("Ad-block restore superseded by explicit toggle");
                return;
            }
        }
    });
}

fn hosts_to_dnsmasq(hosts_content: &str) -> String {
    let mut lines = Vec::new();
    lines.push("# NymVPN ad-block list — auto-generated, do not edit".to_string());
    lines.push("# Source: hagezi/dns-blocklists multi.txt".to_string());

    for line in hosts_content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let domain = parts[1];

        // Skip localhost entries
        if domain == "localhost"
            || domain == "localhost.localdomain"
            || domain == "local"
            || domain.is_empty()
        {
            continue;
        }

        // local= tells dnsmasq to answer NXDOMAIN immediately without
        // forwarding to any upstream — much faster than server= with empty upstream
        lines.push(format!("local=/{domain}/"));
    }

    let count = lines.len() - 2; // subtract header lines
    tracing::info!("Parsed {count} domains for ad-blocking");

    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

async fn download_blocklist() -> Result<String, AdblockError> {
    tracing::info!("Downloading blocklist from {BLOCKLIST_URL}");

    // Use curl since it's always available on OpenWrt and avoids pulling in
    // a heavy HTTP client dependency just for this one request.
    let output = Command::new("curl")
        .args(["-sL", "--connect-timeout", "30", "--max-time", "120", BLOCKLIST_URL])
        .output()
        .await
        .map_err(|e| AdblockError::Io("run curl", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AdblockError::Download(format!(
            "curl failed with status {}: {}",
            output.status, stderr
        )));
    }

    String::from_utf8(output.stdout).map_err(|e| AdblockError::Download(e.to_string()))
}

/// Configure dnsmasq to read from `/tmp/dnsmasq.d/` via UCI.
async fn ensure_dnsmasq_confdir() -> Result<(), AdblockError> {
    // Check if confdir is already set
    let check = Command::new("uci")
        .args(["get", "dhcp.@dnsmasq[0].confdir"])
        .output()
        .await
        .map_err(|e| AdblockError::Io("uci get confdir", e))?;

    let current = String::from_utf8_lossy(&check.stdout).trim().to_string();
    if current == DNSMASQ_CONF_DIR {
        tracing::debug!("dnsmasq confdir already set");
        return Ok(());
    }

    tracing::info!("Setting dnsmasq confdir to {DNSMASQ_CONF_DIR}");

    let set = Command::new("uci")
        .args(["set", &format!("dhcp.@dnsmasq[0].confdir={DNSMASQ_CONF_DIR}")])
        .output()
        .await
        .map_err(|e| AdblockError::Io("uci set confdir", e))?;

    if !set.status.success() {
        tracing::warn!(
            "uci set confdir failed: {}",
            String::from_utf8_lossy(&set.stderr)
        );
    }

    let commit = Command::new("uci")
        .args(["commit", "dhcp"])
        .output()
        .await
        .map_err(|e| AdblockError::Io("uci commit dhcp", e))?;

    if !commit.status.success() {
        tracing::warn!(
            "uci commit dhcp failed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );
    }

    Ok(())
}

/// Detect whether this is an fw4 (nftables) or fw3 (iptables) system.
/// Mirrors the check in `nym-firewall/src/openwrt/detect.rs`.
fn is_fw4() -> bool {
    Path::new("/sbin/fw4").exists() || Path::new("/usr/sbin/fw4").exists()
}

/// Redirect all LAN DNS (port 53) to the router's dnsmasq so the blocklist
/// is enforced even for clients with hardcoded DNS servers.
async fn install_dns_redirect() -> Result<(), AdblockError> {
    if is_fw4() {
        install_dns_redirect_nft().await
    } else {
        install_dns_redirect_ipt().await
    }
}

/// Remove the DNS redirect rules.
async fn remove_dns_redirect() -> Result<(), AdblockError> {
    if is_fw4() {
        remove_dns_redirect_nft().await
    } else {
        remove_dns_redirect_ipt().await
    }
}

// --- nftables (fw4) implementation ---

const NFT_TABLE: &str = "nym_adblock";

async fn install_dns_redirect_nft() -> Result<(), AdblockError> {
    // Idempotent: check if our table already exists
    let check = Command::new("nft")
        .args(["list", "table", "ip", NFT_TABLE])
        .output()
        .await
        .map_err(|e| AdblockError::Io("nft check table", e))?;

    if check.status.success() {
        tracing::debug!("DNS redirect nft table already installed");
        return Ok(());
    }

    tracing::info!("Installing nftables DNS redirect rules for ad-blocking");

    let ruleset = format!(
        "table ip {table} {{\n\
         \tchain prerouting {{\n\
         \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
         \t\tiifname \"br-lan\" udp dport 53 redirect to :53\n\
         \t\tiifname \"br-lan\" tcp dport 53 redirect to :53\n\
         \t}}\n\
         }}",
        table = NFT_TABLE,
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AdblockError::Io("nft spawn", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(ruleset.as_bytes())
            .await
            .map_err(|e| AdblockError::Io("nft write stdin", e))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| AdblockError::Io("nft wait", e))?;

    if !output.status.success() {
        tracing::warn!(
            "Failed to install nft DNS redirect: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

async fn remove_dns_redirect_nft() -> Result<(), AdblockError> {
    tracing::info!("Removing nftables DNS redirect rules");
    // Deleting the whole table is atomic and idempotent-safe
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", NFT_TABLE])
        .output()
        .await;
    Ok(())
}

// --- iptables (fw3) implementation ---

async fn install_dns_redirect_ipt() -> Result<(), AdblockError> {
    let check = Command::new("iptables")
        .args([
            "-t", "nat", "-C", "PREROUTING",
            "-i", "br-lan", "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-ports", "53",
        ])
        .output()
        .await
        .map_err(|e| AdblockError::Io("iptables check", e))?;

    if check.status.success() {
        tracing::debug!("DNS redirect rules already installed");
        return Ok(());
    }

    tracing::info!("Installing iptables DNS redirect rules for ad-blocking");

    for proto in &["udp", "tcp"] {
        let output = Command::new("iptables")
            .args([
                "-t", "nat", "-A", "PREROUTING",
                "-i", "br-lan", "-p", proto, "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "53",
            ])
            .output()
            .await
            .map_err(|e| AdblockError::Io("iptables add redirect", e))?;

        if !output.status.success() {
            tracing::warn!(
                "Failed to add {proto} DNS redirect: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    Ok(())
}

async fn remove_dns_redirect_ipt() -> Result<(), AdblockError> {
    tracing::info!("Removing iptables DNS redirect rules");

    for proto in &["udp", "tcp"] {
        let _ = Command::new("iptables")
            .args([
                "-t", "nat", "-D", "PREROUTING",
                "-i", "br-lan", "-p", proto, "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "53",
            ])
            .output()
            .await;
    }

    Ok(())
}

async fn restart_dnsmasq() -> Result<(), AdblockError> {
    tracing::info!("Restarting dnsmasq");

    let output = Command::new("/etc/init.d/dnsmasq")
        .arg("restart")
        .output()
        .await
        .map_err(|e| AdblockError::Io("restart dnsmasq", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("dnsmasq restart returned non-zero: {stderr}");
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum AdblockError {
    #[error("I/O error ({0}): {1}")]
    Io(&'static str, #[source] std::io::Error),

    #[error("Failed to download blocklist: {0}")]
    Download(String),
}
