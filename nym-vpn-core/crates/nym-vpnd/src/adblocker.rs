// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt dnsmasq-based ad-blocking.
//!
//! Downloads a blocklist and converts it to dnsmasq `local=` directives that
//! resolve blocked domains to NXDOMAIN immediately without upstream forwarding.
//! The blocklist is written to `/tmp/dnsmasq.d/nym-adblock.conf` and dnsmasq is
//! restarted to pick up the changes.

use std::path::Path;
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

/// Re-apply ad-blocking on startup if it was previously enabled.
pub async fn restore_if_enabled(config: &nym_vpn_lib_types::VpnServiceConfig) {
    if config.enable_ad_blocking {
        if let Err(e) = apply_adblock().await {
            tracing::error!("Failed to restore ad-blocking on startup: {e}");
        }
    }
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

/// Redirect all LAN DNS (port 53) to the router's dnsmasq so the blocklist
/// is enforced even for clients with hardcoded DNS servers.
async fn install_dns_redirect() -> Result<(), AdblockError> {
    // Idempotent: check if rule already exists
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

    tracing::info!("Installing DNS redirect rules for ad-blocking");

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

/// Remove the DNS redirect rules.
async fn remove_dns_redirect() -> Result<(), AdblockError> {
    tracing::info!("Removing DNS redirect rules");

    for proto in &["udp", "tcp"] {
        // May fail if rules don't exist — that's fine
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
