// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt dnsmasq DNS backend.
//!
//! Configures dnsmasq upstream servers via UCI commands and writes
//! `/etc/resolv.conf` for local programs (nslookup, curl, etc.).
//!
//! Key design: uses `uci set` without `uci commit`, so changes go to
//! the staging area (`/tmp/.uci/dhcp`). On reboot, the staging area
//! is cleared and dnsmasq automatically reverts to original config.

use std::{
    fs, io,
    net::IpAddr,
    path::Path,
    process::Command,
};

pub type Result<T> = std::result::Result<T, Error>;

/// Prefer IPv4 upstream resolvers when both families are present. IPv6
/// upstreams are only reachable when the exit gateway actually carries IPv6,
/// which cannot be verified from the router; unreachable IPv6 upstreams cause
/// per-lookup timeouts in dnsmasq. AAAA records still resolve fine over IPv4
/// transport, so dropping the IPv6 upstreams loses nothing.
fn prefer_ipv4_upstreams(servers: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
    let v4: Vec<std::net::IpAddr> = servers.iter().copied().filter(|ip| ip.is_ipv4()).collect();
    if v4.is_empty() { servers.to_vec() } else { v4 }
}

const OPENWRT_RELEASE: &str = "/etc/openwrt_release";
const BACKUP_MARKER: &str = "/tmp/nym-dns-backup";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP: &str = "/tmp/resolv.conf.nymbackup";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not running on OpenWrt")]
    NotOpenWrt,

    #[error("dnsmasq not configured via UCI")]
    NoDnsmasq,

    #[error("failed to execute UCI command: {0}")]
    UciCommand(String),

    #[error("failed to restart dnsmasq: {0}")]
    DnsmasqRestart(String),

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: &'static str,
        source: io::Error,
    },

    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: &'static str,
        source: io::Error,
    },
}

pub struct Dnsmasq {
    /// Whether set_dns has been called (backup already created).
    configured: bool,
}

impl Dnsmasq {
    pub fn new() -> Result<Self> {
        // Check if we're on OpenWrt
        if !Path::new(OPENWRT_RELEASE).exists() {
            return Err(Error::NotOpenWrt);
        }

        // Check if dnsmasq is configured via UCI
        let output = Command::new("uci")
            .args(["get", "dhcp.@dnsmasq[0]"])
            .output()
            .map_err(|e| Error::UciCommand(e.to_string()))?;

        if !output.status.success() {
            return Err(Error::NoDnsmasq);
        }

        // Crash recovery: if backup marker exists, a previous session didn't clean up
        if Path::new(BACKUP_MARKER).exists() {
            tracing::info!("Found stale DNS backup, recovering previous state");
            if let Err(e) = Self::do_reset() {
                tracing::warn!("Crash recovery partial failure: {}", e);
            }
        }

        tracing::debug!("OpenWrt dnsmasq DNS backend initialized");
        Ok(Dnsmasq { configured: false })
    }

    pub fn set_dns(&mut self, servers: &[IpAddr]) -> Result<()> {
        if !self.configured {
            // First call: save current state
            self.save_backup()?;
            self.configured = true;
        }

        let servers = prefer_ipv4_upstreams(servers);
        let servers = servers.as_slice();

        // Set noresolv so dnsmasq ignores /tmp/resolv.conf.d/resolv.conf.auto
        uci_set("dhcp.@dnsmasq[0].noresolv", "1")?;

        // Clear existing server list
        // `uci delete` on a list option removes the entire list.
        // It's not an error if the option doesn't exist yet.
        let _ = uci_delete("dhcp.@dnsmasq[0].server");

        // Add each VPN DNS server
        for server in servers {
            uci_add_list("dhcp.@dnsmasq[0].server", &server.to_string())?;
        }

        // Write /etc/resolv.conf for local programs
        self.write_resolv_conf(servers)?;

        // Restart dnsmasq to pick up changes
        restart_dnsmasq()?;

        tracing::info!(
            "Configured dnsmasq with VPN DNS servers: {:?}",
            servers
        );

        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        if !self.configured {
            return Ok(());
        }

        Self::do_reset()?;
        self.configured = false;

        tracing::info!("Restored dnsmasq to original DNS configuration");
        Ok(())
    }

    /// Shared reset logic used by both `reset()` and crash recovery.
    fn do_reset() -> Result<()> {
        // Revert all staged UCI changes for dhcp — restores original config
        uci_revert("dhcp")?;

        // Restore /etc/resolv.conf from backup
        if Path::new(RESOLV_CONF_BACKUP).exists() {
            match fs::read_to_string(RESOLV_CONF_BACKUP) {
                Ok(backup) => {
                    fs::write(RESOLV_CONF, backup.as_bytes()).map_err(|e| Error::WriteFile {
                        path: RESOLV_CONF,
                        source: e,
                    })?;
                }
                Err(e) => {
                    tracing::warn!("Failed to read resolv.conf backup: {}", e);
                }
            }
            let _ = fs::remove_file(RESOLV_CONF_BACKUP);
        }

        // Restart dnsmasq with restored config
        restart_dnsmasq()?;

        // Remove backup marker
        let _ = fs::remove_file(BACKUP_MARKER);

        Ok(())
    }

    /// Save current UCI state and resolv.conf so we can restore on reset.
    fn save_backup(&self) -> Result<()> {
        // Save current noresolv and server values as a simple marker.
        // The actual restore uses `uci revert` which discards staged changes,
        // so we don't need to store the full UCI state — just a marker that
        // we modified things.
        fs::write(BACKUP_MARKER, b"active").map_err(|e| Error::WriteFile {
            path: BACKUP_MARKER,
            source: e,
        })?;

        // Backup /etc/resolv.conf
        if Path::new(RESOLV_CONF).exists() {
            let contents = fs::read_to_string(RESOLV_CONF).map_err(|e| Error::ReadFile {
                path: RESOLV_CONF,
                source: e,
            })?;
            fs::write(RESOLV_CONF_BACKUP, contents.as_bytes()).map_err(|e| Error::WriteFile {
                path: RESOLV_CONF_BACKUP,
                source: e,
            })?;
        }

        Ok(())
    }

    /// Write /etc/resolv.conf with the VPN nameservers.
    fn write_resolv_conf(&self, servers: &[IpAddr]) -> Result<()> {
        let mut contents = String::from("# Generated by nym-vpnd\n");
        for server in servers {
            contents.push_str(&format!("nameserver {}\n", server));
        }
        fs::write(RESOLV_CONF, contents.as_bytes()).map_err(|e| Error::WriteFile {
            path: RESOLV_CONF,
            source: e,
        })
    }
}

/// Run `uci set <key>=<value>` (staged, not committed).
fn uci_set(key: &str, value: &str) -> Result<()> {
    let arg = format!("{}={}", key, value);
    let output = Command::new("uci")
        .args(["set", &arg])
        .output()
        .map_err(|e| Error::UciCommand(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::UciCommand(format!("uci set {} failed: {}", arg, stderr)));
    }
    Ok(())
}

/// Run `uci delete <key>`. Returns Ok even if the key doesn't exist.
fn uci_delete(key: &str) -> Result<()> {
    let output = Command::new("uci")
        .args(["delete", key])
        .output()
        .map_err(|e| Error::UciCommand(e.to_string()))?;

    // uci delete returns non-zero if the entry doesn't exist, which is fine
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::debug!("uci delete {} (may not exist): {}", key, stderr);
    }
    Ok(())
}

/// Run `uci add_list <key>=<value>` (staged, not committed).
fn uci_add_list(key: &str, value: &str) -> Result<()> {
    let arg = format!("{}={}", key, value);
    let output = Command::new("uci")
        .args(["add_list", &arg])
        .output()
        .map_err(|e| Error::UciCommand(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::UciCommand(format!(
            "uci add_list {} failed: {}",
            arg, stderr
        )));
    }
    Ok(())
}

/// Run `uci revert <config>` to discard all staged changes.
fn uci_revert(config: &str) -> Result<()> {
    let output = Command::new("uci")
        .args(["revert", config])
        .output()
        .map_err(|e| Error::UciCommand(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::UciCommand(format!(
            "uci revert {} failed: {}",
            config, stderr
        )));
    }
    Ok(())
}

/// Restart dnsmasq via its init script.
fn restart_dnsmasq() -> Result<()> {
    let output = Command::new("/etc/init.d/dnsmasq")
        .arg("restart")
        .output()
        .map_err(|e| Error::DnsmasqRestart(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::DnsmasqRestart(stderr.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::prefer_ipv4_upstreams;
    use std::net::IpAddr;

    #[test]
    fn prefers_ipv4_upstreams_when_mixed() {
        let servers: Vec<IpAddr> = vec![
            "2620:fe::fe".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let got = prefer_ipv4_upstreams(&servers);
        assert_eq!(
            got,
            vec!["9.9.9.9".parse::<IpAddr>().unwrap(), "1.1.1.1".parse().unwrap()]
        );
    }

    #[test]
    fn keeps_ipv6_when_no_ipv4_available() {
        let servers: Vec<IpAddr> = vec!["2620:fe::fe".parse().unwrap()];
        assert_eq!(prefer_ipv4_upstreams(&servers), servers);
    }
}
