// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! OpenWrt dnsmasq-based ad-blocking.
//!
//! Downloads a blocklist and converts it to dnsmasq `local=` directives that
//! resolve blocked domains to NXDOMAIN immediately without upstream forwarding.
//! The blocklist is written to `/tmp/dnsmasq.d/nym-adblock.conf` and dnsmasq is
//! restarted to pick up the changes.
//!
//! None of this runs on the service loop: the download alone can take two
//! minutes. Every apply and remove, from a toggle or the startup restore,
//! takes one lock, so two never interleave their dnsmasq and firewall edits,
//! and a newer toggle supersedes runs still queued or downloading.

use std::{
    future::Future,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    fs,
    process::Command,
    sync::{Mutex, Notify},
};

const DNSMASQ_CONF_DIR: &str = "/tmp/dnsmasq.d";
const DNSMASQ_CONF_FILE: &str = "/tmp/dnsmasq.d/nym-adblock.conf";

/// Hagezi Multi Normal blocklist — good balance of coverage vs false positives.
const BLOCKLIST_URL: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/multi.txt";

const RESTORE_FIRST_RETRY: Duration = Duration::from_secs(15);
const RESTORE_MAX_RETRY: Duration = Duration::from_secs(300);

/// Install a downloaded blocklist into dnsmasq.
async fn install_blocklist(body: String) -> Result<(), AdblockError> {
    tracing::info!("Applying ad-blocking via dnsmasq");

    // Parse hosts file into domain list, convert to dnsmasq format. Hundreds
    // of thousands of lines: keep it off the async workers.
    let conf = tokio::task::spawn_blocking(move || hosts_to_dnsmasq(&body))
        .await
        .map_err(AdblockError::Convert)?;

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
async fn remove_adblock() -> Result<(), AdblockError> {
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

/// The system side of an apply or remove; a fake in tests.
trait Backend: Sync {
    /// Abandoned midway when a newer toggle supersedes the run.
    fn download(&self) -> impl Future<Output = Result<String, AdblockError>> + Send;
    /// Always runs to completion once started.
    fn install(&self, blocklist: String) -> impl Future<Output = Result<(), AdblockError>> + Send;
    fn remove(&self) -> impl Future<Output = Result<(), AdblockError>> + Send;
}

struct System;

impl Backend for System {
    fn download(&self) -> impl Future<Output = Result<String, AdblockError>> + Send {
        download_blocklist()
    }

    fn install(&self, blocklist: String) -> impl Future<Output = Result<(), AdblockError>> + Send {
        install_blocklist(blocklist)
    }

    fn remove(&self) -> impl Future<Output = Result<(), AdblockError>> + Send {
        remove_adblock()
    }
}

enum Run {
    Done,
    Superseded,
}

/// Orders explicit toggles and serializes every apply and remove.
struct Toggles {
    /// Bumped on every explicit enable/disable, on the service loop, so a run
    /// can tell a newer click has superseded it. Usize, not u64: the 32-bit
    /// tier-3 targets (mips, armv5te) have no `AtomicU64` in std, and only
    /// equality is ever compared so width doesn't matter.
    generation: AtomicUsize,
    /// Held for a whole run, restore included.
    lock: Mutex<()>,
    /// Wakes a download that a newer toggle has superseded.
    toggled: Notify,
}

static TOGGLES: Toggles = Toggles::new();

impl Toggles {
    const fn new() -> Self {
        Self {
            generation: AtomicUsize::new(0),
            lock: Mutex::const_new(()),
            toggled: Notify::const_new(),
        }
    }

    fn current(&self) -> usize {
        self.generation.load(Ordering::SeqCst)
    }

    fn toggle(&self) -> usize {
        let generation = self
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        self.toggled.notify_waiters();
        generation
    }

    /// Resolves once a toggle newer than `generation` has been made.
    async fn superseded(&self, generation: usize) {
        loop {
            let toggled = self.toggled.notified();
            let mut toggled = std::pin::pin!(toggled);
            // Registered before the check, so a toggle in between still wakes us.
            toggled.as_mut().enable();
            if self.current() != generation {
                return;
            }
            toggled.await;
        }
    }

    /// One apply or remove on behalf of `generation`: waits its turn, skips if
    /// a newer toggle came meanwhile and abandons a download one supersedes.
    /// A started install or remove always completes.
    async fn run<B: Backend>(
        &self,
        backend: &B,
        enable: bool,
        generation: usize,
    ) -> Result<Run, AdblockError> {
        let _turn = self.lock.lock().await;
        if self.current() != generation {
            return Ok(Run::Superseded);
        }
        if !enable {
            backend.remove().await?;
            return Ok(Run::Done);
        }
        let blocklist = tokio::select! {
            _ = self.superseded(generation) => return Ok(Run::Superseded),
            blocklist = backend.download() => blocklist?,
        };
        backend.install(blocklist).await?;
        Ok(Run::Done)
    }

    /// Apply with backoff until it lands or an explicit toggle supersedes it.
    async fn restore<B: Backend>(&self, backend: &B, generation: usize) {
        let mut delay = RESTORE_FIRST_RETRY;
        let mut first = true;
        loop {
            match self.run(backend, true, generation).await {
                Ok(Run::Done) => return,
                Ok(Run::Superseded) => {
                    tracing::debug!("Ad-block restore superseded by explicit toggle");
                    return;
                }
                Err(e) if first => {
                    first = false;
                    tracing::warn!("Ad-block restore failed (will keep retrying): {e}");
                }
                Err(e) => tracing::debug!("Ad-block restore retry failed: {e}"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(RESTORE_MAX_RETRY);
        }
    }
}

/// Call on the service loop for every explicit enable/disable, in click
/// order; pass the result to the [`apply_toggle`] it spawns. Supersedes
/// older runs, the startup restore included.
pub fn note_explicit_toggle() -> usize {
    TOGGLES.toggle()
}

/// The slow half of an explicit toggle, to be spawned. Does nothing if a
/// newer toggle has been made by the time its turn comes.
pub async fn apply_toggle(enable: bool, generation: usize) {
    let action = if enable { "apply" } else { "remove" };
    match TOGGLES.run(&System, enable, generation).await {
        Ok(Run::Done) => {}
        Ok(Run::Superseded) => tracing::debug!("Ad-block {action} superseded by a newer toggle"),
        Err(e) => tracing::error!("Failed to {action} ad-blocking: {e}"),
    }
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
        let _turn = TOGGLES.lock.lock().await;
        if let Err(e) = install_dns_redirect().await {
            tracing::warn!("Failed to re-assert ad-block DNS redirect: {e}");
        }
        return;
    }

    let generation = TOGGLES.current();
    tokio::spawn(TOGGLES.restore(&System, generation));
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
        // A superseded download is dropped mid-transfer; curl goes with it.
        .kill_on_drop(true)
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

    #[error("Failed to convert blocklist: {0}")]
    Convert(#[source] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex, atomic::AtomicBool};

    /// Records every step, 30 s each, and whether two ever ran at once.
    struct Fake {
        steps: StdMutex<Vec<&'static str>>,
        busy: AtomicBool,
        overlapped: AtomicBool,
        failing_downloads: AtomicUsize,
    }

    struct Busy<'a>(&'a Fake);

    impl Drop for Busy<'_> {
        fn drop(&mut self) {
            self.0.busy.store(false, Ordering::SeqCst);
        }
    }

    impl Fake {
        fn new(failing_downloads: usize) -> Arc<Self> {
            Arc::new(Self {
                steps: StdMutex::new(Vec::new()),
                busy: AtomicBool::new(false),
                overlapped: AtomicBool::new(false),
                failing_downloads: AtomicUsize::new(failing_downloads),
            })
        }

        async fn step(&self, name: &'static str) {
            if self.busy.swap(true, Ordering::SeqCst) {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            let _busy = Busy(self);
            self.steps.lock().unwrap().push(name);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }

        fn steps(&self) -> Vec<&'static str> {
            self.steps.lock().unwrap().clone()
        }
    }

    impl Backend for Arc<Fake> {
        async fn download(&self) -> Result<String, AdblockError> {
            self.step("download").await;
            if self.failing_downloads.load(Ordering::SeqCst) > 0 {
                self.failing_downloads.fetch_sub(1, Ordering::SeqCst);
                return Err(AdblockError::Download("unreachable".into()));
            }
            Ok("0.0.0.0 ads.example\n".into())
        }

        async fn install(&self, _blocklist: String) -> Result<(), AdblockError> {
            self.step("install").await;
            Ok(())
        }

        async fn remove(&self) -> Result<(), AdblockError> {
            self.step("remove").await;
            Ok(())
        }
    }

    /// An explicit toggle as the service loop makes it.
    fn toggle(
        toggles: &Arc<Toggles>,
        fake: &Arc<Fake>,
        enable: bool,
    ) -> tokio::task::JoinHandle<Result<Run, AdblockError>> {
        let generation = toggles.toggle();
        let (toggles, fake) = (toggles.clone(), fake.clone());
        tokio::spawn(async move { toggles.run(&fake, enable, generation).await })
    }

    fn restore(toggles: &Arc<Toggles>, fake: &Arc<Fake>) -> tokio::task::JoinHandle<()> {
        let generation = toggles.current();
        let (toggles, fake) = (toggles.clone(), fake.clone());
        tokio::spawn(async move { toggles.restore(&fake, generation).await })
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_last_of_several_toggles_applies() {
        let toggles = Arc::new(Toggles::new());
        let fake = Fake::new(0);

        let first = toggle(&toggles, &fake, true);
        tokio::time::sleep(Duration::from_secs(10)).await; // mid-download
        let second = toggle(&toggles, &fake, false);
        let third = toggle(&toggles, &fake, true);

        assert!(matches!(first.await.unwrap(), Ok(Run::Superseded)));
        assert!(matches!(second.await.unwrap(), Ok(Run::Superseded)));
        assert!(matches!(third.await.unwrap(), Ok(Run::Done)));
        // The first download was abandoned and the disable never ran.
        assert_eq!(fake.steps(), ["download", "download", "install"]);
        assert!(!fake.overlapped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn restore_and_toggle_never_overlap() {
        let toggles = Arc::new(Toggles::new());
        let fake = Fake::new(1);

        let restore = restore(&toggles, &fake);
        // The first download fails at 30 s, the retry at 45 s succeeds and
        // its install runs from 75 s.
        tokio::time::sleep(Duration::from_secs(80)).await;
        let disable = toggle(&toggles, &fake, false);

        restore.await.unwrap();
        assert!(matches!(disable.await.unwrap(), Ok(Run::Done)));
        // The started install finished before the disable began.
        assert_eq!(fake.steps(), ["download", "download", "install", "remove"]);
        assert!(!fake.overlapped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_toggle_ends_a_restore_mid_download() {
        let toggles = Arc::new(Toggles::new());
        let fake = Fake::new(0);

        let restore = restore(&toggles, &fake);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let disable = toggle(&toggles, &fake, false);

        restore.await.unwrap();
        assert!(matches!(disable.await.unwrap(), Ok(Run::Done)));
        assert_eq!(fake.steps(), ["download", "remove"]);
        assert!(!fake.overlapped.load(Ordering::SeqCst));
    }
}
