// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! On-disk cache of the Nym VPN API socket addresses last resolved during a
//! Connecting attempt.
//!
//! `SharedState::api_endpoints` is what `DisconnectedState` consults to decide
//! whether to apply the kill-switch Blocked policy on entry. Without this
//! cache the field is empty until the first successful Connecting populates
//! it, which means the kill-switch is effectively off for the entire
//! cold-boot window. Persisting the cache and reloading it before
//! `SharedState` is constructed closes that gap.
//!
//! The cache is bounded by `MAX_AGE_SECS` so a router that sat powered off
//! for a long time can't pin the firewall to truly stale endpoints. An absent
//! or expired cache no longer opens the firewall: idle/initial Connecting
//! states stay blocked with daemon-scoped DNS/NTP bootstrap exceptions until
//! fresh endpoint addresses are resolved.

use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const FILENAME: &str = "api_endpoints.cache";
const FORMAT_TAG: &str = "v1";
const MAX_AGE_SECS: u64 = 7 * 24 * 3600;
/// Tolerate small wall-clock adjustments, but reject a cache timestamp far
/// ahead of the current clock. `saturating_sub` alone treated every future
/// timestamp as age zero, so a router whose RTC reset could trust stale
/// endpoints indefinitely.
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

fn cache_path(data_path: &Path) -> PathBuf {
    data_path.join(FILENAME)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn load(data_path: Option<&Path>) -> Vec<SocketAddr> {
    let Some(data_path) = data_path else {
        return Vec::new();
    };
    let path = cache_path(data_path);

    let contents = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!("Failed to read api_endpoints cache at {}: {e}", path.display());
            return Vec::new();
        }
    };

    let mut lines = contents.lines();
    let Some(tag) = lines.next() else {
        return Vec::new();
    };
    if tag != FORMAT_TAG {
        tracing::warn!("api_endpoints cache has unknown format tag {tag:?}, ignoring");
        return Vec::new();
    }

    let saved_at: u64 = match lines.next().and_then(|l| l.parse().ok()) {
        Some(v) => v,
        None => {
            tracing::warn!("api_endpoints cache is missing timestamp, ignoring");
            return Vec::new();
        }
    };
    let now = now_unix();
    if !timestamp_is_fresh(saved_at, now) {
        tracing::info!("api_endpoints cache timestamp is stale or in the future, ignoring");
        return Vec::new();
    }

    let endpoints: Vec<SocketAddr> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| match l.parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                tracing::warn!("Skipping malformed api_endpoints cache entry {l:?}: {e}");
                None
            }
        })
        .collect();

    if !endpoints.is_empty() {
        tracing::info!(
            "Restored {} api_endpoint(s) from on-disk cache",
            endpoints.len()
        );
    }
    endpoints
}

fn timestamp_is_fresh(saved_at: u64, now: u64) -> bool {
    saved_at <= now.saturating_add(MAX_FUTURE_SKEW_SECS)
        && now.saturating_sub(saved_at) <= MAX_AGE_SECS
}

pub fn save(data_path: Option<&Path>, endpoints: &[SocketAddr]) {
    let Some(data_path) = data_path else { return };
    if endpoints.is_empty() {
        return;
    }

    let mut buf = String::with_capacity(64 + endpoints.len() * 24);
    buf.push_str(FORMAT_TAG);
    buf.push('\n');
    buf.push_str(&now_unix().to_string());
    buf.push('\n');
    for addr in endpoints {
        buf.push_str(&addr.to_string());
        buf.push('\n');
    }

    let path = cache_path(data_path);
    let tmp_path = path.with_extension("cache.tmp");
    if let Err(e) = fs::write(&tmp_path, &buf) {
        tracing::warn!("Failed to write api_endpoints cache to {}: {e}", tmp_path.display());
        return;
    }
    if let Err(e) = fs::rename(&tmp_path, &path) {
        tracing::warn!("Failed to commit api_endpoints cache: {e}");
        let _ = fs::remove_file(&tmp_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_rejects_stale_and_far_future_entries() {
        let now = 1_000_000;
        assert!(timestamp_is_fresh(now, now));
        assert!(timestamp_is_fresh(now + MAX_FUTURE_SKEW_SECS, now));
        assert!(!timestamp_is_fresh(now + MAX_FUTURE_SKEW_SECS + 1, now));
        assert!(timestamp_is_fresh(now - MAX_AGE_SECS, now));
        assert!(!timestamp_is_fresh(now - MAX_AGE_SECS - 1, now));
    }

    #[test]
    fn reset_clock_does_not_make_a_future_cache_fresh_forever() {
        assert!(!timestamp_is_fresh(1_700_000_000, 0));
    }
}
