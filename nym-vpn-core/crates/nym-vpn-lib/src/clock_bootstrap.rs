// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Daemon-owned cold-boot clock bootstrap.
//!
//! A router without an RTC boots with whatever clock `sysfixtime` restored —
//! on first boot, years in the past. Every TLS handshake the daemon needs
//! (vpn API, DoH/DoT resolvers) then fails certificate validation and the
//! account controller deadlocks in `DeviceTimeDesynced`. The platform NTP
//! client can't break the deadlock while the kill switch is up: its pool
//! lookup rides `sysntpd -> dnsmasq -> upstream`, and dnsmasq is exactly the
//! relay the firewall must block (it re-originates LAN clients' queries as
//! its own, so any hole wide enough for it leaks LAN DNS out the WAN).
//!
//! So the daemon bootstraps its own clock, deliberately without TLS anywhere
//! on the path — TLS is the thing that doesn't work yet:
//!
//!  1. Detect a bogus clock: now earlier than the daemon binary's own mtime.
//!  2. Resolve the NTP pool over plain UDP/53 against the static resolver
//!     set, in-process as root — this passes the kill switch's root-scoped
//!     DNS escape hatch.
//!  3. One SNTP exchange (through the rate-limited NTP hatch), then a
//!     forward-only `clock_settime(2)` floored at the binary mtime. A
//!     spoofed reply can only push the clock forward, which makes TLS fail
//!     closed — no worse than the bogus clock we started with.
//!
//! Fine discipline stays sysntpd's job once the tunnel is up.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;

/// Same defaults as stock OpenWrt sysntpd.
const NTP_POOL_HOSTS: &[&str] = &[
    "0.openwrt.pool.ntp.org",
    "1.openwrt.pool.ntp.org",
    "2.openwrt.pool.ntp.org",
];
const SNTP_TIMEOUT: Duration = Duration::from_secs(3);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NTP_SERVERS: usize = 6;
/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
/// A reply this far past the binary's build is garbage or an attack, not time.
const MAX_PLAUSIBLE_AHEAD: Duration = Duration::from_secs(15 * 365 * 24 * 3600);

/// Step an obviously bogus system clock before the first TLS handshake.
/// No-op (one metadata call) when the clock is sane. Never fails the caller:
/// if bootstrap fails, the connect attempt proceeds and fails TLS validation
/// the same way it would have anyway, and the state machine retries.
pub(crate) async fn ensure_sane_clock() {
    let Some(floor) = sanity_floor() else {
        // Can't stat our own binary — no reference to judge the clock by.
        return;
    };
    let now = SystemTime::now();
    if now >= floor {
        return;
    }
    tracing::warn!(
        "System clock ({:?} since epoch) predates this binary's build; \
         bootstrapping time via daemon-owned DNS + SNTP",
        now.duration_since(UNIX_EPOCH).unwrap_or_default()
    );
    match bootstrap(now, floor).await {
        Ok(set_to) => tracing::info!(
            "Clock bootstrapped to {:?} since epoch",
            set_to.duration_since(UNIX_EPOCH).unwrap_or_default()
        ),
        Err(err) => tracing::warn!(
            "Clock bootstrap failed ({err}); TLS validation will likely fail \
             until the clock is corrected, and the connect attempt will retry"
        ),
    }
}

/// The newest time we know is in the past: this binary existed before now.
/// Using the installed binary's mtime instead of a compiled-in constant keeps
/// the floor fresh with every package upgrade and costs one stat.
///
/// Known blind spot: if the package was installed while the clock was
/// already bogus, the mtime inherits that bogus time and detection never
/// fires — same behavior as before this module existed, so it degrades to
/// the status quo, not below it. The stat is load-bearing; don't replace it
/// with a build-time constant, which goes stale the moment a user runs an
/// old binary.
fn sanity_floor() -> Option<SystemTime> {
    std::fs::metadata("/proc/self/exe")
        .and_then(|m| m.modified())
        .ok()
}

async fn bootstrap(now: SystemTime, floor: SystemTime) -> Result<SystemTime, String> {
    let servers = resolve_pool().await;
    if servers.is_empty() {
        return Err("could not resolve any NTP pool address".into());
    }
    for server in servers {
        let t = match sntp_query(server).await {
            Ok(t) => t,
            Err(err) => {
                tracing::debug!("SNTP query to {server} failed: {err}");
                continue;
            }
        };
        // Forward-only, floored at the build, capped at the plausible: a
        // reply that would move the clock backwards or into the far future
        // is rejected, so the worst a spoofed server achieves is TLS failing
        // closed.
        if t <= now || t <= floor {
            tracing::debug!("Rejecting SNTP time from {server}: not ahead of clock/floor");
            continue;
        }
        if t > floor + MAX_PLAUSIBLE_AHEAD {
            tracing::debug!("Rejecting SNTP time from {server}: implausibly far ahead");
            continue;
        }
        set_clock(t).map_err(|e| format!("clock_settime failed: {e}"))?;
        return Ok(t);
    }
    Err("no NTP server returned a usable time".into())
}

/// Resolve the pool hostnames with a deliberately dumb resolver: plain
/// UDP/TCP 53 straight to the static resolver IPs the firewall exceptions
/// are built from. Not the default hickory config — that one is DoH/DoT,
/// which needs the working clock we don't have yet.
async fn resolve_pool() -> Vec<SocketAddr> {
    let resolver_ips: Vec<IpAddr> = crate::DEFAULT_DNS_SERVERS.clone();
    let group = NameServerConfigGroup::from_ips_clear(&resolver_ips, 53, true);
    let config = ResolverConfig::from_parts(None, vec![], group);
    let resolver =
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build();

    let mut out: Vec<SocketAddr> = Vec::new();
    for host in NTP_POOL_HOSTS {
        match tokio::time::timeout(RESOLVE_TIMEOUT, resolver.lookup_ip(*host)).await {
            Ok(Ok(lookup)) => out.extend(lookup.iter().map(|ip| SocketAddr::new(ip, 123))),
            Ok(Err(err)) => tracing::debug!("Bootstrap lookup of {host} failed: {err}"),
            Err(_) => tracing::debug!("Bootstrap lookup of {host} timed out"),
        }
        if out.len() >= MAX_NTP_SERVERS {
            break;
        }
    }
    // v4 first: a v4-only WAN with IPv6 enabled would burn a timeout per v6
    // address before reaching anything that answers.
    out.sort_by_key(|a| a.is_ipv6());
    out.truncate(MAX_NTP_SERVERS);
    out
}

async fn sntp_query(server: SocketAddr) -> std::io::Result<SystemTime> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    let mut req = [0u8; 48];
    req[0] = 0x23; // LI 0, version 4, mode 3 (client)
    sock.send(&req).await?;
    let mut buf = [0u8; 48];
    let n = tokio::time::timeout(SNTP_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SNTP timeout"))??;
    parse_sntp_reply(&buf[..n])
}

fn parse_sntp_reply(buf: &[u8]) -> std::io::Result<SystemTime> {
    let err = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string());
    if buf.len() < 48 {
        return Err(err("short SNTP reply"));
    }
    let li = buf[0] >> 6;
    let mode = buf[0] & 0x07;
    if mode != 4 {
        return Err(err("not a server-mode reply"));
    }
    if li == 3 {
        return Err(err("server clock unsynchronized"));
    }
    let stratum = buf[1];
    if !(1..=15).contains(&stratum) {
        // 0 is a kiss-of-death, >15 is unsynchronized.
        return Err(err("unusable stratum"));
    }
    let secs = u32::from_be_bytes(buf[40..44].try_into().unwrap()) as u64;
    let frac = u32::from_be_bytes(buf[44..48].try_into().unwrap()) as u64;
    if secs == 0 && frac == 0 {
        return Err(err("zero transmit timestamp"));
    }
    // NTP's 32-bit seconds wrap in 2036. Values below the 1970 offset can't
    // be era-0 times we'd ever accept (they'd be pre-1970), so read them as
    // era 1.
    let unix_secs = if secs >= NTP_UNIX_OFFSET {
        secs - NTP_UNIX_OFFSET
    } else {
        secs + (1u64 << 32) - NTP_UNIX_OFFSET
    };
    let nanos = (frac * 1_000_000_000) >> 32;
    Ok(UNIX_EPOCH + Duration::new(unix_secs, nanos as u32))
}

fn set_clock(t: SystemTime) -> std::io::Result<()> {
    let d = t
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let ts = nix::sys::time::TimeSpec::new(d.as_secs() as i64, d.subsec_nanos() as i64);
    nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, ts)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(li: u8, mode: u8, stratum: u8, ntp_secs: u32, frac: u32) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = (li << 6) | (4 << 3) | mode;
        b[1] = stratum;
        b[40..44].copy_from_slice(&ntp_secs.to_be_bytes());
        b[44..48].copy_from_slice(&frac.to_be_bytes());
        b
    }

    #[test]
    fn parses_a_valid_reply() {
        // 2026-01-01T00:00:00Z = unix 1767225600 = ntp 3976214400.
        let t = parse_sntp_reply(&reply(0, 4, 2, 3_976_214_400, 0)).unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_secs(1_767_225_600)
        );
    }

    #[test]
    fn fractional_seconds_convert() {
        // 0x8000_0000 / 2^32 = exactly half a second.
        let t = parse_sntp_reply(&reply(0, 4, 2, 3_976_214_400, 0x8000_0000)).unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().subsec_nanos(),
            500_000_000
        );
    }

    #[test]
    fn era_1_pivot_after_2036_wraparound() {
        // NTP seconds wrap 2^32 in Feb 2036; a small value means era 1.
        // ntp_secs 0 in era 1 = unix 2^32 - NTP_UNIX_OFFSET = 2085978496
        // (2036-02-07T06:28:16Z).
        let t = parse_sntp_reply(&reply(0, 4, 2, 1, 0)).unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            (1u64 << 32) - NTP_UNIX_OFFSET + 1
        );
    }

    #[test]
    fn rejects_bad_replies() {
        assert!(parse_sntp_reply(&[0u8; 47]).is_err(), "short");
        assert!(
            parse_sntp_reply(&reply(0, 3, 2, 3_976_214_400, 0)).is_err(),
            "client mode"
        );
        assert!(
            parse_sntp_reply(&reply(3, 4, 2, 3_976_214_400, 0)).is_err(),
            "LI unsync"
        );
        assert!(
            parse_sntp_reply(&reply(0, 4, 0, 3_976_214_400, 0)).is_err(),
            "kiss-of-death"
        );
        assert!(
            parse_sntp_reply(&reply(0, 4, 16, 3_976_214_400, 0)).is_err(),
            "stratum 16"
        );
        assert!(
            parse_sntp_reply(&reply(0, 4, 2, 0, 0)).is_err(),
            "zero timestamp"
        );
    }
}
