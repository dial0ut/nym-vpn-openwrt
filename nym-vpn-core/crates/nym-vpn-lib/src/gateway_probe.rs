// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! ICMP echo probes towards gateways, sent by the daemon.
//!
//! Backs `nym-vpnc gateway test`. The probe socket carries
//! [`TUNNEL_FWMARK`](crate::TUNNEL_FWMARK), like the WireGuard transport, so
//! its packets are policy-routed out the real WAN even while a tunnel is up,
//! and so the OpenWrt kill switch's probe hatch (`probe_escape_hatch` in
//! nym-firewall) lets them out. Neither is available to an unprivileged
//! `nym-vpnc`: `SO_MARK` needs `CAP_NET_ADMIN`, and unmarked ICMP is rejected
//! while the kill switch is on.

use std::{net::IpAddr, os::fd::BorrowedFd, time::Duration};

use futures::{StreamExt, stream};
use nix::sys::socket::{SetSockOpt, sockopt::Mark};
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};

// The kill-switch hatch matches on this mark; the two crates must agree.
const _: () = assert!(crate::TUNNEL_FWMARK == nym_firewall::TUNNEL_FWMARK);

/// Gap between consecutive probes to the same target.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// Targets probed at the same time. Together with [`PROBE_INTERVAL`] this
/// caps the packet rate at about 40/s, under the firewall hatch's limit.
const MAX_CONCURRENT_TARGETS: usize = 8;

/// Same payload size as `ping(8)`: 56 bytes after the 8-byte ICMP header.
const PAYLOAD: [u8; 56] = [0; 56];

/// Identifier base for the probe pingers. Only used on raw sockets; on Linux
/// `SOCK_DGRAM` ICMP sockets the kernel assigns the identifier.
const IDENT_BASE: u16 = 0x4e00;

#[derive(Debug, Clone, Copy)]
pub struct ProbeParams {
    /// Echo requests per target.
    pub count: u32,
    /// How long to wait for each reply.
    pub timeout: Duration,
}

/// What came back from one target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub sent: u32,
    pub received: u32,
    /// Round-trip time of every reply, in send order.
    pub rtts: Vec<Duration>,
    /// Last error other than a timeout, e.g. "network is unreachable".
    pub error: Option<String>,
}

impl ProbeOutcome {
    pub fn min(&self) -> Option<Duration> {
        self.rtts.iter().min().copied()
    }

    pub fn max(&self) -> Option<Duration> {
        self.rtts.iter().max().copied()
    }

    pub fn avg(&self) -> Option<Duration> {
        let n = u32::try_from(self.rtts.len()).ok().filter(|n| *n > 0)?;
        Some(self.rtts.iter().sum::<Duration>() / n)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("failed to open ICMP socket")]
    OpenSocket(#[source] std::io::Error),

    #[error("failed to set fwmark on ICMP socket")]
    SetMark(#[source] nix::Error),
}

/// Probe every address in `targets`, returning one outcome per address in the
/// same order. Targets are probed concurrently (bounded), each one
/// sequentially with [`PROBE_INTERVAL`] between requests.
pub async fn probe_targets(
    targets: &[IpAddr],
    params: ProbeParams,
) -> Result<Vec<ProbeOutcome>, ProbeError> {
    // One socket per family, opened only when needed: an IPv6 socket can be
    // refused outright on a kernel built without IPv6.
    let v4 = targets
        .iter()
        .any(IpAddr::is_ipv4)
        .then(|| marked_client(ICMP::V4))
        .transpose()?;
    let v6 = targets
        .iter()
        .any(IpAddr::is_ipv6)
        .then(|| marked_client(ICMP::V6))
        .transpose()?;

    // Owned items: a closure over `&IpAddr` makes the spawned future's
    // lifetime bounds too specific for `tokio::spawn`.
    let outcomes = stream::iter(targets.iter().copied().enumerate())
        .map(|(idx, addr)| {
            let client = match addr {
                IpAddr::V4(_) => v4.clone(),
                IpAddr::V6(_) => v6.clone(),
            };
            let ident = PingIdentifier(IDENT_BASE | (idx % 0x100) as u16);
            probe_one(client, addr, ident, params)
        })
        .buffered(MAX_CONCURRENT_TARGETS)
        .collect()
        .await;

    Ok(outcomes)
}

/// Open an ICMP socket and put the tunnel fwmark on it so its packets take
/// the main routing table and the kill switch's probe hatch.
fn marked_client(kind: ICMP) -> Result<Client, ProbeError> {
    let client =
        Client::new(&Config::builder().kind(kind).build()).map_err(ProbeError::OpenSocket)?;
    let raw_fd = client.get_socket().get_native_sock();
    // SAFETY: the descriptor is owned by `client`, which is alive for the
    // whole borrow.
    let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    Mark.set(&fd, &crate::TUNNEL_FWMARK)
        .map_err(ProbeError::SetMark)?;
    Ok(client)
}

async fn probe_one(
    client: Option<Client>,
    addr: IpAddr,
    ident: PingIdentifier,
    params: ProbeParams,
) -> ProbeOutcome {
    let mut outcome = ProbeOutcome::default();
    let Some(client) = client else {
        outcome.error = Some("no ICMP socket for this address family".to_owned());
        return outcome;
    };

    let mut pinger = client.pinger(addr, ident).await;
    pinger.timeout(params.timeout);

    for seq in 0..params.count {
        if seq > 0 {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
        outcome.sent += 1;
        match pinger.ping(PingSequence(seq as u16), &PAYLOAD).await {
            Ok((_reply, rtt)) => {
                outcome.received += 1;
                outcome.rtts.push(rtt);
            }
            Err(SurgeError::Timeout { .. }) => {}
            Err(err) => {
                tracing::debug!("Gateway probe to {addr} failed: {err}");
                outcome.error = Some(err.to_string());
            }
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn outcome_statistics() {
        let outcome = ProbeOutcome {
            sent: 4,
            received: 3,
            rtts: vec![ms(30), ms(10), ms(20)],
            error: None,
        };
        assert_eq!(outcome.min(), Some(ms(10)));
        assert_eq!(outcome.avg(), Some(ms(20)));
        assert_eq!(outcome.max(), Some(ms(30)));
    }

    #[test]
    fn outcome_without_replies_has_no_statistics() {
        let outcome = ProbeOutcome {
            sent: 5,
            ..Default::default()
        };
        assert_eq!(outcome.min(), None);
        assert_eq!(outcome.avg(), None);
        assert_eq!(outcome.max(), None);
    }
}
