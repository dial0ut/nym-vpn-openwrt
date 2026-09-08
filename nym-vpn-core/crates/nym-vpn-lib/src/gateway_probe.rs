// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! ICMP echo probes towards gateways, backing `nym-vpnc gateway test`. Sent
//! by the daemon because the socket carries [`TUNNEL_FWMARK`](crate::TUNNEL_FWMARK)
//! (needs `CAP_NET_ADMIN`) so packets leave via the real WAN and through the
//! kill switch's probe hatch.

use std::{net::IpAddr, os::fd::BorrowedFd, sync::Arc, time::Duration};

use futures::{StreamExt, stream};
use nix::sys::socket::{SetSockOpt, sockopt::Mark};
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};

// The kill-switch hatch matches on this mark; the two crates must agree.
const _: () = assert!(crate::TUNNEL_FWMARK == nym_firewall::TUNNEL_FWMARK);

/// Gap between consecutive probes to the same target.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// With [`PROBE_INTERVAL`] this caps one run at about 40 packets/s, under
/// the firewall hatch's limit; the daemon serializes runs for the same reason.
pub const MAX_CONCURRENT_TARGETS: usize = 8;

/// Same payload size as `ping(8)`.
const PAYLOAD: [u8; 56] = [0; 56];

/// Only used on raw sockets; on `SOCK_DGRAM` ICMP the kernel assigns it.
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
    /// Echo requests that left the socket. Only these count towards loss.
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

    /// Returns `false` when probing this target should stop.
    fn record(&mut self, target: IpAddr, attempt: Result<Duration, SurgeError>) -> bool {
        match attempt {
            Ok(rtt) => {
                self.sent += 1;
                self.received += 1;
                self.rtts.push(rtt);
                true
            }
            Err(SurgeError::Timeout { .. }) => {
                self.sent += 1;
                true
            }
            // Only possible if the `ProbeClient` invariant is broken; a bug,
            // not loss, and every further request would fail the same way.
            Err(SurgeError::ClientDestroyed) => {
                tracing::error!(
                    "ICMP client dropped while probing {target}; this is a bug in gateway_probe"
                );
                self.error = Some("internal error: ICMP client dropped while probing".to_owned());
                false
            }
            // Nothing was sent (e.g. no route): reported, but not path loss.
            Err(err) => {
                tracing::debug!("Gateway probe to {target} failed: {err}");
                self.error = Some(err.to_string());
                true
            }
        }
    }
}

/// Deliberately not `Clone`: dropping any clone of a surge-ping `Client`
/// poisons its shared reply map, failing the other targets' probes with
/// `ClientDestroyed`. Share through `Arc<ProbeClient>` only.
struct ProbeClient(Client);

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("failed to open ICMP socket")]
    OpenSocket(#[source] std::io::Error),

    #[error("failed to set fwmark on ICMP socket")]
    SetMark(#[source] nix::Error),
}

/// One outcome per target, in order. Bounded concurrency across targets,
/// sequential probes per target.
pub async fn probe_targets(
    targets: &[IpAddr],
    params: ProbeParams,
) -> Result<Vec<ProbeOutcome>, ProbeError> {
    // Sockets are opened only when needed: an IPv6 socket can be refused on a
    // kernel without IPv6. They must outlive every probe (see `ProbeClient`);
    // nothing is spawned, so cancelling this future drops probes and sockets.
    let v4 = targets
        .iter()
        .any(IpAddr::is_ipv4)
        .then(|| marked_client(ICMP::V4))
        .transpose()?
        .map(Arc::new);
    let v6 = targets
        .iter()
        .any(IpAddr::is_ipv6)
        .then(|| marked_client(ICMP::V6))
        .transpose()?
        .map(Arc::new);

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

fn marked_client(kind: ICMP) -> Result<ProbeClient, ProbeError> {
    let client =
        Client::new(&Config::builder().kind(kind).build()).map_err(ProbeError::OpenSocket)?;
    let raw_fd = client.get_socket().get_native_sock();
    // SAFETY: `client` owns the descriptor and outlives the borrow.
    let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    Mark.set(&fd, &crate::TUNNEL_FWMARK)
        .map_err(ProbeError::SetMark)?;
    Ok(ProbeClient(client))
}

async fn probe_one(
    client: Option<Arc<ProbeClient>>,
    addr: IpAddr,
    ident: PingIdentifier,
    params: ProbeParams,
) -> ProbeOutcome {
    let mut outcome = ProbeOutcome::default();
    let Some(client) = client else {
        outcome.error = Some("no ICMP socket for this address family".to_owned());
        return outcome;
    };

    let mut pinger = client.0.pinger(addr, ident).await;
    pinger.timeout(params.timeout);

    for seq in 0..params.count {
        if seq > 0 {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
        let attempt = pinger
            .ping(PingSequence(seq as u16), &PAYLOAD)
            .await
            .map(|(_reply, rtt)| rtt);
        if !outcome.record(addr, attempt) {
            break;
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

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

    #[test]
    fn only_replies_and_timeouts_count_as_sent() {
        let mut outcome = ProbeOutcome::default();
        assert!(outcome.record(TARGET, Ok(ms(10))));
        assert!(outcome.record(
            TARGET,
            Err(SurgeError::Timeout {
                seq: PingSequence(1)
            })
        ));
        let unreachable = std::io::Error::from(std::io::ErrorKind::NetworkUnreachable);
        assert!(outcome.record(TARGET, Err(SurgeError::IOError(unreachable))));

        assert_eq!((outcome.sent, outcome.received), (2, 1));
        assert_eq!(outcome.rtts, vec![ms(10)]);
        let error = outcome.error.as_deref().expect("send failure is reported");
        assert!(error.contains("io error"), "{error}");
    }

    #[test]
    fn dropped_client_is_a_bug_not_loss_and_stops_probing() {
        let mut outcome = ProbeOutcome::default();
        assert!(outcome.record(TARGET, Ok(ms(10))));
        assert!(
            !outcome.record(TARGET, Err(SurgeError::ClientDestroyed)),
            "probing must stop once the client is gone"
        );

        assert_eq!((outcome.sent, outcome.received), (1, 1));
        let error = outcome.error.as_deref().expect("bug is reported");
        assert!(error.contains("internal error"), "{error}");
    }

    #[test]
    fn no_targets_opens_no_socket() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let params = ProbeParams {
            count: 1,
            timeout: ms(10),
        };
        // A socket would need CAP_NET_RAW or an open ping_group_range.
        let outcomes = runtime
            .block_on(probe_targets(&[], params))
            .expect("no socket needed");
        assert!(outcomes.is_empty());
    }
}
