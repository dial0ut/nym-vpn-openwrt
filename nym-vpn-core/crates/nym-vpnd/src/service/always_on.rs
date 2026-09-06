// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Always On: the policy that keeps the tunnel up while the daemon runs.
//!
//! The tunnel state machine already reconnects after drops and waits out
//! offline periods on its own; what it never does is leave an error state or
//! escape an endless Connecting loop without a command. This module decides
//! when the service loop should send that command. It is pure: time comes in
//! as `Instant`s, decisions go out as [`Action`]s, and the caller owns the
//! single timer that [`AlwaysOn::next_deadline`] asks for. Nothing here
//! touches tokio, the state machine or the firewall.
//!
//! Error states fall into three classes:
//!
//! * infrastructure (firewall, routing, DNS, TUN, internal): something on the
//!   router failed; retry with a capped exponential backoff, and after enough
//!   failures in a row hand the problem to procd (see the service loop).
//! * environmental (no performant gateway, clock skew, bandwidth exhausted):
//!   the world will change on its own; retry slowly and forever.
//! * terminal (bad configuration, account problems): nothing will change until
//!   the user, the account or the configuration does; latch and wait.

use std::time::{Duration, Instant};

use nym_vpn_lib_types::{AlwaysOnStatus, ErrorStateReason, TargetState, TunnelState};

/// First retry after an infrastructure error; doubles per consecutive error.
pub const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Longest wait between infrastructure retries.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);
/// Retry delays are spread by this much either side to avoid lockstep.
pub const JITTER_PERCENT: u64 = 20;
/// First retry after an environmental error.
pub const ENVIRONMENTAL_FIRST_RETRY: Duration = Duration::from_secs(60);
/// Every later environmental retry.
pub const ENVIRONMENTAL_RETRY: Duration = Duration::from_secs(300);
/// Connecting for this long without reaching Connected forces a fresh
/// gateway selection, and again every period after that.
pub const LONG_CONNECTING: Duration = Duration::from_secs(600);

/// What the service loop should do after feeding the supervisor an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Nothing,
    /// Send `TunnelCommand::Connect` with the session's relaxation flag.
    Connect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Infrastructure,
    Environmental,
    Terminal,
}

pub fn classify(reason: &ErrorStateReason) -> ErrorClass {
    use ErrorStateReason as R;
    match reason {
        R::SetFirewallPolicy
        | R::SetRouting
        | R::SetDns
        | R::TunDevice
        | R::TunnelProvider
        | R::Internal(_) => ErrorClass::Infrastructure,
        R::PerformantEntryGatewayUnavailable
        | R::PerformantExitGatewayUnavailable
        | R::DeviceTimeOutOfSync
        | R::BandwidthExceeded
        | R::CredentialWastedOnEntryGateway
        | R::CredentialWastedOnExitGateway => ErrorClass::Environmental,
        R::SameEntryAndExitGateway
        | R::NeedsRelaxedIndependenceCriteria
        | R::InvalidEntryGatewayIdentity
        | R::InvalidExitGatewayIdentity
        | R::InvalidEntryGatewayCountry
        | R::InvalidExitGatewayCountry
        | R::Ipv6Unavailable
        | R::InactiveAccount
        | R::InactiveSubscription
        | R::MaxDevicesReached
        | R::DeviceLoggedOut => ErrorClass::Terminal,
    }
}

/// The variant name, as the bridge and the CLI show it.
fn reason_ident(reason: &ErrorStateReason) -> String {
    match reason {
        ErrorStateReason::Internal(_) => "Internal".to_owned(),
        other => format!("{other:?}"),
    }
}

/// Coarse memory of the last tunnel state, enough to tell a retry from a
/// re-selection and an offline recovery from an error retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
    Offline,
}

/// Picks a jitter offset in `0..=span` milliseconds.
pub type Jitter = Box<dyn Fn(u64) -> u64 + Send + Sync>;

pub struct AlwaysOn {
    enabled: bool,
    target: TargetState,
    last_seen: Seen,
    /// Consecutive infrastructure errors; the backoff exponent.
    infrastructure_streak: u32,
    /// Environmental errors in the current series; picks 60 s vs 5 min.
    environmental_streak: u32,
    /// Retries scheduled in the current error series, for the status line.
    attempt: u32,
    next_retry_at: Option<Instant>,
    connecting_since: Option<Instant>,
    last_error: Option<ErrorStateReason>,
    latched: bool,
    jitter: Jitter,
}

impl AlwaysOn {
    pub fn new(enabled: bool, jitter: Jitter) -> Self {
        Self {
            enabled,
            target: TargetState::Unsecured,
            last_seen: Seen::Disconnected,
            infrastructure_streak: 0,
            environmental_streak: 0,
            attempt: 0,
            next_retry_at: None,
            connecting_since: None,
            last_error: None,
            latched: false,
            jitter,
        }
    }

    /// Production jitter: uniform over the span.
    pub fn with_random_jitter(enabled: bool) -> Self {
        use rand::Rng;
        Self::new(
            enabled,
            Box::new(|span| rand::thread_rng().gen_range(0..=span)),
        )
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The setting changed. Turning it off drops every pending timer; turning
    /// it on starts from a clean series. The caller decides whether to
    /// connect; a state event afterwards picks up an existing error.
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.enabled == enabled {
            return;
        }
        self.enabled = enabled;
        self.reset_series();
        self.latched = false;
        self.connecting_since = None;
        if !enabled {
            self.last_error = None;
        }
    }

    /// The service's target state changed. Unsecured is a user disconnect:
    /// pause (keep the setting, stop the timers). Secured is a user connect:
    /// a fresh series, and it clears a latch.
    pub fn on_target_state(&mut self, target: TargetState) {
        self.target = target;
        self.reset_series();
        self.latched = false;
        self.connecting_since = None;
    }

    fn supervising(&self) -> bool {
        self.enabled && self.target == TargetState::Secured
    }

    fn reset_series(&mut self) {
        self.infrastructure_streak = 0;
        self.environmental_streak = 0;
        self.attempt = 0;
        self.next_retry_at = None;
    }

    /// A tunnel state event from the state machine.
    pub fn on_tunnel_state(&mut self, state: &TunnelState, now: Instant) -> Action {
        let previous = self.last_seen;
        let action = match state {
            TunnelState::Connected { .. } => {
                self.last_seen = Seen::Connected;
                self.reset_series();
                self.connecting_since = None;
                self.last_error = None;
                self.latched = false;
                Action::Nothing
            }
            TunnelState::Connecting { .. } => {
                self.last_seen = Seen::Connecting;
                // The retry (or the user) got us here; the timer's job is done.
                self.next_retry_at = None;
                if previous == Seen::Offline {
                    // The route came back and the state machine reconnects on
                    // its own: a WAN flap must not count towards escalation.
                    self.reset_series();
                }
                if self.connecting_since.is_none() {
                    self.connecting_since = Some(now);
                }
                Action::Nothing
            }
            TunnelState::Disconnecting { .. } => {
                self.last_seen = Seen::Disconnecting;
                Action::Nothing
            }
            TunnelState::Offline { reconnect } => {
                self.last_seen = Seen::Offline;
                // The state machine owns the reconnect while offline.
                self.next_retry_at = None;
                self.connecting_since = None;
                if self.supervising() && !*reconnect && !self.latched {
                    // Nobody asked the machine to come back once online; we do.
                    Action::Connect
                } else {
                    Action::Nothing
                }
            }
            TunnelState::Error(reason) => {
                self.last_seen = Seen::Error;
                self.connecting_since = None;
                self.last_error = Some(reason.clone());
                if !self.supervising() {
                    self.next_retry_at = None;
                    return Action::Nothing;
                }
                match classify(reason) {
                    ErrorClass::Infrastructure => {
                        self.environmental_streak = 0;
                        let delay = self.backoff(self.infrastructure_streak);
                        self.infrastructure_streak += 1;
                        self.schedule(delay, reason, now);
                    }
                    ErrorClass::Environmental => {
                        self.infrastructure_streak = 0;
                        let delay = if self.environmental_streak == 0 {
                            ENVIRONMENTAL_FIRST_RETRY
                        } else {
                            ENVIRONMENTAL_RETRY
                        };
                        self.environmental_streak += 1;
                        self.schedule(delay, reason, now);
                    }
                    ErrorClass::Terminal => {
                        self.reset_series();
                        self.latched = true;
                        tracing::warn!("always-on: latched ({})", reason_ident(reason));
                    }
                }
                Action::Nothing
            }
            TunnelState::Disconnected => {
                self.last_seen = Seen::Disconnected;
                self.connecting_since = None;
                if self.supervising() && !self.latched {
                    // Only shutdown paths land here with the target still
                    // Secured; treat it as an infrastructure error without
                    // deepening the streak.
                    let delay = self.backoff(self.infrastructure_streak);
                    self.attempt += 1;
                    self.next_retry_at = Some(now + delay);
                    tracing::info!(
                        "always-on: retry {} in {}s (disconnected)",
                        self.attempt,
                        delay.as_secs()
                    );
                }
                Action::Nothing
            }
        };
        action
    }

    fn schedule(&mut self, delay: Duration, reason: &ErrorStateReason, now: Instant) {
        self.attempt += 1;
        self.next_retry_at = Some(now + delay);
        tracing::info!(
            "always-on: retry {} in {}s ({})",
            self.attempt,
            delay.as_secs(),
            reason_ident(reason)
        );
    }

    /// `min(BASE * 2^n, CAP)` spread by ±JITTER_PERCENT.
    fn backoff(&self, exponent: u32) -> Duration {
        let base = BACKOFF_BASE
            .checked_mul(1u32.checked_shl(exponent).unwrap_or(u32::MAX))
            .unwrap_or(BACKOFF_CAP)
            .min(BACKOFF_CAP);
        let base_ms = base.as_millis() as u64;
        let low = base_ms - base_ms * JITTER_PERCENT / 100;
        let span = base_ms * JITTER_PERCENT / 100 * 2;
        let offset = (self.jitter)(span).min(span);
        Duration::from_millis(low + offset)
    }

    /// Something the user controls changed: the tunnel configuration, or the
    /// account became ready. A latch is cleared and a pending backoff is cut
    /// short, either way with one immediate retry; otherwise nothing.
    pub fn on_config_or_account_changed(&mut self) -> Action {
        if !self.supervising() || self.last_seen != Seen::Error {
            return Action::Nothing;
        }
        if self.latched || self.next_retry_at.is_some() {
            self.latched = false;
            self.reset_series();
            tracing::info!("always-on: configuration changed, retrying now");
            Action::Connect
        } else {
            Action::Nothing
        }
    }

    /// When the caller's timer should fire.
    pub fn next_deadline(&self) -> Option<Instant> {
        if !self.supervising() {
            return None;
        }
        let long_connecting = self
            .connecting_since
            .filter(|_| self.last_seen == Seen::Connecting)
            .map(|since| since + LONG_CONNECTING);
        match (self.next_retry_at, long_connecting) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The caller's timer fired.
    pub fn poll(&mut self, now: Instant) -> Action {
        if !self.supervising() {
            return Action::Nothing;
        }
        if let Some(at) = self.next_retry_at
            && now >= at
        {
            self.next_retry_at = None;
            return match self.last_seen {
                Seen::Error | Seen::Disconnected => Action::Connect,
                // Something else moved the machine on since we scheduled.
                _ => Action::Nothing,
            };
        }
        if let Some(since) = self.connecting_since
            && self.last_seen == Seen::Connecting
            && now >= since + LONG_CONNECTING
        {
            self.connecting_since = Some(now);
            tracing::warn!(
                "always-on: connecting for {}m, forcing re-selection",
                LONG_CONNECTING.as_secs() / 60
            );
            return Action::Connect;
        }
        Action::Nothing
    }

    pub fn status(&self, now: Instant) -> AlwaysOnStatus {
        let active = self.supervising();
        AlwaysOnStatus {
            enabled: self.enabled,
            active,
            paused: self.enabled && self.target == TargetState::Unsecured,
            attempt: if active { self.attempt } else { 0 },
            next_retry_in: self
                .next_retry_at
                .filter(|_| active)
                .map(|at| at.saturating_duration_since(now)),
            last_error: self.last_error.clone(),
            latched_reason: if active && self.latched {
                self.last_error.as_ref().map(reason_ident)
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_vpn_lib_types::{
        ConnectionData, EstablishConnectionState, GatewayLightInfo, TunnelConnectionData,
        TunnelType, WireguardConnectionData, WireguardNode,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// Jitter fixed at the low edge so delays are exact.
    fn supervisor() -> AlwaysOn {
        let mut ao = AlwaysOn::new(true, Box::new(|_: u64| 0u64));
        ao.on_target_state(TargetState::Secured);
        ao
    }

    fn connecting() -> TunnelState {
        TunnelState::Connecting {
            retry_attempt: 0,
            state: EstablishConnectionState::SelectingGateways,
            tunnel_type: TunnelType::Wireguard,
            connection_data: None,
        }
    }

    fn error(reason: ErrorStateReason) -> TunnelState {
        TunnelState::Error(reason)
    }

    fn deadline_in(ao: &AlwaysOn, now: Instant) -> Option<Duration> {
        ao.next_deadline().map(|d| d.saturating_duration_since(now))
    }

    #[test]
    fn classification_table() {
        use ErrorStateReason as R;
        for r in [
            R::SetFirewallPolicy,
            R::SetRouting,
            R::SetDns,
            R::TunDevice,
            R::TunnelProvider,
            R::Internal("x".into()),
        ] {
            assert_eq!(classify(&r), ErrorClass::Infrastructure, "{r:?}");
        }
        for r in [
            R::PerformantEntryGatewayUnavailable,
            R::PerformantExitGatewayUnavailable,
            R::DeviceTimeOutOfSync,
            R::BandwidthExceeded,
            R::CredentialWastedOnEntryGateway,
            R::CredentialWastedOnExitGateway,
        ] {
            assert_eq!(classify(&r), ErrorClass::Environmental, "{r:?}");
        }
        for r in [
            R::SameEntryAndExitGateway,
            R::NeedsRelaxedIndependenceCriteria,
            R::InvalidEntryGatewayIdentity,
            R::InvalidExitGatewayIdentity,
            R::InvalidEntryGatewayCountry,
            R::InvalidExitGatewayCountry,
            R::Ipv6Unavailable,
            R::InactiveAccount,
            R::InactiveSubscription,
            R::MaxDevicesReached,
            R::DeviceLoggedOut,
        ] {
            assert_eq!(classify(&r), ErrorClass::Terminal, "{r:?}");
        }
    }

    #[test]
    fn infrastructure_backoff_doubles_and_caps() {
        let mut ao = supervisor();
        let mut now = Instant::now();
        // Low-edge jitter: 80 % of 5, 10, 20, 40, 80, 160, 300, 300 s.
        let expected = [4, 8, 16, 32, 64, 128, 240, 240];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(
                ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now),
                Action::Nothing
            );
            assert_eq!(deadline_in(&ao, now), Some(secs(*want)), "retry {i}");
            assert_eq!(ao.status(now).attempt, i as u32 + 1);
            // Too early: nothing. On time: connect, then the machine reports
            // Connecting and the retry timer is gone.
            assert_eq!(ao.poll(now + secs(*want) - secs(1)), Action::Nothing);
            now += secs(*want);
            assert_eq!(ao.poll(now), Action::Connect);
            assert_eq!(ao.on_tunnel_state(&connecting(), now), Action::Nothing);
            assert_eq!(ao.status(now).next_retry_in, None);
        }
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let now = Instant::now();
        for (jitter, want_ms) in [
            (Box::new(|_: u64| 0u64) as Jitter, 4_000u64),
            (Box::new(|span: u64| span) as Jitter, 6_000),
            (Box::new(|span: u64| span / 2) as Jitter, 5_000),
            // An out-of-range picker is clamped to the span.
            (Box::new(|_: u64| u64::MAX) as Jitter, 6_000),
        ] {
            let mut ao = AlwaysOn::new(true, jitter);
            ao.on_target_state(TargetState::Secured);
            ao.on_tunnel_state(&error(ErrorStateReason::SetDns), now);
            assert_eq!(deadline_in(&ao, now), Some(Duration::from_millis(want_ms)));
        }
    }

    #[test]
    fn environmental_retries_slow_and_flat() {
        let mut ao = supervisor();
        let now = Instant::now();
        ao.on_tunnel_state(
            &error(ErrorStateReason::PerformantEntryGatewayUnavailable),
            now,
        );
        assert_eq!(deadline_in(&ao, now), Some(secs(60)));
        assert_eq!(ao.poll(now + secs(60)), Action::Connect);
        ao.on_tunnel_state(&connecting(), now + secs(61));
        for k in 0..5 {
            let t = now + secs(100 + k * 400);
            ao.on_tunnel_state(&error(ErrorStateReason::DeviceTimeOutOfSync), t);
            assert_eq!(deadline_in(&ao, t), Some(secs(300)), "flat after the first");
            assert_eq!(ao.poll(t + secs(300)), Action::Connect);
            ao.on_tunnel_state(&connecting(), t + secs(301));
        }
        // An environmental error breaks an infrastructure streak.
        let t = now + secs(10_000);
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), t);
        assert_eq!(deadline_in(&ao, t), Some(secs(4)), "infrastructure restarts at the base");
    }

    #[test]
    fn terminal_errors_latch_until_config_change() {
        let mut ao = supervisor();
        let now = Instant::now();
        ao.on_tunnel_state(&error(ErrorStateReason::InactiveSubscription), now);
        assert_eq!(ao.next_deadline(), None, "no timer while latched");
        let status = ao.status(now);
        assert_eq!(
            status.latched_reason.as_deref(),
            Some("InactiveSubscription")
        );
        assert_eq!(status.to_string(), "stopped — InactiveSubscription");
        assert_eq!(ao.poll(now + secs(3_600)), Action::Nothing);

        assert_eq!(ao.on_config_or_account_changed(), Action::Connect);
        assert_eq!(ao.status(now).latched_reason, None);
        // Only once: a second change while still in Error and unlatched, with
        // nothing scheduled, has nothing to do.
        assert_eq!(ao.on_config_or_account_changed(), Action::Nothing);
    }

    #[test]
    fn user_connect_clears_the_latch_and_disconnect_pauses() {
        let mut ao = supervisor();
        let now = Instant::now();
        ao.on_tunnel_state(
            &error(ErrorStateReason::NeedsRelaxedIndependenceCriteria),
            now,
        );
        assert!(ao.status(now).latched_reason.is_some());
        ao.on_target_state(TargetState::Secured);
        assert_eq!(ao.status(now).latched_reason, None);

        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
        assert!(ao.next_deadline().is_some());
        ao.on_target_state(TargetState::Unsecured);
        let status = ao.status(now);
        assert!(status.enabled && status.paused && !status.active);
        assert_eq!(status.to_string(), "paused (disconnected by user)");
        assert_eq!(ao.next_deadline(), None);
        // Errors while paused are remembered but never retried.
        ao.on_tunnel_state(&error(ErrorStateReason::SetDns), now);
        assert_eq!(ao.next_deadline(), None);
        assert_eq!(ao.poll(now + secs(1_000)), Action::Nothing);
    }

    #[test]
    fn connected_resets_everything() {
        let mut ao = supervisor();
        let now = Instant::now();
        for _ in 0..3 {
            ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
            ao.on_tunnel_state(&connecting(), now);
        }
        assert_eq!(ao.status(now).attempt, 3);
        ao.on_tunnel_state(
            &error(ErrorStateReason::SetRouting),
            now,
        );
        assert_eq!(deadline_in(&ao, now), Some(secs(32)));
        ao.on_tunnel_state(&connecting(), now);
        ao.on_tunnel_state(&connected(), now);
        let status = ao.status(now);
        assert_eq!(status.attempt, 0);
        assert_eq!(status.last_error, None);
        assert_eq!(status.to_string(), "active");
        // Next error starts from the base again.
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
        assert_eq!(deadline_in(&ao, now), Some(secs(4)));
    }

    fn connected() -> TunnelState {
        let node = |port| WireguardNode {
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            public_key: String::new(),
            private_ipv4: Ipv4Addr::LOCALHOST,
            private_ipv6: None,
        };
        TunnelState::Connected {
            connection_data: ConnectionData {
                entry_gateway: GatewayLightInfo::new("entry".to_owned(), None, None),
                exit_gateway: GatewayLightInfo::new("exit".to_owned(), None, None),
                connected_at: time::OffsetDateTime::UNIX_EPOCH,
                tunnel: TunnelConnectionData::Wireguard(WireguardConnectionData {
                    entry_bridge_addr: None,
                    entry: node(1),
                    exit: node(2),
                }),
            },
        }
    }

    #[test]
    fn offline_to_connecting_resets_the_streak() {
        let mut ao = supervisor();
        let now = Instant::now();
        for _ in 0..4 {
            ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
            ao.on_tunnel_state(&connecting(), now);
        }
        // Route drops: the machine owns the reconnect, our timer is gone.
        ao.on_tunnel_state(&TunnelState::Offline { reconnect: true }, now);
        assert_eq!(ao.next_deadline(), None);
        // Route returns: fresh series, as if a link event reset the watchdog.
        ao.on_tunnel_state(&connecting(), now);
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
        assert_eq!(deadline_in(&ao, now), Some(secs(4)));
    }

    #[test]
    fn offline_without_reconnect_is_asked_to_come_back() {
        let mut ao = supervisor();
        let now = Instant::now();
        assert_eq!(
            ao.on_tunnel_state(&TunnelState::Offline { reconnect: false }, now),
            Action::Connect
        );
        assert_eq!(
            ao.on_tunnel_state(&TunnelState::Offline { reconnect: true }, now),
            Action::Nothing
        );
        // Not when paused.
        ao.on_target_state(TargetState::Unsecured);
        assert_eq!(
            ao.on_tunnel_state(&TunnelState::Offline { reconnect: false }, now),
            Action::Nothing
        );
    }

    #[test]
    fn long_connecting_forces_reselection_every_period() {
        let mut ao = supervisor();
        let now = Instant::now();
        ao.on_tunnel_state(&connecting(), now);
        // Progress events inside Connecting do not restart the clock.
        ao.on_tunnel_state(&connecting(), now + secs(300));
        assert_eq!(deadline_in(&ao, now), Some(LONG_CONNECTING));
        assert_eq!(ao.poll(now + secs(599)), Action::Nothing);
        assert_eq!(ao.poll(now + secs(600)), Action::Connect);
        // Repeats every period from the re-selection.
        assert_eq!(
            ao.next_deadline(),
            Some(now + secs(600) + LONG_CONNECTING)
        );
        assert_eq!(ao.poll(now + secs(1_200)), Action::Connect);
        // Connected stops it.
        ao.on_tunnel_state(&connected(), now + secs(1_250));
        assert_eq!(ao.next_deadline(), None);
    }

    #[test]
    fn stale_retry_timer_does_not_fire_into_a_live_connect() {
        let mut ao = supervisor();
        let now = Instant::now();
        // Boot race: the initial Disconnected event lands after the target is
        // already Secured, then Connecting follows at once.
        ao.on_tunnel_state(&TunnelState::Disconnected, now);
        assert!(ao.next_deadline().is_some());
        ao.on_tunnel_state(&connecting(), now);
        assert_eq!(deadline_in(&ao, now), Some(LONG_CONNECTING));
        assert_eq!(ao.poll(now + secs(5)), Action::Nothing);
    }

    #[test]
    fn disabled_supervisor_does_nothing() {
        let mut ao = AlwaysOn::new(false, Box::new(|_: u64| 0u64));
        ao.on_target_state(TargetState::Secured);
        let now = Instant::now();
        assert_eq!(
            ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now),
            Action::Nothing
        );
        assert_eq!(ao.next_deadline(), None);
        assert_eq!(ao.status(now).to_string(), "off");
        // Enabling later starts clean and picks up the next event.
        ao.set_enabled(true);
        assert_eq!(ao.status(now).to_string(), "active");
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
        assert_eq!(deadline_in(&ao, now), Some(secs(4)));
        ao.set_enabled(false);
        assert_eq!(ao.next_deadline(), None);
        assert_eq!(ao.status(now).last_error, None);
    }

    #[test]
    fn status_line_while_retrying() {
        let mut ao = supervisor();
        let now = Instant::now();
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now);
        ao.on_tunnel_state(&connecting(), now + secs(4));
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now + secs(5));
        ao.on_tunnel_state(&connecting(), now + secs(13));
        ao.on_tunnel_state(&error(ErrorStateReason::SetRouting), now + secs(14));
        let status = ao.status(now + secs(16));
        assert_eq!(status.attempt, 3);
        assert_eq!(status.next_retry_in, Some(secs(14)));
        assert_eq!(
            status.to_string(),
            "retrying in 14 s (attempt 3, last error SetRouting)"
        );
    }
}
