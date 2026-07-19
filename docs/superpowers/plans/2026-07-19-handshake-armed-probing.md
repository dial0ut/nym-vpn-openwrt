# Handshake-Armed Connection Probing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start the ICMP viability probe when the exit WireGuard handshake completes (instead of on a blind 3-second grid), cutting router time-to-Connected from ~11 s toward registration + handshake + one RTT.

**Architecture:** Three-layer plumbing of a handshake signal that gotatun already tracks: (1) `nym-wg-gotatun` exposes a `StatsReader` over the reference-counted gotatun `Device`; (2) the WireGuard `TunnelHandle` in `nym-vpn-lib` carries an exit-tunnel reader; (3) `tunnel_monitor.rs` polls it after `InterfaceUp` (500 ms / 10 s cap / never fatal) before spawning the connection monitor. Port of upstream nym-vpn-client #5571 (`68b638072`), adapted from wireguard-go UAPI polling to gotatun's native API.

**Tech Stack:** Rust (tokio), gotatun (`Device::read`, `PeerStats.stats.last_handshake`), OpenWrt test router `openwrt25` (x86_64), musl cross-build via `scripts/build-musl.sh`.

Spec: `docs/superpowers/specs/2026-07-19-handshake-armed-probing-design.md`

## Global Constraints

- Probe timings in `nym-connection-monitor` (`TimingConfig::two_hop()`) must NOT change.
- The handshake wait is advisory: on timeout or shutdown it logs and falls through to probing; it must never fail the connect.
- Stats-read ambiguity (no peers listed) is treated as "not yet handshaken".
- No Claude/AI attribution in commits (repo rule).
- Work on branch `feat/handshake-armed-probe` off `develop`.
- All `cargo` commands run from `nym-vpn-core/`.
- `openwrt25` is a live router: benchmark cycles briefly interrupt VPN for LAN clients; always restore the `nym-vpnd` procd service (and a connected state) when a benchmark task ends.

---

### Task 0: Branch setup

**Files:** none (git only)

- [ ] **Step 1: Create the branch**

```bash
cd ~/dev/nym-vpn-openwrt && git checkout develop && git checkout -b feat/handshake-armed-probe
```

Expected: `Switched to a new branch 'feat/handshake-armed-probe'`

---

### Task 1: Phase 0 diagnosis — before-numbers with probe-level tracing

**Files:**
- Create: `notes/2026-07-19-connect-diag-before.log` (benchmark artifact, NOT committed)

**Interfaces:**
- Produces: baseline per-probe and per-handshake timestamps that Task 5 compares against.

Background for the executor: `nym-vpnd` honors `RUST_LOG` (EnvFilter `from_env_lossy()` in `nym-vpn-core/crates/nym-vpnd/src/logging.rs:282`). Neither `nym_connection_monitor` nor `gotatun` is on the forced `INFO_TARGETS`/`WARN_TARGETS` lists, so trace/debug directives for them take effect. The stock init script (`/etc/init.d/nym-vpnd` on the router) sets no env, hence the manual foreground run below.

- [ ] **Step 1: Stop the service and start an instrumented daemon**

```bash
ssh openwrt25 '/etc/init.d/nym-vpnd stop; sleep 2; RUST_LOG="info,nym_connection_monitor=trace,gotatun=debug" nohup /usr/sbin/nym-vpnd >/tmp/nym-diag-before.log 2>&1 & sleep 4; nym-vpnc status'
```

Expected: a `State: ...` line (daemon up and serving RPC).

- [ ] **Step 2: Run 3 timed connect cycles**

```bash
for i in 1 2 3; do ssh openwrt25 "nym-vpnc disconnect >/dev/null 2>&1; sleep 3; echo \"=== CYCLE $i ===\"; time nym-vpnc connect -w 2>&1 | tail -1"; done
```

Expected: three `real 0m XX.XXs` lines, ~10–11 s each (baseline).

- [ ] **Step 3: Collect the log and restore the service**

```bash
scp openwrt25:/tmp/nym-diag-before.log ~/dev/nym-vpn-openwrt/notes/2026-07-19-connect-diag-before.log
ssh openwrt25 'pkill -f /usr/sbin/nym-vpnd; sleep 2; /etc/init.d/nym-vpnd start; sleep 3; nym-vpnc connect -w >/dev/null 2>&1; nym-vpnc status'
```

Expected: `State: Connected ...` at the end (router restored).

- [ ] **Step 4: Extract the probe/handshake timeline**

```bash
grep -E "Sending (initial|next) probe|Probe succeeded|Next probe|handshake|HANDSHAKE|New tunnel state" ~/dev/nym-vpn-openwrt/notes/2026-07-19-connect-diag-before.log | head -80
```

Record (as a comment block appended to the log file): for each cycle, (a) timestamps of each probe send, (b) timestamp of first probe success, (c) gotatun entry/exit handshake completion timestamps, (d) whether the exit handshake landed well before the successful probe (cadence-bound — the expected finding) or at ~5 s (`REKEY_TIMEOUT`-bound). Do not commit the log; `notes/` is untracked scratch.

---

### Task 2: `nym-wg-gotatun` — handshake predicate and `StatsReader`

**Files:**
- Modify: `nym-vpn-core/crates/nym-wg-gotatun/src/wireguard_go.rs` (tests go in a `#[cfg(test)]` module in the same file — the crate has no separate tests dir)

**Interfaces:**
- Consumes: `gotatun::device::Device::read`, `DeviceRead::peers() -> Vec<gotatun::device::configure::PeerStats>` (fields `peer: Peer`, `stats: Stats`; `stats.last_handshake: Option<Duration>`). `PeerStats` is `#[non_exhaustive]` — it cannot be constructed in tests, which is why the predicate is a free function over `Option<Duration>`.
- Produces: `pub struct StatsReader` (Clone) with `pub async fn all_peers_have_handshake(&self) -> bool`; `Tunnel::stats_reader(&self) -> StatsReader`. Task 3 relies on these exact names.

- [ ] **Step 1: Write the failing tests**

Append to `nym-vpn-core/crates/nym-wg-gotatun/src/wireguard_go.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::all_peers_handshaken;

    #[test]
    fn no_peers_is_not_handshaken() {
        assert!(!all_peers_handshaken(Vec::<Option<Duration>>::new()));
    }

    #[test]
    fn peer_without_handshake_is_not_handshaken() {
        assert!(!all_peers_handshaken([None::<Duration>]));
    }

    #[test]
    fn all_peers_with_handshake_is_handshaken() {
        assert!(all_peers_handshaken([
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(2)),
        ]));
    }

    #[test]
    fn mixed_peers_are_not_handshaken() {
        assert!(!all_peers_handshaken([Some(Duration::from_secs(1)), None]));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/dev/nym-vpn-openwrt/nym-vpn-core && cargo test -p nym-wg-gotatun`
Expected: compile error — `all_peers_handshaken` not found.

- [ ] **Step 3: Implement predicate, `StatsReader`, and `Tunnel::stats_reader()`**

In `nym-vpn-core/crates/nym-wg-gotatun/src/wireguard_go.rs`:

Change the first import block (line 9) from `use std::fmt;` to:

```rust
use std::{fmt, time::Duration};
```

Add after the `impl Tunnel { ... }` block (after line 150):

```rust
/// Read-only handle for querying live peer stats off a running tunnel.
///
/// Holds a reference-counted clone of the gotatun device, so it stays usable
/// after the `Tunnel` itself has moved into the tunnel event-handler task.
#[derive(Clone)]
pub struct StatsReader {
    device: device::Device<DeviceTransports>,
}

impl StatsReader {
    /// Returns true once every peer on the device has completed a handshake.
    ///
    /// An empty peer list (e.g. transiently during reconfiguration) counts as
    /// not handshaken — callers treat "unknown" as "not yet".
    pub async fn all_peers_have_handshake(&self) -> bool {
        let last_handshakes = self
            .device
            .read(async |device| {
                device
                    .peers()
                    .await
                    .into_iter()
                    .map(|peer_stats| peer_stats.stats.last_handshake)
                    .collect::<Vec<_>>()
            })
            .await;
        all_peers_handshaken(last_handshakes)
    }
}

/// True iff the list is non-empty and every entry has a handshake timestamp.
fn all_peers_handshaken(last_handshakes: impl IntoIterator<Item = Option<Duration>>) -> bool {
    let mut any = false;
    for last_handshake in last_handshakes {
        if last_handshake.is_none() {
            return false;
        }
        any = true;
    }
    any
}
```

Add inside `impl Tunnel` (after `update_peers`, before the closing brace at line 150):

```rust
    /// Create a read-only stats handle sharing this tunnel's device.
    pub fn stats_reader(&self) -> StatsReader {
        StatsReader {
            device: self.device.clone(),
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/dev/nym-vpn-openwrt/nym-vpn-core && cargo test -p nym-wg-gotatun`
Expected: 4 tests pass (`no_peers_is_not_handshaken`, `peer_without_handshake_is_not_handshaken`, `all_peers_with_handshake_is_handshaken`, `mixed_peers_are_not_handshaken`).

- [ ] **Step 5: Commit**

```bash
cd ~/dev/nym-vpn-openwrt && git add nym-vpn-core/crates/nym-wg-gotatun/src/wireguard_go.rs && git commit -m "feat(wg): expose peer handshake stats from gotatun wrapper"
```

---

### Task 3: Plumb the reader through `TunnelHandle` and `AnyTunnelHandle`

**Files:**
- Modify: `nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel/wireguard/connected_tunnel.rs:110-145`
- Modify: `nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel/any_tunnel_handle.rs:28`

**Interfaces:**
- Consumes: `wireguard_go::StatsReader`, `Tunnel::stats_reader()` from Task 2 (module already imported in `connected_tunnel.rs:8` as `use nym_wg_gotatun::{amnezia::AmneziaConfig, wireguard_go};`).
- Produces: `WireguardTunnelHandle::exit_handshake_complete(&self) -> bool` (async); `AnyTunnelHandle::as_wireguard(&self) -> Option<&WireguardTunnelHandle>`. Task 4 relies on these exact names.

No new unit test: both methods are one-line delegation over a live gotatun device, which cannot be constructed without a TUN interface; behavior is covered by the Task 5 hardware validation. Verification for this task is `cargo check` + clippy.

- [ ] **Step 1: Capture the stats reader in `ConnectedTunnel::run`**

In `connected_tunnel.rs`, after the `exit_tunnel` is started (after line 108, before `let shutdown_token = CancellationToken::new();`):

```rust
        let exit_stats_reader = exit_tunnel.stats_reader();
```

- [ ] **Step 2: Store it in `TunnelHandle`**

Change the `TunnelHandle` construction (lines 123-126) to:

```rust
        Ok(TunnelHandle {
            shutdown_token,
            event_handler_task,
            exit_stats_reader,
        })
```

Change the struct definition (lines 142-145) to:

```rust
pub struct TunnelHandle {
    shutdown_token: CancellationToken,
    event_handler_task: JoinHandle<Tombstone>,
    exit_stats_reader: wireguard_go::StatsReader,
}
```

Add inside `impl TunnelHandle` (after `cancel()`):

```rust
    /// Returns true once every exit-tunnel peer has completed a WireGuard handshake.
    pub async fn exit_handshake_complete(&self) -> bool {
        self.exit_stats_reader.all_peers_have_handshake().await
    }
```

- [ ] **Step 3: Add `as_wireguard()` to `AnyTunnelHandle`**

In `any_tunnel_handle.rs`, inside `impl AnyTunnelHandle` (before `cancel()` at line 29):

```rust
    /// Returns the wireguard tunnel handle when this is a wireguard tunnel.
    pub fn as_wireguard(&self) -> Option<&WireguardTunnelHandle> {
        match self {
            Self::Wireguard(handle) => Some(handle),
            Self::Mixnet(_) => None,
        }
    }
```

- [ ] **Step 4: Check it compiles clean**

Run: `cd ~/dev/nym-vpn-openwrt/nym-vpn-core && cargo check -p nym-vpn-lib && cargo clippy -p nym-vpn-lib -- -D warnings`
Expected: no errors, no warnings. (If clippy flags `as_wireguard` as dead code at this point, that is expected until Task 4 — suppress nothing; proceed to Task 4 in the same session and re-run clippy there. If clippy fails ONLY on pre-existing issues untouched by this diff, note them and move on.)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/nym-vpn-openwrt && git add nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel/wireguard/connected_tunnel.rs nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel/any_tunnel_handle.rs && git commit -m "feat(wg): surface exit handshake state on tunnel handles"
```

---

### Task 4: `tunnel_monitor.rs` — the handshake wait

**Files:**
- Modify: `nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel_monitor.rs` (new fn near the top-level consts at line ~74-80; call site after the `InterfaceUp` reply block ending at line 710)

**Interfaces:**
- Consumes: `AnyTunnelHandle::as_wireguard()` and `exit_handshake_complete()` from Task 3; `tunnel_handle` local (destructured from `StartTunnelResult` at line ~633); `self.shutdown_token: CancellationToken` (field at line 191). `Duration` and `CancellationToken` are already imported in this file; the wireguard handle path resolves via the existing `tunnel::` import (`use super::{... tunnel::{self, ...}}`).
- Produces: nothing consumed later; behavior change only.

- [ ] **Step 1: Add `wait_for_exit_handshake`**

Insert after the `REGISTRATION_CLIENT_STARTUP_TIMEOUT` const (line 80):

```rust
/// Poll the exit WireGuard tunnel's peer stats until the handshake completes.
///
/// Advisory only: on timeout or shutdown this logs and returns, and the
/// caller proceeds to connectivity probing exactly as before. Ported from
/// upstream #5571, adapted to gotatun's native stats API.
async fn wait_for_exit_handshake(
    tunnel_handle: &tunnel::wireguard::connected_tunnel::TunnelHandle,
    shutdown_token: &CancellationToken,
) {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    let started = std::time::Instant::now();
    let wait = async {
        loop {
            if tunnel_handle.exit_handshake_complete().await {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };

    tokio::select! {
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, wait) => match result {
            Ok(()) => tracing::info!(
                "Exit WireGuard handshake completed after {} ms",
                started.elapsed().as_millis()
            ),
            Err(_) => tracing::warn!(
                "Exit WireGuard handshake not observed within {HANDSHAKE_TIMEOUT:?}; proceeding to connectivity probing"
            ),
        },
        _ = shutdown_token.cancelled() => {
            tracing::debug!("Shutdown requested while waiting for exit handshake");
        }
    }
}
```

- [ ] **Step 2: Call it after the `InterfaceUp` reply**

Immediately after the block ending at line 710 (`tracing::warn!("Interface up reply timeout"); }`), before the `// Send metadata endpoint data to the bandwidth controller` comment:

```rust
        // Routes and firewall are up. Wait for the exit WG handshake so the
        // first connectivity probe isn't lost to the handshake window (which
        // otherwise quantizes time-to-Connected to the 3s probe cadence).
        if let Some(wg_handle) = tunnel_handle.as_wireguard() {
            wait_for_exit_handshake(wg_handle, &self.shutdown_token).await;
        }
```

- [ ] **Step 3: Check it compiles clean**

Run: `cd ~/dev/nym-vpn-openwrt/nym-vpn-core && cargo check -p nym-vpn-lib && cargo clippy -p nym-vpn-lib -- -D warnings && cargo test -p nym-wg-gotatun`
Expected: no errors/warnings from this diff; the 4 Task-2 tests still pass.

- [ ] **Step 4: Commit**

```bash
cd ~/dev/nym-vpn-openwrt && git add nym-vpn-core/crates/nym-vpn-lib/src/tunnel_state_machine/tunnel_monitor.rs && git commit -m "sync: gate connectivity probing on exit wg handshake (#5571)"
```

---

### Task 5: Build, deploy to `openwrt25`, after-benchmark

**Files:**
- Create: `notes/2026-07-19-connect-diag-after.log` (benchmark artifact, NOT committed)

**Interfaces:**
- Consumes: baseline timeline from Task 1.

- [ ] **Step 1: Cross-build for the router (x86_64 musl)**

```bash
cd ~/dev/nym-vpn-openwrt && ./scripts/build-musl.sh x86_64
```

Expected: build succeeds; binary at `nym-vpn-core/target/x86_64-unknown-linux-musl/release/nym-vpnd` (the script prints the artifact path — use the printed path if it differs).

- [ ] **Step 2: Deploy and restart**

```bash
scp nym-vpn-core/target/x86_64-unknown-linux-musl/release/nym-vpnd openwrt25:/tmp/nym-vpnd.new
ssh openwrt25 '/etc/init.d/nym-vpnd stop; cp /usr/sbin/nym-vpnd /tmp/nym-vpnd.bak; mv /tmp/nym-vpnd.new /usr/sbin/nym-vpnd; chmod 755 /usr/sbin/nym-vpnd'
```

Expected: no errors. (Rollback if needed later: `mv /tmp/nym-vpnd.bak /usr/sbin/nym-vpnd`.)

- [ ] **Step 3: Instrumented after-benchmark (same protocol as Task 1)**

```bash
ssh openwrt25 'RUST_LOG="info,nym_connection_monitor=trace,gotatun=debug" nohup /usr/sbin/nym-vpnd >/tmp/nym-diag-after.log 2>&1 & sleep 4; nym-vpnc status'
for i in 1 2 3; do ssh openwrt25 "nym-vpnc disconnect >/dev/null 2>&1; sleep 3; echo \"=== CYCLE $i ===\"; time nym-vpnc connect -w 2>&1 | tail -1"; done
scp openwrt25:/tmp/nym-diag-after.log ~/dev/nym-vpn-openwrt/notes/2026-07-19-connect-diag-after.log
ssh openwrt25 'pkill -f /usr/sbin/nym-vpnd; sleep 2; /etc/init.d/nym-vpnd start; sleep 3; nym-vpnc connect -w >/dev/null 2>&1; nym-vpnc status'
```

Expected: three `real` lines; router restored to `State: Connected` at the end.

- [ ] **Step 4: Compare against the baseline and judge success**

```bash
grep -E "Exit WireGuard handshake|Sending (initial|next) probe|Probe succeeded|New tunnel state" ~/dev/nym-vpn-openwrt/notes/2026-07-19-connect-diag-after.log | head -60
```

Success criterion (from the spec): the "tunnel up → viable" phase (second `Connecting wg to ...` state → `Connected`) tracks handshake-complete + one probe RTT instead of ~8.7 s constant; the new `Exit WireGuard handshake completed after N ms` line appears each cycle. Record per-cycle phase timings alongside the Task 1 numbers in a comment block appended to the after-log.

If totals do NOT improve: check whether the handshake itself only lands at ~5 s (gotatun `REKEY_TIMEOUT` retry). That outcome is the spec's designated follow-up (gotatun first-handshake retry tuning), NOT a bug in this change — report it, don't chase it in this plan.

---

### Task 6: Changelog

**Files:**
- Modify: `CHANGELOG.md` (add entry under the unreleased/1.31.0 section, matching the existing entry style — inspect the top of the file and mimic it)

- [ ] **Step 1: Add the entry**

Add one bullet in the current unreleased section (wording exactly):

```markdown
- Faster connects: connectivity probing now starts as soon as the exit WireGuard handshake completes, instead of on a fixed 3-second probe grid (port of upstream #5571 adapted to gotatun). Cuts typical time-to-Connected on the router from ~11 s to ~3–5 s.
```

Adjust the measured numbers to match the Task 5 results before committing.

- [ ] **Step 2: Commit**

```bash
cd ~/dev/nym-vpn-openwrt && git add CHANGELOG.md && git commit -m "docs: changelog for handshake-armed connection probing"
```

---

## Self-review notes

- Spec coverage: Phase 0 → Task 1; Component 1 → Task 2; Component 2 → Task 3 (plus the `as_wireguard` accessor the spec's Component 3 call-site implies); Component 3 → Task 4; Testing/hardware validation → Tasks 2 & 5; error-handling rules → Global Constraints + Task 4 code. Spec's "amnezia symmetry" question resolved during planning: the amnezia variant is a UDP-factory wrapper inside the same `Tunnel` type, so Task 2 covers it with no extra work.
- The spec's "unit test against gotatun device test scaffolding" was refined: `PeerStats` is `#[non_exhaustive]` (not constructible outside gotatun), so the tested unit is the `all_peers_handshaken` predicate; the device-touching layer is one-line delegation validated on hardware in Task 5.
