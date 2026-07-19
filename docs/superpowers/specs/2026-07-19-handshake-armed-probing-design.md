# Handshake-armed connection probing

Date: 2026-07-19
Status: approved

## Problem

Time-to-Connected on the router is ~11 s. Benchmarks on the AX1800 (three
disconnect→connect cycles, phase boundaries from daemon log timestamps) break
it down as:

| Phase | Run 1 (stale cache) | Run 2 (warm) | Run 3 (warm) |
|---|---|---|---|
| Resolve API addresses | 0.14 s | 0.12 s | ~0.1 s |
| Await account readiness | ~0 s | ~0 s | ~0 s |
| Refresh + select gateways | 0.50 s | 0.07 s | 0.07 s |
| Register with gateways (LP) | 1.69 s | 1.85 s | 1.67 s |
| Tunnel up → viable | 8.82 s | 8.67 s | 8.68 s |
| Total (`nym-vpnc connect -w`) | 11.15 s | 10.85 s | ~10.6 s |

The dominant phase is the viability gate: "Connected" is only declared when
the connection monitor's first ICMP probe (single ping to 1.1.1.1 through the
exit tunnel) succeeds. The monitor keeps one probe in flight and retransmits
at `last_sent + timeout`; with `TimingConfig::two_hop()`'s 3 s initial timeout
the probes fire at t=0, 3, 6, 9… — so time-to-Connected quantizes to a 3-second
grid, and probes sent before the two-hop WireGuard handshakes complete are
simply lost. The ~8.7 s constant across runs (with and without a logged
handshake retry) is this cadence artifact, not network variance.

Gateway selection is NOT the bottleneck (0.07–0.5 s); upstream's
`gateway_provider` pre-selection work is out of scope here.

## Prior art

Upstream #5571 (`68b638072`, still live at their HEAD) solves exactly this for
wireguard-go: expose per-peer `last_handshake_time` from the WG stack via a
shareable stats reader, then in `tunnel_monitor.rs` call
`wait_for_exit_handshake()` — poll every 500 ms, cap at 10 s, never fatal —
after the `InterfaceUp` event is acknowledged and before spawning the
connection monitor. The first probe then fires when the tunnel can actually
carry it.

Our fork uses gotatun, which makes the port easier than upstream had it:
`device.read(async |d| d.peers().await)` returns `Vec<PeerStats>` with
`last_handshake: Option<Duration>`. No FFI handle-sharing workarounds needed.
Only our `nym-wg-gotatun` wrapper fails to surface it today.

(Implementation correction: `Device` derives `Clone` but the bound requires
the transport tuple to be `Clone`, which our UDP factories are not — so the
built design shares an `Arc<tokio::sync::RwLock<Option<Device>>>` slot between
`Tunnel` and `StatsReader` instead of cloning `Device`; `stop()` takes the
slot, readers treat a stopped device as "not handshaken".)

## Design

### Phase 0 — diagnosis baseline (no code changes)

On `openwrt25`, raise logging (`nym_connection_monitor=trace` plus gotatun
handshake logs), run 3 connect cycles, and record per-probe send/reply
timestamps and entry/exit handshake completion times. This produces the
before-numbers and pins down where inside the 8.7 s the handshake actually
lands, so the after-benchmark can attribute any residual gap (e.g. gotatun's
5 s `REKEY_TIMEOUT` first-handshake retry) correctly.

### Component 1 — `nym-wg-gotatun`: stats surface

- New `StatsReader` struct holding a clone of `gotatun::device::Device`.
- `Tunnel::stats_reader()` returns one.
- `StatsReader::all_peers_have_handshake() -> bool` implemented as
  `device.read(async |d| d.peers().await)`, true iff every peer has
  `last_handshake.is_some()`.
- Applies to whichever tunnel variant the two-hop exit actually uses
  (`wireguard_go.rs`, and `amnezia.rs` if trivially symmetric — confirm during
  implementation).

### Component 2 — `connected_tunnel.rs`: expose it on the handle

Before the exit tunnel moves into the event-handler task, take
`exit_tunnel.stats_reader()` and store it in `TunnelHandle` (currently just
shutdown token + join handle). Add `TunnelHandle::exit_handshake_complete()`
delegating to the reader. Mixnet tunnels unaffected — the wait is WG-only,
guarded the same way as upstream's `as_wireguard()`.

### Component 3 — `tunnel_monitor.rs`: the wait

Port `wait_for_exit_handshake()` in shape: poll every 500 ms, cap at 10 s,
cancel-safe via the shutdown token, never fatal — on timeout, log and fall
through to probing exactly as today. Call site: immediately after the
`InterfaceUp` reply (firewall/routes ready), before
`create_tunnel_connection_monitor`. Probe timings (`two_hop()`) stay
untouched.

## Error handling

Stats-read failures are treated as "not yet handshaken" and polling continues
until the cap. Worst case is identical to today's behavior plus at most the
10 s cap, and only in the pathological case where the handshake never
completes — where today's probes were all failing anyway on their way to
`Failed`.

## Testing

- Unit test in `nym-wg-gotatun` for the reader against a device whose peers
  have no handshake (gotatun has test scaffolding under `device/tests`).
- Build for the router target.
- Hardware validation: rerun the exact 3-cycle benchmark on `openwrt25` with
  the same log-timestamp method, comparing per-phase numbers before/after.
- Success criterion: the "tunnel up → viable" phase tracks
  handshake-complete + one probe RTT instead of a ~8.7 s constant.

## Out of scope

- Gateway-selection pre-buffering (`gateway_provider` restructure).
- Probe cadence/timeout changes in `nym-connection-monitor`.
- gotatun first-handshake retry tuning — becomes a follow-up decision if the
  after-benchmark shows handshake latency binding at ~5 s.
