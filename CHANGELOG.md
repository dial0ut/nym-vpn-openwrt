# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Add entries under `[Unreleased]` as changes land on `develop`;
`scripts/release.sh` promotes the section at release time and CI uses it as
the GitHub release notes.

## [Unreleased]

## [1.35.0] - 2026-09-21

### Added

- Daemon-managed Always On connects at startup, recovers from network outages
  and retries transient failures with backoff. Disconnect pauses it; account
  and gateway-selection errors wait for corrective action. CLI and LuCI show
  its status, and upgrades migrate the old UCI setting (#6).
- `nym-vpnc gateway test` reports gateway latency and packet loss, including
  while the kill-switch is on. Supports gateway/country selection and JSON
  output, with bounded concurrency, target counts and execution time (#8).
- Stealth API Connect sends API requests through cover domains from the first
  request. Available in CLI and LuCI, it applies without reconnecting and
  reports when the network provides no cover domains.
- Gateway independence requires different operator families, ASNs and
  non-overlapping network prefixes by default. CLI and LuCI can preview the
  pair, show operator families and relax the criteria for one connection.
  LuCI offers **Connect anyway** or **Change servers** when a pair conflicts.
- Private custom DNS resolvers on non-WAN interfaces work with the kill-switch
  on, including while disconnected. Resolver access is pinned to its route
  device; WAN-side private resolvers are not admitted by this exception.

### Removed

- The shell watchdog, its hotplug hook, UCI retry settings and RPC methods,
  replaced by daemon-managed Always On.
- Anonymous network statistics and Sentry crash reporting, their CLI/RPC/UI
  controls and the local statistics database. Old configuration fields are
  ignored and removed on the next save.
- The ineffective Lewes Protocol toggle. Status now reports automatic
  negotiation with gateways that support it.

### Security

- Packages install their files as root. Both packagers recorded the building
  user's uid and umask, so the daemon binary, its init script, the firewall
  helpers, the LuCI assets and the rpcd ACL arrived owned by that uid
  (`runner` in released packages) and, depending on the builder's umask,
  group-writable.
- Firewall runtime state now lives in the root-owned, mode-0700
  `/var/run/nym-firewall` directory, with ownership checks and safe temporary
  file creation. Package-hook state also moved out of world-writable `/tmp`.
- The kill-switch installs a block before initial endpoint discovery and at
  boot before the daemon starts. Missing or unreadable settings default to
  protection enabled. Bootstrap and management traffic retain their scoped
  exceptions.
- Daemon restart, LuCI restart, account reset, upgrade and shutdown preserve
  the enabled kill-switch. Explicit service stop removes protection.
- fw3 policy writers share a lock; incomplete transitions use an emergency
  block. Policy persistence and idle policy-application failures now surface
  as errors. IPv6-capable kernels reject IPv4-only daemon policies when
  `ip6tables` is unavailable.
- Release workflows use pinned actions, restricted token permissions and
  environment variables for dispatch inputs and signing keys.

### Fixed

- Account registration and API access while disconnected with the kill-switch
  on no longer require an existing endpoint cache (#15). Disconnected and
  Error states refresh admitted API addresses and pin clients to that
  resolution; failed resolution keeps the firewall blocked and retries.
- Successful firewall reapplication lets the daemon leave the error state.
  Future-dated endpoint caches are rejected after a clock reset.
- Private custom DNS reaches dnsmasq while idle; disabling it restores the
  WAN resolver list. WAN detection covers all devices in WAN/masquerading
  zones, including secondary uplinks, for DNS and inbound exemptions.
- LuCI package upgrades defer rpcd refresh until the package transaction
  exits, targeting the reported Software-page hang (#13). Backend-only
  changes use a session-preserving reload; ACL changes require a restart.
- Upgrades preserve the running daemon's routing rules and firewall include,
  restart through the new init script, and remove retired tunnel-plane chains.
  Failed include registration remains retryable.
- Required firewall helpers are always packaged; missing helpers fail the
  build or lifecycle operation instead of using fallback definitions.
- fw3 reloads preserve foreign chains; restart restores persisted policy.
  **Known limitation:** fw3's own flush/rebuild window can permit WAN traffic
  before the include restores protection; uninterrupted protection during
  `firewall restart` is not guaranteed. See the
  [restart exposure](docs/architecture/fw3-restart.md).
- fw3 policy changes avoid unnecessarily unhooking kill-switch chains and
  bound lock waits. Missing CONNMARK support disables inbound exemptions with
  an error log while retaining protection; mark restoration no longer
  clobbers the daemon's socket mark.
- LAN forwarding with the kill-switch off and tunnel TCP MSS clamping work
  on fw3 routers.
- `nym-vpnc` exits quietly when its output pipe closes early.

### Changed

- Tunnel forwarding, masquerade and MSS clamping use the UCI `nym` firewall
  zone with `lan → nym` forwarding. Guest networks need their own forwarding
  to `nym`.
- Idle account sync runs less frequently and background discovery pauses
  until connection is requested. Manual refresh and error recovery remain
  available.
- LuCI groups Tunnel Settings into Protection and Transport, gives Split
  Tunneling its own card, and adds per-control help links and reconnect tags.
  Gateway pickers display performance, transport support and operator family.
- Emergency firewall rules are generated from one Rust definition for both
  shell backends; builds reject stale generated rules.
- Development checks cover Rust workspace tests, dependency policy, secret
  scanning, shell scripts and workflows. Dependency advisories are currently
  reported without failing CI.
- Integration and fault-injection suites cover package lifecycle, DNS,
  kill-switch behavior, management access and recovery. See the
  [integration harness](tests/harness/README.md) and
  [fault-injection suite](tests/leak/README.md) for usage and coverage.

## [1.34.0] - 2026-08-21

### Fixed

- Closed a DNS leak in the kill switch's disconnected state (reported with
  packet captures by a forum user — thank you). While disconnected with the
  kill switch on, a LAN client's DNS query answered by the router's dnsmasq was
  re-sent upstream as the router's own traffic, which slipped through the
  firewall exceptions that exist for the daemon's reconnect lookups and left in
  plaintext over the WAN. Those exceptions are now scoped to the daemon's own
  processes (root-owned sockets): the daemon can still resolve enough to
  reconnect, while relayed LAN queries fail closed. This covers the connecting
  state too, not just disconnected — previously every reconnect attempt
  briefly reopened unscoped DNS for a cold-boot corner case (see below).
  Consequence you will notice: with the kill switch on and the VPN not yet
  connected, LAN devices and the router itself (opkg/apk, wget) cannot resolve
  DNS at all — before, they silently leaked instead. On fw3/iptables routers
  the scoping additionally needs the `iptables-mod-extra` package; without it
  the daemon omits the daemon-only DNS exceptions and keeps the kill switch
  active — meaning connecting itself fails closed until the package is
  installed or the kill switch is disabled (the log says which). Note that
  installing the package needs network, which the locked state blocks:
  disable the kill switch first, install, then re-enable.

- The installer no longer leaves apk (OpenWrt 24.10+/25.x) pinned to the
  exact package file it sideloaded. That pin silently blocked the advertised
  `apk upgrade nym-vpn` path, and an interrupted upgrade (reported: ENOSPC
  mid-upgrade) left the pin pointing at a package that was never installed,
  after which apk refused every transaction on the system with
  `breaks: world[nym-vpn><…]`. The installer now normalizes the world entry
  to a bare `nym-vpn` after installing; re-running the installer also
  recovers an already-wedged system. Verified on a 25.12 device, including
  the wedge and recovery paths.

- Fixed the kill switch on fw3/iptables routers (OpenWrt 21.02 and older),
  broken in every release since v1.27.0: the generated ICMPv6 rules lacked a
  `-p icmpv6` protocol flag, which legacy `ip6tables-restore` rejects, so
  every policy application failed with a SetFirewallPolicy error. nftables
  routers were unaffected. Found by on-device testing on 21.02.7.

### Changed

- The daemon now fixes a cold-boot clock itself instead of relying on the
  router's NTP client. A router without a real-time clock can boot with a time
  so wrong that no TLS certificate validates, and with the kill switch up the
  stock `sysntpd → dnsmasq` path is blocked along with all other non-daemon
  DNS (that path was why the connecting state kept an unscoped DNS hole). On
  connect, if the clock predates the daemon binary itself, the daemon resolves
  the NTP pool over plain DNS to its built-in resolvers, makes one SNTP
  exchange, and steps the clock forward — never backward — before the first
  TLS handshake. With a sane clock this does nothing. sysntpd still handles
  ongoing timekeeping once the tunnel is up.

## [1.33.1] - 2026-08-01

### Changed

- The DNS settings now tell you when they aren't in effect. If dnsmasq is set to
  ignore its resolv file — the "Ignore resolv file" box under Network → DHCP and
  DNS → Resolv & Hosts Files, which AdGuard Home, https-dns-proxy and stubby all
  tick when installed — the daemon deliberately leaves your upstream DNS alone,
  so the servers configured here are ignored and your own entries under the
  Forwards tab are what resolve (riding the tunnel while connected). That was
  already the behaviour, but nothing said so: `nym-vpnc dns get` and the web UI
  both reported the setting as active. Both now state plainly that it is not
  applied, and why.

### Fixed

- Changing a setting while connected no longer moves you to a different
  server. Settings that need a reconnect to take effect (IPv6, DNS, the
  kill-switch, split tunneling) tore the tunnel down and then re-ran server
  selection from scratch, so anyone connected via a country or random pick
  landed on a new entry/exit pair. The reconnect now keeps the pair it was
  running on, and only re-selects when the change is one selection actually
  depends on — the entry/exit points themselves, mixnet vs 2-hop, QUIC,
  residential exit, or the minimum-performance thresholds.

## [1.33.0] - 2026-07-26

### Added

- The gateway pickers come back pre-filled with the previously selected
  country and server after a disconnect, instead of forcing a full re-pick
  before every reconnect.

### Changed

- The web UI's backend has been rewritten. The previous rpcd plugin was a
  ~2000-line shell script that reconstructed every answer by parsing
  nym-vpnc's human-readable output — hundreds of process spawns per
  request. It is now a native bridge built into nym-vpnc (`nym-vpnc rpcd`)
  that speaks the daemon's typed API directly and emits JSON, which also
  removes a whole class of silent parsing breakage when output formats
  change.
- The connection card no longer changes size or shifts when connecting or
  disconnecting — state changes are a pure cross-fade.

### Fixed

- Gateway lists in the web UI no longer fail or time out on slower
  routers. Loading the server list for a country took seconds of pure
  process-spawning on router CPUs (measured 2.2s on a quad-core ARM
  router, far worse on single-core MIPS — past the web UI's request
  timeout); it now completes in ~0.15s. The status poll also no longer
  fetches the full gateway directory four times per refresh while
  connected.
- Opening a gateway picker after the dashboard sat idle no longer stalls
  on a directory re-fetch: the daemon keeps recently-used gateway lists
  fresh in the background (measured 1.15s → 0.05s). Lists nobody has
  asked about in the last half hour are not refreshed, so an idle router
  does zero background directory fetches. The UI also warms the picker
  data right after page load, covering the window right after a daemon
  restart.

- A WAN outage no longer switches the connected server. When the tunnel
  dropped and a reconnect attempt failed (typically because the line had
  not recovered yet), the daemon blamed the gateway: it was blacklisted
  and a different server selected. 1.32.0 made this much more likely —
  connects got ~4x faster, so the retry now lands inside the outage
  window. Reconnect failures shortly after a drop of a working session
  now check whether the local network is actually up (a quick probe of
  the VPN API): if it is down too, the same server is retried instead of
  blamed, for up to two minutes; if the network is up, the server really
  is at fault and is blacklisted after one confirming retry — so a
  genuinely dead server still fails over within seconds, not minutes.
  Outages that drop the default route (PPPoE/DSL resync) get the same
  shield when connectivity returns.
- Connecting no longer stalls five seconds when the first WireGuard
  handshake packet is lost — which it reliably is: the WG devices start
  a moment before their routes and firewall exceptions exist, so the
  first initiation dies locally and WireGuard waited the protocol's full
  5s before retrying. Lost initiations are now retransmitted after ~1s,
  bringing connects from ~6.5s back to ~2.5s (measured), and making
  mid-session recovery from packet loss faster as well.

## [1.32.1] - 2026-07-21

### Fixed

- Routers with a committed `noresolv` in the dnsmasq config (AdGuard Home,
  https-dns-proxy, stubby and similar user-owned DNS setups) could not
  connect on 1.32.0: the restart-free DNS handover verified a `resolv-file=`
  repoint that OpenWrt's init script never emits under `noresolv`, so every
  connect failed with a DNS error after restarting dnsmasq twice. The daemon
  now detects this and steps aside — dnsmasq is left untouched (zero
  restarts), the connect succeeds, and the user's chosen upstreams simply
  ride the tunnel while connected.
- Ad-blocking no longer silently fails to restore when the daemon starts
  while the kill-switch is engaged (the blocklist download was rejected by
  our own firewall). After a daemon restart the already-installed list is
  reused without a download or dnsmasq restart; after a reboot the download
  retries in the background and completes once a tunnel is up.
- A dead or hung nym-vpnd no longer strands the router behind its own
  kill switch (reproduced on real hardware: WAN egress and LAN forwarding
  blocked, DNS still resolving, with no process left able to clear the
  firewall). `/etc/init.d/nym-vpnd stop` now tears down the kill-switch
  table after the daemon is gone — including when the daemon is
  unresponsive and cannot be asked to disconnect (the graceful disconnect
  is bounded at 10s instead of wedging stop forever) — and procd now
  respawns the daemon indefinitely instead of abandoning it after a crash
  loop with the fail-closed firewall left up.

### Security

- Bumped the bundled WireGuard implementation (mullvad/gotatun) from the
  March 2026 pin (~0.4.1) to 0.8.1, picking up upstream security fixes:
  a remotely triggerable crash in the UDP receive path (an oversized
  datagram could panic the batched `recvmmsg` handler; fixed in 0.7.2),
  cross-peer allowed-IPs subnet spoofing (a peer could hijack another
  peer's routed subnets; fixed in 0.7.2), enforcement of the WireGuard
  nonce limit (Reject-After-Messages), and cookie replies being sent from
  a mismatched source port (fixed in 0.6.0).

### Changed

- WireGuard anti-replay window grew from 1024 to 8192 packets (fewer
  spurious drops under heavy packet reordering) and passive-keepalive
  timers now match wireguard-go semantics — idle tunnels no longer
  keepalive-ping-pong each other. The 7 MB UDP socket buffers that
  gotatun 0.7.0 stopped setting are restored explicitly, so throughput
  on OpenWrt's small default socket buffers is unaffected by the bump.

## [1.32.0] - 2026-07-19

### Changed

- Connects are ~4x faster: time-to-Connected drops from ~11.5 s to 2.2-3 s
  on the reference router (what remains is dominated by gateway registration
  latency, 1.3-4 s, which is upstream-parity). Three fixes stack up:
  - gotatun is pinned past mullvad/gotatun@a89bba8, fixing in-flight
    handshake indices being purged every 250 ms — the bug that silently
    discarded the exit hop's first handshake response and forced a 5-second
    WireGuard retry on nearly every connect.
  - Connectivity probing starts the moment the exit WireGuard handshake
    completes (port of upstream #5571 adapted to gotatun) instead of on a
    fixed 3-second probe grid, with handshake completion detected within
    50 ms of it happening.
  - Connecting and disconnecting no longer restart dnsmasq. Upstream DNS now
    switches through a daemon-managed resolv file
    (`/tmp/resolv.conf.d/nym-resolv.conf`) that dnsmasq reloads via inotify,
    removing the ~3.3 s `/etc/init.d/dnsmasq restart` from every connect and
    the LAN-wide DNS outage window at teardown. dnsmasq is restarted at most
    once per boot (the first daemon start repoints its `resolvfile`; staged
    uci only, so a reboot reverts to stock automatically) and never by a
    crash-looping daemon. While the VPN is disconnected the daemon mirrors
    netifd's WAN resolvers into the managed file, tracking WAN DHCP renewals.
- Behavior change: user-configured `dhcp.@dnsmasq[0].server` entries (e.g.
  `server=/corp.example/10.0.0.1` domain forwards) are no longer overridden
  while the VPN is connected — they stay active, with queries routed through
  the tunnel. Previous releases replaced the whole server list for the
  session.

## [1.31.0] - 2026-07-16

### Added

- Mixnet Tuning card in LuCI: adjust Sphinx traffic knobs (Poisson delays,
  background cover traffic, cover/mixing/sending delays) for mixnet mode —
  the daemon-side support existed; this exposes it on the router, matching
  the upstream apps' new Mixnet Tuning screens. Includes a new
  `nym-vpnc tunnel set --disable-background-cover-traffic` flag and a short
  `-l` alias for `nym-vpnc status --listen`.

### Changed

- Fresh installs now default IPv6-into-tunnel to off. Tunneled IPv6 toward
  exits without IPv6 egress was silently dropped, so dual-stack LAN clients
  tried IPv6 first and waited out a timeout before falling back to IPv4 on
  every new connection. Existing installs keep their stored setting; the
  LuCI toggle still enables IPv6.

### Fixed

- Kill-switch no longer leaks established IPv6 (or IPv4) flows out the WAN
  during tunnel reconnects. The firewall's established-connection accept was
  unqualified; it is now scoped to the tunnel interface, so only genuine
  tunnel return traffic is allowed while new and pre-existing WAN-bound flows
  are blocked. Most visible with circumvention (QUIC) transports, which
  reconnect frequently.
- Toggling the kill-switch in LuCI (or `nym-vpnc tunnel set --killswitch`) now
  takes effect immediately instead of silently doing nothing until the daemon
  was restarted.
- The firewall backend is re-detected instead of caching an early "unknown"
  result, so the kill-switch installs correctly even if the firewall service
  starts late or is restarted (previously surfaced as `Error state:
  SetFirewallPolicy`).
- TCP MSS is now clamped to the tunnel path MTU for forwarded LAN traffic
  (both in the daemon's fw4 integration and the reload-restore script). The
  2-hop WireGuard tun runs at MTU 1340; without clamping, LAN clients hit
  PMTU blackholes — web pages stalled while bulk transfers still passed.
- dnsmasq now gets only IPv4 upstream resolvers when any are available.
  IPv6 upstreams (half of the default set) are unreachable through exits
  without IPv6 egress and added per-lookup timeout stalls; AAAA records
  still resolve over IPv4 transport.
- Explicitly selected gateways are no longer dropped by the failure
  blacklist — a transient failure on your chosen entry no longer forces
  "switch gateways" errors (upstream #5529).
- QUIC bridge connections are bounded by a 10 s timeout instead of hanging
  the connect (upstream #5740).
- A reconnect can no longer race a throttled settings update and re-run
  with stale tunnel settings (upstream #5686, #5817).
- Reconnecting now retries account sync when the account controller is
  stuck on device-time-desync (upstream #5551).

- .apk packages shipped with only `rpcd` in their dependency list: repeated
  `-I depends:` flags to `apk mkpkg` overwrite each other, so `kmod-tun` and
  the other dependencies were silently dropped and fresh apk-based installs
  ended up without the TUN driver (`Error state: TunDevice`). All dependencies
  are now passed as a single space-separated `depends:` value.
- install.sh now runs `opkg update`/`apk update` before installing so
  dependencies resolve on routers with stale package lists, and verifies the
  TUN device is available after install (installing `kmod-tun` explicitly if
  not).

## [1.30.5] - 2026-07-03

### Fixed

- .apk packages now register pre-upgrade/post-upgrade scripts: apk (unlike
  opkg) does not run post-install or pre-deinstall on upgrades, so apk-based
  upgrades silently skipped the service refresh, rpcd ACL reload, watchdog
  re-enable, and feed self-heal.

## [1.30.4] - 2026-07-03

### Fixed

- postinst now scrubs stale apk feed lines (pre-1.30.1 bare directory URLs)
  from /etc/apk/repositories and always rewrites the canonical
  packages.adb repo line, fixing "APKINDEX.tar.gz: unexpected end of file"
  warnings on every apk operation. Arch detection falls back to
  /etc/os-release when /etc/openwrt_release is absent, which previously
  skipped feed registration entirely.

## [1.30.3] - 2026-07-03

### Fixed

- riscv64 builds: fetch kernel headers from GitHub's kernel mirror —
  cdn.kernel.org removed the pinned 6.1.119 tarball, which broke the release
  pipeline.
- .apk packages (OpenWrt 25.x+) now ship the always-on watchdog
  (`/etc/init.d/nym-vpn-watchdog` and `/usr/sbin/nym-vpn-watchdog`), matching
  the .ipk contents — the LuCI "Always on" toggle previously did nothing on
  apk-based installs. Also added the missing `kmod-ipt-conntrack-extra`
  dependency and corrected the daemon data directory to `/etc/nym/data`.

## [1.30.2] - 2026-07-01

### Added

- Legacy split tunneling (PBR) toggle.

### Fixed

- Anchor inbound exemptions to the WAN L3 device (PPPoE).
- Spelling "tunnelling" → "tunneling" (incl. shipped LuCI label).

## [1.30.1] - 2026-06-29

### Added

- Managed split-tunnel exclusions in LuCI.

### Fixed

- Kill-switch firewall policy: split-tunnel bypass + NTP DNS hatch.
- Self-healing fw4 firewall integration on reload.
- apk feed URL and signing key for OpenWrt 25.x.

## [1.30.0] - 2026-06-24

Large upstream sync (nym-vpn-client core) plus LuCI redesign.

### Added

- Redesigned LuCI frontend for consistency and clarity.
- Connectivity diagnostics surfaced in LuCI.
- CT-capable gateway flags in the entry picker.
- Circumvention transport support.

### Fixed

- Route LAN traffic into the tunnel independently of the kill-switch.
- Account state desync, live account UI, and session timer.
- Allow NTP while connecting; forget account from an error state.
- Don't blacklist the entry gateway for an exit registration failure.
- Numerous upstream core fixes (Lewes Protocol registration, per-peer
  preshared keys, control socket permissions, account-sync backoff, etc.).

## Older releases

See the [GitHub releases page](https://github.com/dial0ut/nym-vpn-openwrt/releases)
for v1.27.1 and earlier.
