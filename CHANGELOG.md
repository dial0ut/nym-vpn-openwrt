# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Add entries under `[Unreleased]` as changes land on `develop`;
`scripts/release.sh` promotes the section at release time and CI uses it as
the GitHub release notes.

## [Unreleased]

### Fixed

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
