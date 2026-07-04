# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Add entries under `[Unreleased]` as changes land on `develop`;
`scripts/release.sh` promotes the section at release time and CI uses it as
the GitHub release notes.

## [Unreleased]

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
