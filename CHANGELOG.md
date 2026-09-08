# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Add entries under `[Unreleased]` as changes land on `develop`;
`scripts/release.sh` promotes the section at release time and CI uses it as
the GitHub release notes.

## [Unreleased]

### Added

- A custom DNS server on a private address (a Pi-hole or AdGuard on the LAN)
  is now admitted on every interface except the WAN one, in every
  kill-switch state, so it keeps answering while connected and while
  disconnected with the kill-switch on. A private address on the WAN side,
  such as the upstream router behind another NAT, stays rejected like any
  public resolver outside the tunnel. Private custom resolvers were also
  never handed to dnsmasq before, so the setting had no effect at all; while
  disconnected, dnsmasq now uses the LAN resolver instead of the WAN-provided
  ones the kill-switch rejects.
- Always On now lives in the daemon. With the setting on, the tunnel
  connects at boot, waits for a default route instead of polling for one,
  retries error states with backoff (5 s doubling to 5 min for
  firewall/routing/DNS/TUN failures, 60 s then 5 min for missing gateways,
  clock skew or exhausted bandwidth) while moving off blacklisted gateways,
  forces a fresh gateway selection after ten minutes of Connecting, stops on
  errors that need a change from you (account state, a non-independent pinned
  pair) until the configuration or account changes, and pauses when you
  disconnect. After six consecutive infrastructure failures the daemon exits
  for procd to respawn it with the kill-switch table still in place, and an
  in-process liveness check does the same for a service loop that stops
  answering. Set it with `nym-vpnc tunnel set --always-on on` or the Tunnel
  Settings row; `nym-vpnc status` and the LuCI row show what it is doing
  (`Always on: retrying in 42 s (attempt 3, last error SetRouting)`). The
  bridge reports the daemon's Offline state as `offline` instead of
  `unknown`, so the web UI says "Waiting for network" during a WAN outage.
  An upgrade carries UCI `always_on=1` over to the daemon setting. Closes #6.
- `nym-vpnc gateway test` probes gateways with ICMP echo from the router and
  prints RTT min/avg/max and packet loss per gateway, plus a summed pair RTT
  for every entry/exit combination. Without options it tests the configured
  (or, when connected, the active) pair; `--entry-country`/`--exit-country`
  probe the best-scored gateways of a country (`--top N`), `--entry-id`,
  `--exit-id` and `--id` name gateways directly, `--count` and `--timeout`
  tune the probes and `--json` prints the raw report. The probes are sent by
  the daemon over a socket carrying the tunnel fwmark, so the test works
  while disconnected and while connected with the kill switch on; the
  kill-switch policy gained a matching rate-limited, mark-scoped echo-request
  accept in every state. Requested by a forum user (#8).
- "Stealth API connect", the same switch the NymVPN mobile and desktop apps
  have: `nym-vpnc tunnel set --stealth-api on|off` and a toggle in the LuCI
  Tunnel Settings card. The daemon reaches the Nym API (account, gateway
  directory, discovery) directly and only falls back to cover domains after a
  direct request fails; with this on, every API request goes through the cover
  domains from the start. Helps where the API hosts are blocked, at the cost
  of slower API calls. It covers every daemon API request, including the
  long-lived gateway directory client and start-up discovery, and applies
  from the next request without a reconnect; it is persisted in the daemon
  config. CLI and web
  UI both say so when the network environment publishes no cover domains, in
  which case the setting has nothing to route through.
- Gateway independence, the same guarantee upstream calls node families: the
  entry and exit gateway of a two-hop tunnel must be run by unrelated
  parties. The daemon now picks the exit first and only accepts an entry in
  a different node family (operator group), a different ASN and a
  non-overlapping announced prefix, for random and country selections as
  well as pinned gateways. All three criteria are on by default and apply to
  existing installs without a migration; `nym-vpnc tunnel set
  --gateway-independence on|off` switches them together and
  `--family-reminders on|off` controls the reminder shown by user interfaces.
  When only a related pair matches the settings the connect stops in a
  distinct error state that says so instead of quietly pairing them;
  `nym-vpnc connect-v2 --relax-independence` connects anyway for that
  session only (automatic reconnects keep it, the next disconnect ends it)
  and never changes the persisted setting. `nym-vpnc gateway tentative`
  previews the pair a connect would pick, or reports that relaxed criteria
  are needed, without connecting or creating key material; `gateway list`
  gained a Family column and `status` names each gateway's family. The rpcd
  bridge exposes all of it for LuCI: a `gateway_independence` object in the
  tunnel config, `tunnel_set` toggles, a `relax_independence` flag on
  `connect`, a `tentative_gateways` method and family fields on gateway rows
  and on the status entry/exit.
- Gateway independence in LuCI (the NymVPN apps' *node families*): a
  **Gateway Independence** switch and a **Server Family Reminders** switch in
  the Tunnel Settings card, the operator family as a chip on every gateway
  picker row and under the connected entry and exit (both marked in amber
  when they share one), and a pre-connect check that asks the daemon which
  pair it would pick. A same-family pair brings up "The selected servers are
  in the same operator family!" with **Connect anyway** — relaxing the
  criteria for that connection only — and **Change servers**; with reminders
  off the connect goes ahead relaxed and a notice says so. The check is
  bounded to a few seconds and falls back to a plain connect on an older
  daemon, and the `NEEDS_RELAXED_INDEPENDENCE_CRITERIA` error state offers
  the same two choices. The bridge's `tentative_gateways` method is now in
  the LuCI ACL.

### Removed

- The `nym-vpn-watchdog` service, its WAN hotplug hook, `/tmp/nym-watchdog.state`
  and the UCI `always_on`/`watchdog_interval`/`watchdog_max_retries` options,
  replaced by the daemon's Always On above. The rpcd `watchdog_get`/
  `watchdog_set` methods and the interval pills in the web UI go with them.
- All telemetry. The daemon no longer collects or reports anonymous network
  statistics and no longer carries Sentry crash reporting; neither can be
  turned on. `nym-vpnc network-stats`, `nym-vpnc sentry`, the matching gRPC
  calls and the rpcd `stats_get`/`stats_set` methods behind the web UI's
  Privacy switch are gone, as is the local `stats.db`. Existing daemon
  configs that still contain the old `network_stats`, `sentry_monitoring`
  or `collect_network_statistics` fields load unchanged; the fields are
  ignored and dropped on the next save.

### Security

- Kill-switch runtime state (the fw3 rules files and transition marker, the
  fw4 policy hint, the interface list, the lock and the init script's stop
  marker) moved from world-writable `/tmp` into the root-owned private
  directory `/var/run/nym-firewall` (mode 0700). The firewall includes and the
  boot guard trust a file only inside a directory that passes ownership and
  mode checks, so an unprivileged local process can no longer plant a stop
  marker to keep the boot block off or a rules file for the fw3 include to
  load. The daemon writes state with create-new, no-follow temp files.
  The package hooks' rpcd stash moved out of `/tmp` for the same reason
  (`/var/run`, root-only parent).
- CI now runs the workspace test suite and a fast security job on every push
  to `develop` and feature branches: secret scanning of the pushed commits,
  dependency policy and advisory checks (`cargo deny`), shellcheck over the
  scripts that run as root on the router, and a lint of the workflows
  themselves. A weekly run repeats the secret scan over the full history and
  re-checks advisories against a fresh database.
- Release pipeline hardened: every action pinned to a commit, workflow tokens
  read-only except where a job needs to write, checkouts no longer persist
  credentials, dispatch inputs and signing keys reach shell steps through the
  environment instead of expression interpolation.

### Fixed

- The firewall helper scripts (`fw3-include.sh`, `fw4-include.sh`,
  `fw-boot-guard.sh`, `fw-rules.sh`) are shipped unconditionally: the
  package build fails without any of them, and the includes, init script,
  uci-defaults and prerm refuse to run instead of falling back to stand-in
  definitions when one is missing. The separate `fw-backend.sh` detector is
  folded into the guard.
- A daemon settings file with the `killswitch` key removed by hand now loads
  with the kill-switch on, as a fresh config and the boot-time firewall guard
  already treat it; the daemon used to read it as off, so its first policy
  opened the WAN that the guard had blocked.
- A private custom DNS server was admitted on "every interface except the
  WAN", with the WAN found by name: a second uplink (mwan3 `wanb`) or a WAN
  interface not called `wan` could carry the lookup out in the clear, and
  once connected the last-resort lookup named the tunnel as the WAN. The WAN
  is now the firewall zone (every device of the `wan` and masquerading
  zones) and the resolver is admitted only on the one device it is routed
  on, never a WAN device or the tunnel. Inbound exemptions are now marked on
  every WAN device as well, so replies on a second uplink stay on it.
- With the kill switch on, the daemon's API clients are now pinned to the
  admitted addresses whenever it sits in Disconnected or Error with a live
  resolution, instead of only right after a resolution; the Error state also
  refreshes the allow-list on the same hourly cadence as Disconnected.
- Installing or upgrading from LuCI's Software page reportedly never finished
  while the same upgrade from a shell worked (#13). Likely cause: the
  package's post-install step restarted rpcd — the service LuCI runs opkg/apk
  through — inside the transaction, cutting off the reply the page was
  waiting for and dropping every login session. The rpcd refresh is now
  detached and runs once the package manager process has exited. On
  upgrades it is also scaled down: skipped when neither the LuCI backend nor
  its ACL file changed, a session-preserving reload when only the backend
  changed, and a restart — which asks you to log in again — only when the ACL
  file changed. Not reproduced here; the fix targets the most likely cause.
- The kill-switch no longer has a fail-open window on a fresh install or an
  expired endpoint cache: with the kill-switch enabled, the firewall goes to
  the Blocked policy the moment the daemon starts and stays there through the
  first `Connecting` phase. Only the daemon's own DNS/NTP bootstrap traffic is
  let through until the API and gateway addresses are resolved and added to
  the allow-list. Previously "kill-switch on" could mean an open firewall
  until the first successful connect.
- The kill-switch now also covers the boot window before the daemon starts.
  `firewall` starts at S19 and `network` at S20, but `nym-vpnd` only at S90,
  so until its first policy landed nothing fenced WAN egress (reported on the
  forum during a reboot; unconfirmed by capture, closed defensively). The
  firewall include now installs a boot-time emergency block when the
  kill-switch is on in the daemon's saved settings, the daemon is enabled to
  start at boot, it was not stopped explicitly, and no policy has been
  applied since boot — fw4 in a separate `inet nym_boot` table, fw3 through
  the existing emergency chains. It drops new router-originated and forwarded
  traffic but always lets loopback, LAN/link-local, DHCP/DHCPv6, IPv6 ND and
  reply traffic through, so SSH and LuCI from the LAN keep working even if
  the daemon never comes up. As in the daemon's own policy, DNS is rejected
  ahead of the LAN allowance, so a router behind another router does not
  leak lookups to a private-address upstream resolver during boot. The
  daemon lifts it with its first policy (kill-switch on or off);
  `/etc/init.d/nym-vpnd stop` and package removal remove it, and a setting
  that is absent or cannot be read takes the daemon's default (kill-switch
  on).
- `/etc/init.d/nym-vpnd restart` and a package upgrade no longer open the
  kill-switch for the seconds until the new daemon's first policy: the daemon
  leaves its Blocked policy in place on shutdown while the kill-switch is on
  (the Error and Offline states used to reset the firewall unconditionally),
  the init script tears the firewall down only on an explicit `stop`, and an
  upgrade leaves the old daemon running through the file swap and restarts it
  through the newly installed init script, so the old package's stop hooks
  never run. A system shutdown or reboot keeps the block as well: the
  K-script stop used to open the firewall for the last seconds of a reboot,
  and a capture on the WAN showed a LAN client's DNS and HTTPS leaving in
  that window. Measured on OpenWrt 25.12 (fw4) and 21.02 (fw3): the
  kill-switch never opened across upgrade, daemon restart, firewall reload
  and restart, and a LAN client saw no leak.
- fw3: the daemon, the firewall include and the init script now serialize
  their changes to the kill-switch chains with a lock. Before, a `firewall
  reload` that observed the daemon mid-change could install its emergency
  block after the daemon had already finished and lifted it, leaving the
  router blocked until the next policy change or reload. When the lock
  cannot be taken at all (no `flock`, or the runtime directory fails its
  checks) the include no longer runs unlocked: it leaves a live policy
  untouched, installs the boot-time block when nothing is hooked and the
  kill-switch is on (re-checking afterwards and lifting it if the daemon
  hooked a policy meanwhile), logs CRITICAL and exits non-zero. The include
  also honours the administrator's stop marker ahead of any persisted
  policy, so a stop whose teardown could not take the lock is completed by
  the next firewall reload instead of leaving the router blocked.
- On a package upgrade `prerm` no longer deletes the running daemon's policy
  routing rules (the fwmark lookups); with inbound exemptions active that
  left replies without their WAN route until the restart. The cleanup is
  removal-only.
- `nym-vpnc gateway test` is bounded: one test runs at a time per daemon (a
  second request is refused instead of doubling the probe rate and reporting
  phantom loss), `--id` accepts at most 20 gateways and duplicates are
  collapsed, every run has a deadline derived from its parameters, a client
  that disconnects cancels the probes, and socket errors such as a missing
  capability now reach the error message instead of a generic "failed to
  probe gateways".
- Package upgrades decide whether rpcd needs a reload from the exported RPC
  method list instead of the plugin wrapper file, which never changes; a new
  `nym-vpnc` with new methods therefore refreshes rpcd even when the ACL file
  is unchanged.
- With the kill-switch on and the tunnel disconnected, the daemon now
  resolves the API endpoints through its own DNS hatch and admits them in the
  Blocked policy, refreshing them hourly while idle. A fresh install can
  register an account, sync and list gateways without turning the kill-switch
  off; a failed resolution leaves the firewall Blocked and retries after a
  minute (#15). Reproduced on 23.05, 24.10 and 25.12 before the fix.
- After a failed firewall policy apply the daemon no longer stays parked in
  the error state once a settings change re-applies the policy successfully;
  it returns to Disconnected.
- `nym-vpnc` exits quietly when its output pipe is closed early (for example
  `nym-vpnc tunnel get | grep -q ...`) instead of reporting a broken pipe.
- The firewall include registration script (`uci-defaults`) exits non-zero
  when a `uci set` or the commit fails, so postinst and the boot-time
  defaults runner keep it for another attempt instead of treating the failure
  as success.
- fw3/iptables routers (OpenWrt 21.02 and older): the kill-switch now survives
  `/etc/init.d/firewall restart`, which flushes every chain, by persisting the
  applied ruleset and re-applying it from the firewall include; on a plain
  `reload` fw3 leaves foreign chains alone and the include only reconciles
  (re-hooks a displaced jump, lifts a stale emergency block). An earlier
  version of this note claimed reload wiped the chains; that was our own
  include's cleanup deleting them. `/etc/init.d/nym-vpnd stop` tears
  everything down through the same path. An include run that lands in the
  middle of a policy change (or after a daemon crash mid-change) installs a
  fail-closed emergency block instead of reading half-written state as
  "kill-switch off"; the daemon lifts it once the policy has converged. Reply
  traffic for SSH/LuCI sessions is exempted from that block, so a stuck state
  never locks you out. Known limit: during fw3's own restart the built-in
  policy is ACCEPT until fw3 has rebuilt its tables and run the includes;
  nothing in an include can cover that window.
- fw3: hook jumps are only inserted when missing or when a foreign rule has
  been placed ahead of them, instead of being deleted and re-inserted on every
  policy change (which briefly left the kill-switch chains unhooked). A rule
  inserted at the head of `output_rule`/`forwarding_rule` by another include
  can no longer run ahead of the kill-switch.
- fw3: the `CONNMARK` target (needed for inbound exemptions) is not in stock
  images; its absence no longer fails the whole policy — exemptions are
  dropped with a loud log while the kill-switch stays active.
- fw3: configuring an inbound exemption while the kill-switch was on broke
  every connect attempt (`failed to send icmp packet: Operation not
  permitted`) because the exemption mark restore clobbered the daemon's
  socket mark. Restores are now scoped to exempted flows. This affected
  nftables routers too.
- fw3: LAN clients were not forwarded into the tunnel at all with the
  kill-switch off, and TCP MSS was never clamped for the 1340-MTU tunnel.
- If the kernel routes IPv6 but `ip6tables` is missing or unusable, the
  kill-switch now refuses to install an IPv4-only policy (visible as
  `Error state: SetFirewallPolicy`) instead of silently leaving an IPv6
  bypass.
- Kill-switch policy failures while idle (Disconnected) now surface as an
  error state instead of being logged only.
- Failures to persist the fw3 ruleset are now reported as policy failures
  rather than logged and ignored.
- An endpoint cache stamped in the future (RTC reset) is now rejected instead
  of being treated as fresh forever.
- `nym-vpnc tunnel get` no longer reports `Lewes protocol: off` while the
  tunnel negotiates the Lewes Protocol with every gateway that advertises it.
  The line now reads `auto (used when the gateway supports it)`, the
  `tunnel set --lewes-protocol` toggle — which never affected the connection —
  is gone, and the LuCI bridge's `lewes_protocol` field reports `auto`.

### Changed

- The tunnel plane — masquerade, the TCP MSS clamp and LAN-to-tunnel
  forwarding — is a firewall zone `nym` (`device 'nym+'`) with a `lan -> nym`
  forwarding in `/etc/config/firewall`, declared at install, shown on LuCI's
  firewall page and rendered by fw3/fw4 on every reload; the daemon and the
  firewall includes no longer install it. A guest zone that should reach the
  VPN needs its own forwarding to `nym`.
- The emergency and boot-time kill-switch rule sets are now defined once, in
  Rust (`nym-firewall/src/openwrt/boot_rules.rs`), and rendered at build time
  into `fw-rules.sh`, which the fw3 and fw4 firewall includes source. The
  three hand-maintained copies of that rule text are gone, and the build
  fails if the committed fragment is stale. The include owns chain teardown
  on fw3; `prerm` and the init script go through it under the shared lock.
- One device evidence suite is tracked, `tests/leak/`: it injects failures
  (daemon killed mid-transition and while connected, rule application
  failing, lock lost, firewall reload and restart, corrupt config, unusable
  binary, crash loop, reload storms, untrusted runtime directory,
  kill-switch toggles, WAN flap, interrupted upgrade, reboot) under a WAN
  packet capture with a positive control, on an fw3 VM bed or an fw4
  container bed selected with `BED=`, and records management access (a held
  ssh session, a wired probe from the hypervisor, LuCI) and a recovery clock
  for every scenario. Verdicts are gated: a probe that fails for a reason
  other than being blocked, an empty or tunnel-less capture, a missing
  positive control or a scenario that was not connected before its injection
  is `INCONCLUSIVE`, a scenario whose recovery did not complete is `FAIL`,
  and the run exits non-zero on either. The 2026-09-07 runs of the earlier
  fw3 and fw4 suites are kept under `docs/evidence/`.
- New architecture documents: the kill-switch contract (what is protected in
  every state and lifecycle event, how each cell was verified, and which are
  not protected or unverified), a decision record on the fw3 firewall-restart
  window, and a state-ownership table for every runtime file, chain and table.
- The OpenWrt integration test harness (Proxmox container harness with
  kill-switch and DNS cases) is now tracked under `tests/harness/`, and made
  runnable: the mnemonic is delivered on stdin, a failed slot fails the run,
  a case that aborts before recording a result is counted as a failure, and
  the connected-state checks require `State: Connected`, a `nym` interface
  and a moved egress address. Every selected case ends in exactly one of
  PASS, FAIL, SKIP (with a reason) or MISSING, and the harness installs the
  exact release artifacts under procd with an upgrade case that samples the
  kill-switch every second (the sampler is now stopped by pid, so its samples
  are complete) and a connected-state case whose DNS check fails when a plain
  DNS query from the router is seen leaving the WAN, whatever the rule set
  says. Run on 2026-09-07 against 23.05.5, 24.10.0 and 25.12.4: the install,
  daemon and upgrade cases pass on all three; the account and idle
  kill-switch cases fail because a fresh install with the default
  kill-switch cannot reach the API until an endpoint cache exists (issue
  #15), which is the main open item before a release. The QEMU
  multi-architecture runner and the single-machine helper scripts that used
  to sit next to it were removed: the runner could not start under `set -u`
  and everything it covered the harness covers.
- Less background traffic while the daemon is up but not connected (reported
  from a mirrored-port capture by a forum user). The account state is now
  re-checked every 30 minutes instead of every 2 while the tunnel is down and
  nothing has asked for it, and the hourly network discovery check is
  suspended. A connect request switches both back at once: the account state
  is re-synced immediately if it is more than 2 minutes old and discovery
  re-checks if its last run is more than an hour old, before the tunnel is
  brought up. The sync on daemon start and the manual refresh from the
  account card / `nym-vpnc account get` are unchanged, and so is error
  recovery: while the account is in an error state (API unreachable, clock
  not yet synced at boot) retries stay at the 2-minute cadence.
- The firewall include is registered for the *active* backend (fw4 vs fw3 —
  live state, then the firewall init script, then binary presence, so
  boot-time runs on images shipping both stacks pick correctly) and applied
  at package install time, so a fresh install is protected before the first
  reboot. Existing registrations are reconciled on upgrade, and `prerm` no
  longer deletes the include on upgrades, so an interrupted upgrade cannot
  leave the router without it.
- LuCI page redesign. **Split Tunneling** is its own card; **Tunnel
  Settings** groups its switches into *Protection* (Always On, Kill-Switch
  with Inbound Services nested under it, Gateway Independence, Server Family
  Reminders) and *Transport* (Two-Hop, Circumvention Transports, Stealth API
  Connect, IPv6), with a `reconnect` tag on switches that apply on the next
  connect. Every switch row carries one short clause with the full
  explanation behind an ⓘ expander that links to the LuCI guide; amber notes
  stay only for live state. Gateway picker rows are a fixed-height ledger
  (name, performance tier, `No CT` tag, load/uptime/city line, operator
  family) and the hero gives the pickers most of its width. Nothing changes
  in what the switches do or send. Behind the page, the view was split into
  a module tree (`api`, `store`, `components/`, `flows/`, `cards/`) with a
  jsdom test harness under `luci-app-nym-vpn/tests/`.

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
