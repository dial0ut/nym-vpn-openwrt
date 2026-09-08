# Kill-Switch Contract

What the kill-switch protects, in which situation, by which mechanism, and how each claim was
verified. This is the reference for anyone changing the firewall code, the includes, the init
script or the package hooks: every row names the code that enforces it, so a change to that code
is a change to this contract. Where nothing enforces a cell it says **not protected**; where a
cell is enforced but has never been observed on a device it says **unverified**.

Companion pages: [Firewall Integration](firewall.md) explains the mechanisms in prose;
[fw3 restart exposure](fw3-restart.md) is the decision record for the one known hole.

## Scope and vocabulary

The kill-switch is the setting `killswitch=true && legacy_split_tunnel=false`
(`nym-vpnd/src/service/config/config_manager.rs:519` computes the effective value; the boot guard
mirrors it in `fw-boot-guard.sh:nym_boot_block_wanted`). Everything below assumes it is on unless
the row says otherwise. With it off, nothing here applies and the router behaves like stock
OpenWrt plus tunnel routing.

Columns:

- **Router egress**: new connections the router itself opens toward the WAN (its own processes,
  including dnsmasq's upstream lookups). The daemon's own bootstrap traffic (API, DoT/DoH to its
  resolvers, NTP, WireGuard to the entry gateway) is *always* allowed when a daemon policy is
  live; the column says whether anything *else* gets out.
- **LAN forward**: new connections forwarded from LAN clients toward the WAN.
- **DNS**: port 53 leaving on the WAN, from the router (dnsmasq relaying LAN queries) or
  forwarded from a LAN client directly. The router's own dnsmasq answering LAN clients from its
  cache is never counted as a leak.
- **IPv6**: whether the row's protection also covers IPv6, given the kernel has it enabled.
- **Management**: SSH/LuCI from the LAN, and existing sessions from the WAN side.
- **Enforced by**: file and function.
- **Recovery**: what returns the router to normal operation.
- **Evidence**: `unit:<name>` is a test in `nym-vpn-core/crates/nym-firewall/src/openwrt/`,
  `capture` is a WAN-side packet capture with a LAN client probing, on the boxes listed under
  [Evidence](#evidence); `device` is a manual on-device check without capture; `unverified` means
  the code exists but no test or observation backs the cell.

Three policies exist (`policy.rs:compile`): **Blocked** (idle and error states: loopback,
DHCP, ND, mwan3 pings, cached API endpoints and the daemon's resolvers root-scoped, rate-limited
root-scoped DNS and NTP hatches, the mark-scoped probe hatch, LAN if allowed, then reject),
**Connecting** (Blocked plus the peer endpoints and the tunnel interface once it exists) and
**Connected** (Connecting minus the DNS/NTP hatches, plus tunnel DNS and the CVE-2019-14899 drop).
In every policy, OUTPUT and FORWARD end in a terminal reject (`policy.rs:final_reject`) and INPUT
is left to fw3/fw4 (management is never ours to break).

## Steady states

| Event | Router egress | LAN forward | DNS | IPv6 | Management | Enforced by | Recovery | Evidence |
|---|---|---|---|---|---|---|---|---|
| Daemon idle (Disconnected) | blocked except daemon bootstrap and the resolved API endpoints (nyxd, nym-api, nym-vpn-api and their cover domains), root-scoped | blocked (LAN-to-LAN allowed if `allow_lan`) | rejected; root-scoped rate-limited hatch for the daemon only; a **private** custom resolver (LAN Pi-hole) is admitted on the one device it is routed on, unscoped, for the router and LAN clients (daemon-only instead when that device is a WAN zone device, or the WAN zone or route is unknown), and dnsmasq is pointed at it while idle (the WAN resolvers are dropped from its upstream list because they are rejected; kept only with the kill-switch off) | yes when `enable_ipv6`; fw3 refuses to apply if kernel v6 is up and ip6tables is unusable | LAN: fw3/fw4 INPUT policy; WAN sessions: reply direction | `tunnel_state_machine/mod.rs:apply_killswitch_policy` → `policy.rs:compile` Blocked; the allow-list comes from `mod.rs:resolve_api_endpoints` (the same resolver Connecting uses, through the DNS hatch, 30 s timeout), run by `states/disconnected_state.rs` on entry when nothing is known or the addresses are cache-only, then every hour (`API_ENDPOINT_REFRESH_INTERVAL`), with a 60 s retry after a failure; a successful resolution re-applies Blocked with the endpoints and pins the HTTP clients to them (`install_idle_api_access`). Until one succeeds the policy is Blocked with **no** endpoints — fail closed, so on a fresh install the API is unreachable only for the seconds the first resolution takes | connect, or turn the kill-switch off | unit:`blocked_policy_terminates_in_reject`, `blocked_state_blocks_forward_lan_to_wan`, `blocked_dns_exceptions_are_root_scoped`, `no_unscoped_dns_output_while_tunnel_down`, `idle_refresh_is_needed_when_nothing_is_known_or_only_cached`, `idle_refresh_follows_the_interval`, `idle_policy_without_endpoints_is_blocked_with_none`, `idle_policy_admits_resolved_endpoints_for_the_daemon_only`; capture (fw3, fw4: LAN client blocked while disconnected); harness `30-killswitch-disconnected`; **unverified on a device** that a fresh install registers with the kill-switch on after this change (acceptance test: `nym-vpnc account set` with the default settings) |
| Connecting | as Blocked plus peer endpoints and tunnel interface | into the tunnel only | rejected on the WAN; hatch root-scoped; private custom resolver pinned to its route device as when idle | as above | as above | `states/connecting_state.rs:set_firewall_policy` → Connecting | connection completes or fails to Disconnected/Error | unit:`connecting_policy_terminates_in_reject`, `connecting_dns_hatch_is_root_scoped`; capture (connect attempts observed, no LAN egress) |
| Connected | tunnel and peer endpoints only | into the tunnel only | tunnel resolvers via tunnel only; private custom resolver pinned to the one device it is routed on; public non-tunnel resolvers any interface; WAN port 53 otherwise rejected. WAN zone unknown, or the route device is a WAN device or the tunnel → private resolver tunnel-only (fail closed) | as above | as above | `states/connected_state.rs:set_firewall_policy` → Connected | n/a | unit:`connected_forward_output_have_no_unqualified_established_accept`, `connected_lan_collects_tunnel_iface_and_emits_cve_drop`; capture baseline (fw3: 20 s connected, zero non-WireGuard egress); harness `32-killswitch-connected` |
| Disconnecting | Connected policy stays until Disconnected applies Blocked | same | same | same | same | `states/disconnecting_state.rs` → `DisconnectedState::enter` → Blocked | automatic | unit only (state machine); **unverified** by capture across the transition |
| Error state | Blocked re-applied on entry; if that apply fails the previous policy (or the boot block) stays | as Blocked | as Blocked | as Blocked | as Blocked | `states/error_state.rs:enter` → `apply_killswitch_policy`; failure only logged | settings change re-applies; `stop` opens | harness `33-killswitch-error`; **unverified** for the apply-fails branch |
| Offline (no WAN) | Blocked-shaped policy with `allow_lan` | as Blocked | as Blocked | as Blocked | as Blocked | `states/offline_state.rs:set_firewall_policy` | WAN returns → reconnect (Always On re-connects on the route event; without it the tunnel stays down) | **unverified** by capture (`tests/leak/scenarios/17-wan-flap.sh` observed the reconnect only) |
| Exemptions configured | unchanged: only *replies* to marked inbound flows leave via the WAN | unchanged plus marked replies | unchanged | v4 and v6 restores share the `ct mark` scoping | unchanged | `policy.rs:exemption_mangle_rules` (restores scoped to `ct mark 0x14e`; one set rule per WAN zone device), `exemption_filter_accepts`, `bypass_mark_forward_accept` | n/a | unit:`exemption_mangle_restores_meta_mark_after_set`, `exemptions_emit_filter_mark_accepts_before_final_reject`, `unmarked_lan_to_wan_still_rejected_with_bypass_accept`; device (fw3 21.02: connmark fixes reproduced and verified, commits d33383d76, 15c93b7d4, 0e6ff520c); **unverified** by capture that an exempt service cannot originate outbound |
| `allow_lan` off | unchanged | LAN-to-LAN through the router rejected too | unchanged | unchanged | **INPUT untouched**, so LAN SSH/LuCI keep working (`policy.rs:final_reject` never touches INPUT) | `policy.rs:allow_lan_traffic` skipped | turn `allow_lan` on | unit (policy compiles without LAN accepts); **unverified** on device |
| Legacy split tunnel on | **not protected** by design: effective kill-switch is off | not protected | not protected | n/a | normal | `config_manager.rs:519`; boot guard `nym_boot_block_wanted` returns 1 | n/a | unit (guard text-scan); device (mock run of the guard, 2026-09-07) |
| Kill-switch toggled off at runtime | **not protected** by design; `reset_policy` opens, boot table removed | same | same | n/a | normal | `apply_killswitch_policy` else-branch; fw4 `reset` / fw3 `reset` | n/a | harness `30-killswitch-disconnected` (KS off leg); **unverified** by capture of the toggle instant |
| Kill-switch toggled on at runtime | Blocked applied immediately in idle states; Connecting/Connected re-applied via settings diff | as row above | as row above | as row above | as row above | `states/*:killswitch_changed()` → `set_firewall_policy` / `apply_killswitch_policy` | n/a | unit (state diff tests in `tunnel_state_machine/mod.rs`); device (toggle observed, no capture) |

## Lifecycle events

| Event | Router egress | LAN forward | DNS | IPv6 | Management | Enforced by | Recovery | Evidence |
|---|---|---|---|---|---|---|---|---|
| Boot: firewall start (S19) → daemon's first policy (S90) | blocked: boot block drops new flows except loopback, DHCP/DHCPv6, ND, LAN/link-local/multicast destinations | blocked except LAN/link-local destinations | **rejected before the LAN accepts**, so a private-address upstream resolver is covered | fw4: `ip6 daddr` sets + drop; fw3: `ip6tables` boot block when kernel v6 is up — **not protected if `ip6tables` is missing** (logged CRITICAL) | LAN: INPUT untouched; WAN-side sessions: reply-direction accept | `fw4-include.sh:install_boot_block`, `fw3-include.sh:emergency_block … boot`, decision in `fw-boot-guard.sh:nym_boot_block_wanted` | daemon's first `apply`/`apply_forwarding_only`/`reset` removes it last; `stop` writes the marker and removes it | unit:`boot_block_keeps_the_router_reachable_and_ends_in_drop`, `boot_block_rejects_dns_before_the_lan_accepts`, `include_script_boot_rules_reject_dns_before_lan_accepts`; capture (fw4 CT 425 and fw3 VM 902 reboots 2026-09-07: block installed at firewall start, zero upstream DNS, zero LAN egress); capture (simulated block: LAN dig to private upstream refused, tcpdump 0 DNS packets on WAN) |
| Boot: daemon's own bootstrap under the boot block | daemon API/DoH/NTP are **blocked** until its first policy replaces the block (the block has no uid hatches) | n/a | n/a | n/a | n/a | same | daemon applies Blocked (which lifts the block); the idle state then resolves the API endpoints through the DNS hatch and admits them, so account sync, registration and the gateway directory work without a connect | capture (first daemon egress appears seconds after the block is lifted). **Not protected against a startup deadlock on a non-mainnet network with no cached discovery**: environment discovery in `nym-vpnd/src/main.rs` runs before the service exists and therefore before the idle allow-list; on mainnet the embedded defaults cover it and the discovery refresher re-fetches once the endpoints are admitted, on other networks the daemon exits and the block stays (issue #15, startup ordering part) |
| Daemon restart (`/etc/init.d/nym-vpnd restart`) | Blocked/Connected policy left in place by the exiting daemon | same | same | same | same | `tunnel_state_machine/mod.rs:release_firewall_on_shutdown` (keeps policy when kill-switch on); init script `keep_killswitch` (action `restart`: no marker, no teardown) | new daemon's first apply replaces the policy atomically | capture (fw4 and fw3: policy present at every 1 s sample, LAN client zero leaks) |
| Package upgrade, apk (25.x) or opkg (≤24.10) from a package that already has `keep_killswitch` | as daemon restart: old daemon keeps running through the file swap | same | same | same | same | `scripts/ipk/prerm` (no daemon stop on `PKG_UPGRADE=1`, no firewall teardown, ip rules untouched), `scripts/ipk/postinst` (`restart` through the new init script) | postinst restart | capture (fw4 p8→p9→p10→p12 via apk, fw3 p10→p11→p12 via opkg: policy continuous, zero leaks) |
| First upgrade from a package *without* `keep_killswitch` (≤1.34.0) | apk: covered (the new pre-upgrade script runs). opkg: **not protected** for the seconds between the old prerm's `stop` and postinst's start; the old stop hook opens the firewall | same | same | same | normal | package manager semantics: opkg runs the *old* prerm, apk runs the *new* pre-upgrade | postinst start | capture (apk p6→p8 on fw4: continuous); capture (apk p6→p7 before the fix: ~15 s open, one LAN request left on the real address — the measurement of the hole); opkg case **unverified** (no pre-keep opkg install available) |
| Firewall reload (`/etc/init.d/firewall reload`) | fw4: `inet nym` is not fw4's table, untouched. fw3: reload deletes only fw3-tagged rules and skips `*_rule` chains; our chains and jumps survive, the include reconciles | same | same | same | same | fw4: table separation; fw3: firewall3 `fw3_flush_rules(reload=true)`, include `main → restore_policy` (idempotent) | n/a | capture (fw3: policy hooked at every sample, zero leaks; fw4: earlier session); unit:`include_script_names_the_same_tables`, `include_script_only_ever_deletes_the_boot_table` |
| Firewall restart (`/etc/init.d/firewall restart`) | fw4: unaffected. fw3: **not protected** between fw3's flush (built-in policies set to ACCEPT, every chain deleted) and its include run at the end of `start`; only fw3's own zone rules apply once rebuilt | same | same | same | normal | fw3 restore: `fw3-include.sh:restore_policy` from `/var/run/nym-firewall/{v4,v6}.rules` when the include finally runs | the include | capture (fw3 VM 902: policy hooked at every 1 s sample and zero leaks, i.e. the window is sub-second and the tunnel kept LAN traffic routed inside it; **the window itself was not measured**). Decision: [fw3-restart.md](fw3-restart.md) |
| Explicit stop (`/etc/init.d/nym-vpnd stop`) | **not protected** by design: stop marker written, tables and chains removed | not protected | not protected | n/a | normal | init script `stop_service`/`service_stopped`; fw3 include `main` honours the marker before restoring anything | `start` removes the marker; the boot block re-arms only after a reboot | capture (fw3 and fw4: LAN client reached the internet on the real address within seconds — the intended behaviour) |
| System shutdown / reboot | kept: K-script runs with `action=shutdown`, treated like `restart` | same | same | same | n/a | init script `keep_killswitch` | boot block on the way up | capture (fw3 VM 902 before the fix: LAN DNS and HTTPS SYN left 2 s after `reboot`; after: only FINs of the daemon's own connections; fw4 CT 425: zero upstream DNS, zero LAN egress) |
| Daemon crash, steady state | policy stays (nothing removes it) | same | same | same | same | no code path removes a live policy on process death | procd respawns (`respawn 3600 5 0`: retry 0 = forever), new daemon re-applies | **unverified** by capture; reasoning only |
| Daemon crash mid-apply, fw4 | old or new table, never neither: `nft -f` replaces atomically | same | same | same | same | `fw4.rs:run_nft_script` | respawn | unit-level reasoning; **unverified** by fault injection |
| Daemon crash mid-apply, fw3 | transition marker stays; the next include run installs the strict emergency block (reply-only OUTPUT, DROP FORWARD) instead of reading half-written state; if the crash happened on a family's *first* activation the daemon had already installed the same block before touching chains | LAN forwarding dropped entirely (transition set has no LAN accepts) | rejected | v6 block when kernel v6 is up | LAN SSH/LuCI via INPUT; WAN sessions via reply accept | `fw3.rs:apply` (marker first; first-activation block), `fw3-include.sh:main` transition branch | respawned daemon's next successful apply/reset removes marker and block; `stop` opens | unit:`transition_marker_is_explicitly_cleared_only_on_success`, `emergency_script_keeps_reply_traffic_and_never_touches_input`; **unverified** by fault injection on a device |
| procd respawn exhaustion | does not occur: retry count 0 means respawn forever | — | — | — | — | init script `procd_set_param respawn 3600 5 0` | n/a | config only; **unverified** that procd honours 0 as "forever" on every OpenWrt release in scope |
| IPv6 newly enabled while a v4-only policy is persisted (fw3) | the next include run installs a v6 emergency block until the daemon re-applies; the daemon installs a v6 first-activation block on its next apply | same | same | this row *is* the v6 story | as boot block | `fw3-include.sh:restore_policy` (`kernel_ipv6_enabled` without `v6.rules`), `fw3.rs:apply` per-family `jumps_present` | daemon re-apply | **unverified** on a device |
| Kernel IPv6 up, `ip6tables` unusable (fw3) | daemon refuses to apply any policy (Error state); whatever was live stays | same | same | **not protected** on a fresh boot: the boot block's v6 half fails (CRITICAL) and nothing else filters v6 | as before | `fw3.rs:apply` `Ipv6Status::Unusable` → `Err`; `fw3-include.sh:handle_no_policy` logs CRITICAL | install `ip6tables`/`kmod-ip6tables` or disable IPv6 | **unverified** |
| Corrupt or missing daemon config | boot guard takes the daemon's defaults (kill-switch on) — block installed | same | same | same | same | `fw-boot-guard.sh:nym_config_bool` → `nym_boot_block_wanted`; daemon `config_manager.rs:new` renames an unparseable file to `.json.bak` and starts with defaults | daemon starts with defaults and lifts the block | device (mock run of the guard with valid/corrupt/absent files, 2026-09-07); **unverified** end to end |
| Runtime directory untrusted (wrong owner/mode, symlink) | fw4: marker and hints ignored, boot-block decision proceeds; fw3: include takes the lockless path — live policy left alone, or boot block if nothing is hooked; daemon refuses to apply on top of it | same | same | same | same | `common.rs:ensure_runtime_dir_at`, `fw-boot-guard.sh:nym_runtime_dir_trusted`, `fw3-include.sh:run_without_lock` | fix the directory; `stop` still opens (marker ignored → **`stop` cannot open a boot block while the directory is untrusted**; remove the directory instead) | unit:`runtime_dir_rejects_*`, `every_runtime_path_lives_in_the_runtime_dir`, `scripts_derive_every_state_path_from_the_runtime_dir`; device (fw4: marker ignored with the directory at 0755, block kept, logged) |
| `flock` missing (fw3 only) | include never reconciles unlocked: hooked policy left as is; nothing hooked → boot block, re-checked; init `stop` skips the teardown and leaves it to the next locked include run | same | same | same | same | `fw3-include.sh:run_without_lock`; init script stop-time lock check | restore `flock`, `firewall reload` (the stop marker is honoured first); daemon applies still work (they use `flock(2)`, not the binary) | device (fw3 VM 902 with `/usr/bin/flock` moved away, 2026-09-07: all three branches observed). Note OpenWrt's own `procd.sh` also requires `flock`, so this is not a realistic image |

## Traps

Things that cost a debugging session at least once. Read before changing anything in this area.

- **A marker file is not a lock.** The fw3 transition marker covers crashes; only the `flock`
  on `/var/run/nym-firewall/lock` covers concurrency between the daemon, the include and the init
  script. An include that tests the marker without the lock can install a block after the
  daemon lifted its own.
- **An upgrade runs the old package's hooks** (opkg: old `prerm`; apk: the *new* pre-upgrade
  script, but the *old* init script is still what `stop` executes). Whatever the new package
  wants during the swap must not depend on old code cooperating. That is why prerm no longer
  stops the daemon on upgrade and postinst runs `restart` through the new init script.
- **`fw3 reload` preserves foreign chains; `fw3 restart` flushes everything.** Upstream
  `fw3_flush_rules(reload=true)` skips user chains. An earlier version of this project
  misdiagnosed its own cleanup branch as fw3 wiping chains on reload.
- **Shutdown runs `stop`.** The K-script is invoked with `action=shutdown`, which rc.common
  maps onto the stop functions. Without the keep path a reboot opened the firewall for its last
  seconds, and a LAN client's packets left on the WAN.
- **The include scripts ship in the package, not in the daemon.** `scripts/ipk/build-ipk.sh`
  copies `nym-firewall/scripts/*.sh` to `/usr/share/nym-vpn/`; the Rust tests `include_str!`
  them only to pin the contract, and `fw-rules.sh` is rendered from `boot_rules.rs`
  (`NYM_FW_RULES_REGEN=1 cargo build -p nym-firewall`). Changing a script needs a package
  rebuild and reinstall.
- **Stock busybox lacks `stat`, `nohup`, `setsid`, `timeout`.** Use `find -user -perm` for
  ownership checks and `( trap "" HUP; cmd & )` to detach. `pkill -f`/`pgrep -f <name>` from an
  ssh one-liner matches the shell running the one-liner.
- **The ad blocker redirects all LAN DNS to the router's dnsmasq** (`nym-vpnd/src/adblocker.rs`,
  a NAT `REDIRECT` in PREROUTING). A LAN client's query "to" a WAN resolver therefore traverses
  INPUT, not FORWARD, and can be answered from cache. Counting FORWARD rejects proves nothing
  about it; capture the WAN.
- **`policy accept` on our nft chains means "let the next table decide".** The boot table
  and `inet nym` sit at lower priority than fw4; an accept there is not a final verdict, the
  terminal `drop`/`reject` is.
- **The WAN is the firewall zone, not an interface name.** `common.rs:wan_zone_devices` takes
  every `network` of the zones named `wan` or with `masq` and resolves it through ubus
  `l3_device` (PPPoE: `pppoe-wan`); mwan3 setups have several. `ip route get` never finds the
  WAN — connected, it answers with the tunnel. It only names the private resolver's own device
  (`policy.rs:private_dns_device`), which is then matched positively, since iptables cannot
  express "not any of these".
- **The daemon's default kill-switch is on.** An unreadable config does not make it off: the
  daemon starts with defaults after stashing the bad file. The boot guard mirrors that.
- **Tests that scan script text prove the text is there.** They pin contracts (names, paths,
  ordering); they do not prove packet behaviour. Only the captures do.

## Evidence

Captures referenced above were taken on 2026-09-07 with tcpdump on the Proxmox host's tap/veth
of each router's WAN, a LAN client polling its egress address over HTTPS and DNS through the
router every second, and a state watcher on the router:

- fw4: OpenWrt 25.12.4 x86_64, LXC 425 (`openwrt25`), LAN client `ubuntu-dev` (VM 114).
- fw3: OpenWrt 21.02.7 x86_64, VM 902, LAN client LXC 903 (Alpine).

The changelog entry for the unreleased version summarises them; the recorded runs are under
`docs/evidence/`. The capture files themselves were not committed. The reproducible harness
lives in `tests/harness/` (LXC); its kill-switch cases are `30-killswitch-disconnected`,
`32-killswitch-connected` and `33-killswitch-error`. Fault injection under a WAN capture
(crash mid-apply, interrupted upgrade, failed rule application, corrupt config, crash loop,
WAN flap, reboot) is `tests/leak/`, run against an fw3 VM or an fw4 container bed; IPv6
transitions are still not exercised (the beds have no v6 upstream), and every row marked
**unverified** is a candidate for a new scenario there.
