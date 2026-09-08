# Firewall State Ownership

Every piece of kill-switch runtime state has one owner. This page is the
table a maintainer should be able to read before touching any of the
scripts: who creates and removes each artefact, on which transition, under
which lock, and what happens when it is stale or missing. The mechanics
behind each row are in [Firewall Backends](firewall.md); the rule text the
emergency and boot-time blocks install is defined once, in
`nym-firewall/src/openwrt/boot_rules.rs`, and rendered into
`scripts/fw-rules.sh` by the crate's `build.rs` (the build fails while the
committed fragment is stale).

## Actors

| Actor | Runs as | When |
|---|---|---|
| **daemon** | `nym-vpnd`, fw3/fw4 backend | every policy apply, forwarding-only apply and reset |
| **include** | `fw3-include.sh` / `fw4-include.sh`, run by fw3/fw4 | firewall start, reload, restart; explicitly by the init script and `prerm` |
| **init** | `/etc/init.d/nym-vpnd` | start, explicit `stop`; `restart` and `shutdown` take the keep path and touch nothing |
| **prerm** | package pre-removal hook | real removal only; on upgrade it leaves the daemon running and touches no firewall state |
| **postinst** | package post-install hook | install and upgrade (restarts the daemon through the new init script) |
| **guard** | `fw-boot-guard.sh`, sourced by the includes, init, uci-defaults and prerm | read-only helper: runtime-directory trust check, boot-block decision, fw3/fw4 detection (`nym_fw_backend`) |

## Runtime directory `/var/run/nym-firewall`

Root-owned, mode 0700, under a root-owned 0755 parent, so nothing
unprivileged can pre-create anything in it. The daemon creates it
(`ensure_runtime_dir`) and refuses to run a policy unless it passes the
symlink/owner/mode checks; the includes and the init script apply the same
check (`nym_runtime_dir_prepare` / `nym_runtime_dir_trusted`) before they
trust any file inside. Cleared by reboot (tmpfs) and by `prerm` on removal.

| File | Writer (creates / updates) | Remover | Readers | Lock | If stale or missing |
|---|---|---|---|---|---|
| `v4.rules`, `v6.rules` | daemon (fw3 apply, forwarding-only apply): temp + rename, 0600 | daemon (fw3 reset); include (stop marker present) | include (fw3 restart: restore; reload: reconcile) | fw3 state lock | missing = no policy persisted: include takes the no-policy path (boot block or cleanup). Stale: replaced atomically by the next apply |
| `transition` | daemon (fw3, first thing in every apply/reset) | daemon (last step on success); include (stop marker present) | include | fw3 state lock | present without the lock held = a daemon died mid-transition: include installs the transition emergency block and restores nothing |
| `lock` | daemon (created on first use, 0600, `O_NOFOLLOW`) | `prerm` (removal) | daemon, fw3 include, init (fw3 teardown), prerm (fw3 teardown) — all `flock(2)` exclusive | is the lock | never deleted while installed; a missing `flock` binary makes every include run take the fail-closed `run_without_lock` path |
| `policy.nft` | nobody today (reserved; the fw4 backend pipes to `nft -f -`) | `prerm` | fw4 include (optional hint) | none | ignored when absent |
| `stopped` | init (`stop_service`, explicit stop only); prerm (before its locked teardown) | init (`start_service`) | guard (boot-block decision), fw3 include (stop wins over persisted state), init | written before any teardown, so a racing include already sees it | present = administrator wants the network open: no boot block, persisted fw3 state discarded. Absent after a crash, so reloads keep the block |
| `stop-pid` | init (`stop_service`) | init (`service_stopped`) | init | none (init-private) | stale pid is ignored via the `/proc/<pid>/cmdline` check |

The daemon and the include are the two legitimate writers of the fw3
rules/transition files, with disjoint responsibilities: the daemon
owns their content for as long as it lives, the include owns their removal
after an explicit stop. The init script no longer removes them itself; it
writes the marker and runs the include under the lock. `prerm` does the
same and falls back to an inline chain teardown only when the include is
already gone.

## Live firewall objects

| Object | Creates | Removes | Reconciles | Lock |
|---|---|---|---|---|
| `inet nym` (fw4 policy table) | daemon (`nft -f -`, atomic replace) | daemon (reset); init (explicit stop); prerm (removal) | — (fw4 include never touches it) | none needed: single-transaction nft loads; the include only probes existence |
| `inet nym_boot` (fw4 boot block) | fw4 include, from `nym_boot_block_nft` | daemon (last step of apply/reset); fw4 include (conditions no longer hold); init (explicit stop); prerm (removal) | fw4 include re-checks after install and lifts if the daemon's table appeared | none: atomic replace; the stop marker prevents re-arming; the include re-checks after install |
| `NYM_INPUT`, `NYM_OUTPUT`, `NYM_FORWARD` (+ `NYM_MANGLE_*`) and their jumps from `*_rule` | daemon (`iptables-restore --noflush`, jumps inserted at position 1 or ahead of a foreign rule) | daemon (reset); include (no-policy path, stop marker); prerm (inline fallback only) | include after an fw3 restart (restore from `v4.rules`/`v6.rules`), after a reload (re-hook if displaced) | fw3 state lock |
| `NYM_EMERGENCY_OUT`, `NYM_EMERGENCY_FWD` | daemon (transition set, first activation of a family); include (transition set on a stale marker or failed restore; boot set at boot) | daemon (last step of every apply/reset); include (conditions no longer hold, stop marker); prerm (inline fallback only) | include re-checks after installing without a lock | fw3 state lock; the unlocked fallback re-checks and lifts if the daemon hooked a policy meanwhile |
| zone `nym` rules (masquerade, MSS clamp, `lan -> nym` forwarding; fw3 `zone_nym_*` chains, fw4 `inet fw4` zone chains) | fw3/fw4, from the `nym` zone and forwarding sections in `/etc/config/firewall` | fw3/fw4 on the reload after prerm deletes the sections | fw3/fw4 on every reload and restart; the daemon and the includes never touch them | none: fw3/fw4's own transaction |
| fwmark `ip rule`s (0x14d → table 333, 0x14e → main) | daemon | daemon; prerm (removal only — the running daemon owns them across an upgrade) | — | none |

## Configuration and package state

| Artefact | Writer | Remover | Readers | Notes |
|---|---|---|---|---|
| `/etc/config/firewall` `include 'nym_vpn'` | `uci-defaults/luci-app-nym-vpn`, run by postinst and by the boot-time defaults runner; fails loudly so it is retried | prerm (removal only) | fw3/fw4 | left in place across an interrupted upgrade on purpose |
| `/etc/config/firewall` zone `nym_zone` (name `nym`, device `nym+`, `masq`, `masq6`, `mtu_fix`, input/forward REJECT) and forwarding `nym_lan_fwd` (`lan -> nym`) | `uci-defaults/luci-app-nym-vpn`, only when no zone named `nym` / no `lan -> nym` forwarding exists; reloads the firewall when it changed anything | prerm (removal only; only these two section names, an administrator's own `nym` zone stays) | fw3/fw4 (the tunnel plane); `common.rs:wan_zone_devices` skips it despite `masq` | the LuCI firewall page shows it like any zone; a guest zone needs its own `forwarding` to `nym` |
| `/usr/share/nym-vpn/{fw3-include,fw4-include,fw-boot-guard,fw-rules}.sh` | package (build-ipk.sh / build-apk.sh copy the fixed list from the crate and fail without any of them) | package manager | fw3/fw4, init, uci-defaults, prerm | every consumer refuses to run without the two it sources; `fw-rules.sh` is generated, never edit it by hand |
| `/var/run/nym-vpn.rpcd-state` | prerm (upgrade) | postinst (consumed), prerm (removal) | postinst | rpcd refresh decision; root-only parent directory |
| `/var/run/nym-watchdog.state`, `/tmp/nym-watchdog.state` | retired shell watchdog (packages ≤ 1.34.x) | postinst (upgrade), prerm | nobody | legacy; Always On lives in the daemon config now |

## Synchronization, per writer

The rule is the same on every path, normal or failing: **no fw3 mutation
without the fw3 state lock**, and the stop marker is written before the
teardown it authorizes.

| Writer | How it holds the lock | Failure path |
|---|---|---|
| daemon fw3 backend | `flock` on `lock` for the whole apply / forwarding-only / reset; runtime directory verified first | any error returns before the marker is cleared, so the include installs the transition block on its next run |
| fw3 include | `exec 9>lock; flock 9` before `main`; skipped only when the caller exports `NYM_FW_LOCKED=1` (init, prerm) | untrusted directory, no `flock`, or `flock` failure → `run_without_lock`: leave a hooked policy untouched, otherwise install the boot block if wanted, log CRITICAL, exit 1; re-check after installing |
| init `service_stopped` (explicit stop) | writes `stopped` first; takes the lock; runs the include with `NYM_FW_LOCKED=1` | cannot lock → logs and exits; the marker makes the include complete the teardown on its next locked run |
| prerm (removal) | writes `stopped`; takes the lock; runs the include with `NYM_FW_LOCKED=1` | include or guard missing, or the locked run fails → inline teardown of the same chains |
| daemon fw4 backend, fw4 include, init, prerm on fw4 | none | each nft command is one atomic transaction; the include never touches `inet nym`, re-checks after installing `inet nym_boot`, and the stop marker stops it re-arming |

## Transitions at a glance

| Transition | fw3 | fw4 |
|---|---|---|
| boot | include installs the boot set (marker absent, kill-switch on, daemon enabled) → daemon applies its policy → lifts the emergency chains | include installs `inet nym_boot` → daemon applies `inet nym` → deletes `inet nym_boot` |
| daemon crash mid-apply | `transition` stays → include installs the transition set on every reload until the daemon's next successful apply or an explicit stop | policy table stays as it was (single transaction); nothing to do |
| firewall reload | fw3 leaves foreign chains alone and re-renders the `nym` zone; include reconciles (re-hook, lift stale block) | fw4 rebuilds only its own table, the `nym` zone with it; include reconciles the boot block only |
| firewall restart | fw3 flushes everything, rebuilds, runs the include last, which restores from `v4.rules`/`v6.rules`. Known limit: fw3 itself runs with an ACCEPT policy between the flush and the include | `inet nym` survives; same as reload |
| daemon restart, upgrade, shutdown | init takes the keep path: nothing removed, policy stays live; the new daemon replaces it atomically | same |
| explicit stop | marker → include discards persisted state, removes chains, no block | marker → tables deleted |
| removal | prerm stops the daemon (as above), runs the include under the lock once more, removes the runtime directory, the UCI include and the `nym` zone, and reloads the firewall | prerm deletes the tables, the UCI include and the `nym` zone, and reloads the firewall |
