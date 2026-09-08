> The scripts that produced this run now live in `tests/leak/` (bed `fw4-ct`, scenarios `11`–`18`); `tests/recovery/` is gone. Content below is unchanged.

# Recovery and management-access evidence, fw4 bed

Date: 2026-09-07. Bed: `openwrt25` = Proxmox LXC CT 425, OpenWrt 25.12.4 x86_64,
fw4/nftables, WAN `eth0` 192.168.1.252 behind an upstream router at 192.168.1.1,
LAN 10.10.10.1/24. Package under test: nym-vpn 1.34.0_p12 built from develop
f82ea1871 (the interrupted-upgrade scenario moves the box to p13/p14 test
builds of the same tree). Kill-switch on, account registered, watchdog running.

Question answered here: when something goes wrong, does the router **stay
protected**, does it **stay manageable**, and does it **recover**? A router
that is blocked forever is a failure, not a pass.

## Method

`run.sh` (with `lib.sh`, `scenarios.sh`) drives each scenario from a dev
machine and records, per scenario:

- a WAN capture on the hypervisor's `veth425i0`, the router's WAN side;
- LAN client probes from `ubuntu-vm` (10.10.10.178): egress IP over HTTPS and
  DNS through the router. `blocked` = no answer, `vpn:<ip>` = an exit
  gateway, `LEAK:<ip>` = the ISP address 203.0.113.1;
- router-originated HTTPS egress;
- management access: an ssh session held open over the WAN address for the
  whole scenario, a TCP connect to LuCI (10.10.10.1:80) from the LAN client,
  TCP connects to 192.168.1.252:22 and :80 from the dev machine, and a wired
  `nc -z :22` loop from the hypervisor as a second vantage;
- a recovery clock: seconds from the injected failure to "the daemon's policy
  is back" and to "service usable".

Evidence lines are in `results/<scenario>.log`, one-line verdicts in
`results/verdicts.log`. Captures stay on the hypervisor under
`/tmp/recovery-caps/` (gitignored here). `host-s8.sh` is scenario 8 rewritten
to run on the hypervisor via `pct exec`, used because the dev machine's path
to the segment was too unreliable to trust for that run.

## Verdicts

| # | Scenario | Protection | Management | Recovery | Verdict |
|---|---|---|---|---|---|
| 1 | Corrupt daemon config (`{ this is not json`), restart | Daemon started on defaults, kill-switch **on**, Blocked policy applied; bad file preserved as `nym-vpnd.json.bak` | ssh held, LuCI LAN ok | policy back 1 s after restart, connected 14 s after injection | PASS |
| 2 | Daemon binary unusable (`chmod 000`), restart, firewall reload | Stale Blocked policy kept by the include (`inet nym` present, no daemon) through the reload; LAN blocked | ssh held, LuCI LAN ok, WAN:22 ok | `/etc/init.d/nym-vpnd stop` opened the router as documented (LAN egress on the ISP address); restore + start: protection back in 1 s | PASS |
| 3 | Crash loop (binary exits 1), 60 s | Policy held for the whole minute; LAN blocked every probe | ssh held 81 s, LuCI ok | restart with the real binary: 0 s | PASS. `respawn 3600 5 0`: retry 0, procd never gives up; CLAUDE.md's "5 max" is stale |
| 4 | fw3 lock held by a foreign process during policy changes; then 12 `fw4 reload`s during a connect | fw4 ignores the fw3 lock: 4 policy applies in 6 s with the lock held 60 s; after the reload storm `policy=yes boot=no`, no leak | ssh held | connected 0 s after the storm | PASS |
| 5 | Runtime dir `chmod 0755`, stop, reload, restore | stop wrote **no** marker ("not a private root-owned directory"), reload installed the boot block with the reason logged, LAN blocked | ssh held, LuCI LAN ok | `chmod 0700` + start: policy back in 1 s | PASS, caveat: while the dir is untrusted `stop` cannot open the router; the fix is the mode and the log says so |
| 6 | Disconnected: kill-switch off + reload, then on + reload | off: no policy, no boot block, LAN egress on the ISP address and DNS to 8.8.8.8 (intended), stayed open across a reload; on: Blocked re-armed, stayed armed across a reload, LAN blocked | ssh held | n/a | PASS |
| 7 | WAN link down 15 s while connected | no upstream DNS, no probe-target packets in the capture; LAN blocked while down | held session dropped while the link itself was down (expected); LuCI LAN ok after | reconnected 8 s after link up | PASS |
| 8a | `kill -9 apk` during upgrade, landed during unpack (before post-upgrade) | policy and daemon untouched, no leak | ssh held | package db still p12; re-running `apk add` installed p13 cleanly | PASS |
| 8b | `kill -9 apk` during the post-upgrade step (our postinst), driven from the hypervisor | apk killed while `/etc/init.d/nym-vpnd restart` was running; policy table never left, new daemon came up Blocked (LAN probe `blocked`, no leak), package db still recorded the old version | wired ssh ok 36/36 (host run), held session survived 22/22 (jump run), LuCI LAN ok | re-running `apk add` completed the upgrade; daemon with policy 1 s later, connected on request | PASS (two runs: `s8b-host-postupgrade.log` from the hypervisor, `s8-upgrade-interrupted.log` with ubuntu-vm as LAN client) |

Positive controls: scenario 2's escape hatch and scenario 6's kill-switch-off
step both produced `LEAK:203.0.113.1` on the LAN probe and the probe
target / upstream DNS in the capture, so the probes and the capture do detect
an open firewall.

## Management access, summarised

In every scenario where the WAN link itself was up, a WAN ssh session held
open before the failure survived it, LuCI on the LAN address accepted TCP
connections, and new ssh over the WAN address connected. WAN port 80 is not
open in this box's zone config, so `wan:80=no` throughout is the firewall
config, not a nym effect. The boot-time block and the Blocked policy leave
INPUT to fw4's rules and accept established/related replies, which is what
keeps existing sessions alive.

## Product findings

- No leak and no permanent blackhole in any scenario. Every blocked state had
  a documented, working way out: `stop` (2), restoring the file or mode (1,
  5), or the daemon coming back on its own (3, 7, 8).
- Scenario 5 caveat belongs in the troubleshooting docs: with the runtime
  directory untrusted, `stop` does not open the router; `logread` names the
  directory and the reason.
- `luci-app-nym-vpn/root/etc/init.d/nym-vpnd` respawn parameters are
  `3600 5 0`; retry 0 means procd respawns forever. CLAUDE.md still says "5
  max". Behaviourally the safer choice, since the block never lapses because a
  supervisor gave up; the doc should match.
- No product bug found in the failure paths exercised here.

## Environment notes (why some runs were repeated)

The dev machine reaches the 192.168.1.0/24 segment over Wi-Fi provided by the
upstream router at 192.168.1.1. That router was rebooted by its owner during
the session and the path flapped several more times afterwards. Any attempt
whose log shows only the dev-machine vantage dropping was re-run and its
verdict discarded rather than recorded; `results/setup.log` notes the window.
The wired vantage, `SSH_JUMP=<hypervisor>` in `lib.sh`, and `host-s8.sh` were
added so the suite does not depend on that path. `ping` to the router's WAN
address is dropped by policy and is not a reachability signal; the suite uses
TCP connects to :22.
