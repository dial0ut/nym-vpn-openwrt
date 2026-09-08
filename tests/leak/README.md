# Packet-level kill-switch evidence suite

Proves what the kill-switch does under failure with a WAN capture, not with a
grep of the rules, and whether the router stays manageable and recovers. Runs
from a dev machine against one of two Proxmox beds:

| Bed (`BED=`) | Router | Control path | LAN client | Capture |
|---|---|---|---|---|
| `fw3-vm` (default) | OpenWrt 21.02 fw3/iptables VM | ssh to the WAN address | Alpine LXC behind it | the VM's tap on the host |
| `fw4-ct` | OpenWrt 25.x fw4/nftables LXC | `pct exec` from the host (survives a WAN outage) | Alpine LXC behind it | the CT's veth on the host |

`beds/<bed>.env` holds every host-specific value (VM/CT ids, host interface,
addresses, ssh target and options, package paths) as a default; set the same
`LEAK_*` variable in the environment to override one without editing the
file. The real egress address (what a leak shows) is learned from the
hypervisor at start unless `LEAK_REAL_PUBLIC_IP` is set.

```
BED=fw3-vm tests/leak/run.sh                    # every scenario
BED=fw4-ct tests/leak/run.sh 01-control 13-crash-loop
KEEP_BED=1 tests/leak/run.sh ...                # leave the VM/CTs running
```

## What the runner does per scenario

WAN capture on the host (`cap_start` checks with `pgrep` that tcpdump is
running), a 1 s LAN probe loop (HTTPS to a pinned address so a SYN is
attempted even with DNS blocked, DNS through the router, DNS straight to the
upstream resolver), a 1 s router state watcher (policy hooked, boot block,
stop and transition markers, daemon pid, kill-switch setting, tunnel state),
an ssh session held open over the WAN address plus a wired TCP-connect loop
to the router's ssh port from the hypervisor, then the injection, the
scenario's own checks (recovery clock, one-shot probes, LuCI TCP connect), and
the pcap analysis.

## Scenarios

| Scenario | Bed | Injection | Gate |
|---|---|---|---|
| `01-control` | any | `nym-vpnd stop` | positive control: a leak MUST be visible or every later verdict is INCONCLUSIVE |
| `02-kill-mid-transition` | any | SIGKILL while Connecting | respawned with policy hooked |
| `03-kill-connected` | any | SIGKILL while Connected | respawned with policy hooked |
| `04-restore-fails` | fw3 | `iptables-restore` exits 1 on a policy change | previous rules kept; re-applied after restore |
| `05-lock-lost` | fw3 | `flock` hidden, firewall reload | CRITICAL logged, policy untouched |
| `06a`–`06d` | any | firewall reload/restart, connected/disconnected | policy hooked afterwards |
| `07-ipv6` | any | v6 probes | SKIP without a global v6 address |
| `08-interrupted-upgrade` | opkg | opkg SIGKILLed as postinst starts | old daemon kept its policy; re-install completes |
| `09-boot` | VM | reboot | policy hooked after boot; SKIP on an LXC |
| `11-corrupt-config` | any | invalid JSON, restart | defaults with kill-switch on, `.json.bak` kept, connected on request; management kept |
| `12-binary-unusable` | any | `chmod 000`, restart, reload | block held without a daemon; restore + start recovers; management kept |
| `12b-binary-unusable-stop-opens` | any | then `nym-vpnd stop` | expected open (the escape hatch works without the binary); start re-arms |
| `13-crash-loop` | any | binary exits 1, 60 s | block held; real binary restarts; management kept |
| `14-lock-and-reload-race` | fw4 | fw3 lock held; 12 reloads during connect | policy changes not blocked; `policy=yes boot=no`, Connected |
| `15-untrusted-runtime-dir` | any | dir mode 0755, stop, reload | no marker, boot block installed; `chmod 0700` + start recovers |
| `16a-killswitch-off-reload` | any | disconnected, kill-switch off, reload | expected open, stays open across the reload |
| `16b-killswitch-on-reload` | any | off then on before capture, reload | re-armed, stays armed |
| `17-wan-flap` | any | host-side WAN link down 15 s | no leak, reconnects after link up |
| `18-upgrade-interrupted-apk` | apk | apk SIGKILLed in post-upgrade | policy never left; re-running `apk add` completes |

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | no leak signal, the scenario's gate held, the capture was live and trusted |
| `FAIL` | a leak signal fired (SYN from the router's WAN address to the probe target, plain DNS to the upstream resolver, or a LAN probe answered on the real egress address), the scenario reported `not_recovered`, or management access was lost in a scenario that gates on it; for `01-control`, `12b` and `16a` (expected open): nothing fired |
| `INCONCLUSIVE` | the evidence cannot be trusted: tcpdump not running, an empty capture, no tunnel packets to the entry gateway in a connected scenario, no positive control yet, a connected scenario that was not Connected before the injection, or a probe that failed for a reason other than being blocked |
| `SKIP` | the bed cannot exercise the scenario; the reason is printed |

The LAN probe classifies from curl's exit code: 7/28 = `blocked`, 6 =
`dns-blocked`, 0 with an address = `LEAK:<ip>` on the real egress address or
`egress:<ip>` otherwise; anything else is `probe-failed` and never counts as
blocked. Every verdict line carries `total=` (packets in the capture) and
`capture=live|dead(...)`. Packets to destinations that are not the tunnel
gateways, the daemon's own hatches, the operator's ssh or DHCP/NTP/DoT are
listed as unattributed on every verdict and never silently accepted. The run
exits non-zero on any `FAIL` or `INCONCLUSIVE`.

Results land in `results/<timestamp>/` (gitignored): one `.pcap`, `.log`,
`.probe` and `.verdict` per scenario plus `verdicts.txt`. `LEAK_RESULTS_DIR`
resumes into an earlier directory and `LEAK_CONTROL_OK=1` trusts a positive
control recorded there. The recorded runs are in `docs/evidence/`.
