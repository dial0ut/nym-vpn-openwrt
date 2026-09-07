# Packet-level kill-switch failure-injection suite

Proves what the kill-switch does under failure with a WAN capture, not with a
grep of the rules. Runs from a dev machine against the fw3 test bed:

| Role | Where | Default |
|---|---|---|
| Capture point | Proxmox host, the router VM's WAN tap | `ssh proxmox`, `tap902i1` |
| Router under test | OpenWrt 21.02 fw3 VM | `ssh -i ~/.ssh/id_ed25519 root@192.168.1.180`, VM 902 |
| LAN client | Alpine LXC behind the router | CT 903, 10.30.30.50 |

Every default is an environment variable in `lib.sh` (`LEAK_*`), so another
bed can be substituted without editing scripts.

```
tests/leak/run.sh                      # every scenario
tests/leak/run.sh 01-control 05-lock-lost
KEEP_BED=1 tests/leak/run.sh ...       # leave the VM and container running
```

Per scenario the runner starts a WAN capture, a LAN probe loop (HTTPS to a
pinned address so a SYN is attempted even with DNS blocked, DNS through the
router, DNS straight to the upstream resolver) and a 1 s router state watcher
(policy hooked, emergency chains, transition and stop markers, daemon pid,
`nym-vpnc status`), injects the failure, runs the scenario's own checks
(including recovery), then analyses the pcap.

**Leak signals** are SYNs from the router's WAN address to the probe target
and plain DNS from the router to the upstream resolver. **Unattributed**
packets (not WireGuard to the current gateways, not the daemon's own hatches,
not the operator's ssh, not DHCP/NTP/DoT) are listed on every verdict and never
silently accepted. The **positive control** (`01-control`, an explicit
`nym-vpnd stop`) must show a leak; if it does not, every later verdict is
`INCONCLUSIVE` because the capture cannot be trusted. Scenarios the bed cannot
exercise report `SKIP` with the reason, never `PASS`.

Results land in `results/<timestamp>/`: one `.pcap`, `.log` and `.verdict`
per scenario plus `verdicts.txt`. Captures and logs are gitignored; verdicts
are kept. The scenario `08-interrupted-upgrade` needs a package with a higher
version than the installed one at `/tmp/nym-vpn_1.34.0_p13_x86_64.ipk` on the
router (`scripts/ipk/build-ipk.sh 1.34.0_p13 x86_64 <bindir> luci-app-nym-vpn out`).

See `REPORT.md` for the last recorded run.
