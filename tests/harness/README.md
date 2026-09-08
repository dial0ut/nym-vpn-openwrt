# Proxmox container harness

Runs the OpenWrt package under test in LXC containers on a Proxmox host, one
slot per OpenWrt release, with a LAN client and a DNS logger behind each
router. The containers boot procd, so the package's init script, `enable`,
`start`, `restart` and the upgrade path run exactly as on a router.

## What a run proves

Per slot (`versions.conf`: 23.05.5, 24.10.0, 25.12.4 on x86-64):

| Step / case | Asserts |
|---|---|
| `install` | the package under test installs from a local file (`opkg`, after `opkg update`, or `apk`) and leaves `nym-vpnd`/`nym-vpnc` and the four firewall helpers under `/usr/share/nym-vpn/` behind |
| `daemon-up` | the daemon answers and **procd** lists it as a running instance |
| `account-set` | the mnemonic registers and the account reaches `ReadyToConnect` |
| `10-upgrade` | with a previous artifact configured: upgrade to the package under test through the package manager while the kill-switch table is sampled every second inside the router — it must never disappear; the new daemon runs under procd, the init script logged the restart keep path, the account survived. Without a previous artifact: SKIP with that reason |
| `20-connect-random`, `21-connect-country` | tunnel reaches `Connected` |
| `30-killswitch-disconnected` | kill-switch on: LAN client blocked, router still reaches the API; off: LAN client forwards |
| `32-killswitch-connected` | LAN client's egress differs from the router's real public address (learned with the kill-switch off); a plain DNS query from the router to an outside resolver never leaves on the WAN wire (tcpdump on the router's WAN veth on the host) |
| `33-killswitch-error` | error-state exemptions regression |
| `40-custom-dns` | configured DNS server actually receives the router's queries |

Every selected case ends as exactly one of `PASS`, `FAIL`, `SKIP` (with a
reason) or `MISSING` (selected but recorded nothing). The run exits non-zero
on any `FAIL` or `MISSING`, or when a slot runner exits non-zero. Skips never
make a run green or red on their own; they are listed with their reason.

## Running it

```sh
cp .env.example .env          # fill in NYM_MNEMONIC and PROXMOX_HOST
# packages under test (built by scripts/build-musl.sh + scripts/{ipk,apk}/build-*.sh)
export NYM_PKG_APK=/path/nym-vpn_1.35.0_x86_64.apk       # 25.x slots
export NYM_PKG_IPK=/path/nym-vpn_1.35.0_x86_64.ipk       # older slots
export NYM_PKG_APK_PREV=/path/nym-vpn_1.34.0_x86_64.apk  # enables 10-upgrade
export NYM_PKG_IPK_PREV=/path/nym-vpn_1.34.0_x86_64.ipk
./run.sh                 # all slots, staggered launches, parallel cases
./run.sh --slot 3        # one slot
./run.sh --serial        # one slot at a time
```

Results land in `runs/<timestamp>/`: `report.md`, one `slot-N.results`
(the `STATUS|case|seconds|note` lines) and one `slot-N.log` per slot. The
`runs/` directory and `.env` are gitignored.

Without the `NYM_PKG_*` variables the slots install from the public feed's
install script, which tests whatever is published, not the revision you are
looking at.

### Running on the Proxmox host itself

Every control step is an ssh session to the host, and three slots
provisioning at once are dozens of them a minute. If the operator's link to
the host is not rock solid, copy the harness onto the host and run it there
with `PROXMOX_HOST=local`, which executes `pct` directly:

```sh
tar czf - -C tests harness | ssh proxmox 'mkdir -p /root/nym-harness && tar xzf - -C /root/nym-harness'
scp nym-vpn_*.{apk,ipk} proxmox:/root/nym-harness/artifacts/
ssh proxmox 'cd /root/nym-harness/harness && sed -i "s/^PROXMOX_HOST=.*/PROXMOX_HOST=local/" .env \
  && NYM_PKG_APK=... NYM_PKG_IPK=... nohup ./run.sh > ../run.log 2>&1 &'
```

## Requirements on the Proxmox host

- `ssh $PROXMOX_HOST` as root, key auth (or local mode, above).
- ifupdown2 (`ifup`/`ifdown`), `pct`, `pveam`; the harness creates
  `vmbr-test<N>` bridges and CTs `5<N>0`–`5<N>2` and removes them again.
  Bridges are created and destroyed through ifupdown2 so its state stays
  consistent; deleting one behind its back breaks every later `ifreload`.
- OpenWrt rootfs templates are downloaded into `/var/lib/vz/template/cache`
  on demand from downloads.openwrt.org; an Alpine template is used for the
  client and DNS logger.
- `/dev/net/tun` is bind-mounted into the OpenWrt CT (done by `provision.sh`).
- `tcpdump` on the host: `32-killswitch-connected` watches the router's WAN
  veth for plain DNS.
- The router's WAN is DHCP on `vmbr0` by default. `WAN_CIDR=<ip/prefix>`
  (with `WAN_GW`, default `192.168.1.1`) in the environment gives it a static
  address instead; `provision.sh` refuses an address that already answers
  ping on the host's segment.

## Prerequisites the results depend on

- **An account with an active subscription.** Registration is the first
  thing every slot does after install, exactly as a user would, and every
  tunnel case needs it. With an inactive subscription the API answers
  `Inactive subscription`, `account-set` is a FAIL and the tunnel cases SKIP
  with that state; the install, procd and upgrade cases still run.
- **Fresh-install registration with the default kill-switch.** The daemon's
  idle Blocked policy admits no API hosts until an endpoint cache exists
  (issue #15), so on a brand-new install `account set` cannot reach the API
  while the kill-switch is on. The harness records that as the `account-set`
  failure it is on every release, then retries with the kill-switch off for
  the registration only. Do not read that failure as a harness bug.

## What this harness does not cover

- Real boot ordering of a router (firewall before network before the daemon)
  and reboots: an LXC restart is not a router boot. Use a VM or a device.
- fw3 (iptables) routers: every slot here is fw4. The fw3 test bed is the
  `openwrt-fw3-x86` VM on the same host (see the project notes).
- Packet-level leak evidence and failure injection: apart from the DNS
  probe in `32-killswitch-connected`, the assertions here are reachability
  checks from inside the containers. WAN captures under injected failures
  live in `tests/leak/`, which also has the fw3 bed.
- Other architectures: every slot is x86-64. Release packages for the other
  targets are only build-verified.

## Teardown

`run-slot.sh` tears its slot down on every exit path. If a run is killed hard:

```sh
PROXMOX_HOST=proxmox ./teardown.sh 1   # and 2, 3
```
