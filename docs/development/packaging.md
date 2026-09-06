# Packaging

`.ipk` for OpenWrt ≤24.10 (`opkg`), `.apk` for 25.x+ (`apk`). Both are built from the same payload
by `scripts/ipk/build-ipk.sh` and `scripts/apk/build-apk.sh`.

```bash
./scripts/ipk/build-ipk.sh <version> <openwrt_arch> <binary_dir> [luci_dir] [output_dir]
./scripts/ipk/build-ipk.sh 1.33.1 aarch64_generic ./binaries
```

`luci_dir` defaults to `luci-app-nym-vpn/` in the repo, `output_dir` to the current directory. The
script checks every required file is present, assembles the tree, computes installed size from
`du -sk`, fills in the control template, and emits `nym-vpn_{version}_{arch}.ipk`.

## What's in it

```text
nym-vpn_1.33.1_aarch64_generic.ipk (tar.gz)
├── debian-binary          # "2.0"
├── control.tar.gz
│   ├── control            # generated from control.template
│   ├── conffiles          # /etc/config/nym-vpn
│   ├── postinst
│   └── prerm
└── data.tar.gz
    ├── usr/sbin/nym-vpnd
    ├── usr/sbin/nym-vpn-watchdog
    ├── usr/bin/nym-vpnc
    ├── usr/libexec/rpcd/nym-vpn
    ├── www/luci-static/resources/view/nym-vpn/*.js
    ├── www/luci-static/resources/nym-vpn/*.js
    ├── etc/init.d/nym-vpnd
    ├── etc/init.d/nym-vpn-watchdog
    ├── etc/hotplug.d/iface/90-nym-vpn-watchdog
    ├── etc/config/nym-vpn
    ├── etc/uci-defaults/luci-app-nym-vpn
    ├── etc/nym/data/                       # empty, for daemon state
    ├── usr/share/luci/menu.d/luci-app-nym-vpn.json
    ├── usr/share/rpcd/acl.d/luci-app-nym-vpn.json
    ├── usr/share/nym-vpn/fw3-include.sh
    ├── usr/share/nym-vpn/fw4-include.sh
    ├── usr/share/nym-vpn/fw-backend.sh       # fw3-or-fw4 detector shared by the scripts
    ├── usr/share/nym-vpn/fw-boot-guard.sh    # sourced by both includes, not executable
    ├── etc/opkg/keys/<fingerprint>
    └── etc/apk/keys/dial0ut.pub
```

The opkg key is installed under its **fingerprint**, not its filename — `build-ipk.sh` derives it
by base64-decoding the second line of `scripts/feed/dial0ut.pub` and taking bytes from the header.
usign looks keys up that way.

`etc/uci-defaults/luci-app-nym-vpn` runs once on first boot after install. It is what registers
the firewall include, so the kill-switch survives `fw4 reload`.

`etc/hotplug.d/iface/90-nym-vpn-watchdog` is sourced by netifd's `hotplug-call` on every
interface event. On `ifup`/`ifdown` of a WAN-facing interface it signals the always-on watchdog
(pid from `/var/run/nym-vpn-watchdog.pid`, written by procd) so the tunnel is checked at once
instead of at the next poll tick.

Dependencies come from `scripts/ipk/control.template`, and `build-apk.sh` repeats the same list:

| Package | Why |
|---------|-----|
| `libc` | musl libc |
| `kmod-tun` | TUN device for userspace WireGuard |
| `libmnl` | netlink — the binaries link against it |
| `libnftnl` | nftables netlink — likewise |
| `kmod-ipt-conntrack-extra` | conntrack marking for inbound exemptions on fw3 |
| `luci-base` | LuCI web framework |
| `rpcd` | RPC backend for LuCI |

For apk these go in a **single** `-I "depends:..."` flag. Repeated `-I depends:` flags overwrite
each other rather than accumulating — every `.apk` up to 1.30.5 shipped depending on `rpcd` alone,
so `kmod-tun` was never pulled in and the daemon died at TUN device creation.

## postinst

1. **TUN device** — `mknod /dev/net/tun c 10 200` if it does not already exist
2. **Feed registration** — reads the architecture from `/etc/openwrt_release`, falling back to
   `/etc/os-release` since not every image ships both. Then:
    - apk: removes any stale nym-vpn lines from `/etc/apk/repositories` and
      `/etc/apk/repositories.d/*.list`, then writes `/etc/apk/repositories.d/nym-vpn.list`
    - opkg: appends a `src/gz nym-vpn` line to `/etc/opkg/customfeeds.conf`
3. **Service** — enables and starts `nym-vpnd`. If `nym-vpn.settings.always_on` is already `1`
   (i.e. this is an upgrade), enables and starts `nym-vpn-watchdog` too.
4. **LuCI plumbing** — clears `/tmp/luci-indexcache*` and `/tmp/luci-modulecache/`, then refreshes
   rpcd from a detached job that fires about five seconds *after* the transaction has returned.
   rpcd scans `/usr/libexec/rpcd` only at start-up and computes a session's ACL grants at login,
   so a fresh install restarts it. An upgrade compares the new rpcd plugin and ACL file against
   the checksums prerm stashed in `/tmp/nym-vpn.rpcd-state`: nothing changed → no refresh; only
   the plugin changed → `rpcd reload` (SIGHUP — rpcd re-executes itself and keeps its sessions);
   the ACL file changed, or no stash → `rpcd restart`, which drops the sessions and forces the
   re-login that picks up the new grants. Deferred because LuCI's Software page runs opkg/apk
   *through* rpcd (`file exec`): a restart inside the transaction kills the request the page is
   waiting on (#13). Detached means a subshell with every fd on `/dev/null` — opkg only waits for
   the script's pid, but apk also reads its stdout/stderr pipes to EOF, so an inherited pipe would
   make apk sit out the delay.
5. Prints both upgrade commands, `opkg` and `apk`, without picking between them

## prerm

On an upgrade (`PKG_UPGRADE=1`) prerm first stashes `md5sum`s of the rpcd plugin and the ACL file
in `/tmp/nym-vpn.rpcd-state` for postinst's rpcd decision above. Steps 1–3 then run on **every**
removal including upgrades. The rest is gated on `PKG_UPGRADE != 1`, so an upgrade does not tear
down state the incoming version is about to reuse.

1. **Stop** `nym-vpn-watchdog` and `nym-vpnd`; disable both on real removal only
2. **Firewall cleanup** — the part that matters. fw4: `nft delete table inet nym`, then walk fw4's
   own chains deleting rules tagged `nym-vpn:` by handle. fw3: remove jump rules from the hook
   chains, flush and delete the `NYM_*` chains, delete the NAT POSTROUTING masquerade rules by
   line number. Skip this and an uninstall leaves the kill-switch up with nothing to take it down.
3. **Stray routing rules** — flush any `ip rule` entries matching the daemon's fwmarks, v4 and v6.
   The daemon normally clears these itself on stop; a crashed one does not. Matching on fwmark
   rather than priority avoids touching unrelated rules.
4. **UCI** — delete the `firewall.nym_vpn` include and commit
5. **Temp files** — the saved firewall rulesets, the adblock dnsmasq drop-in, DNS backups, the
   watchdog state file

Then, full removal only:

6. **DNS** — revert `dhcp.@dnsmasq[0].resolvfile` to stock, remove the managed resolv file, and
   restart dnsmasq *only* if the running instance still points at the file just deleted. On
   upgrade none of this happens: the new daemon reconverges without a restart, and restarting
   dnsmasq here would be a LAN-wide DNS outage for no reason.
7. **Data** — `rm -rf /etc/nym` and `/var/log/nym-vpnd`
8. **Feed** — strip nym-vpn lines from `customfeeds.conf`, remove
   `/etc/apk/repositories.d/nym-vpn.list`

## apk hook mapping

apk does not run `post-install`/`pre-deinstall` on an upgrade; it runs `pre-upgrade`/`post-upgrade`
instead, always from the *incoming* package. `build-apk.sh` registers postinst as both
`post-install` and `post-upgrade`, prerm as `pre-deinstall`, and a copy of prerm with
`PKG_UPGRADE=1` exported as `pre-upgrade` — apk never sets that variable itself. One visible
consequence: on the first upgrade to a package that stashes the rpcd checksums, apk runs the new
prerm (stash present, checksums compared) while opkg runs the old one (no stash, rpcd restart).

## conffiles

`/etc/config/nym-vpn` is marked as a config file, so an upgrade keeps your version and writes new
defaults to `.new` alongside it.

The shipped default:

```text
config nym-vpn 'settings'
    option enabled '0'
    option network 'mainnet'
    option always_on '0'
    option watchdog_interval '30'
    option watchdog_max_retries '3'
```

Disabled on install — you enable it from LuCI or the CLI.
