# Firewall Backends

## Overview

NymVPN automatically manages firewall rules to route LAN traffic through the VPN tunnels and prevent DNS leaks. It supports both OpenWrt firewall frameworks.

**Location:** `nym-vpn-core/crates/nym-firewall/src/openwrt/`

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 120 | Public API and unified dispatcher |
| `detect.rs` | 139 | fw3 vs fw4 detection with `OnceLock` caching |
| `common.rs` | 114 | Shared constants, IPv6 detection, mwan3 integration |
| `fw3.rs` | 792 | iptables backend for OpenWrt 18.06-21.02 |
| `fw4.rs` | 607 | nftables backend for OpenWrt 22.03+ |

## Public API

Both backends implement the same interface through enum dispatch:

```rust
pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()>
pub fn reset_policy(&mut self) -> Result<()>
pub fn install_include_scripts() -> Result<()>
```

The `fwmark` parameter accepted by `new()` is unused on OpenWrt routers. It exists for API compatibility with other platforms.

When `apply_policy()` is called during the `Connecting` state with no peer endpoints, the firewall skips rule installation to avoid triggering mwan3 WAN-down cascades.

## Detection

The firewall backend is auto-detected at runtime and cached with `OnceLock` so detection runs only once per process.

**fw4 detection (checked first):**

1. `/sbin/fw4` or `/usr/sbin/fw4` exists
2. `nft --version` succeeds
3. `nft list table inet fw4` confirms fw4 is active

**fw3 detection (fallback):**

1. `/sbin/fw3` or `/usr/sbin/fw3` exists
2. `iptables --version` succeeds
3. `iptables -L input_rule -n` confirms fw3's hook chain exists

Falls back to `Unknown` if neither is found. OpenWrt version is parsed from `/etc/openwrt_release`.

## Kill-Switch Rule Ordering

Rule ordering is critical for correct DNS handling. Rules are applied in this order:

```text
1. ct state established,related accept
2. Allow DNS to VPN's DNS servers
3. Allow traffic TO tunnel interface      <-- BEFORE DNS block
4. Allow traffic FROM tunnel interface    <-- BEFORE DNS block
5. Block DNS port 53 (reject)            <-- Catches leaks only
6. Allow LAN traffic (RFC1918)
7. Final reject (catch-all)
```

!!! warning "Critical"
    Tunnel interface rules MUST come before the DNS block. Otherwise, LAN clients' DNS queries routed through the VPN tunnel get incorrectly rejected by rule 5.

## Base Rules

Both backends share the same base rule set applied before policy-specific rules:

- Accept loopback traffic
- Accept established/related connections
- Accept DHCP (ports 67/68 bidirectional)
- Accept DHCPv6 (ports 546/547 bidirectional, when IPv6 enabled)
- Accept ICMPv6 Neighbor Discovery (router-advert, neighbor-solicit, neighbor-advert)
- Allow mwan3 tracking pings to avoid false WAN-down detection

### LAN Networks

Traffic to RFC1918 private ranges is allowed when LAN policy permits:

- IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- IPv6: `fe80::/10`, `fc00::/7`

### IPv6 Support

IPv6 rules are only installed when `/proc/sys/net/ipv6/conf/all/disable_ipv6` is `0` and `ip6tables` is available.

### mwan3 Compatibility

The firewall reads mwan3 tracking IPs from UCI (`mwan3.*.track_ip`) and adds explicit allow rules for ICMP to those addresses. This prevents the kill-switch from blocking mwan3's health-check pings, which would cause it to mark WAN interfaces as down.

## fw3 (iptables)

Creates three custom chains: `NYM_INPUT`, `NYM_OUTPUT`, `NYM_FORWARD`.

**Rule application:**

- Builds rules in `iptables-restore` format and writes to `/tmp/nym-firewall-v4.rules`
- Applies atomically with `iptables-restore --noflush -w` (preserves existing rules, waits for xtables lock)
- Inserts jump rules into fw3's hook chains: `input_rule`, `output_rule`, `forwarding_rule`
- Adds masquerade rules in the NAT table for tunnel interfaces via individual `iptables -t nat` commands
- When IPv6 is enabled, repeats the process with `ip6tables-restore` using `/tmp/nym-firewall-v6.rules`

**Rule cleanup:**

- Scans POSTROUTING with `--line-numbers` and deletes masquerade rules in reverse order
- Flushes and removes custom chains
- Removes temporary rules files

**Firewall persistence:**

- Installs a UCI include script at `/usr/share/nym-vpn/fw3-include.sh`
- Adds a `firewall.nym_vpn` UCI section with `type=include`, `reload=1`, `enabled=1`
- Rules survive `fw3 reload` via the include mechanism

## fw4 (nftables)

Creates a separate `inet nym` table at priority `filter - 10`, running before fw4's default priority of 0.

**Rule application:**

- Builds a complete nftables script and writes to `/tmp/nym-firewall.nft`
- Applies atomically with `nft -f /tmp/nym-firewall.nft`
- Creates three chains: `input`, `output`, `forward` (all at priority -10)
- Integrates with fw4's `srcnat` and `forward_lan` chains for masquerade and forwarding

**Rule cleanup:**

- Removes fw4 integration rules
- Deletes the entire `inet nym` table with `nft delete table inet nym`
- Removes the temporary rules file

**Firewall persistence:**

- Installs a UCI include script at `/usr/share/nym-vpn/fw4-include.sh`
- Adds a `firewall.nym_vpn` UCI section with `fw4_compatible=1`, `enabled=1`

## Known Issues

On very old kernels (4.14.90), the nftables netlink API may be broken, and iptables can have xtables lock contention with fw3. See `PROBLEM.md` for details.
