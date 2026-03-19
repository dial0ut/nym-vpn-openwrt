# Firewall Backends

## Overview

NymVPN automatically manages firewall rules to route LAN traffic through the VPN tunnels and prevent DNS leaks. It supports both OpenWrt firewall frameworks.

**Location:** `nym-vpn-core/crates/nym-firewall/src/openwrt/`

| File | Purpose |
|------|---------|
| `mod.rs` | Public API, unified dispatcher |
| `detect.rs` | fw3 vs fw4 detection (checks `/sbin/fw4`, cached) |
| `common.rs` | Shared constants (chain names, LAN networks) |
| `fw3.rs` | iptables backend (OpenWrt 18.06–21.02) |
| `fw4.rs` | nftables backend (OpenWrt 22.03+) |

## Detection

The firewall backend is auto-detected at runtime:

- If `/sbin/fw4` exists → nftables (fw4)
- Otherwise → iptables (fw3)

The result is cached with `OnceLock` so detection runs only once.

## API

Both backends implement:

- `apply_policy()` — install firewall rules for VPN routing
- `reset_policy()` — remove all NymVPN firewall rules
- `install_include_scripts()` — persist rules across firewall restarts

## Kill-Switch Rule Ordering

Rule ordering is critical for correct DNS handling. Rules are applied in this order:

```
1. ct state established,related accept
2. Allow DNS to VPN's DNS servers
3. Allow traffic TO tunnel interface      ← BEFORE DNS block
4. Allow traffic FROM tunnel interface    ← BEFORE DNS block
5. Block DNS port 53 (reject)            ← Catches leaks only
6. Allow LAN traffic (RFC1918)
7. Final reject (catch-all)
```

!!! warning "Critical"
    Tunnel interface rules MUST come before the DNS block. Otherwise, LAN clients' DNS queries routed through the VPN tunnel get incorrectly rejected by rule 5.

## fw3 (iptables)

- Integrates with fw3's `input_rule`, `output_rule`, and `forwarding_rule` chains
- Uses `iptables-restore` for atomic rule application
- Adds masquerade rules in the NAT table

## fw4 (nftables)

- Creates a separate `inet nym` table at priority `filter - 10`
- Integrates with fw4's `srcnat` and `forward_lan` chains
- Uses `nft -f` for atomic rule application

## Known Issues

On very old kernels (4.14.90), the nftables netlink API may be broken, and iptables can have xtables lock contention with fw3. See `PROBLEM.md` for details.
