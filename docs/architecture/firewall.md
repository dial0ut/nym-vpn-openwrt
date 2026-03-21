# Firewall Integration

## Supporting the Entire OpenWrt Ecosystem

OpenWrt migrated from iptables to nftables in version 22.03. Devices running older firmware use fw3, the iptables-based firewall framework. Devices on current firmware use fw4, which wraps nftables. Both frameworks are actively deployed across the router ecosystem.

NymVPN supports both backends rather than requiring a minimum OpenWrt version. This was a deliberate choice to maximize device coverage. Many routers run stable older firmware that their owners have no reason to upgrade, and forcing a firmware upgrade as a prerequisite for a VPN package would exclude a significant portion of the target audience.

## Kill-Switch Design

A single binary runs across OpenWrt versions, so the firewall backend is detected at startup: a three-step probe (binary exists, tool works, framework active) checks for fw4 first, then fw3. Both backends apply rules atomically (fw3 via `iptables-restore --noflush -w`, fw4 via `nft -f`) to avoid xtables lock contention with mwan3 and to prevent windows where the ruleset is only partially applied.

### Rule Ordering and DNS

The kill-switch must allow VPN tunnel traffic while blocking DNS leaks. The critical constraint is that tunnel interface rules must appear before the DNS port 53 reject rule.

```text
1. ct state established,related accept
2. Allow DNS to VPN's DNS servers
3. Allow traffic TO tunnel interface
4. Allow traffic FROM tunnel interface
5. Block DNS port 53 (reject)
6. Allow LAN traffic (RFC1918)
7. Final reject (catch-all)
```

> **Warning:** If rules 3 and 4 come after rule 5, DNS fails silently for all LAN clients. From the router's perspective, a DNS query from a LAN client routed through the VPN tunnel arrives on the tunnel interface destined for port 53. A blanket DNS reject at rule 5 catches it before the tunnel allow rule has a chance to pass it through.

The correct ordering allows tunnel traffic first, then blocks only non-tunnel DNS. This ensures LAN clients' DNS queries travel through the VPN while preventing any DNS from leaking to non-VPN destinations.

### Deferred Application During Connection

During the initial `Connecting` state, gateway endpoints are not yet resolved. Applying the kill-switch at this point would block all outbound traffic, including the connection setup itself. The daemon would be unable to reach the gateways it needs to establish the tunnel.

The firewall skips rule installation until peer endpoints are known. Once the connection is established and the daemon has real gateway addresses, the full kill-switch is applied.

## Surviving Firewall Reloads

OpenWrt rebuilds all firewall rules from scratch on every reload event. Reloads happen frequently: network reconfiguration, DHCP changes, dnsmasq restarts, and manual `fw3 reload` or `fw4 reload` commands all trigger a full rebuild.

Without special handling, the kill-switch rules would be wiped on any of these events. Both backends install UCI include scripts that OpenWrt's firewall framework calls during its reload cycle. fw3 uses a UCI section with `type=include` and `reload=1`, which tells fw3 to execute the script on every reload. fw4 uses `fw4_compatible=1` for the same purpose.

This is the standard OpenWrt mechanism for third-party firewall integration. The scripts re-apply the saved rules from temporary files, so the kill-switch is restored automatically after every firewall reload.

## mwan3 Compatibility

mwan3 is an OpenWrt package for multi-WAN load balancing and failover. It continuously pings tracking IPs to determine whether each WAN interface is alive. Several supported devices, particularly GL.iNet routers, ship with mwan3 pre-installed and enabled even on single-WAN configurations.

The kill-switch blocks all traffic that does not go through the VPN tunnel. Without an exception, it would block mwan3's health-check pings. mwan3 would then declare the WAN interface down and trigger a failover cascade, even though the WAN is working fine.

The firewall reads mwan3's tracking IPs from UCI configuration at rule-build time and adds explicit ICMP allow rules for those addresses. If mwan3 is not installed, no tracking IPs are found and no extra rules are added. This makes the compatibility a no-op on devices without mwan3.

