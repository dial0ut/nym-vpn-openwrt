# Inbound Services

Expose port-forwarded services (LuCI on the router, SSH, a self-hosted website, a docker on the LAN) to the WAN while the NymVPN kill-switch is on.

## Why this exists

When the kill-switch is on, every outbound packet that isn't explicitly allowed is sent through the VPN tunnel. That includes the **reply** to any inbound connection — so a port-forwarded service on the router or behind it will:

1. Accept the inbound SYN on the WAN
2. Try to reply
3. Send the reply through the VPN tunnel
4. Hit the wrong source IP at the egress, and the client connection dies

Inbound exemptions short-circuit that. For ports you declare here, replies are routed via the **real WAN** instead of the tunnel.

## How it works

For each `{proto, port}` you declare:

- A `mangle` rule marks the inbound connection's `conntrack` mark on the WAN interface, **before DNAT runs**, so the original public port is what matches.
- The mark is restored onto the reply packet's mark via `meta mark set ct mark`.
- A routing rule at priority 90 — `ip rule fwmark 0x14e lookup main` — sends marked replies via the main routing table (real WAN) instead of the tunnel routing table.
- The kill-switch's filter chains get a `meta mark 0x14e accept` so the reject-all rule doesn't fire on the marked reply.

The exemption only adds a reply path. It does not weaken outbound enforcement: the daemon's own outbound traffic is unaffected, and a compromised exempt service cannot exfiltrate through the exempt port because the mark is only set on `iif=wan ct state new` — not on connections the router itself initiates.

## When you need a port forward

NymVPN's inbound exemption only handles the **reply routing**. It does **not** set up the DNAT that delivers an inbound connection to a host on your LAN. Use OpenWrt's native firewall UI for that.

| Service location | Port forward needed? | Where to set it up |
|------------------|----------------------|--------------------|
| On the router itself (LuCI, SSH, WireGuard listener on the router) | No | — |
| On a LAN host (Jellyfin on a NAS, docker on a server, etc.) | Yes | `Network → Firewall → Port Forwards` in LuCI |

**For LAN-hosted services, set up the port forward first.** Then add the exemption with the WAN-side port. The exemption matches by `(proto, WAN-port)` before DNAT rewrites the destination — so the LAN target IP doesn't need to be declared on the NymVPN side.

## CLI

```bash
# List configured exemptions
nym-vpnc inbound list

# Add an exemption with optional label
nym-vpnc inbound add tcp:443 --label "HTTPS reverse proxy"
nym-vpnc inbound add tcp:22222
nym-vpnc inbound add udp:51820 --label "WireGuard"

# Remove an exemption
nym-vpnc inbound del tcp:443

# Tunnel summary now shows the exemption list too
nym-vpnc tunnel get
# … Inbound exemptions: tcp/443, tcp/22222, udp/51820 …
```

Add and delete persist to `/etc/nym/nym-vpnd.json` and survive daemon restart. Changes apply on the next state transition; while the VPN is connected, the daemon debounces tunnel-settings updates by ~1s and then triggers a reconnect to re-apply the firewall and routing rules.

## LuCI

The **Inbound Services** card sits between `Tunnel Settings` and `DNS & Ad Blocking`.

- Pick `TCP` or `UDP`, type the port, optionally a label, press **Save** (or `Enter`).
- Rows show proto / port / label / status (`● Active` when kill-switch is on, `● Inert` when off) with a `×` to delete.
- If the kill-switch is off, a warning banner explains that exemptions are inert — exemptions only matter when the tunnel default route is enforcing.

## Recipes

### Expose LuCI to the WAN

The router's web UI listens on `:443`.

```bash
# 1. Allow WAN input to TCP/443 in OpenWrt firewall
uci set firewall.luci_wan=rule
uci set firewall.luci_wan.name='Allow-LuCI-WAN'
uci set firewall.luci_wan.src='wan'
uci set firewall.luci_wan.proto='tcp'
uci set firewall.luci_wan.dest_port='443'
uci set firewall.luci_wan.target='ACCEPT'
uci commit firewall
fw4 reload

# 2. Allow LuCI to accept RFC1918-source requests (only needed if the
#    test client is on a private network)
uci set uhttpd.main.rfc1918_filter='0'
uci commit uhttpd
/etc/init.d/uhttpd restart

# 3. Add the NymVPN exemption
nym-vpnc inbound add tcp:443 --label "LuCI"
```

### Expose a LAN service (e.g. Jellyfin at 192.168.1.50:8096)

```bash
# 1. Create the port forward in OpenWrt — public:8096 → 192.168.1.50:8096
uci add firewall redirect
uci set firewall.@redirect[-1].name='Jellyfin'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].src_dport='8096'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.1.50'
uci set firewall.@redirect[-1].dest_port='8096'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].target='DNAT'
uci commit firewall
fw4 reload

# 2. Add the exemption for the WAN-side port (same number here)
nym-vpnc inbound add tcp:8096 --label "Jellyfin"
```

The exemption uses the **public** port (`src_dport`), not the internal one — even if the port forward remaps them.

### Remap example (`WAN:8443 → LAN:443`)

```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='HomeAssistant'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].src_dport='8443'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.1.20'
uci set firewall.@redirect[-1].dest_port='443'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].target='DNAT'
uci commit firewall
fw4 reload

# Use the WAN port (8443), not the LAN port (443)
nym-vpnc inbound add tcp:8443 --label "Home Assistant"
```

## Verification

```bash
# Mark-set rule in mangle PREROUTING (only present in Connecting/Connected)
nft list table inet nym | grep -A4 'chain mangle_prerouting'

# Mark restore in mangle output
nft list table inet nym | grep -A2 'chain mangle_output'

# Filter accepts for the exempt mark
nft list table inet nym | grep 'meta mark 0x'

# The fwmark routing rule at priority 90
ip rule | grep 0x14e
# 90: from all fwmark 0x14e lookup main
```

On `fw3`/iptables routers the equivalent is:

```bash
iptables -t mangle -L NYM_MANGLE_PREROUTING -v -n
iptables -t mangle -L NYM_MANGLE_OUTPUT -v -n
iptables -L NYM_OUTPUT -v -n | grep '0x14e'
```

## Caveats

- **Single WAN only in v1.** If `mwan3` reports more than one enabled WAN, the daemon logs a warning and the exemption may apply to the wrong egress.
- **PPPoE / tunnelled WANs are handled.** The exemption anchors its `iif` match to the WAN's real L3 device (e.g. `pppoe-wan`), resolved from `ubus call network.interface.wan status`, not the underlying ethernet. Confirm with the `mangle_prerouting` command under [Verification](#verification) that the `iifname` matches `ip route get 1.1.1.1`'s device.
- **Kernel module `kmod-ipt-conntrack-extra`.** The IPK declares this as a hard dependency on `fw3` builds; if you've manually stripped it, exemption rule application will fail at `iptables-restore` time with a clear error.
- **Hot-apply takes ~1s.** When you `add` or `del` while connected, the daemon debounces the tunnel-settings update by ~1s and then reconnects to re-apply the firewall/routing — connections may briefly drop. Existing in-flight flows keep their original routing (no retroactive marking).
- **Exemption is not a port forward.** If you `add tcp:8096` without an OpenWrt port forward for `8096`, nothing forwards traffic to your LAN host — the exemption only fixes the reply path.

## See also

- [Split Tunneling with PBR](split-tunneling.md) — for *outbound* exclusions (route specific clients/destinations around the VPN). Inbound exemption and PBR can coexist; both use the daemon's published fwmark/table layout.
- [LuCI Web Interface](luci.md) — Inbound Services card reference.
- [CLI Usage](cli.md) — full `nym-vpnc` reference.
