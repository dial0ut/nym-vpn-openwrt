# Inbound Services

Keep port-forwarded services — LuCI on the router, SSH, a self-hosted site, something on a NAS —
reachable from the WAN while the kill-switch is on.

## The problem

With the kill-switch on, every outbound packet that is not explicitly allowed goes through the
tunnel. That includes the **reply** to an inbound connection. So a port-forwarded service:

1. Accepts the inbound SYN on the WAN
2. Replies
3. Sends the reply through the tunnel
4. Egresses with the wrong source IP, and the client's connection dies

An inbound exemption routes replies for the ports you declare via the **real WAN** instead.

## How it works

Per `{proto, port}`:

- A `mangle` rule sets the inbound connection's conntrack mark on the WAN interface, **before
  DNAT runs**, so the match is against the original public port.
- `meta mark set ct mark` restores that mark onto the reply packet.
- `ip rule fwmark 0x14e lookup main` at priority 90 sends marked replies via the main routing
  table (real WAN) rather than the tunnel table.
- The kill-switch's filter chains get `meta mark 0x14e accept`, so the reject-all rule does not
  fire on the marked reply.

**This only adds a reply path.** Outbound enforcement is unchanged — the daemon's own traffic is
unaffected, and a compromised exempt service cannot exfiltrate through its own port, because the
mark is only ever set on `iif=wan ct state new`, never on connections the router initiates.

## Do you need a port forward too?

The exemption handles **reply routing** only. It does **not** set up the DNAT that delivers an
inbound connection to a LAN host — that stays in OpenWrt's own firewall.

| Service lives | Port forward? | Where |
|---------------|---------------|-------|
| On the router (LuCI, SSH, a WireGuard listener) | No | — |
| On a LAN host (Jellyfin on a NAS, docker on a server) | Yes | `Network → Firewall → Port Forwards` |

For LAN-hosted services, create the port forward first, then add the exemption for the **WAN-side**
port. The exemption matches `(proto, WAN-port)` before DNAT rewrites the destination, so the LAN
target IP never needs declaring on the NymVPN side.

## CLI

```bash
nym-vpnc inbound list

nym-vpnc inbound add tcp:443 --label "HTTPS reverse proxy"
nym-vpnc inbound add tcp:22222
nym-vpnc inbound add udp:51820 --label "WireGuard"

nym-vpnc inbound del tcp:443
```

`nym-vpnc tunnel get` lists them too:

```
… Inbound exemptions: tcp/443, tcp/22222, udp/51820 …
```

Entries persist to `/etc/nym/nym-vpnd.json` and survive a daemon restart. Changes apply on the
next state transition; while connected, the daemon debounces tunnel-settings updates by ~1s and
then reconnects to re-apply firewall and routing rules.

## LuCI

The **Inbound Services** card sits between `Tunnel Settings` and `DNS & Ad Blocking`.

Pick `TCP` or `UDP`, type the port, optionally a label, **Save** (or `Enter`). Rows show
proto / port / label / status — `● Active` with the kill-switch on, `● Inert` with it off — and a
`×` to delete. With the kill-switch off a banner explains why the entries are inert: exemptions
only matter while something is enforcing.

## Recipes

### Expose LuCI to the WAN

The router's web UI listens on `:443`.

```bash
# 1. allow WAN input to TCP/443
uci set firewall.luci_wan=rule
uci set firewall.luci_wan.name='Allow-LuCI-WAN'
uci set firewall.luci_wan.src='wan'
uci set firewall.luci_wan.proto='tcp'
uci set firewall.luci_wan.dest_port='443'
uci set firewall.luci_wan.target='ACCEPT'
uci commit firewall
fw4 reload

# 2. only if your test client is on a private network
uci set uhttpd.main.rfc1918_filter='0'
uci commit uhttpd
/etc/init.d/uhttpd restart

# 3. the exemption
nym-vpnc inbound add tcp:443 --label "LuCI"
```

### Expose a LAN service — Jellyfin at 192.168.1.50:8096

```bash
# 1. port forward, public:8096 -> 192.168.1.50:8096
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

# 2. exemption for the WAN-side port
nym-vpnc inbound add tcp:8096 --label "Jellyfin"
```

### Remapped ports — WAN:8443 → LAN:443

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

nym-vpnc inbound add tcp:8443 --label "Home Assistant"
```

The exemption always takes the **public** port (`src_dport`), never the internal one.

## Verification

```bash
# mark-set rule in mangle PREROUTING — only present in Connecting/Connected
nft list table inet nym | grep -A4 'chain mangle_prerouting'

# mark restore in mangle output
nft list table inet nym | grep -A2 'chain mangle_output'

# filter accepts for the exempt mark
nft list table inet nym | grep 'meta mark 0x'

# the routing rule
ip rule | grep 0x14e
# 90: from all fwmark 0x14e lookup main
```

On fw3/iptables routers:

```bash
iptables -t mangle -L NYM_MANGLE_PREROUTING -v -n
iptables -t mangle -L NYM_MANGLE_OUTPUT -v -n
iptables -L NYM_OUTPUT -v -n | grep '0x14e'
```

## Caveats

- **Single WAN only in v1.** If `mwan3` reports more than one enabled WAN, the daemon warns and
  the exemption may apply to the wrong egress.
- **PPPoE and tunnelled WANs work.** The `iif` match is anchored to the WAN's real L3 device (e.g.
  `pppoe-wan`), resolved from `ubus call network.interface.wan status`, not the underlying
  ethernet. Confirm with the `mangle_prerouting` command under [Verification](#verification) that
  `iifname` matches the device from `ip route get 1.1.1.1`.
- **`kmod-ipt-conntrack-extra`** is a hard dependency on fw3 builds. If you have stripped it
  manually, rule application fails at `iptables-restore` time with a clear error.
- **Hot-apply takes ~1s and drops connections.** `add` or `del` while connected debounces ~1s then
  reconnects to re-apply firewall and routing. In-flight flows keep their original routing —
  marking is not retroactive.
- **An exemption is not a port forward.** `add tcp:8096` with no OpenWrt port forward for 8096
  forwards nothing to your LAN host. It only fixes the reply path.

## See also

- [Split Tunneling](split-tunneling.md) — *outbound* exclusions. The two coexist; both use the
  daemon's published fwmark and routing-table layout.
- [LuCI Web Interface](luci.md) — the Inbound Services card
- [CLI Usage](cli.md) — the rest of `nym-vpnc`
