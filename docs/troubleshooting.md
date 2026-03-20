# Troubleshooting

## Not Enough Disk Space

NymVPN binaries are ~57MB (nym-vpnd) + ~5MB (nym-vpnc). Devices with
small `/tmp` (tmpfs backed by RAM) may not have room.

**Check available space:**
```bash
df -h
```

**Use the overlay filesystem instead of /tmp:**

Most OpenWrt devices have a writable overlay partition with more space
than tmpfs:
```bash
mkdir -p /overlay/tmp
# copy or install binaries to /overlay/tmp/
```

**Free up space:**
```bash
# Remove opkg package lists (can be re-fetched with opkg update)
rm -rf /tmp/opkg-lists

# Remove old log files
rm -f /tmp/sf_log.txt /tmp/log/*
```

## Not Enough RAM (OOM Crash)

NymVPN needs roughly 80-100MB RAM to run. Devices with 128MB RAM or
less may hit out-of-memory errors, especially when both WireGuard
tunnels start.

**Symptoms:**
```text
memory allocation of 26214400 bytes failed
Aborted
```

**Fix: Enable zram swap**

zram creates compressed swap in RAM, effectively doubling usable
memory through compression:
```
opkg update
opkg install zram-swap
/etc/init.d/zram start
```

Verify it's working:
```bash
free -m
```
You should see a Swap line with non-zero total.

**Make zram persist across reboots:**

zram-swap starts automatically via its init script after installation.
Verify with:
```bash
/etc/init.d/zram enabled && echo "enabled" || echo "disabled"
```

**Note:** File-based swap (`swapon /path/to/swapfile`) does not work on
UBIFS/JFFS2 filesystems commonly used by OpenWrt. Use zram instead.

## Firewall Stuck After Crash

If nym-vpnd crashes or is killed while connected, its firewall rules
may remain active, blocking internet access.

**Symptoms:** No internet connectivity after nym-vpnd exits unexpectedly.

**Fix:**
```
# Flush nym firewall chains
iptables -F NYM_INPUT 2>/dev/null
iptables -F NYM_OUTPUT 2>/dev/null
iptables -F NYM_FORWARD 2>/dev/null
iptables -t nat -F NYM_NAT 2>/dev/null

# Remove jumps to nym chains
iptables -D input_rule -j NYM_INPUT 2>/dev/null
iptables -D output_rule -j NYM_OUTPUT 2>/dev/null
iptables -D forwarding_rule -j NYM_FORWARD 2>/dev/null
iptables -t nat -D postrouting_rule -j NYM_NAT 2>/dev/null

# Restart firewall to restore defaults
/etc/init.d/firewall restart
```

For fw4 (OpenWrt 22.03+), replace the above with:
```
nft delete table inet nym 2>/dev/null
/etc/init.d/firewall restart
```

## Gateway Timeout on Connect

**Symptoms:**
```text
timeout waiting for connect response from exit gateway (authenticator)
```

This means the mixnet connection succeeded but the exit gateway was
slow or unresponsive. Try connecting again — a different gateway will
usually be selected:
```
nym-vpnc disconnect
nym-vpnc connect
```

## WireGuard Handshake Timeout

**Symptoms:**
```text
HANDSHAKE(REKEY_TIMEOUT)
```

This is normal during initial connection. The tunnel monitor will retry
and usually succeeds within a few attempts. If it persists, the entry
or exit gateway may be down — disconnect and reconnect to pick new
gateways.

## UDP GRO Warnings

**Symptoms:**
```text
Failed to enable UDP GRO for IPv4 socket: Protocol not available (os error 99)
```

This is harmless. UDP Generic Receive Offload requires kernel 5.x+.
Most OpenWrt devices run older kernels. Performance is fine without it.
