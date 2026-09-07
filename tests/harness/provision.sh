#!/usr/bin/env bash
# Bring up one test slot:
#   - dedicated LAN bridge
#   - OpenWrt CT (WAN=vmbr0 DHCP, LAN=bridge static .1)
#   - DNS-logger Alpine CT on LAN at .2 (static)
#   - client Alpine CT on LAN (DHCP from OpenWrt)
#
# Usage: provision.sh <slot> <openwrt_version>
#
# Reads env: PROXMOX_HOST
# Writes: nothing on disk locally; all state is in Proxmox CTs.
# Echoes a summary line that the slot runner parses.

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HARNESS_DIR/lib/ctl.sh"

SLOT="${1:?slot index required}"
VERSION="${2:?openwrt version required}"

BRIDGE="vmbr-test${SLOT}"
OPENWRT_CTID="5${SLOT}0"
CLIENT_CTID="5${SLOT}1"
DNS_CTID="5${SLOT}2"
LAN_CIDR="10.9${SLOT}.0.1/24"
DNS_IP="10.9${SLOT}.0.2"
DNS_CIDR="10.9${SLOT}.0.2/24"

log() { printf '[slot%s] %s\n' "$SLOT" "$*" >&2; }

log "ensuring bridge $BRIDGE"
bridge_ensure "$BRIDGE"

log "creating OpenWrt $VERSION (CT $OPENWRT_CTID, LAN $LAN_CIDR)"
pct_create_openwrt "$OPENWRT_CTID" "$VERSION" vmbr0 "$BRIDGE" "$LAN_CIDR"

log "creating DNS logger CT $DNS_CTID at $DNS_IP"
pct_create_alpine "$DNS_CTID" "$BRIDGE" "dns-logger-slot${SLOT}" "$DNS_CIDR"
# Default route on the dns CT goes through OpenWrt so it can apk-fetch
# dnsmasq. ip route add default ... is bridge-side and survives reboots.
pct_sh "$DNS_CTID" "ip route add default via ${LAN_CIDR%/*} 2>/dev/null || true"
pct_sh "$DNS_CTID" "printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf"
dns_logger_start "$DNS_CTID" "$DNS_IP"

log "creating client CT $CLIENT_CTID (DHCP)"
pct_create_alpine "$CLIENT_CTID" "$BRIDGE" "client-slot${SLOT}" ""

# Sanity: the client should have gotten a DHCP lease from OpenWrt.
for _ in 1 2 3 4 5; do
    if pct_sh "$CLIENT_CTID" "ip -4 addr show eth0 | grep -q 'inet 10\\.9${SLOT}\\.'"; then
        break
    fi
    sleep 2
done

CLIENT_IP=$(pct_sh "$CLIENT_CTID" "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1")
log "client got IP: $CLIENT_IP"

# The reachability checks run curl and dig on the client; the Alpine template
# ships neither, and without them every "unreachable" assertion would pass
# for the wrong reason. Install them now, while the router still forwards
# freely (nym-vpn is not installed yet).
log "installing curl/dig on the client"
for _ in 1 2 3; do
    if pct_sh "$CLIENT_CTID" "apk add --quiet curl bind-tools >/dev/null 2>&1 && command -v curl >/dev/null"; then
        break
    fi
    sleep 3
done
pct_sh "$CLIENT_CTID" "command -v curl >/dev/null" || { log "client has no curl; reachability checks would be meaningless"; exit 1; }

# Emit machine-readable summary on stdout for the slot runner to consume.
cat <<EOF
SLOT=$SLOT
VERSION=$VERSION
BRIDGE=$BRIDGE
OPENWRT_CTID=$OPENWRT_CTID
CLIENT_CTID=$CLIENT_CTID
DNS_CTID=$DNS_CTID
LAN_GW=${LAN_CIDR%/*}
DNS_IP=$DNS_IP
CLIENT_IP=$CLIENT_IP
EOF
