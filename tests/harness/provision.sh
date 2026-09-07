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

set -Eeuo pipefail

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
# set -e aborts silently otherwise; name the step so a failed provision is
# diagnosable from the slot log alone.
trap 'log "provision failed in ${FUNCNAME[0]:-main} at line $LINENO: $BASH_COMMAND"' ERR

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

# The client must get a DHCP lease from the OpenWrt CT's dnsmasq. Observed
# to take 15-25 s after the client starts (dnsmasq comes up after the
# network restart), so wait for it rather than sampling once; without a
# lease nothing downstream means anything, so a missing lease fails the
# provision loudly.
CLIENT_IP=""
for i in $(seq 1 25); do
    CLIENT_IP=$(pct_sh "$CLIENT_CTID" "ip -4 -o addr show eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1")
    case "$CLIENT_IP" in 10.9"${SLOT}".*) break ;; esac
    CLIENT_IP=""
    # udhcpc backs off after its first unanswered discovers; ask again
    # explicitly every few rounds instead of waiting out its timer.
    if [ $((i % 4)) -eq 0 ]; then
        pct_sh "$CLIENT_CTID" "udhcpc -i eth0 -n -q -t 3 -T 2 >/dev/null 2>&1 || true"
    fi
    sleep 2
done
if [ -z "$CLIENT_IP" ]; then
    log "client got no DHCP lease from $LAN_CIDR within 50 s"
    {
        echo "  router: dnsmasq pid=$(pct_sh "$OPENWRT_CTID" 'pidof dnsmasq' || true) addrs=$(pct_sh "$OPENWRT_CTID" 'ip -4 -o addr | awk "{print \$2, \$4}" | tr "\n" " "' || true)"
        pct_sh "$OPENWRT_CTID" "logread | grep -iE 'dnsmasq|dhcp' | tail -6" || true
        echo "  client: $(pct_sh "$CLIENT_CTID" 'ip -4 -o addr show eth0; ps | grep -c [u]dhcpc' | tr '\n' ' ' || true)"
    } >&2
    exit 1
fi
log "client got IP: $CLIENT_IP"

# The reachability checks run curl and dig on the client; the Alpine template
# ships neither, and without them every "unreachable" assertion would pass
# for the wrong reason. Install them now, while the router still forwards
# freely (nym-vpn is not installed yet).
log "installing curl/dig on the client"
ct_apk_add "$CLIENT_CTID" curl bind-tools || { log "client has no curl; reachability checks would be meaningless"; exit 1; }
pct_sh "$CLIENT_CTID" "command -v curl >/dev/null" || { log "client has no curl after install; reachability checks would be meaningless"; exit 1; }

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
