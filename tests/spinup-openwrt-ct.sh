#!/usr/bin/env bash
# Spin up a fresh OpenWrt LXC container on a Proxmox host for nym-vpn testing.
#
# Driven by SSH from your workstation. Idempotent-ish: creates the LAN bridge
# and downloads the OpenWrt rootfs template only when missing.
#
# Usage:
#   tests/spinup-openwrt-ct.sh [options]
#
# Options:
#   --version <X.Y.Z>     OpenWrt release (default: 25.12.4)
#   --arch <arch>         OpenWrt arch target (default: x86_64; downloads
#                         openwrt-<ver>-x86-64-rootfs.tar.gz)
#   --ctid <N>            Container ID (default: first free ID >= 423,
#                         skipping any VM that already claims the ID)
#   --proxmox <host>      SSH alias for the Proxmox host (default: proxmox)
#   --wan-bridge <name>   Bridge for the WAN-side NIC (default: vmbr0)
#   --wan-ip <CIDR>       WAN static IP. If omitted, WAN uses DHCP.
#                         If set, the script ping-sweeps from the Proxmox host
#                         first and refuses to proceed if the IP is occupied.
#   --wan-gw <ip>         WAN gateway (only used with --wan-ip; default 192.168.1.1)
#   --lan-bridge <name>   Bridge for the LAN-side NIC. Created if absent
#                         (default: vmbr-nym-test)
#   --lan-ip <CIDR>       LAN IP on the OpenWrt side (default: 10.99.0.1/24)
#   --memory <MB>         Memory in MB (default: 512)
#   --install-nym         Run the curl-to-sh nym-vpn installer post-boot
#   --keep-default-net    Skip the /etc/config/network rewrite (use template
#                         defaults — eth0=lan, eth1=wan)
#   -h, --help            Show this help
#
# Notes
# -----
# * Container is created --unprivileged 0 with nesting+keyctl features and
#   /dev/net/tun bind-mounted (required for nym-vpnd).
# * /etc/resolv.conf is rewritten to direct upstream resolvers — the stock
#   template points at 127.0.0.1 expecting dnsmasq, which isn't always running
#   in our LXC. Without this fix, DNS-based installers and the nym daemon
#   itself fail to resolve anything.
# * The script does NOT load a Nym account. Copy /etc/nym/data/mainnet from
#   another box yourself if you want a logged-in container.

set -euo pipefail

# ---- defaults ----
OPENWRT_VERSION="25.12.4"
ARCH_OPENWRT="x86_64"     # used for filenames; rootfs uses "x86-64"
CTID=""
PROXMOX_HOST="proxmox"
WAN_BRIDGE="vmbr0"
WAN_IP=""                  # empty => DHCP
WAN_GW="192.168.1.1"
LAN_BRIDGE="vmbr-nym-test"
LAN_IP="10.99.0.1/24"
MEMORY=512
INSTALL_NYM=0
KEEP_DEFAULT_NET=0

# ---- arg parse ----
while [ $# -gt 0 ]; do
    case "$1" in
        --version) OPENWRT_VERSION="$2"; shift 2 ;;
        --arch) ARCH_OPENWRT="$2"; shift 2 ;;
        --ctid) CTID="$2"; shift 2 ;;
        --proxmox) PROXMOX_HOST="$2"; shift 2 ;;
        --wan-bridge) WAN_BRIDGE="$2"; shift 2 ;;
        --wan-ip) WAN_IP="$2"; shift 2 ;;
        --wan-gw) WAN_GW="$2"; shift 2 ;;
        --lan-bridge) LAN_BRIDGE="$2"; shift 2 ;;
        --lan-ip) LAN_IP="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --install-nym) INSTALL_NYM=1; shift ;;
        --keep-default-net) KEEP_DEFAULT_NET=1; shift ;;
        -h|--help) sed -n '1,/^set -e/p' "$0" | sed '/^set -e/d' | sed 's/^# \?//'; exit 0 ;;
        *) echo "[error] unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Map a few common arch shorthands to OpenWrt's filename convention.
case "$ARCH_OPENWRT" in
    x86_64|x86-64) ROOTFS_ARCH="x86-64"; ROOTFS_TARGET="x86/64" ;;
    aarch64)        ROOTFS_ARCH="armsr-armv8"; ROOTFS_TARGET="armsr/armv8" ;;
    *) echo "[error] unsupported --arch: $ARCH_OPENWRT" >&2; exit 2 ;;
esac

ROOTFS_NAME="openwrt-${OPENWRT_VERSION}-${ROOTFS_ARCH}-rootfs.tar.gz"
ROOTFS_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${ROOTFS_TARGET}/${ROOTFS_NAME}"

pmx() { ssh "$PROXMOX_HOST" "$@"; }

log() { printf '\033[1;34m[spinup]\033[0m %s\n' "$*"; }

# ---- 1. Ensure LAN bridge exists ----
log "ensuring LAN bridge ${LAN_BRIDGE} exists on ${PROXMOX_HOST}"
if ! pmx "ip -br link show ${LAN_BRIDGE} >/dev/null 2>&1"; then
    log "creating ${LAN_BRIDGE} via /etc/network/interfaces.d/"
    pmx "cat > /etc/network/interfaces.d/${LAN_BRIDGE} <<EOF
auto ${LAN_BRIDGE}
iface ${LAN_BRIDGE} inet manual
	bridge-ports none
	bridge-stp off
	bridge-fd 0
EOF
ifreload -a"
else
    log "${LAN_BRIDGE} already exists, skipping"
fi

# ---- 2. Ensure rootfs template is on the host ----
log "ensuring template ${ROOTFS_NAME} is on the host"
if ! pmx "test -f /var/lib/vz/template/cache/${ROOTFS_NAME}"; then
    log "downloading ${ROOTFS_URL}"
    pmx "cd /var/lib/vz/template/cache && wget -q '${ROOTFS_URL}'"
fi

# ---- 3. Resolve CTID (avoid existing CT *or* VM) ----
if [ -z "$CTID" ]; then
    log "finding free CTID"
    for candidate in 423 424 425 426 427 428 429 430 431 432 440 450 499; do
        if pmx "pct config $candidate >/dev/null 2>&1 || qm config $candidate >/dev/null 2>&1"; then
            continue
        fi
        CTID="$candidate"
        break
    done
    [ -z "$CTID" ] && { echo "[error] no free CTID in default range" >&2; exit 1; }
fi
log "using CTID=${CTID}"

if pmx "pct config $CTID >/dev/null 2>&1"; then
    echo "[error] CT $CTID already exists. Stop and destroy it first, or pass --ctid." >&2
    exit 1
fi

# ---- 4. Create container ----
log "creating CT ${CTID}"
pmx "pct create $CTID local:vztmpl/${ROOTFS_NAME} \
    --hostname openwrt-test-${OPENWRT_VERSION//./-} \
    --memory $MEMORY \
    --swap $((MEMORY / 2)) \
    --rootfs local-lvm:2 \
    --net0 name=eth0,bridge=${WAN_BRIDGE},hwaddr=BC:24:11:00:04:$(printf '%02X' $((CTID % 256))),firewall=0 \
    --net1 name=eth1,bridge=${LAN_BRIDGE},hwaddr=BC:24:11:00:14:$(printf '%02X' $((CTID % 256))),firewall=0 \
    --features nesting=1,keyctl=1 \
    --ostype unmanaged \
    --unprivileged 0 \
    --onboot 0" 2>&1 | tail -3 || true

log "adding TUN passthrough to /etc/pve/lxc/${CTID}.conf"
pmx "grep -q 'lxc.mount.entry: /dev/net/tun' /etc/pve/lxc/${CTID}.conf || {
    echo 'lxc.cgroup2.devices.allow: c 10:200 rwm' >> /etc/pve/lxc/${CTID}.conf
    echo 'lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file' >> /etc/pve/lxc/${CTID}.conf
}"

log "starting CT ${CTID}"
pmx "pct start $CTID"
sleep 3

# ---- 4.5 Ping sweep the requested WAN IP (static only) ----
if [ -n "$WAN_IP" ]; then
    WAN_ADDR_CHECK="${WAN_IP%/*}"
    log "checking ${WAN_ADDR_CHECK} is not already on the network"
    if pmx "ping -c 2 -W 1 ${WAN_ADDR_CHECK} >/dev/null 2>&1"; then
        echo "[error] ${WAN_ADDR_CHECK} is already responding to ping. Pick a different --wan-ip." >&2
        echo "        (Or omit --wan-ip to use DHCP.)" >&2
        # Stop the half-created CT so re-runs don't trip on the existing CTID.
        pmx "pct stop $CTID >/dev/null 2>&1 || true; pct destroy $CTID >/dev/null 2>&1 || true"
        exit 1
    fi
fi

# ---- 5. Configure network inside the container ----
if [ "$KEEP_DEFAULT_NET" -eq 0 ]; then
    LAN_ADDR="${LAN_IP%/*}"
    LAN_PREFIX="${LAN_IP#*/}"
    # Compute netmasks from prefix length so we don't have to import a tool.
    mask_from_prefix() {
        local prefix="$1" mask="" i
        for i in 1 2 3 4; do
            if [ "$prefix" -ge 8 ]; then mask="${mask}.255"; prefix=$((prefix-8))
            elif [ "$prefix" -gt 0 ]; then mask="${mask}.$((256 - (1 << (8 - prefix))))"; prefix=0
            else mask="${mask}.0"; fi
        done
        echo "${mask#.}"
    }
    LAN_MASK=$(mask_from_prefix "$LAN_PREFIX")

    if [ -n "$WAN_IP" ]; then
        WAN_ADDR="${WAN_IP%/*}"
        WAN_PREFIX="${WAN_IP#*/}"
        WAN_MASK=$(mask_from_prefix "$WAN_PREFIX")
        log "rewriting /etc/config/network (WAN=eth0 static ${WAN_IP}, LAN=eth1 ${LAN_IP})"
        WAN_BLOCK="config interface \"wan\"
	option device \"eth0\"
	option proto \"static\"
	option ipaddr \"${WAN_ADDR}\"
	option netmask \"${WAN_MASK}\"
	option gateway \"${WAN_GW}\"
	list dns \"1.1.1.1\"
	list dns \"8.8.8.8\""
    else
        log "rewriting /etc/config/network (WAN=eth0 dhcp, LAN=eth1 ${LAN_IP})"
        WAN_BLOCK="config interface \"wan\"
	option device \"eth0\"
	option proto \"dhcp\""
    fi

    pmx "pct exec $CTID -- sh -c 'cat > /etc/config/network <<EOF
config interface \"loopback\"
	option device \"lo\"
	option proto \"static\"
	option ipaddr \"127.0.0.1\"
	option netmask \"255.0.0.0\"

${WAN_BLOCK}

config interface \"lan\"
	option device \"eth1\"
	option proto \"static\"
	option ipaddr \"${LAN_ADDR}\"
	option netmask \"${LAN_MASK}\"
EOF
/etc/init.d/network restart'" 2>&1 | tail -3 || true
    sleep 4
fi

# ---- 6. Fix /etc/resolv.conf so DNS works without local dnsmasq ----
log "pinning resolv.conf to 1.1.1.1 / 8.8.8.8 (template default points at 127.0.0.1)"
pmx "pct exec $CTID -- sh -c 'printf \"nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n\" > /etc/resolv.conf'"

# ---- 7. Restart firewall so fw4 re-renders zones against new /etc/config/network ----
log "restarting fw4 to pick up new network config"
pmx "pct exec $CTID -- sh -c 'fw4 reload >/dev/null 2>&1 || true'"

# ---- 8. Sanity check ----
log "connectivity check from inside CT"
pmx "pct exec $CTID -- sh -c '
ip addr show eth0 | grep -o \"inet [0-9.]*\" | head -1
wget -qO- --timeout=5 https://1.1.1.1 -O /dev/null && echo \"internet ok\" || echo \"internet FAILED\"
nft list table inet fw4 >/dev/null 2>&1 && echo \"fw4 active\" || echo \"fw4 missing\"
'"

# ---- 9. Optional: install nym ----
if [ "$INSTALL_NYM" -eq 1 ]; then
    log "running nym-vpn installer"
    pmx "pct exec $CTID -- sh -c 'wget -qO- https://packages.dial0ut.org/install.sh | sh' 2>&1 | tail -20"
    log "daemon version:"
    pmx "pct exec $CTID -- nym-vpnc --version"
fi

log "done"
cat <<EOF

  CTID:        ${CTID}
  OpenWrt:     ${OPENWRT_VERSION} ${ARCH_OPENWRT}
  WAN bridge:  ${WAN_BRIDGE}      WAN IP: ${WAN_IP:-dhcp}
  LAN bridge:  ${LAN_BRIDGE}      LAN IP: ${LAN_IP}

  Enter:       ssh ${PROXMOX_HOST} -t pct enter ${CTID}
  Exec:        ssh ${PROXMOX_HOST} 'pct exec ${CTID} -- <cmd>'
  Destroy:     ssh ${PROXMOX_HOST} 'pct stop ${CTID}; pct destroy ${CTID}'
EOF
