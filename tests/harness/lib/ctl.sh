# shellcheck shell=bash
# Proxmox / pct control wrappers. Source me.
#
# Expects PROXMOX_HOST in the environment: an SSH alias for the host, or
# the word "local" when the harness itself runs on the Proxmox host. Local
# mode keeps the control path off the network entirely, which matters when
# the operator's link to the host is the flaky part of the setup.

set -euo pipefail

: "${PROXMOX_HOST:?PROXMOX_HOST must be set (load .env first)}"

# ssh to the host with retries on transport failure. Three slots provisioning
# at once make the host slow to accept connections; a transient connect
# timeout must not turn into a failed provision or a skipped teardown.
#
# Exit code 255 is not enough to tell a transport failure apart: opkg and
# pct exit 255 for their own errors too. Only ssh's own diagnostics on stderr
# count as transport failures; every other outcome is the command's and is
# returned as is. Stdin is buffered so a retry replays the same script
# instead of feeding `sh -s` an empty one, which would exit 0 and turn a
# failed command into a pass.
_ssh_host() {
    if [ "$PROXMOX_HOST" = local ]; then
        bash -c "$*"
        return
    fi
    local attempt=1 rc in err
    in=$(mktemp) || return 1
    err=$(mktemp) || { rm -f "$in"; return 1; }
    if [ ! -t 0 ]; then cat > "$in"; fi
    while :; do
        ssh -o BatchMode=yes -o ConnectTimeout=15 "$PROXMOX_HOST" "$@" < "$in" 2> "$err"
        rc=$?
        if [ "$rc" -eq 255 ] && grep -qE '^(ssh: connect to host|kex_exchange_identification|Connection (timed out|closed|reset)|client_loop: send disconnect)' "$err"; then
            if [ "$attempt" -ge 4 ]; then
                cat "$err" >&2
                echo "[ctl] ssh to $PROXMOX_HOST failed $attempt times" >&2
                rm -f "$in" "$err"
                return 255
            fi
            sleep $((attempt * 5))
            attempt=$((attempt + 1))
            continue
        fi
        cat "$err" >&2
        rm -f "$in" "$err"
        return "$rc"
    done
}

# Run an arbitrary command on the Proxmox host. Stdout/stderr pass through.
pmx() {
    _ssh_host "$@"
}

# Run a command inside a container. Errors propagate.
pct_exec() {
    local ctid="$1"; shift
    pmx "pct exec $ctid -- $*"
}

# Run a shell snippet inside a CT. Snippet is piped via stdin to `sh -s` so
# quoting inside it is unaffected by the outer ssh+pct framing.
pct_sh() {
    local ctid="$1"; shift
    # shellcheck disable=SC2087  # the snippet is meant to expand here, not on the host
    _ssh_host "pct exec $ctid -- sh -s" <<EOF
$*
EOF
}

# True if a CT or VM with this ID already exists.
ctid_in_use() {
    pmx "pct config $1 >/dev/null 2>&1 || qm config $1 >/dev/null 2>&1"
}

# Idempotent bridge creation. Writes /etc/network/interfaces.d/<name>
# on the host and brings up just that interface. (`ifreload -a` would
# re-evaluate every interface and fails outright when ifupdown2 still
# remembers a bridge that was deleted behind its back.)
bridge_ensure() {
    local name="$1"
    if pmx "ip -br link show $name >/dev/null 2>&1"; then
        return 0
    fi
    pmx "cat > /etc/network/interfaces.d/$name <<EOF
auto $name
iface $name inet manual
	bridge-ports none
	bridge-stp off
	bridge-fd 0
EOF
for i in 1 2 3 4 5 6; do ifup $name && exit 0; sleep 3; done; echo '[ctl] ifup $name kept failing' >&2; exit 1"
}

# Best-effort destroy. Does not fail if the bridge is already gone. The
# bridge is taken down through ifupdown2 while its stanza still exists, so
# the tool forgets it; deleting the link directly would leave stale state
# that breaks every later ifreload on the host.
bridge_destroy() {
    local name="$1"
    pmx "if [ -f /etc/network/interfaces.d/$name ]; then ifdown --force $name >/dev/null 2>&1 || true; fi; rm -f /etc/network/interfaces.d/$name; ip link set $name down 2>/dev/null || true; ip link del $name 2>/dev/null || true"
}

# Ensure an OpenWrt rootfs template is on the host. Downloads on demand.
template_ensure_openwrt() {
    local version="$1"
    local arch="${2:-x86-64}"
    local target
    case "$arch" in
        x86-64) target="x86/64" ;;
        *) echo "[ctl] unsupported arch: $arch" >&2; return 2 ;;
    esac
    local name="openwrt-${version}-${arch}-rootfs.tar.gz"
    local url="https://downloads.openwrt.org/releases/${version}/targets/${target}/${name}"

    pmx "test -f /var/lib/vz/template/cache/$name || (cd /var/lib/vz/template/cache && wget -q '$url')"
    echo "$name"
}

# Create an OpenWrt CT, configure WAN (DHCP, or static when wan_cidr is
# given) + LAN (static), pin /etc/resolv.conf and reload fw4 so its zones
# reflect the new network config.
#
# Args: ctid version wan_bridge lan_bridge lan_cidr [wan_cidr wan_gw]
pct_create_openwrt() {
    local ctid="$1" version="$2" wan_bridge="$3" lan_bridge="$4" lan_cidr="$5"
    local wan_cidr="${6:-}" wan_gw="${7:-}"
    local rootfs
    rootfs="$(template_ensure_openwrt "$version")"

    if ctid_in_use "$ctid"; then
        echo "[ctl] CTID $ctid already exists" >&2
        return 1
    fi

    # A static WAN address that is already in use would collide with another
    # machine on the host's segment; refuse before the CT exists.
    local wan_block
    if [ -n "$wan_cidr" ]; then
        if pmx "ping -c 2 -W 1 ${wan_cidr%/*} >/dev/null 2>&1"; then
            echo "[ctl] WAN address ${wan_cidr%/*} already answers on the segment" >&2
            return 1
        fi
        wan_block="config interface \"wan\"
	option device \"eth0\"
	option proto \"static\"
	option ipaddr \"${wan_cidr%/*}\"
	option netmask \"$(_mask_from_prefix "${wan_cidr#*/}")\"
	option gateway \"${wan_gw:-192.168.1.1}\"
	list dns \"1.1.1.1\"
	list dns \"8.8.8.8\""
    else
        wan_block="config interface \"wan\"
	option device \"eth0\"
	option proto \"dhcp\""
    fi

    local hwaddr_oct
    hwaddr_oct=$(printf '%02X' $((ctid % 256)))

    pmx "pct create $ctid local:vztmpl/$rootfs \
        --hostname openwrt-${version//./-}-${ctid} \
        --memory 512 --swap 256 --rootfs local-lvm:2 \
        --net0 name=eth0,bridge=$wan_bridge,hwaddr=BC:24:11:00:04:$hwaddr_oct,firewall=0 \
        --net1 name=eth1,bridge=$lan_bridge,hwaddr=BC:24:11:00:14:$hwaddr_oct,firewall=0 \
        --features nesting=1,keyctl=1 --ostype unmanaged --unprivileged 0 --onboot 0" \
        >/dev/null 2>&1 || true

    # TUN passthrough — required for nym-vpnd.
    pmx "grep -q 'lxc.mount.entry: /dev/net/tun' /etc/pve/lxc/${ctid}.conf || {
        echo 'lxc.cgroup2.devices.allow: c 10:200 rwm' >> /etc/pve/lxc/${ctid}.conf
        echo 'lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file' >> /etc/pve/lxc/${ctid}.conf
    }"

    pmx "pct start $ctid"
    sleep 3

    local lan_addr="${lan_cidr%/*}" lan_prefix="${lan_cidr#*/}"
    local lan_mask
    lan_mask=$(_mask_from_prefix "$lan_prefix")

    pmx "pct exec $ctid -- sh -c 'cat > /etc/config/network <<EOF
config interface \"loopback\"
	option device \"lo\"
	option proto \"static\"
	option ipaddr \"127.0.0.1\"
	option netmask \"255.0.0.0\"

$wan_block

config interface \"lan\"
	option device \"eth1\"
	option proto \"static\"
	option ipaddr \"$lan_addr\"
	option netmask \"$lan_mask\"
EOF
/etc/init.d/network restart >/dev/null 2>&1; sleep 3'"

    # Stock template's resolv.conf points at 127.0.0.1 expecting dnsmasq,
    # which is half-broken in our LXCs. Pin upstreams directly.
    pct_sh "$ctid" 'printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf'

    # Everything downstream (the sidecars' package installs, the client's
    # lease, the daemon's registration) needs the router on the WAN. The
    # DHCP lease from the lab network has taken up to a minute; wait for the
    # default route rather than letting the first consumer fail obscurely.
    local i=0
    while [ "$i" -lt 30 ]; do
        if pct_sh "$ctid" 'ip -4 route show default 2>/dev/null | grep -q default'; then
            break
        fi
        sleep 2; i=$((i + 1))
    done
    if [ "$i" -ge 30 ]; then
        echo "[ctl] OpenWrt CT $ctid got no WAN default route within 60 s" >&2
        pct_sh "$ctid" 'ip -4 -o addr; logread | grep -iE "udhcpc|wan" | tail -4' >&2 || true
        return 1
    fi
    # Re-render the firewall zones now that both interfaces exist. In a
    # container no hotplug event does this for us; a reload before the WAN
    # was up leaves the wan zone without its device and the LAN unmasqueraded.
    pct_sh "$ctid" 'fw4 reload >/dev/null 2>&1 || /etc/init.d/firewall reload >/dev/null 2>&1 || true'
    # dnsmasq started before eth1 existed; make sure it serves the LAN now.
    pct_sh "$ctid" '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true'
    sleep 2
}

# Ensure an Alpine LXC template is on the host. Returns template filename.
template_ensure_alpine() {
    local name
    name=$(pmx "ls /var/lib/vz/template/cache/ 2>/dev/null | grep -E '^alpine-3\\.[0-9]+-default_.*amd64\\.tar\\.xz$' | sort | tail -1")
    if [ -z "$name" ]; then
        name=$(pmx "pveam available --section system 2>&1 | awk '/alpine-3\\.[0-9]+-default_.*amd64\\.tar\\.xz/ {print \$2}' | sort | tail -1")
        pmx "pveam download local '$name' >/dev/null"
    fi
    echo "$name"
}

# Create an Alpine sidecar CT. ip_cidr empty => DHCP on the bridge.
# Args: ctid bridge hostname ip_cidr
pct_create_alpine() {
    local ctid="$1" bridge="$2" hostname="$3" ip_cidr="${4:-}"
    local tmpl
    tmpl="$(template_ensure_alpine)"

    if ctid_in_use "$ctid"; then
        echo "[ctl] CTID $ctid already exists" >&2
        return 1
    fi

    local hwaddr_oct
    hwaddr_oct=$(printf '%02X' $((ctid % 256)))
    local netcfg="name=eth0,bridge=$bridge,hwaddr=BC:24:11:00:24:$hwaddr_oct,firewall=0"
    if [ -n "$ip_cidr" ]; then
        netcfg="$netcfg,ip=$ip_cidr"
    else
        netcfg="$netcfg,ip=dhcp"
    fi

    # Errors are the one thing worth seeing here (a CTID collision, a full
    # storage, a template that failed to download), so stderr stays.
    pmx "pct create $ctid local:vztmpl/$tmpl \
        --hostname $hostname \
        --memory 128 --swap 64 --rootfs local-lvm:1 \
        --net0 $netcfg \
        --features nesting=1 --unprivileged 1 --onboot 0" \
        >/dev/null

    pmx "pct start $ctid"
    sleep 3
}

# apk add on an Alpine sidecar, through the freshly created OpenWrt router.
# Its forwarding and DNS settle over the first minute, so a single attempt
# fails often for reasons that have nothing to do with the package under
# test; retry for up to two minutes and show the last error when giving up.
# Args: ctid pkg...
ct_apk_add() {
    local ctid="$1" attempt err; shift
    err=$(mktemp)
    for attempt in 1 2 3 4 5 6 7 8; do
        if pct_sh "$ctid" "apk add --quiet $* >/dev/null" 2> "$err"; then
            rm -f "$err"; return 0
        fi
        sleep 15
    done
    echo "[ctl] apk add $* on CT $ctid failed after $attempt attempts:" >&2
    tail -4 "$err" >&2; rm -f "$err"
    return 1
}

# Install dnsmasq with query logging on an Alpine CT, listening on $ip:53,
# forwarding to 1.1.1.1. Query log goes to /tmp/queries.log inside the CT.
# Args: ctid listen_ip
dns_logger_start() {
    local ctid="$1" listen_ip="$2"
    ct_apk_add "$ctid" dnsmasq || return 1
    pct_sh "$ctid" "cat > /etc/dnsmasq.conf <<EOF
listen-address=$listen_ip
bind-interfaces
no-resolv
server=1.1.1.1
log-queries
log-facility=/tmp/queries.log
EOF
killall dnsmasq 2>/dev/null; rm -f /tmp/queries.log; dnsmasq --conf-file=/etc/dnsmasq.conf"
    sleep 1
}

ct_destroy() {
    local ctid="$1"
    pmx "pct stop $ctid >/dev/null 2>&1 || true; pct destroy $ctid --purge >/dev/null 2>&1 || true"
}

# Internal: dotted netmask from a CIDR prefix length.
_mask_from_prefix() {
    local prefix="$1" mask=""
    for _ in 1 2 3 4; do
        if [ "$prefix" -ge 8 ]; then mask="${mask}.255"; prefix=$((prefix-8))
        elif [ "$prefix" -gt 0 ]; then mask="${mask}.$((256 - (1 << (8 - prefix))))"; prefix=0
        else mask="${mask}.0"; fi
    done
    echo "${mask#.}"
}
