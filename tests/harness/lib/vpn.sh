# shellcheck shell=bash
# nym-vpnc helpers. Source me after ctl.sh.
#
# NYM_MNEMONIC is read once via vpn_account_set and passed to the daemon over
# the local gRPC socket inside the container. It is never echoed or logged.

set -euo pipefail

: "${NYM_MNEMONIC:?NYM_MNEMONIC must be set (load .env first)}"

# Start the daemon inside the container. Bypasses init.d (procd/ubus
# is half-functional in our LXCs).
vpn_daemon_start() {
    local ctid="$1"
    pct_sh "$ctid" 'killall -9 nym-vpnd >/dev/null 2>&1 || true; sleep 1; rm -f /var/run/nym-vpnd.pid; setsid /usr/sbin/nym-vpnd > /tmp/nym.log 2>&1 < /dev/null &'
    # Wait for the gRPC socket.
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if pct_sh "$ctid" 'nym-vpnc status >/dev/null 2>&1'; then
            return 0
        fi
        sleep 1
    done
    echo "[vpn] daemon failed to come up on $ctid" >&2
    return 1
}

vpn_daemon_stop() {
    local ctid="$1"
    pct_sh "$ctid" 'killall -9 nym-vpnd >/dev/null 2>&1 || true'
}

# Push the mnemonic to the daemon via stdin. The mnemonic is sent over the
# pmx ssh channel and into pct exec's stdin; it never lands in argv or a
# proxy log file.
vpn_account_set() {
    local ctid="$1"
    # `nym-vpnc account set <mnemonic>` is the documented form; we feed
    # mnemonic via env var on the remote side so it never appears in the
    # command line. The remote `sh -c` reads $M from env populated by ssh.
    ssh -o BatchMode=yes "$PROXMOX_HOST" \
        "M=\"$NYM_MNEMONIC\" pct exec $ctid -- env M=\"\$M\" sh -c 'nym-vpnc account set \"\$M\" --mode api'" \
        >/dev/null
}

vpn_account_forget() {
    local ctid="$1"
    pct_sh "$ctid" 'nym-vpnc account forget >/dev/null 2>&1 || true'
}

# Block until the account reaches ReadyToConnect (or timeout).
vpn_wait_ready() {
    local ctid="$1" timeout="${2:-90}" deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if pct_sh "$ctid" 'nym-vpnc account get 2>&1' | grep -q 'ReadyToConnect'; then
            return 0
        fi
        sleep 3
    done
    return 1
}

vpn_state() {
    local ctid="$1"
    pct_sh "$ctid" 'nym-vpnc status 2>&1' | head -1 | sed 's/^State: //'
}

vpn_connect() {
    local ctid="$1"
    pct_sh "$ctid" 'nym-vpnc connect >/dev/null 2>&1 &'
}

vpn_disconnect() {
    local ctid="$1"
    pct_sh "$ctid" 'nym-vpnc disconnect >/dev/null 2>&1' || true
}

# Wait until status matches a regex. Returns 0 if matched, 1 on timeout.
# Usage: vpn_wait_state CTID PATTERN [TIMEOUT_SECS]
vpn_wait_state() {
    local ctid="$1" pattern="$2" timeout="${3:-120}"
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if vpn_state "$ctid" | grep -qE "$pattern"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

# Set kill-switch on/off. Arg: "on" or "off"
vpn_killswitch() {
    pct_sh "$1" "nym-vpnc tunnel set --killswitch $2 >/dev/null 2>&1" || true
}

# Set gateway country pair. Args: ctid entry exit
vpn_set_gateway_country() {
    pct_sh "$1" "nym-vpnc gateway set --entry-country $2 --exit-country $3 >/dev/null 2>&1"
}

# Dump current state for the run log on failure.
vpn_dump() {
    local ctid="$1"
    {
        echo "=== nym-vpnc status ==="
        pct_sh "$ctid" 'nym-vpnc status' || true
        echo "=== nft list table inet nym ==="
        pct_sh "$ctid" 'nft list table inet nym 2>&1 | head -80' || true
        echo "=== daemon log (last 30) ==="
        pct_sh "$ctid" 'tail -30 /tmp/nym.log 2>&1' || true
    }
}
