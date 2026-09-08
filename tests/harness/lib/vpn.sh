# shellcheck shell=bash
# nym-vpnc helpers. Source me after ctl.sh.
#
# NYM_MNEMONIC is read once via vpn_account_set and passed to the daemon over
# the local gRPC socket inside the container. It is never echoed or logged.

set -euo pipefail

: "${NYM_MNEMONIC:?NYM_MNEMONIC must be set (load .env first)}"

# Install a local .apk or .ipk into the OpenWrt CT. The package's postinst
# enables and (re)starts the daemon through /etc/init.d/nym-vpnd under procd,
# which is the path a real router takes; nothing in the harness starts the
# daemon by hand. Copies over stdin (the CTs have no shared filesystem).
# Args: ctid path
vpn_pkg_install() {
    local ctid="$1" file="$2" name rc=0
    name=$(basename "$file")
    _ssh_host "pct exec $ctid -- sh -c 'cat > /tmp/$name'" < "$file" || return 1
    case "$name" in
        *.apk)
            # apk resolves the local file's dependencies from its index.
            pct_sh "$ctid" "apk update >/tmp/pkg-update.log 2>&1 || true; apk add --allow-untrusted /tmp/$name >/tmp/pkg-install.log 2>&1" || rc=$? ;;
        *.ipk)
            # A fresh rootfs has no package lists; without `opkg update` the
            # dependencies (libmnl, libnftnl, kmod-*) cannot be resolved and
            # opkg exits 255.
            pct_sh "$ctid" "opkg update >/tmp/pkg-update.log 2>&1 || true; opkg install /tmp/$name >/tmp/pkg-install.log 2>&1" || rc=$? ;;
        *) echo "[vpn] package must end in .apk or .ipk: $name" >&2; return 1 ;;
    esac
    # Do not trust the exit code alone: the package manager's own view of
    # success is what matters, and it must have left the binaries behind.
    if [ "$rc" -ne 0 ] || ! pct_sh "$ctid" 'command -v nym-vpnc >/dev/null && command -v nym-vpnd >/dev/null'; then
        echo "[vpn] package install of $name failed (rc=$rc); package manager output:" >&2
        pct_sh "$ctid" 'tail -15 /tmp/pkg-install.log 2>/dev/null' >&2 || true
        return 1
    fi
    return 0
}

# The firewall helpers the package must ship: the includes fw3/fw4 run and
# the two files they source. An install that lacks one has no boot block
# and no reload survival, so this is asserted right after every install of
# the package under test.
# Args: ctid
vpn_fw_helpers_present() {
    local ctid="$1" f ok=0
    for f in fw3-include.sh fw4-include.sh fw-boot-guard.sh fw-rules.sh; do
        if ! pct_sh "$ctid" "[ -f /usr/share/nym-vpn/$f ]"; then
            echo "  missing /usr/share/nym-vpn/$f" >&2
            ok=1
        fi
    done
    return "$ok"
}

# Installed package version as the package manager reports it.
vpn_version() {
    local ctid="$1"
    pct_sh "$ctid" 'apk list --installed 2>/dev/null | grep -o "nym-vpn-[0-9][^ ]*" || opkg list-installed 2>/dev/null | grep "^nym-vpn " | awk "{print \$3}"' | head -1
}

# Wait until the daemon answers on its socket. Args: ctid [timeout]
vpn_daemon_wait() {
    local ctid="$1" timeout="${2:-30}" i=0
    while [ "$i" -lt "$timeout" ]; do
        if pct_sh "$ctid" 'nym-vpnc status >/dev/null 2>&1'; then
            return 0
        fi
        sleep 1; i=$((i + 1))
    done
    echo "[vpn] daemon did not answer on $ctid within ${timeout}s" >&2
    return 1
}

# True when procd lists a running nym-vpnd instance.
vpn_daemon_under_procd() {
    local ctid="$1"
    pct_sh "$ctid" 'ubus call service list "{\"name\":\"nym-vpnd\"}" 2>/dev/null | grep -q "\"running\": true"'
}

# Stop/start/restart through the init script, like an administrator would.
vpn_daemon_stop()    { pct_sh "$1" '/etc/init.d/nym-vpnd stop >/dev/null 2>&1'; }
vpn_daemon_start()   { pct_sh "$1" '/etc/init.d/nym-vpnd start >/dev/null 2>&1' && vpn_daemon_wait "$1" 30; }
vpn_daemon_restart() { pct_sh "$1" '/etc/init.d/nym-vpnd restart >/dev/null 2>&1' && vpn_daemon_wait "$1" 30; }

# Register the account. The mnemonic travels on stdin the whole way — local
# ssh, pct exec, the container's sh — so it is in no argv on this machine or
# on the Proxmox host. nym-vpnc has no stdin form for `account set`, so inside
# the container it is that one process's argument for the duration of the
# call; nothing else on the container sees it.
vpn_account_set() {
    local ctid="$1"
    printf '%s\n' "$NYM_MNEMONIC" | _ssh_host \
        "pct exec $ctid -- sh -c 'IFS= read -r M && exec nym-vpnc account set \"\$M\" --mode api'" \
        >/dev/null
}

vpn_account_forget() {
    local ctid="$1"
    pct_sh "$ctid" 'nym-vpnc account forget >/dev/null 2>&1 || true'
}

# Block until the account reaches ReadyToConnect (or timeout).
vpn_wait_ready() {
    local ctid="$1" timeout="${2:-90}"
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if pct_sh "$ctid" 'nym-vpnc account get 2>&1' | grep -q '^Account state: ReadyToConnect$'; then
            return 0
        fi
        sleep 3
    done
    return 1
}

# "Account state: <State>" as printed by nym-vpnc, or "unknown".
vpn_account_state() {
    pct_sh "$1" 'nym-vpnc account get 2>&1' | sed -n 's/^Account state: //p' | head -1 | grep . || echo unknown
}

# Account identity line, for asserting an upgrade kept the account.
vpn_account_identity() {
    pct_sh "$1" 'nym-vpnc account get 2>&1' | sed -n 's/^Account identity: //p' | head -1
}

# For cases that need a tunnel: SKIP with the reason when the slot's account
# never became ReadyToConnect (the slot runner exports ACCOUNT_READY).
vpn_require_ready() {
    if [ "${ACCOUNT_READY:-0}" != 1 ]; then
        case_skip "needs a connectable account; registration ended in $(vpn_account_state "$OPENWRT_CTID")"
        return 1
    fi
    return 0
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
        echo "=== procd view ==="
        pct_sh "$ctid" 'ubus call service list "{\"name\":\"nym-vpnd\"}" 2>&1' || true
        echo "=== daemon + include log (last 40) ==="
        pct_sh "$ctid" 'logread 2>&1 | grep -E "nym-vpnd|nym-vpn:" | tail -40' || true
    }
}

# Whether the daemon can reach the Nym API right now. Probes through the
# daemon (an unknown gateway id forces a directory lookup, and "not found"
# means the API answered), not with wget from the router shell: under the
# Blocked policy only the daemon's own DNS hatch is open, so a router-shell
# lookup fails by design and would say nothing about issue #15.
vpn_api_reachable() {
    local out
    out=$(pct_sh "$1" 'nym-vpnc gateway test --id 11111111111111111111111111111111 --count 1 --timeout 1 2>&1 | tail -1')
    echo "$out" | grep -q 'not found'
}
