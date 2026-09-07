#!/bin/sh
# Reproduce the ErrorState kill-switch deadlock present in nym-vpn <= 1.27.0
# on OpenWrt. Run as root on the OpenWrt device under test. Requires:
#  - nym-vpnd installed and running
#  - account credentials already stored (`nym-vpnc account get` succeeds)
#  - kill-switch on (default in <=1.27.0)
#  - fw4 backend (OpenWrt 22.03+); nft available at /usr/sbin/nft
#
# The script forces ErrorState by temporarily moving the `nft` binary aside
# so the daemon's firewall apply fails with SetFirewallPolicy. It then nudges
# ErrorState to re-apply its policy via the `lan` toggle, which exposes the
# hardcoded empty-exemption Blocked policy in
# `error_state.rs:BlockedPolicyParameters::as_policy()`.
#
# Exit codes:
#   0 - bug reproduced (empty-exemption Blocked policy installed)
#   1 - bug not reproduced (state machine recovered, or fix is present)
#   2 - environment precondition failed
#
# WARNING: This script will briefly remove /usr/sbin/nft. If interrupted, run
#   mv /tmp/nft.bak /usr/sbin/nft
# to restore.

set -u

NFT_BIN=/usr/sbin/nft
NFT_BAK=/tmp/nft.bak.repro.$$
TABLE_BEFORE=/tmp/nym-nft-before.$$
TABLE_AFTER=/tmp/nym-nft-after.$$

cleanup() {
    if [ -f "$NFT_BAK" ] && [ ! -x "$NFT_BIN" ]; then
        echo "[cleanup] restoring nft binary"
        mv "$NFT_BAK" "$NFT_BIN"
    fi
    rm -f "$TABLE_BEFORE" "$TABLE_AFTER"
}
trap cleanup EXIT INT TERM

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[FAIL] precondition: $1 not in PATH" >&2
        exit 2
    fi
}

require nym-vpnc
require nft
require wget

if [ "$(id -u)" -ne 0 ]; then
    echo "[FAIL] must run as root" >&2
    exit 2
fi

echo "=== nym-vpn version ==="
nym-vpnc --version

echo
echo "=== preconditions ==="
if ! nym-vpnc account get 2>&1 | grep -q 'ReadyToConnect\|Connected'; then
    echo "[FAIL] account is not ready. Run nym-vpnc account store-account <mnemonic> first." >&2
    exit 2
fi

ks=$(nym-vpnc tunnel get 2>&1 | awk -F': ' '/Kill-switch/ {print $2}')
if [ "$ks" != "on" ]; then
    echo "[FAIL] kill-switch is '$ks', need 'on' to reproduce. Run: nym-vpnc tunnel set --killswitch on" >&2
    exit 2
fi
echo "kill-switch: $ks"

state=$(nym-vpnc status 2>&1 | head -1)
echo "initial state: $state"
case "$state" in
    *Disconnected*) ;;
    *)
        echo "[FAIL] expected Disconnected state at start, got: $state" >&2
        echo "       run: nym-vpnc disconnect; then re-run this script" >&2
        exit 2
        ;;
esac

echo
echo "=== baseline: DisconnectedState kill-switch with proper exemptions ==="
nft list table inet nym > "$TABLE_BEFORE" 2>/dev/null || true
endpoint_count_before=$(awk '/ip saddr .* tcp sport 443 accept/ {n++} END {print n+0}' "$TABLE_BEFORE")
dns_count_before=$(awk '/sport 53 accept/ {n++} END {print n+0}' "$TABLE_BEFORE")
echo "API endpoint accepts: $endpoint_count_before"
echo "DNS server accepts:   $dns_count_before"
if [ "$endpoint_count_before" -eq 0 ]; then
    echo "[FAIL] DisconnectedState has no API exemptions. Either no cache file exists" >&2
    echo "       (try connecting successfully once first), or fix is already applied." >&2
    exit 2
fi

echo
echo "=== inducing SetFirewallPolicy error ==="
mv "$NFT_BIN" "$NFT_BAK"
echo "[trigger] nft binary moved aside"

nym-vpnc connect >/dev/null 2>&1 &
sleep 6
mv "$NFT_BAK" "$NFT_BIN"
echo "[trigger] nft binary restored"

state=$(nym-vpnc status 2>&1 | head -1)
echo "post-trigger state: $state"
case "$state" in
    *Error*) ;;
    *)
        echo "[FAIL] daemon did not enter ErrorState. State: $state" >&2
        echo "       (may indicate the fix is in place; check error_state.rs)" >&2
        exit 1
        ;;
esac

echo
echo "=== forcing ErrorState to re-apply its (buggy) firewall policy ==="
# In <=1.27.0, ErrorState's SetTunnelSettings handler re-runs apply_policy on
# allow_lan changes. Toggle lan policy to nudge it. Restore after.
current_lan=$(nym-vpnc lan get 2>&1 | awk -F': ' '{print $2}')
case "$current_lan" in
    allow) new_lan=block ;;
    block) new_lan=allow ;;
    *)     new_lan=allow ;;
esac
echo "current lan policy: $current_lan -> $new_lan -> $current_lan"
nym-vpnc lan set "$new_lan" >/dev/null 2>&1
sleep 1
nym-vpnc lan set "$current_lan" >/dev/null 2>&1
sleep 1

echo
echo "=== bug state ==="
nft list table inet nym > "$TABLE_AFTER" 2>/dev/null || true
endpoint_count_after=$(awk '/ip saddr .* tcp sport 443 accept/ {n++} END {print n+0}' "$TABLE_AFTER")
dns_count_after=$(awk '/sport 53 accept/ {n++} END {print n+0}' "$TABLE_AFTER")
echo "API endpoint accepts: $endpoint_count_after  (was $endpoint_count_before)"
echo "DNS server accepts:   $dns_count_after  (was $dns_count_before)"

echo
echo "=== daemon API reachability (should fail when bug is present) ==="
if wget --timeout=3 -qO- https://validator.nymtech.net/api/v1/epoch/key-rotation-info >/dev/null 2>&1; then
    api_reachable=1
    echo "API reachable: YES"
else
    api_reachable=0
    echo "API reachable: NO (Operation not permitted)"
fi

echo
echo "=== verdict ==="
if [ "$endpoint_count_after" -eq 0 ] && [ "$dns_count_after" -eq 0 ] && [ "$api_reachable" -eq 0 ]; then
    cat <<EOF
[BUG REPRODUCED]
ErrorState applied FirewallPolicy::Blocked with empty allowed_endpoints and
empty dns_servers. The daemon's own API is now unreachable from the device,
which means it cannot self-recover. Original report:
a forum user, May 2026, https://forum.nymtech.net/

To recover the device manually:
  nft delete table inet nym
  /etc/init.d/nym-vpnd restart

The fix on develop populates allowed_endpoints from the cached API endpoints
and dns_servers from tunnel_settings. See:
  nym-vpn-lib/src/tunnel_state_machine/mod.rs::apply_killswitch_policy
EOF
    exit 0
else
    echo "[NOT REPRODUCED] daemon did not lock itself out as expected."
    echo "Possible causes:"
    echo "  - fix is already deployed"
    echo "  - cache file repopulated between trigger steps"
    echo "  - daemon transitioned out of ErrorState before re-apply"
    exit 1
fi
