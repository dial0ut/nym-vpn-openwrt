# shellcheck shell=bash
# Package upgrade under procd with the kill-switch on.
#
# The slot runner installed PKG_PREV (the previous artifact) when one was
# configured; this case upgrades to PKG_CURRENT with the package manager,
# exactly as a router would, and asserts:
#   - the kill-switch table (fw4: inet nym) is present at every 1 s sample
#     taken inside the router from before the upgrade starts until the new
#     daemon is up — the upgrade must not open the firewall
#   - the daemon is running under procd afterwards and reports the new version
#   - the account survived (same identity before and after)
# Without a previous artifact there is nothing to upgrade from: SKIP.

case_begin upgrade

if [ -z "${PKG_PREV:-}" ]; then
    case_skip "no previous artifact configured (NYM_PKG_APK_PREV / NYM_PKG_IPK_PREV)"
    return 0 2>/dev/null || exit 0
fi
if [ -z "${PKG_CURRENT:-}" ]; then
    case_fail "PKG_PREV is set but no current package to upgrade to"
    return 0 2>/dev/null || exit 0
fi

vpn_killswitch "$OPENWRT_CTID" on
sleep 2
before_ver=$(vpn_version "$OPENWRT_CTID")
before_id=$(vpn_account_identity "$OPENWRT_CTID")
echo "  installed before upgrade: $before_ver (account ${before_id:-none})"

# Sampler inside the router: one line per second, table present or GONE.
pct_sh "$OPENWRT_CTID" 'rm -f /tmp/ks-poll.log; ( for i in $(seq 1 90); do if nft list table inet nym >/dev/null 2>&1; then echo "$(date +%T) present"; else echo "$(date +%T) GONE"; fi; sleep 1; done > /tmp/ks-poll.log 2>&1 & )'
sleep 2

upgrade_ok=true
if ! vpn_pkg_install "$OPENWRT_CTID" "$PKG_CURRENT"; then
    echo "  package manager returned non-zero:"
    pct_sh "$OPENWRT_CTID" 'tail -15 /tmp/pkg-install.log' >&2 || true
    upgrade_ok=false
fi

# Let the new daemon come up (postinst restarts through the init script),
# then stop sampling.
vpn_daemon_wait "$OPENWRT_CTID" 40 || { echo "  daemon did not answer after upgrade"; upgrade_ok=false; }
sleep 5
pct_sh "$OPENWRT_CTID" 'pkill -f "seq 1 90" >/dev/null 2>&1 || true'

samples=$(pct_sh "$OPENWRT_CTID" 'wc -l < /tmp/ks-poll.log' | tr -d ' ')
gone=$(pct_sh "$OPENWRT_CTID" 'grep -c GONE /tmp/ks-poll.log' | tr -d ' ')
echo "  kill-switch samples: $samples, table gone in: ${gone:-?}"
if [ "${samples:-0}" -lt 5 ]; then
    echo "  too few samples; the sampler did not run"
    upgrade_ok=false
fi
if [ "${gone:-1}" -ne 0 ]; then
    echo "  the kill-switch table disappeared during the upgrade"
    pct_sh "$OPENWRT_CTID" 'grep -n GONE /tmp/ks-poll.log | head -5' >&2 || true
    upgrade_ok=false
fi

after_ver=$(vpn_version "$OPENWRT_CTID")
echo "  installed after upgrade: $after_ver"
if [ "$after_ver" = "$before_ver" ] || [ -z "$after_ver" ]; then
    echo "  version did not change"
    upgrade_ok=false
fi
if ! vpn_daemon_under_procd "$OPENWRT_CTID"; then
    echo "  procd does not list the new daemon as running"
    upgrade_ok=false
fi
if ! pct_sh "$OPENWRT_CTID" 'logread 2>/dev/null | grep -q "nym-vpnd restart: leaving the kill-switch armed"'; then
    echo "  init script did not log the restart keep path"
    upgrade_ok=false
fi
after_id=$(vpn_account_identity "$OPENWRT_CTID")
if [ -n "$before_id" ] && [ "$after_id" != "$before_id" ]; then
    echo "  account identity changed across the upgrade: '$before_id' -> '$after_id'"
    upgrade_ok=false
fi

if $upgrade_ok; then
    case_pass "$before_ver -> $after_ver, table present in all $samples samples"
else
    case_fail "upgrade $before_ver -> ${after_ver:-?} (see log)"
    vpn_dump "$OPENWRT_CTID"
fi
