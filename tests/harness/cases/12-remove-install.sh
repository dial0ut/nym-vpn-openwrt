# shellcheck shell=bash
# Remove the package, then install it again (opkg remove / apk del, then a
# plain install of the package under test).
#
# The removal takes prerm's real-removal path, which used to `rm -rf
# /etc/nym`. Asserts:
#   - /etc/nym is still there after the removal and prerm said so
#   - after the install the daemon runs under procd with the same account
#     identity and the same daemon settings (the kill-switch is turned off
#     first, the non-default value, so a lost settings file shows as "on")

case_begin remove-install

if [ -z "${PKG_CURRENT:-}" ]; then
    case_skip "no package under test (NYM_PKG_APK / NYM_PKG_IPK / NYM_PKG_FILE)"
    return 0 2>/dev/null || exit 0
fi
if ! vpn_keep_begin "$OPENWRT_CTID"; then
    case_skip "no registered account to compare across the reinstall"
    return 0 2>/dev/null || exit 0
fi

ok=true
if ! vpn_pkg_remove "$OPENWRT_CTID"; then
    echo "  package removal returned non-zero:"
    pct_sh "$OPENWRT_CTID" 'tail -15 /tmp/pkg-remove.log' >&2 || true
    ok=false
fi
if ! pct_sh "$OPENWRT_CTID" '[ -d /etc/nym ]'; then
    echo "  /etc/nym is gone after the removal"
    ok=false
fi
if ! pct_sh "$OPENWRT_CTID" 'grep -q "kept in /etc/nym" /tmp/pkg-remove.log'; then
    echo "  prerm did not print the /etc/nym hint"
    ok=false
fi
# procd delivers the stop asynchronously; give it a few seconds.
if ! pct_sh "$OPENWRT_CTID" 'for i in 1 2 3 4 5 6 7 8 9 10; do pidof nym-vpnd >/dev/null || exit 0; sleep 1; done; exit 1'; then
    echo "  nym-vpnd still runs 10 s after the removal"
    ok=false
fi

if ! vpn_pkg_install "$OPENWRT_CTID" "$PKG_CURRENT"; then
    echo "  reinstall failed"
    ok=false
fi
vpn_keep_end "$OPENWRT_CTID" || ok=false

if $ok; then
    case_pass "account ${KEEP_ID} and settings kept across remove + install"
else
    case_fail "remove + install lost state (see log)"
    vpn_dump "$OPENWRT_CTID"
fi
