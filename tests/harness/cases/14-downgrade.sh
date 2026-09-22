# shellcheck shell=bash
# Downgrade to the previous artifact, then upgrade back to the package
# under test, so the cases after this one still test the current package.
#
# Both package managers run a downgrade as an upgrade (PKG_UPGRADE=1), so
# prerm never takes its removal path. Asserts the same account identity and
# settings after the downgrade and again after the upgrade back, with the
# daemon under procd both times. Without a previous artifact: SKIP.

case_begin downgrade

if [ -z "${PKG_PREV:-}" ] || [ -z "${PKG_CURRENT:-}" ]; then
    case_skip "no previous artifact configured (NYM_PKG_APK_PREV / NYM_PKG_IPK_PREV)"
    return 0 2>/dev/null || exit 0
fi
if ! vpn_keep_begin "$OPENWRT_CTID"; then
    case_skip "no registered account to compare across the downgrade"
    return 0 2>/dev/null || exit 0
fi

ok=true
current_ver=$(vpn_version "$OPENWRT_CTID")
flags=""
[ "$(vpn_pkg_manager "$OPENWRT_CTID")" = opkg ] && flags="--force-downgrade"
if ! vpn_pkg_install "$OPENWRT_CTID" "$PKG_PREV" "$flags"; then
    echo "  downgrade failed"
    ok=false
fi
prev_ver=$(vpn_version "$OPENWRT_CTID")
echo "  downgraded $current_ver -> $prev_ver"
if [ "$prev_ver" = "$current_ver" ]; then
    echo "  version did not change"
    ok=false
fi
# vpn_keep_end turns the kill-switch back on; the upgrade back is checked
# against the same "off" marker, so set it again first.
vpn_keep_end "$OPENWRT_CTID" || { echo "  (after the downgrade)"; ok=false; }

if vpn_keep_begin "$OPENWRT_CTID"; then
    if ! vpn_pkg_install "$OPENWRT_CTID" "$PKG_CURRENT"; then
        echo "  upgrade back failed"
        ok=false
    fi
    vpn_keep_end "$OPENWRT_CTID" || { echo "  (after the upgrade back)"; ok=false; }
else
    ok=false
fi
after_ver=$(vpn_version "$OPENWRT_CTID")
if [ "$after_ver" != "$current_ver" ]; then
    echo "  not back on the package under test: $after_ver (expected $current_ver)"
    ok=false
fi

if $ok; then
    case_pass "$current_ver -> $prev_ver -> $after_ver, account ${KEEP_ID} and settings kept"
else
    case_fail "downgrade round trip lost state (see log)"
    vpn_dump "$OPENWRT_CTID"
fi
