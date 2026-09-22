# shellcheck shell=bash
# `opkg install --force-reinstall` of the package under test.
#
# opkg removes the installed package first (prerm's real-removal path, no
# PKG_UPGRADE), which used to `rm -rf /etc/nym`. Asserts the daemon runs
# under procd afterwards with the same account identity and settings. apk
# has no forced reinstall of a sideloaded file; 12-remove-install covers
# the removal path there.

case_begin force-reinstall

if [ -z "${PKG_CURRENT:-}" ]; then
    case_skip "no package under test (NYM_PKG_APK / NYM_PKG_IPK / NYM_PKG_FILE)"
    return 0 2>/dev/null || exit 0
fi
if [ "$(vpn_pkg_manager "$OPENWRT_CTID")" != opkg ]; then
    case_skip "apk router: no forced reinstall of a local package (remove-install covers it)"
    return 0 2>/dev/null || exit 0
fi
if ! vpn_keep_begin "$OPENWRT_CTID"; then
    case_skip "no registered account to compare across the reinstall"
    return 0 2>/dev/null || exit 0
fi

ok=true
if ! vpn_pkg_install "$OPENWRT_CTID" "$PKG_CURRENT" --force-reinstall; then
    echo "  forced reinstall failed"
    ok=false
fi
vpn_keep_end "$OPENWRT_CTID" || ok=false

if $ok; then
    case_pass "account ${KEEP_ID} and settings kept across --force-reinstall"
else
    case_fail "--force-reinstall lost state (see log)"
    vpn_dump "$OPENWRT_CTID"
fi
