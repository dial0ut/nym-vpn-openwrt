#!/bin/bash
# Run shellcheck over every shell script the project ships or runs.
#
# Single source of truth for the file set and the severity gate, so CI and
# local runs agree. Covers the *.sh helpers plus the suffix-less scripts that
# run as root on the router: the rpcd plugin, the procd init scripts, the
# hotplug hook, the package hooks and the watchdog.
#
# Usage: scripts/security/shellcheck.sh [extra shellcheck args...]
#   SHELLCHECK  override the binary, e.g. SHELLCHECK="uvx --from shellcheck-py shellcheck"
#
# The gate is --severity=error. Raise it to warning once the existing
# warning-level findings (mostly SC2155/SC2046) have been cleaned up.
set -euo pipefail

cd "$(dirname "$0")/../.."
SHELLCHECK="${SHELLCHECK:-shellcheck}"

# shellcheck disable=SC2086  # SHELLCHECK may be a multi-word command
git ls-files -z \
    '*.sh' \
    'luci-app-nym-vpn/root/etc/init.d/*' \
    'luci-app-nym-vpn/root/etc/hotplug.d/iface/*' \
    'luci-app-nym-vpn/root/usr/libexec/rpcd/*' \
    'scripts/ipk/postinst' \
    'scripts/ipk/prerm' \
    'scripts/ipk/nym-vpn-watchdog' \
    | xargs -0 $SHELLCHECK --severity=error --external-sources "$@"

echo "shellcheck: OK"
