#!/bin/bash
# Run shellcheck over every shell script the project ships or runs; the one
# file set and severity gate for CI and local runs.
#
# Usage: scripts/security/shellcheck.sh [extra shellcheck args...]
#   SHELLCHECK  override the binary, e.g. SHELLCHECK="uvx --from shellcheck-py shellcheck"
#
# Gate is --severity=error until the SC2155/SC2046 warnings are cleaned up.
set -euo pipefail

cd "$(dirname "$0")/../.."
SHELLCHECK="${SHELLCHECK:-shellcheck}"

# shellcheck disable=SC2086  # SHELLCHECK may be a multi-word command
git ls-files -z \
    '*.sh' \
    'luci-app-nym-vpn/root/etc/init.d/*' \
    'luci-app-nym-vpn/root/usr/libexec/rpcd/*' \
    'scripts/ipk/postinst' \
    'scripts/ipk/prerm' \
    | xargs -0 $SHELLCHECK --severity=error --external-sources "$@"

echo "shellcheck: OK"
