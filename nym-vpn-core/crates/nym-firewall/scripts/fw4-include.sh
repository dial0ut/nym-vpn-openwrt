#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw4 (nftables). Run by fw4 on
# start, restart and reload via a `config include` in /etc/config/firewall.
#
# `fw4 reload` rebuilds `inet fw4` from scratch, and nothing of ours lives
# in it: masquerade, MSS clamp and LAN-to-tunnel forwarding come from the
# `nym` zone in /etc/config/firewall, which fw4 renders itself. The
# kill-switch is the daemon's separate `inet nym` table, which survives a
# reload and must never be deleted here. What this script covers is boot:
# firewall S19 and network S20 come up long before nym-vpnd S90, so when
# fw-boot-guard.sh says the kill-switch is armed and no `inet nym` exists
# yet, an `inet nym_boot` block goes in. The daemon deletes it once its
# first policy is live; this script, the init script and prerm remove it
# when the conditions no longer hold.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Optional hints, read only once nym_runtime_dir_trusted has vouched for the
# directory (RULES_NFT is fed to `nft -f`). Nothing writes policy.nft today;
# the fw4 backend pipes its ruleset to `nft -f -`.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
RULES_NFT="$NYM_RUNTIME_DIR/policy.nft"

# The daemon's table; present in every tunnel state once a policy is applied.
NYM_TABLE="nym"

# Both helpers ship in the package. Without the guard there is no runtime
# directory check and no boot decision; without the generated rule set no
# block can be built. Either way nothing this script could install would
# be lifted by anything, so it fails towards not blocking, loudly.
NYM_SHARE_DIR="${NYM_SHARE_DIR:-/usr/share/nym-vpn}"
[ -r "$NYM_SHARE_DIR/fw-boot-guard.sh" ] || {
    logger -t nym-vpn "CRITICAL: $NYM_SHARE_DIR/fw-boot-guard.sh is missing; the fw4 include cannot run and installs no block"
    exit 1
}
# shellcheck source-path=SCRIPTDIR
# shellcheck source=fw-boot-guard.sh
. "$NYM_SHARE_DIR/fw-boot-guard.sh"

[ -r "$NYM_SHARE_DIR/fw-rules.sh" ] || {
    logger -t nym-vpn "CRITICAL: $NYM_SHARE_DIR/fw-rules.sh is missing; the fw4 include cannot run and installs no block"
    exit 1
}
# shellcheck source-path=SCRIPTDIR
# shellcheck source=fw-rules.sh
. "$NYM_SHARE_DIR/fw-rules.sh"

BOOT_TABLE="$NYM_BOOT_TABLE"

STATE_TRUSTED=0
have_state() {
    [ "$STATE_TRUSTED" = 1 ] && [ -f "$1" ]
}

nym_table_present() {
    nft list table inet "$NYM_TABLE" >/dev/null 2>&1
}

boot_block_present() {
    nft list table inet "$BOOT_TABLE" >/dev/null 2>&1
}

# Atomic replace of the generated table; rules and order: boot_rules.rs.
install_boot_block() {
    nym_boot_block_nft | nft -f -
}

# $1 is the reason, for the log.
remove_boot_block() {
    boot_block_present || return 0
    if nft delete table inet "$BOOT_TABLE" 2>/dev/null; then
        logger -t nym-vpn "Removed boot-time kill-switch block: $1"
        return 0
    fi
    logger -t nym-vpn "CRITICAL: failed to remove boot-time kill-switch block (inet $BOOT_TABLE)"
    return 1
}

# The daemon applies `inet nym` first and deletes `inet nym_boot` last, and
# persists a kill-switch toggle before opening the firewall, so the re-check
# after the install catches a decision that raced either.
reconcile_boot_block() {
    if nym_table_present; then
        remove_boot_block "daemon policy is live" || return 1
        return 0
    fi
    if ! nym_boot_block_wanted; then
        remove_boot_block "$NYM_BOOT_REASON" || return 1
        return 0
    fi

    logger -t nym-vpn "Installing boot-time kill-switch block: $NYM_BOOT_REASON"
    if ! install_boot_block; then
        logger -t nym-vpn "CRITICAL: failed to install boot-time kill-switch block (inet $BOOT_TABLE)"
        return 1
    fi

    if nym_table_present; then
        remove_boot_block "daemon policy went live meanwhile" || return 1
    elif ! nym_boot_block_wanted; then
        remove_boot_block "$NYM_BOOT_REASON" || return 1
    fi
    return 0
}

main() {
    local failed=0

    # Dead today (nothing writes RULES_NFT); `inet nym` survives reloads on its own.
    if have_state "$RULES_NFT"; then
        logger -t nym-vpn "Re-applying saved nftables rules after fw4 restart"
        nft -f "$RULES_NFT" 2>/dev/null || logger -t nym-vpn "Failed to apply saved rules"
    fi

    reconcile_boot_block || failed=1
    return "$failed"
}

# Missing is normal before the daemon's first run: no hints.
if nym_runtime_dir_trusted; then
    STATE_TRUSTED=1
elif [ -e "$NYM_RUNTIME_DIR" ] || [ -L "$NYM_RUNTIME_DIR" ]; then
    logger -t nym-vpn "$NYM_RUNTIME_DIR is not a private root-owned directory; ignoring persisted state"
fi

main "$@"
