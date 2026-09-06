#!/bin/sh
# Boot-time kill-switch guard, shared by fw3-include.sh and fw4-include.sh.
#
# Sourced, not executed: defines nym_boot_block_wanted() and the paths it
# reads. It answers one question for the firewall include — should a
# boot-time emergency block for WAN egress be in force right now? — from
# state that exists before the daemon has run at all since power-on:
#
#   /etc/nym/nym-vpnd.json  the daemon's persisted settings (killswitch,
#                           legacy_split_tunnel); written atomically by the
#                           daemon, only read here
#   /etc/rc.d/S*nym-vpnd    the daemon is enabled to start at boot
#   /tmp/nym-vpnd.stopped   the administrator stopped the daemon explicitly
#                           (the init script writes it on stop and clears it
#                           on start; /tmp is tmpfs, so a reboot clears it)
#
# Whether the daemon has already applied a policy is backend-specific and is
# checked by the caller. The verdict errs towards NOT blocking: a setting
# that cannot be read with confidence counts as "off" — the same default the
# daemon falls back to for an unreadable config — and NYM_BOOT_REASON tells
# the caller why, for the log.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 Nym Technologies SA <contact@nymtech.net>

NYM_VPND_CONFIG="${NYM_VPND_CONFIG:-/etc/nym/nym-vpnd.json}"
NYM_RC_DIR="${NYM_RC_DIR:-/etc/rc.d}"
NYM_VPND_STOPPED="${NYM_VPND_STOPPED:-/tmp/nym-vpnd.stopped}"
NYM_BOOT_REASON=""

# Print the JSON boolean stored under a top-level key of the daemon config:
# "true"/"false" when present, "absent" when the key or the file is missing
# (the daemon then uses its default, which is false for both keys read here),
# "unknown" when the file exists but cannot be read with confidence.
nym_config_bool() {
    local key="$1" value

    [ -f "$NYM_VPND_CONFIG" ] || { echo absent; return 0; }

    if command -v jsonfilter >/dev/null 2>&1; then
        # OpenWrt's JSON extractor. It exits non-zero and prints nothing both
        # for a missing key and for unparseable JSON; the daemon handles both
        # the same way (defaults), so "absent" is the faithful answer.
        value=$(jsonfilter -i "$NYM_VPND_CONFIG" -e "@.$key" 2>/dev/null) \
            || { echo absent; return 0; }
        case "$value" in
            true | false) echo "$value" ;;
            "") echo absent ;;
            *) echo unknown ;;
        esac
        return 0
    fi

    # No jsonfilter (not an OpenWrt image): a conservative text scan. The
    # daemon pretty-prints one key per line; accept the key anywhere in the
    # file but only when it occurs exactly once, since a second occurrence
    # could belong to a nested object.
    value=$(grep -oE "\"$key\"[[:space:]]*:[[:space:]]*(true|false)" "$NYM_VPND_CONFIG" 2>/dev/null \
        | sed 's/.*://; s/[[:space:]]//g') || value=""
    # shellcheck disable=SC2086  # word-split on purpose: one token per match
    set -- $value
    case $# in
        0)
            if grep -q "\"$key\"" "$NYM_VPND_CONFIG" 2>/dev/null; then
                echo unknown
            else
                echo absent
            fi
            ;;
        1) echo "$1" ;;
        *) echo unknown ;;
    esac
}

# The daemon is enabled to start at boot: its rc.d start link exists and
# points at an executable init script.
nym_vpnd_enabled_at_boot() {
    local link
    for link in "$NYM_RC_DIR"/S[0-9]*nym-vpnd; do
        [ -x "$link" ] && return 0
    done
    return 1
}

# Succeeds when a boot-time block belongs in the firewall right now, fails
# otherwise. NYM_BOOT_REASON explains the verdict either way. The effective
# kill-switch is `killswitch && !legacy_split_tunnel`, exactly as the daemon
# computes it: legacy split tunnelling routes LAN clients past the tunnel on
# purpose, so it must never be fenced off, at boot or otherwise.
nym_boot_block_wanted() {
    local killswitch legacy

    if [ -f "$NYM_VPND_STOPPED" ]; then
        NYM_BOOT_REASON="nym-vpnd was stopped by the administrator ($NYM_VPND_STOPPED present)"
        return 1
    fi
    if ! nym_vpnd_enabled_at_boot; then
        NYM_BOOT_REASON="nym-vpnd is not enabled to start at boot (no $NYM_RC_DIR/S*nym-vpnd)"
        return 1
    fi

    killswitch=$(nym_config_bool killswitch)
    case "$killswitch" in
        true) ;;
        false | absent)
            NYM_BOOT_REASON="kill-switch is off in $NYM_VPND_CONFIG"
            return 1
            ;;
        *)
            NYM_BOOT_REASON="cannot read the kill-switch setting from $NYM_VPND_CONFIG; not blocking"
            return 1
            ;;
    esac

    legacy=$(nym_config_bool legacy_split_tunnel)
    case "$legacy" in
        false | absent) ;;
        true)
            NYM_BOOT_REASON="legacy split tunnelling forces the kill-switch off"
            return 1
            ;;
        *)
            NYM_BOOT_REASON="cannot read the legacy split-tunnel setting from $NYM_VPND_CONFIG; not blocking"
            return 1
            ;;
    esac

    NYM_BOOT_REASON="kill-switch on, nym-vpnd enabled at boot, no policy applied yet"
    return 0
}
