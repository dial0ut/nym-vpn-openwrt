#!/bin/sh
# Boot-time kill-switch guard, sourced by fw3-include.sh and fw4-include.sh.
# nym_boot_block_wanted() decides from state that exists before the daemon
# has run since power-on: the daemon's settings file, its rc.d start link,
# and the init script's stop marker (honoured only inside a private
# root-owned directory). Whether a policy is already applied is the caller's
# check. Absent or unreadable settings take the daemon's own defaults
# (kill-switch on, legacy split tunnelling off) so guard and daemon agree;
# only an explicit "false" opens. A daemon that cannot come up leaves the
# block until `stop` (docs/architecture/killswitch-contract.md).
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 Nym Technologies SA <contact@nymtech.net>

NYM_VPND_CONFIG="${NYM_VPND_CONFIG:-/etc/nym/nym-vpnd.json}"
NYM_RC_DIR="${NYM_RC_DIR:-/etc/rc.d}"
# RUNTIME_DIR in common.rs. Under /var/run, never /tmp: a local user could
# plant the stop marker or a rules file there.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
NYM_VPND_STOPPED="${NYM_VPND_STOPPED:-$NYM_RUNTIME_DIR/stopped}"
NYM_BOOT_REASON=""

# A real directory (not a symlink), uid 0, mode exactly 0700; anything else,
# missing included, means "no state".
nym_runtime_dir_trusted() {
    [ -d "$NYM_RUNTIME_DIR" ] && [ ! -L "$NYM_RUNTIME_DIR" ] || return 1
    # Stock busybox has no stat(1); find -user/-perm is always built in and
    # does not follow a symlinked argument without -L.
    [ -n "$(find "$NYM_RUNTIME_DIR" -maxdepth 0 -type d -user root -perm 0700 -print 2>/dev/null)" ]
}

# For writers. Never repairs an existing entry: a wrong one is a reason to
# refuse, not to fix up.
nym_runtime_dir_prepare() {
    if [ ! -e "$NYM_RUNTIME_DIR" ] && [ ! -L "$NYM_RUNTIME_DIR" ]; then
        mkdir -m 0700 "$NYM_RUNTIME_DIR" 2>/dev/null
    fi
    nym_runtime_dir_trusted
}

# Prints "true"/"false", "absent" (key or file missing) or "unknown"
# (unreadable); the caller maps the last two to the daemon's default.
nym_config_bool() {
    local key="$1" value

    [ -f "$NYM_VPND_CONFIG" ] || { echo absent; return 0; }

    if command -v jsonfilter >/dev/null 2>&1; then
        # jsonfilter fails silently for a missing key and for bad JSON alike;
        # the daemon takes its default in both cases, so "absent" serves both.
        value=$(jsonfilter -i "$NYM_VPND_CONFIG" -e "@.$key" 2>/dev/null) \
            || { echo absent; return 0; }
        case "$value" in
            true | false) echo "$value" ;;
            "") echo absent ;;
            *) echo unknown ;;
        esac
        return 0
    fi

    # No jsonfilter: text scan, accepted only when the key occurs exactly
    # once (a second occurrence could belong to a nested object).
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

nym_vpnd_enabled_at_boot() {
    local link
    for link in "$NYM_RC_DIR"/S[0-9]*nym-vpnd; do
        [ -x "$link" ] && return 0
    done
    return 1
}

# Effective kill-switch is `killswitch && !legacy_split_tunnel`, as the
# daemon computes it. NYM_BOOT_REASON explains the verdict either way.
nym_boot_block_wanted() {
    local killswitch legacy

    if [ -f "$NYM_VPND_STOPPED" ]; then
        if nym_runtime_dir_trusted; then
            NYM_BOOT_REASON="nym-vpnd was stopped by the administrator ($NYM_VPND_STOPPED present)"
            return 1
        fi
        # Could have been planted to keep the boot block off.
        logger -t nym-vpn "ignoring $NYM_VPND_STOPPED: $NYM_RUNTIME_DIR is not a private root-owned directory"
    fi
    if ! nym_vpnd_enabled_at_boot; then
        NYM_BOOT_REASON="nym-vpnd is not enabled to start at boot (no $NYM_RC_DIR/S*nym-vpnd)"
        return 1
    fi

    # Only an explicit false opens; only an explicit true forces legacy off.
    killswitch=$(nym_config_bool killswitch)
    if [ "$killswitch" = "false" ]; then
        NYM_BOOT_REASON="kill-switch is off in $NYM_VPND_CONFIG"
        return 1
    fi

    legacy=$(nym_config_bool legacy_split_tunnel)
    if [ "$legacy" = "true" ]; then
        NYM_BOOT_REASON="legacy split tunnelling forces the kill-switch off"
        return 1
    fi

    NYM_BOOT_REASON="kill-switch on (config: killswitch=$killswitch, legacy_split_tunnel=$legacy), nym-vpnd enabled at boot, no policy applied yet"
    return 0
}
