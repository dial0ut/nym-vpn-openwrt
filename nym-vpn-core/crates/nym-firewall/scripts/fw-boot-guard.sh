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
#   $NYM_RUNTIME_DIR/stopped  the administrator stopped the daemon explicitly
#                           (the init script writes it on stop and clears it
#                           on start; /var/run is tmpfs, so a reboot clears
#                           it). Honoured only inside a private root-owned
#                           directory — see nym_runtime_dir_trusted below.
#
# Whether the daemon has already applied a policy is backend-specific and is
# checked by the caller. A setting that is absent or cannot be read takes the
# daemon's own default — kill-switch on, legacy split tunnelling off — so the
# guard and the daemon that is about to start agree. The daemon preserves an
# unparseable config as .json.bak and starts with defaults, and writes a
# missing config on its first start; either way a daemon that comes up
# applies a Blocked policy and lifts the boot block itself. (A daemon that
# cannot come up — a non-mainnet network with no cached discovery fails
# before its first policy — leaves the block in place until `stop`; see
# docs/architecture/killswitch-contract.md.) Only an explicit "false" turns
# the block off. NYM_BOOT_REASON tells the caller what was
# decided and from which value, for the log.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 Nym Technologies SA <contact@nymtech.net>

NYM_VPND_CONFIG="${NYM_VPND_CONFIG:-/etc/nym/nym-vpnd.json}"
NYM_RC_DIR="${NYM_RC_DIR:-/etc/rc.d}"
# Runtime-state directory shared with the daemon (RUNTIME_DIR in the fw3/fw4
# backends), both firewall includes and the init script. It sits under
# /var/run, where only root can create entries — never /tmp, where any local
# user could plant the stop marker to suppress the boot block, or a rules
# file for the fw3 include to load. The daemon creates it 0700; nothing in
# it is trusted unless it still is a plain directory owned by root with no
# group/other access.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
NYM_VPND_STOPPED="${NYM_VPND_STOPPED:-$NYM_RUNTIME_DIR/stopped}"
NYM_BOOT_REASON=""

# Whether the runtime directory can be trusted: a real directory (not a
# symlink), owned by uid 0, mode exactly 0700. Anything else, including a
# missing directory, means "no state".
nym_runtime_dir_trusted() {
    [ -d "$NYM_RUNTIME_DIR" ] && [ ! -L "$NYM_RUNTIME_DIR" ] || return 1
    # busybox has no stat(1) on stock OpenWrt images; find(1) with -user and
    # -perm is always built in. Without -L it does not follow a symlinked
    # argument, so a planted symlink fails -type d here as well.
    [ -n "$(find "$NYM_RUNTIME_DIR" -maxdepth 0 -type d -user root -perm 0700 -print 2>/dev/null)" ]
}

# For writers: create the directory when missing (root only — /var/run is
# root-owned 0755), then apply the same verdict. Never repairs an existing
# entry: a wrong one is a reason to refuse, not to fix up.
nym_runtime_dir_prepare() {
    if [ ! -e "$NYM_RUNTIME_DIR" ] && [ ! -L "$NYM_RUNTIME_DIR" ]; then
        mkdir -m 0700 "$NYM_RUNTIME_DIR" 2>/dev/null
    fi
    nym_runtime_dir_trusted
}

# Print the JSON boolean stored under a top-level key of the daemon config:
# "true"/"false" when present, "absent" when the key or the file is missing
# (an older config version the daemon migrates, or no config yet), "unknown"
# when the file exists but cannot be read with confidence. The caller maps
# both "absent" and "unknown" to the daemon's default for the key.
nym_config_bool() {
    local key="$1" value

    [ -f "$NYM_VPND_CONFIG" ] || { echo absent; return 0; }

    if command -v jsonfilter >/dev/null 2>&1; then
        # OpenWrt's JSON extractor. It exits non-zero and prints nothing both
        # for a missing key and for unparseable JSON. The daemon falls back
        # to its default in both cases (migration default for a missing key,
        # a preserved .json.bak plus defaults for bad JSON), so "absent"
        # serves both.
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
        if nym_runtime_dir_trusted; then
            NYM_BOOT_REASON="nym-vpnd was stopped by the administrator ($NYM_VPND_STOPPED present)"
            return 1
        fi
        # A marker outside a private root-owned directory could have been
        # planted to keep the boot block off; it does not count.
        logger -t nym-vpn "ignoring $NYM_VPND_STOPPED: $NYM_RUNTIME_DIR is not a private root-owned directory"
    fi
    if ! nym_vpnd_enabled_at_boot; then
        NYM_BOOT_REASON="nym-vpnd is not enabled to start at boot (no $NYM_RC_DIR/S*nym-vpnd)"
        return 1
    fi

    # Absent or unreadable settings take the daemon's defaults (see header):
    # only an explicit false opens, only an explicit true forces legacy off.
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
