#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw3 (iptables). Run by fw3 on
# start, restart and reload, and by the init script on explicit stop.
#
# `fw3 reload` leaves foreign chains and the *_rule hooks alone, so a reload
# only reconciles. `fw3 restart`/`stop` flush every table and run this script
# last; the daemon's persisted restore scripts in $NYM_RUNTIME_DIR (v4.rules,
# v6.rules, ifaces, transition, lock) are what rebuild the kill-switch then.
# The files are fed to iptables-restore as root, so the directory must be a
# private root-owned one (never /tmp). The whole run holds the same flock the
# daemon holds for every apply/reset. A transition marker means a daemon died
# mid-apply: install the emergency block rather than read half-written
# state. No rules file: tear down leftovers, or, when fw-boot-guard.sh says
# the kill-switch is armed, install the boot rule set (firewall S19 and
# network S20 come up long before nym-vpnd S90); the daemon lifts either
# block with its first policy. The rule sets come from fw-rules.sh, generated
# from boot_rules.rs, so the block installed here is the one the daemon lifts.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Names are a contract with the fw3 backend (common.rs). Trusted only after
# nym_runtime_dir_prepare.
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
RULES_V4="$NYM_RUNTIME_DIR/v4.rules"
RULES_V6="$NYM_RUNTIME_DIR/v6.rules"
IFACES_FILE="$NYM_RUNTIME_DIR/ifaces"
TRANSITION_FILE="$NYM_RUNTIME_DIR/transition"
LOCK_FILE="$NYM_RUNTIME_DIR/lock"

# fw3 user chains, preserved on reload and recreated empty on restart.
HOOK_INPUT="input_rule"
HOOK_OUTPUT="output_rule"
HOOK_FORWARD="forwarding_rule"

# Same chain names as the daemon's fw3 backend.
NYM_INPUT="NYM_INPUT"
NYM_OUTPUT="NYM_OUTPUT"
NYM_FORWARD="NYM_FORWARD"
NYM_MANGLE_PRE="NYM_MANGLE_PREROUTING"
NYM_MANGLE_OUT="NYM_MANGLE_OUTPUT"
NAT_CHAIN="NYM_POSTROUTING"
FORWARD_LAN_CHAIN="NYM_FORWARD_LAN"

# A missing guard must fail towards not blocking, never towards a block
# nothing can lift.
NYM_SHARE_DIR="${NYM_SHARE_DIR:-/usr/share/nym-vpn}"
if [ -r "$NYM_SHARE_DIR/fw-boot-guard.sh" ]; then
    # shellcheck source-path=SCRIPTDIR
    # shellcheck source=fw-boot-guard.sh
    . "$NYM_SHARE_DIR/fw-boot-guard.sh"
else
    nym_boot_block_wanted() {
        NYM_BOOT_REASON="$NYM_SHARE_DIR/fw-boot-guard.sh is missing; not blocking"
        return 1
    }
    nym_runtime_dir_prepare() { return 1; }
fi

# Emergency and boot-time rule sets, generated from boot_rules.rs. Without
# the file the generators print nothing and no block can be built.
if [ -r "$NYM_SHARE_DIR/fw-rules.sh" ]; then
    # shellcheck source-path=SCRIPTDIR
    # shellcheck source=fw-rules.sh
    . "$NYM_SHARE_DIR/fw-rules.sh"
else
    logger -t nym-vpn "CRITICAL: $NYM_SHARE_DIR/fw-rules.sh is missing; no emergency block can be installed"
    NYM_EMERGENCY_OUT="NYM_EMERGENCY_OUT"
    NYM_EMERGENCY_FWD="NYM_EMERGENCY_FWD"
    NYM_BOOT_TABLE="nym_boot"
    nym_emergency_rules_v4() { return 1; }
    nym_emergency_rules_v6() { return 1; }
    nym_boot_block_nft() { return 1; }
fi

EMERGENCY_OUT="$NYM_EMERGENCY_OUT"
EMERGENCY_FWD="$NYM_EMERGENCY_FWD"

# Every state-file test goes through here; an untrusted directory reads as
# "no state" and lands in the fail-closed branches.
STATE_TRUSTED=0
have_state() {
    [ "$STATE_TRUSTED" = 1 ] && [ -f "$1" ]
}

# Mode "first": rule 1 exactly. Mode "leading": only NYM_* jumps may precede
# it, or a foreign rule could accept past the kill-switch. A jump in a valid
# position is left alone; delete + re-insert would unhook it briefly.
ensure_jump() {
    local ipt="$1" hook="$2" target="$3" mode="$4" rules pos n ok first

    rules=$($ipt -w -S "$hook" 2>/dev/null | grep -e "^-A ") || rules=""
    pos=$(printf "%s\n" "$rules" | grep -n -x -e "-A $hook -j $target" | head -1 | cut -d: -f1)
    ok=0
    if [ "$pos" = 1 ]; then
        ok=1
    elif [ -n "$pos" ] && [ "$mode" = leading ] \
        && ! printf "%s\n" "$rules" | head -n $((pos - 1)) | grep -qv -e "-j NYM_"; then
        ok=1
    fi
    if [ "$ok" != 1 ]; then
        $ipt -w -I "$hook" 1 -j "$target" 2>/dev/null || return 1
    fi
    # Highest first so the remaining rule numbers stay valid.
    first=""
    for n in $($ipt -w -S "$hook" 2>/dev/null | grep -e "^-A " \
        | grep -n -x -e "-A $hook -j $target" | cut -d: -f1 | sort -rn); do
        first="$n"
    done
    for n in $($ipt -w -S "$hook" 2>/dev/null | grep -e "^-A " \
        | grep -n -x -e "-A $hook -j $target" | cut -d: -f1 | sort -rn); do
        [ "$n" -gt "${first:-1}" ] && $ipt -w -D "$hook" "$n" 2>/dev/null
    done
    return 0
}

# Presence is enough in mangle: an unmarked exempted flow stays blocked.
ensure_mangle_jump() {
    local ipt="$1" hook="$2" target="$3"

    $ipt -w -t mangle -C "$hook" -j "$target" 2>/dev/null \
        || $ipt -w -t mangle -I "$hook" 1 -j "$target" 2>/dev/null
}

setup_jumps() {
    local ipt="$1"

    ensure_jump "$ipt" "$HOOK_INPUT" "$NYM_INPUT" leading || return 1
    ensure_jump "$ipt" "$HOOK_OUTPUT" "$NYM_OUTPUT" leading || return 1
    ensure_jump "$ipt" "$HOOK_FORWARD" "$NYM_FORWARD" leading || return 1
}

# Fail-closed OUTPUT/FORWARD block in dedicated chains, one atomic restore.
# "transition" (default) passes only reply traffic and ND; "boot" adds what
# a router needs to come up. Rules, order and rationale: boot_rules.rs.
emergency_block() {
    local ipt="$1" mode="${2:-transition}" restore="${1}-restore" rules

    case "$ipt" in
        ip6tables) rules=nym_emergency_rules_v6 ;;
        *) rules=nym_emergency_rules_v4 ;;
    esac
    $rules "$mode" | $restore --noflush -w 2>/dev/null \
        || $rules "$mode" | $restore --noflush 2>/dev/null
}

cleanup_emergency() {
    local ipt="$1" hook chain

    for hook in "$HOOK_OUTPUT" "$HOOK_FORWARD"; do
        if [ "$hook" = "$HOOK_OUTPUT" ]; then chain="$EMERGENCY_OUT"; else chain="$EMERGENCY_FWD"; fi
        while $ipt -w -D "$hook" -j "$chain" 2>/dev/null; do :; done
        # A command error must not masquerade as "rule absent".
        $ipt -w -C "$hook" -j "$chain" 2>/dev/null && return 1
        if $ipt -w -L "$chain" -n >/dev/null 2>&1; then
            $ipt -w -F "$chain" 2>/dev/null || return 1
            $ipt -w -X "$chain" 2>/dev/null || return 1
        fi
    done
}

# fw3 has no *_rule hooks in mangle; jump from the built-ins.
setup_mangle_jumps() {
    local ipt="$1"

    ensure_mangle_jump "$ipt" PREROUTING "$NYM_MANGLE_PRE" || true
    ensure_mangle_jump "$ipt" OUTPUT "$NYM_MANGLE_OUT" || true
}

cleanup_filter() {
    local ipt="$1"

    $ipt -w -D "$HOOK_INPUT" -j "$NYM_INPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null || true
    $ipt -w -D "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null || true

    local chain
    for chain in "$NYM_INPUT" "$NYM_OUTPUT" "$NYM_FORWARD"; do
        $ipt -w -F "$chain" 2>/dev/null || true
        $ipt -w -X "$chain" 2>/dev/null || true
    done
}

cleanup_mangle() {
    local ipt="$1"

    $ipt -w -t mangle -D PREROUTING -j "$NYM_MANGLE_PRE" 2>/dev/null || true
    $ipt -w -t mangle -D OUTPUT -j "$NYM_MANGLE_OUT" 2>/dev/null || true

    local chain
    for chain in "$NYM_MANGLE_PRE" "$NYM_MANGLE_OUT"; do
        $ipt -w -t mangle -F "$chain" 2>/dev/null || true
        $ipt -w -t mangle -X "$chain" 2>/dev/null || true
    done
}

# The persisted script carries chain declarations and -F lines, so
# --noflush re-application is idempotent.
apply_rules() {
    local restore="$1" file="$2" ipt="$3"

    if ($restore --noflush -w < "$file" 2>/dev/null || $restore --noflush < "$file") \
        && setup_jumps "$ipt"; then
        if grep -q '^\*mangle' "$file"; then
            setup_mangle_jumps "$ipt"
        else
            cleanup_mangle "$ipt"
        fi
        if cleanup_emergency "$ipt"; then
            logger -t nym-vpn "Restored $ipt kill-switch rules after firewall reload/restart"
            return 0
        fi
    fi

    logger -t nym-vpn "Failed to restore $ipt kill-switch; installing emergency output/forward block"
    if emergency_block "$ipt"; then
        logger -t nym-vpn "Emergency $ipt kill-switch block installed"
    else
        logger -t nym-vpn "CRITICAL: failed to install emergency $ipt kill-switch block"
    fi
    return 1
}

restore_masquerade() {
    if ! have_state "$IFACES_FILE"; then
        cleanup_masquerade
        return 0
    fi

    iptables -w -t nat -N "$NAT_CHAIN" 2>/dev/null || true
    iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true

    local iface
    while read -r iface; do
        [ -n "$iface" ] || continue
        iptables -w -t nat -A "$NAT_CHAIN" -o "$iface" -j MASQUERADE 2>/dev/null || true
        logger -t nym-vpn "Restored masquerade for interface $iface"
    done < "$IFACES_FILE"

    iptables -w -t nat -C POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || \
        iptables -w -t nat -A POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || true
}

cleanup_masquerade() {
    while iptables -w -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null; do :; done
    iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true
    iptables -w -t nat -X "$NAT_CHAIN" 2>/dev/null || true
}

# Needed with the kill-switch off too: tun devices are in no fw3 zone, so
# fw3's forward policy rejects LAN clients without these accepts.
restore_forwarding() {
    if ! have_state "$IFACES_FILE"; then
        cleanup_forwarding
        return 0
    fi

    local ipt iface
    for ipt in iptables ip6tables; do
        $ipt -w -N "$FORWARD_LAN_CHAIN" 2>/dev/null || true
        $ipt -w -F "$FORWARD_LAN_CHAIN" 2>/dev/null || true
        while read -r iface; do
            [ -n "$iface" ] || continue
            $ipt -w -A "$FORWARD_LAN_CHAIN" -o "$iface" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            $ipt -w -A "$FORWARD_LAN_CHAIN" -i "$iface" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            $ipt -w -A "$FORWARD_LAN_CHAIN" -o "$iface" -j ACCEPT 2>/dev/null || true
            $ipt -w -A "$FORWARD_LAN_CHAIN" -i "$iface" -m conntrack \
                --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        done < "$IFACES_FILE"
        # Rule 1: the MSS clamp must run before NYM_FORWARD accepts.
        ensure_jump "$ipt" "$HOOK_FORWARD" "$FORWARD_LAN_CHAIN" first || true
    done
}

cleanup_forwarding() {
    local ipt
    for ipt in iptables ip6tables; do
        $ipt -w -D "$HOOK_FORWARD" -j "$FORWARD_LAN_CHAIN" 2>/dev/null || true
        $ipt -w -F "$FORWARD_LAN_CHAIN" 2>/dev/null || true
        $ipt -w -X "$FORWARD_LAN_CHAIN" 2>/dev/null || true
    done
}

kernel_ipv6_enabled() {
    [ -d /proc/sys/net/ipv6 ] \
        && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" != "1" ]
}

restore_policy() {
    local failed=0

    apply_rules "iptables-restore" "$RULES_V4" "iptables" || failed=1
    if have_state "$RULES_V6"; then
        apply_rules "ip6tables-restore" "$RULES_V6" "ip6tables" || failed=1
    elif kernel_ipv6_enabled; then
        # IPv6 came up after the v4-only policy was persisted: block v6
        # until the daemon reapplies, never bypass.
        logger -t nym-vpn "IPv6 became enabled without a saved policy; installing emergency block"
        emergency_block "ip6tables" || failed=1
    else
        cleanup_filter "ip6tables"
        cleanup_mangle "ip6tables"
    fi
    return "$failed"
}

# A live (hooked) IPv4 policy, not merely a persisted one.
policy_hooked() {
    iptables -w -C "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null \
        && iptables -w -C "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null
}

lift_emergency() {
    logger -t nym-vpn "Lifting boot-time kill-switch block: $1"
    cleanup_emergency "iptables" || return 1
    cleanup_emergency "ip6tables" 2>/dev/null || true
}

# No persisted policy: kill-switch off, daemon stopped, or not yet run since
# boot. Tear down stale chains, then arm the boot block or make sure none is left.
handle_no_policy() {
    local failed=0

    cleanup_filter "iptables"
    cleanup_mangle "iptables"
    cleanup_filter "ip6tables"
    cleanup_mangle "ip6tables"

    if ! nym_boot_block_wanted; then
        logger -t nym-vpn "No active rules, cleaning up ($NYM_BOOT_REASON)"
        cleanup_emergency "iptables" || failed=1
        cleanup_emergency "ip6tables" 2>/dev/null || true
        return "$failed"
    fi

    logger -t nym-vpn "Installing boot-time kill-switch block: $NYM_BOOT_REASON"
    if emergency_block "iptables" boot; then
        logger -t nym-vpn "Boot-time iptables kill-switch block installed"
    else
        logger -t nym-vpn "CRITICAL: failed to install boot-time iptables kill-switch block"
        failed=1
    fi
    if kernel_ipv6_enabled; then
        if emergency_block "ip6tables" boot; then
            logger -t nym-vpn "Boot-time ip6tables kill-switch block installed"
        else
            logger -t nym-vpn "CRITICAL: failed to install boot-time ip6tables kill-switch block"
            failed=1
        fi
    fi

    # Re-check: the daemon persists before it lifts the emergency chains and
    # before it opens the firewall, so a raced decision is caught here. A
    # transition marker or an unhooked persisted policy means the daemon is
    # mid-apply and lifts the block itself.
    if have_state "$TRANSITION_FILE"; then
        :
    elif have_state "$RULES_V4"; then
        if policy_hooked; then
            lift_emergency "daemon policy went live meanwhile" || failed=1
        fi
    elif ! nym_boot_block_wanted; then
        lift_emergency "$NYM_BOOT_REASON" || failed=1
    fi
    return "$failed"
}

# Runs under the fw3 state lock (taken at the bottom of the file).
main() {
    local failed=0

    # Stop intent wins over persisted state: the init script writes the
    # marker first and, if it could not take the lock, leaves the teardown
    # to this run.
    if have_state "$NYM_VPND_STOPPED"; then
        logger -t nym-vpn "nym-vpnd was stopped by the administrator; discarding persisted fw3 state"
        rm -f "$RULES_V4" "$RULES_V6" "$IFACES_FILE" "$TRANSITION_FILE" 2>/dev/null
        handle_no_policy || failed=1
        restore_masquerade
        restore_forwarding
        return "$failed"
    fi

    # The daemon holds the lock from creating the marker to removing it, so
    # seeing it here means a daemon died mid-transition: never read the
    # rules files as kill-switch-off while it exists.
    if have_state "$TRANSITION_FILE"; then
        logger -t nym-vpn "Firewall transition in progress; enforcing emergency block"
        emergency_block "iptables" || failed=1
        if kernel_ipv6_enabled; then
            emergency_block "ip6tables" || failed=1
        fi
        return 1
    fi

    if have_state "$RULES_V4"; then
        restore_policy || failed=1
    else
        handle_no_policy || failed=1
    fi

    # The tunnel plane is needed with the kill-switch on and off.
    restore_masquerade
    restore_forwarding
    return "$failed"
}

# Without the lock, main() never runs: a live kill-switch is left as it is,
# and when nothing is hooked the boot block goes in if wanted. The marker
# alone is no mutual exclusion (see FW3_LOCK_PATH in common.rs).
run_without_lock() {
    if policy_hooked; then
        logger -t nym-vpn "CRITICAL: fw3 include ran without the state lock ($1); the live kill-switch is left untouched and reconciliation is skipped"
        return 1
    fi
    if ! nym_boot_block_wanted; then
        logger -t nym-vpn "CRITICAL: fw3 include ran without the state lock ($1); nothing is hooked and no block is wanted ($NYM_BOOT_REASON)"
        return 1
    fi
    logger -t nym-vpn "CRITICAL: fw3 include ran without the state lock ($1); nothing is hooked, installing the boot-time emergency block"
    emergency_block "iptables" boot
    if kernel_ipv6_enabled; then
        emergency_block "ip6tables" boot
    fi
    # The daemon may have hooked its policy since the check above; a later
    # apply still lifts the emergency chains itself.
    if policy_hooked; then
        logger -t nym-vpn "daemon policy went live during the unlocked fallback; lifting the emergency block"
        cleanup_emergency "iptables" || true
        cleanup_emergency "ip6tables" 2>/dev/null || true
    fi
    return 1
}

# The lock lives inside the runtime directory, so untrusted means no lock.
if ! nym_runtime_dir_prepare; then
    run_without_lock "$NYM_RUNTIME_DIR is not a private root-owned directory"
    exit 1
fi
STATE_TRUSTED=1

# NYM_FW_LOCKED=1: the caller (init script) already holds the lock; taking
# it again on a fresh descriptor would deadlock against the inherited one.
if [ "${NYM_FW_LOCKED:-}" != "1" ]; then
    if ! command -v flock >/dev/null 2>&1; then
        run_without_lock "flock is not installed"
        exit 1
    fi
    exec 9>"$LOCK_FILE"
    flock 9 || { run_without_lock "flock failed on $LOCK_FILE"; exit 1; }
fi

main "$@"
