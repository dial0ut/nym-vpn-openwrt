#!/bin/sh
# Nym VPN firewall include script for OpenWrt fw3 (iptables)
#
# This script is called by fw3 on start, restart, and reload (reload=1).
#
# Why this exists (mirror of fw4-include.sh, adapted to fw3's world):
#   On fw4 the kill-switch lives in a separate `inet nym` table that a
#   firewall reload cannot touch — only the small in-fw4 integration has to
#   be restored. fw3 shares its filter/mangle/nat tables with everyone. A
#   `fw3 reload` is selective: it removes only fw3's own tagged rules and
#   leaves the user *_rule chains and foreign chains (ours) alone, so on a
#   reload this script only reconciles — re-hooks a jump a foreign rule got
#   ahead of, lifts a stale emergency block, converges. A `fw3 restart` or
#   `stop` flushes every table, chains included; `start` then rebuilds fw3's
#   rules and runs this script last, and without it the whole kill-switch
#   would stay gone until the daemon's next state change. (Between the flush
#   and this script fw3 itself runs with an ACCEPT policy; that window is
#   fw3's and nothing here can close it.)
#   For that rebuild the daemon persists exactly what it applied, in the
#   root-owned runtime directory $NYM_RUNTIME_DIR (default
#   /var/run/nym-firewall, shared with fw-boot-guard.sh and the init script):
#     v4.rules    iptables-restore script (filter [+ mangle])
#     v6.rules    ip6tables-restore script, if IPv6 is up
#     ifaces      tunnel interfaces needing masquerade
#     transition  fail-closed multi-file update marker
#     lock        flock(2) serializing every writer
#   Nothing in that directory is used unless it still is a plain directory
#   owned by root with no group/other access (this script runs as root and
#   feeds the rules files to iptables-restore, so a world-writable location
#   such as /tmp would let any local user hand it a ruleset). This script
#   re-applies the files whenever fw3 runs it, holding the lock for
#   the whole run like the daemon does for every apply/reset: the two never
#   interleave, so this script only ever sees fw3 state between complete
#   transitions. While the transition marker exists — a daemon crashed
#   mid-transition — it installs dedicated emergency OUTPUT/FORWARD drops
#   (reply traffic for inbound management sessions excepted) instead of
#   reading or cleaning partially-updated state. No rules files means no blocking policy
#   is in force: the kill-switch is off, the daemon was stopped, or — the boot
#   window — the daemon (S90) has not run yet since power-on while the
#   firewall (S19) and network (S20) are already up. In that last case, when
#   fw-boot-guard.sh says the kill-switch is armed, the same emergency chains
#   are installed with a boot rule set that also lets the router come up and
#   stay manageable from the LAN; the daemon lifts them with its first policy
#   exactly as it lifts a transition block. Otherwise any leftover Nym chains
#   are torn down. The init script runs this script for that cleanup branch on
#   explicit daemon stop, too.
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 Nym Technologies SA <contact@nymtech.net>

set -e

# Persisted daemon state (directory and names are a contract with the fw3
# backend, common.rs). Trusted only after nym_runtime_dir_prepare (below).
NYM_RUNTIME_DIR="${NYM_RUNTIME_DIR:-/var/run/nym-firewall}"
RULES_V4="$NYM_RUNTIME_DIR/v4.rules"
RULES_V6="$NYM_RUNTIME_DIR/v6.rules"
IFACES_FILE="$NYM_RUNTIME_DIR/ifaces"
TRANSITION_FILE="$NYM_RUNTIME_DIR/transition"
LOCK_FILE="$NYM_RUNTIME_DIR/lock"

# fw3 hook chains (user chains fw3 preserves on reload and recreates empty
# on restart).
HOOK_INPUT="input_rule"
HOOK_OUTPUT="output_rule"
HOOK_FORWARD="forwarding_rule"

# Our chains — kept identical to the daemon's fw3 backend so this script and
# the daemon converge on a single structure instead of two competing sets.
NYM_INPUT="NYM_INPUT"
NYM_OUTPUT="NYM_OUTPUT"
NYM_FORWARD="NYM_FORWARD"
NYM_MANGLE_PRE="NYM_MANGLE_PREROUTING"
NYM_MANGLE_OUT="NYM_MANGLE_OUTPUT"
NAT_CHAIN="NYM_POSTROUTING"
FORWARD_LAN_CHAIN="NYM_FORWARD_LAN"
EMERGENCY_OUT="NYM_EMERGENCY_OUT"
EMERGENCY_FWD="NYM_EMERGENCY_FWD"

# Destinations the boot-time block always lets through: the LAN set the
# daemon's Blocked policy uses (RFC1918, ULA) plus link-local, and multicast
# for router-originated traffic only. Mirrors policy.rs.
LAN_NETS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"
LAN_NETS_V6="fe80::/10 fc00::/7"
MCAST_V4="224.0.0.0/4"
MCAST_V6="ff00::/8"

# Boot-time kill-switch guard: the shared decision logic. A missing helper
# must fail towards not blocking, never towards a block nothing can lift.
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
    # Without the shared checks nothing in the runtime directory is trusted.
    nym_runtime_dir_prepare() { return 1; }
fi

# A persisted state file exists AND lives in a directory that passed the
# ownership/mode checks. Every test of a state file goes through here; a
# directory that cannot be trusted reads as "no state", which lands in the
# fail-closed branches below (boot guard verdict, emergency block).
STATE_TRUSTED=0
have_state() {
    [ "$STATE_TRUSTED" = 1 ] && [ -f "$1" ]
}

# Make a jump lead its hook chain. Mode "first": it must be rule 1. Mode
# "leading": only jumps to our own NYM_* chains may precede it (a foreign
# rule inserted ahead of the kill-switch could accept traffic past it). A
# jump already in a valid position is left alone — deleting and re-inserting
# would leave the chain unhooked for a moment. Otherwise insert at 1 first,
# then drop stale later copies, so there is never a moment without it.
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
    # Drop stale duplicates after the leading occurrence, highest first.
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

# Mangle has no fw3 *_rule hook chains and position is not security-relevant
# there (an unmarked exempted flow stays blocked), so presence is enough.
ensure_mangle_jump() {
    local ipt="$1" hook="$2" target="$3"

    $ipt -w -t mangle -C "$hook" -j "$target" 2>/dev/null \
        || $ipt -w -t mangle -I "$hook" 1 -j "$target" 2>/dev/null
}

# Set up jump rules from fw3's hook chains to our filter chains. Insertion is
# mandatory: restored chain contents provide no protection when unreachable.
setup_jumps() {
    local ipt="$1"

    ensure_jump "$ipt" "$HOOK_INPUT" "$NYM_INPUT" leading || return 1
    ensure_jump "$ipt" "$HOOK_OUTPUT" "$NYM_OUTPUT" leading || return 1
    ensure_jump "$ipt" "$HOOK_FORWARD" "$NYM_FORWARD" leading || return 1
}

# Last-resort fail-closed policy when a transition is active or a saved
# restore/jump setup fails. Dedicated chains avoid clobbering the desired
# policy while it is built. The restore transaction creates, fills and hooks
# both drops atomically. INPUT is deliberately untouched so LuCI/SSH continue
# to follow fw3's management policy — and because fw3 runs output_rule BEFORE
# its own established-accept, the OUTPUT block must itself let reply-direction
# packets through (--ctdir REPLY: the router answering a connection someone
# opened to it) or those management sessions would be dropped on the way out.
# Router-originated flows are in the ORIGINAL direction and stay blocked.
# IPv6 neighbour discovery is kept so on-link reachability survives.
#
# Two rule sets share the chains. "transition" (the default) is the strict
# block for a policy change in flight or a failed restore. "boot" covers the
# window before the daemon's first policy since power-on and additionally
# lets the router come up and stay manageable: loopback, DHCP/DHCPv6 as client
# and server, IPv6 router solicitation, and LAN/link-local/multicast
# destinations — the base of the daemon's own Blocked policy. As in that
# policy (block_dns before allow_lan_traffic), DNS is rejected BEFORE the
# LAN-destination accepts: a private address is not a LAN interface, and
# behind another router the upstream resolver is 192.168.x.1, so dnsmasq's
# forwarded lookups and LAN clients' direct queries would otherwise leave in
# plaintext during the boot window. The router's own dnsmasq answering the
# LAN is unaffected — those answers match the reply-direction accept above.
# The daemon tears both rule sets down the same way once its live state has
# converged.
emergency_block() {
    local ipt="$1" mode="${2:-transition}" restore="${1}-restore"

    emergency_rules() {
        local net chain udp_reject
        cat <<EOF
*filter
:$EMERGENCY_OUT - [0:0]
:$EMERGENCY_FWD - [0:0]
-F $EMERGENCY_OUT
-F $EMERGENCY_FWD
-A $EMERGENCY_OUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
EOF
        if [ "$mode" = "boot" ]; then
            echo "-A $EMERGENCY_OUT -o lo -j ACCEPT"
            if [ "$ipt" = "ip6tables" ]; then
                cat <<EOF
-A $EMERGENCY_OUT -p udp --sport 546 --dport 547 -j ACCEPT
-A $EMERGENCY_OUT -p udp --sport 547 --dport 546 -j ACCEPT
-A $EMERGENCY_OUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
EOF
            else
                cat <<EOF
-A $EMERGENCY_OUT -p udp --sport 68 --dport 67 -j ACCEPT
-A $EMERGENCY_OUT -p udp --sport 67 --dport 68 -j ACCEPT
EOF
            fi
        fi
        if [ "$ipt" = "ip6tables" ]; then
            cat <<EOF
-A $EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT
-A $EMERGENCY_OUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT
EOF
        fi
        if [ "$mode" = "boot" ]; then
            if [ "$ipt" = "ip6tables" ]; then
                # shellcheck disable=SC2086  # word-split the network lists
                set -- $LAN_NETS_V6
                udp_reject="icmp6-port-unreachable"
            else
                # shellcheck disable=SC2086
                set -- $LAN_NETS_V4
                udp_reject="icmp-port-unreachable"
            fi
            # DNS first, then the LAN/multicast accepts (see above).
            for chain in "$EMERGENCY_OUT" "$EMERGENCY_FWD"; do
                echo "-A $chain -p udp --dport 53 -j REJECT --reject-with $udp_reject"
                echo "-A $chain -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
            done
            if [ "$ipt" = "ip6tables" ]; then
                echo "-A $EMERGENCY_OUT -d $MCAST_V6 -j ACCEPT"
            else
                echo "-A $EMERGENCY_OUT -d $MCAST_V4 -j ACCEPT"
            fi
            for net in "$@"; do
                echo "-A $EMERGENCY_OUT -d $net -j ACCEPT"
                echo "-A $EMERGENCY_FWD -d $net -j ACCEPT"
            done
        fi
        cat <<EOF
-A $EMERGENCY_OUT -j DROP
-A $EMERGENCY_FWD -j DROP
-I $HOOK_OUTPUT 1 -j $EMERGENCY_OUT
-I $HOOK_FORWARD 1 -j $EMERGENCY_FWD
COMMIT
EOF
    }

    emergency_rules | $restore --noflush -w 2>/dev/null \
        || emergency_rules | $restore --noflush 2>/dev/null
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

# Mangle has no fw3 *_rule hook chains — jump straight from the built-ins,
# exactly like the daemon's fw3 backend does.
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

# Re-apply one family's persisted ruleset and its jumps. The daemon renders
# the restore script with chain declarations and -F lines, so re-applying
# with --noflush is idempotent. Mangle jumps are set up only when the script
# actually carries a *mangle block (inbound exemptions configured).
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

# Rebuild the masquerade chain from the daemon's interface list. Mirrors
# add_masquerade_rules in the fw3 backend: owned chain, flush + repopulate,
# jump added only when missing.
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

# Rebuild the LAN<->tunnel forwarding plane (fw3 analogue of fw4's
# nym_forward_lan): per-interface MSS clamps and forward accepts, jumped
# from forwarding_rule. Mirrors add_forwarding_rules in the fw3 backend.
# Needed with the kill-switch on AND off — the tun devices are in no fw3
# zone, so fw3's global forward policy rejects LAN clients without it.
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
        # Rule 1: the MSS clamp must run before NYM_FORWARD accepts flows.
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

# Re-apply the persisted policy (the daemon has applied one since boot) for
# every family in force.
restore_policy() {
    local failed=0

    apply_rules "iptables-restore" "$RULES_V4" "iptables" || failed=1
    if have_state "$RULES_V6"; then
        apply_rules "ip6tables-restore" "$RULES_V6" "ip6tables" || failed=1
    elif kernel_ipv6_enabled; then
        # The daemon persisted a v4 policy while IPv6 was disabled, but
        # the kernel now routes v6. Never turn that state transition into
        # a v6 bypass during reload; block until the daemon reapplies.
        logger -t nym-vpn "IPv6 became enabled without a saved policy; installing emergency block"
        emergency_block "ip6tables" || failed=1
    else
        cleanup_filter "ip6tables"
        cleanup_mangle "ip6tables"
    fi
    return "$failed"
}

# Whether the daemon's own kill-switch chains are hooked for IPv4 — a live
# policy, not merely a persisted one, protects the router.
policy_hooked() {
    iptables -w -C "$HOOK_OUTPUT" -j "$NYM_OUTPUT" 2>/dev/null \
        && iptables -w -C "$HOOK_FORWARD" -j "$NYM_FORWARD" 2>/dev/null
}

lift_emergency() {
    logger -t nym-vpn "Lifting boot-time kill-switch block: $1"
    cleanup_emergency "iptables" || return 1
    cleanup_emergency "ip6tables" 2>/dev/null || true
}

# No persisted policy: the kill-switch is off, the daemon was stopped, or it
# has not run yet since boot. Stale policy chains go either way; then either
# arm the boot-time block or make sure none is left behind.
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

    # Re-check after installing. The daemon persists its state before it lifts
    # the emergency chains and persists a kill-switch toggle before it opens
    # the firewall, so a decision that raced either is caught here instead of
    # leaving a block only the daemon's next state change would lift. A
    # transition marker means the daemon is mid-apply and lifts the block
    # itself; a persisted policy that is not hooked yet means the daemon is
    # about to activate it and does the same.
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

# Main logic. Runs under the fw3 state lock (see the bottom of the file).
main() {
    local failed=0

    # An explicit administrative stop is authorisation to open, and it must
    # win over everything persisted: the init script writes the marker
    # first, then tears down under the lock — but if it could not take the
    # lock it leaves the teardown to this run. Drop the persisted state so a
    # stale policy cannot be restored, then take the no-policy path, which
    # cleans the chains and (marker present) installs no block.
    if have_state "$NYM_VPND_STOPPED"; then
        logger -t nym-vpn "nym-vpnd was stopped by the administrator; discarding persisted fw3 state"
        rm -f "$RULES_V4" "$RULES_V6" "$IFACES_FILE" "$TRANSITION_FILE" 2>/dev/null
        handle_no_policy || failed=1
        restore_masquerade
        restore_forwarding
        return "$failed"
    fi

    # Rust creates this marker before touching live or persisted fw3 state
    # and holds the state lock until it has removed the marker again, so
    # finding it here means a daemon died mid-transition. Never interpret
    # missing/partially-updated rules files as kill-switch-off while it
    # exists; a later successful apply/reset or explicit service stop clears
    # it.
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

    # Always reconcile the tunnel plane (masquerade + LAN forwarding) with
    # the persisted interface list — it is needed with the kill-switch both
    # on and off (forwarding-only mode).
    restore_masquerade
    restore_forwarding
    return "$failed"
}

# Serialize with the daemon's fw3 backend and the init script's stop-time
# teardown. Existence checks on the marker are not mutual exclusion: without
# the lock this script could see the marker, lose the CPU while the daemon
# finished and lifted its block, and then install an emergency block that
# nothing removes until the next transition. fd 9 stays open for the rest of
# the script, so the lock is released when it exits. A caller that already
# holds the lock (the init script) sets NYM_FW_LOCKED=1; taking it again on a
# fresh descriptor would deadlock against the inherited one.
#
# The lock is a prerequisite, not a nicety: with no lock, main() never runs.
# What happens instead is fail-closed (run_without_lock): a live kill-switch
# is left exactly as it is, and when nothing is hooked — a firewall restart
# flushed everything, or first boot — the boot-time emergency block goes in
# so the router is protected until the daemon's next apply lifts it. Either
# way it is logged as CRITICAL: a box that gets here has no flock, or a
# runtime directory somebody tampered with, and needs an administrator.
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
    # Without the lock the daemon may have hooked its policy between the
    # check above and the install; re-check and lift so its live policy is
    # not shadowed by a block nobody removes. A daemon apply that lands
    # after this re-check still lifts the emergency chains itself as its last
    # step, so the residual window is that of a single apply, not "until the
    # next transition".
    if policy_hooked; then
        logger -t nym-vpn "daemon policy went live during the unlocked fallback; lifting the emergency block"
        cleanup_emergency "iptables" || true
        cleanup_emergency "ip6tables" 2>/dev/null || true
    fi
    return 1
}

# Establish trust in the runtime directory first: create it when missing (fw3
# starts before the daemon has ever run), then verify owner and mode. The lock
# lives inside it, so an untrusted directory means no lock as well.
if ! nym_runtime_dir_prepare; then
    run_without_lock "$NYM_RUNTIME_DIR is not a private root-owned directory"
    exit 1
fi
STATE_TRUSTED=1

if [ "${NYM_FW_LOCKED:-}" != "1" ]; then
    if ! command -v flock >/dev/null 2>&1; then
        run_without_lock "flock is not installed"
        exit 1
    fi
    exec 9>"$LOCK_FILE"
    flock 9 || { run_without_lock "flock failed on $LOCK_FILE"; exit 1; }
fi

main "$@"
