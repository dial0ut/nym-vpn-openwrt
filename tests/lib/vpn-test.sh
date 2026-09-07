#!/bin/bash
# VPN test sequence for a single architecture.
# Tests account registration, 2-hop connection, 5-hop connection, and cleanup.

# ---------------------------------------------------------------------------
# Connection Verification
# ---------------------------------------------------------------------------

# Verify that the VPN tunnel is actually carrying traffic.
# Every check is mandatory: the daemon must report Connected (exact state
# line — "State: Disconnected" also contains the word "connected"), a nym
# tunnel interface must exist with an address, DNS must resolve, and the
# router's egress address must differ from the public address it had while
# disconnected. Working DNS alone proves nothing about the tunnel.
# Usage: verify_vpn_connection <arch> <public_ip_while_disconnected>
verify_vpn_connection() {
    local arch="$1" wan_public_ip="${2:-}"

    # Check 1: exact state. `nym-vpnc status` opens with
    # "State: Connected wg to ..." when the tunnel is up.
    local status
    status=$(vm_ssh "$arch" "nym-vpnc status 2>&1") || true
    if ! echo "$status" | grep -qE '^State: Connected( |$)'; then
        log_error "[$arch]   Status not Connected: $(echo "$status" | head -1)"
        return 1
    fi
    log_info "[$arch]   Status: Connected"

    # Check 2: a nym tunnel interface (nym0/nym1) exists and has an address.
    local tun_addr
    tun_addr=$(vm_ssh "$arch" "ip -o -4 addr show 2>/dev/null | awk '\$2 ~ /^nym[0-9]+\$/ {print \$2, \$4}'" 2>/dev/null || true)
    if [[ -z "$tun_addr" ]]; then
        log_error "[$arch]   No nym tunnel interface with an address"
        vm_ssh "$arch" "ip -o link show" 2>/dev/null || true
        return 1
    fi
    log_info "[$arch]   Tunnel interface: $tun_addr"

    # Check 3: DNS resolves (through the tunnel, given checks 1 and 4).
    if ! vm_ssh "$arch" "nslookup example.com" >/dev/null 2>&1; then
        log_error "[$arch]   DNS resolution failed"
        return 1
    fi
    log_info "[$arch]   DNS resolution: OK"

    # Check 4: egress moved. The public address seen from the tunnel must
    # differ from the one captured before connecting; without a baseline
    # the check can only require that some egress exists.
    local ext_ip
    ext_ip=$(vm_ssh "$arch" "wget -qO- -T 15 https://api.ipify.org 2>/dev/null" || true)
    if [[ -z "$ext_ip" ]]; then
        log_error "[$arch]   Could not determine egress IP through the tunnel"
        return 1
    fi
    if [[ -n "$wan_public_ip" && "$ext_ip" == "$wan_public_ip" ]]; then
        log_error "[$arch]   Egress IP $ext_ip is the router's own public address — traffic bypasses the tunnel"
        return 1
    fi
    if [[ -z "$wan_public_ip" ]]; then
        log_warn "[$arch]   No pre-connect public IP known; cannot prove egress moved"
    fi
    log_info "[$arch]   Egress IP: $ext_ip (before connect: ${wan_public_ip:-unknown})"
    return 0
}

# ---------------------------------------------------------------------------
# Main Test Sequence
# ---------------------------------------------------------------------------

# Run the full VPN test for a single architecture.
# Returns 0 on pass, 1 on fail. Outputs detailed log to stdout.
# Requires NYM_MNEMONIC to be set in environment.
# Usage: run_vpn_test <arch>
run_vpn_test() {
    local arch="$1"
    local connect_timeout="${ARCH_CONNECT_TIMEOUT[$arch]}"
    local two_hop_ok=false
    local five_hop_ok=false

    log_step "[$arch] ===== Starting VPN test ====="

    # --- Step 1: Start daemon ---
    log_info "[$arch] Starting nym-vpnd..."
    vm_ssh "$arch" "/etc/init.d/nym-vpnd start" || {
        log_error "[$arch] Failed to start nym-vpnd"
        return 1
    }
    sleep 5

    # Verify daemon is running
    if ! vm_ssh "$arch" "pgrep -x nym-vpnd" >/dev/null 2>&1; then
        log_error "[$arch] nym-vpnd is not running"
        # Grab any crash logs
        vm_ssh "$arch" "logread | grep -i nym | tail -20" 2>/dev/null || true
        return 1
    fi
    log_info "[$arch] nym-vpnd is running"

    # --- Step 2: Set account ---
    log_info "[$arch] Setting account..."
    if ! vm_ssh "$arch" "nym-vpnc account set '${NYM_MNEMONIC}' --mode api" 2>&1; then
        log_error "[$arch] Failed to set account"
        return 1
    fi

    # Wait for account to be ready (poll with timeout)
    log_info "[$arch] Waiting for account registration..."
    local reg_timeout=120
    local reg_start
    reg_start=$(date +%s)
    while true; do
        local acct_status
        acct_status=$(vm_ssh "$arch" "nym-vpnc account get 2>&1") || true
        if echo "$acct_status" | grep -qi "registered\|ready\|active"; then
            log_info "[$arch] Account registered"
            break
        fi
        local elapsed=$(( $(date +%s) - reg_start ))
        if [[ "$elapsed" -ge "$reg_timeout" ]]; then
            log_error "[$arch] Account registration timeout (${reg_timeout}s)"
            log_error "[$arch] Last status: $acct_status"
            cleanup_account "$arch"
            return 1
        fi
        sleep 5
    done

    # Baseline for the egress check: the router's public address with no
    # tunnel up. Captured once, before the first connect.
    local wan_public_ip
    wan_public_ip=$(vm_ssh "$arch" "wget -qO- -T 15 https://api.ipify.org 2>/dev/null" || true)
    if [[ -n "$wan_public_ip" ]]; then
        log_info "[$arch] Public IP while disconnected: $wan_public_ip"
    else
        log_warn "[$arch] Could not learn the public IP while disconnected"
    fi

    # --- Step 3: Two-hop test ---
    log_step "[$arch] Testing TWO-HOP mode..."
    vm_ssh "$arch" "nym-vpnc tunnel set --two-hop on" 2>&1 || true

    if timeout_cmd "$connect_timeout" vm_ssh "$arch" "nym-vpnc connect --wait" 2>&1; then
        if verify_vpn_connection "$arch" "$wan_public_ip"; then
            log_info "[$arch] TWO-HOP: PASS"
            two_hop_ok=true
        else
            log_error "[$arch] TWO-HOP: verification failed"
        fi
    else
        log_error "[$arch] TWO-HOP: connect failed/timeout (${connect_timeout}s)"
        # Dump daemon logs for debugging
        vm_ssh "$arch" "logread | grep -i nym | tail -30" 2>/dev/null || true
    fi

    # Disconnect
    log_info "[$arch] Disconnecting..."
    vm_ssh "$arch" "nym-vpnc disconnect --wait" 2>&1 || true
    sleep 3

    # --- Step 4: Five-hop test ---
    log_step "[$arch] Testing FIVE-HOP (mixnet) mode..."
    vm_ssh "$arch" "nym-vpnc tunnel set --two-hop off" 2>&1 || true

    # Five-hop is slower, give extra time
    local mixnet_timeout=$(( connect_timeout + 120 ))
    if timeout_cmd "$mixnet_timeout" vm_ssh "$arch" "nym-vpnc connect --wait" 2>&1; then
        if verify_vpn_connection "$arch" "$wan_public_ip"; then
            log_info "[$arch] FIVE-HOP: PASS"
            five_hop_ok=true
        else
            log_error "[$arch] FIVE-HOP: verification failed"
        fi
    else
        log_error "[$arch] FIVE-HOP: connect failed/timeout (${mixnet_timeout}s)"
        vm_ssh "$arch" "logread | grep -i nym | tail -30" 2>/dev/null || true
    fi

    # Disconnect
    log_info "[$arch] Disconnecting..."
    vm_ssh "$arch" "nym-vpnc disconnect --wait" 2>&1 || true
    sleep 3

    # --- Step 5: Cleanup ---
    cleanup_account "$arch"

    # --- Result ---
    if $two_hop_ok && $five_hop_ok; then
        log_info "[$arch] ===== RESULT: PASS ====="
        return 0
    else
        local detail=""
        $two_hop_ok  && detail+="2hop:PASS " || detail+="2hop:FAIL "
        $five_hop_ok && detail+="5hop:PASS " || detail+="5hop:FAIL "
        log_error "[$arch] ===== RESULT: FAIL ($detail) ====="
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Forget the account to free the device slot.
cleanup_account() {
    local arch="$1"
    log_info "[$arch] Forgetting account (freeing device slot)..."
    vm_ssh "$arch" "nym-vpnc account forget" 2>/dev/null || true
}

# Run a command with a timeout.
# Usage: timeout_cmd <seconds> <command...>
#
# The command is usually a shell function (vm_ssh), which coreutils `timeout`
# cannot exec (it would exit 127), so the command runs in a background
# subshell that inherits our functions and is raced against a sleeper.
# Returns the command's exit code, or 124 when the sleeper killed it (same
# convention as coreutils timeout).
timeout_cmd() {
    local secs="$1"
    shift
    local pid watchdog rc=0
    ( "$@" ) &
    pid=$!
    ( sleep "$secs"; kill "$pid" 2>/dev/null ) &
    watchdog=$!
    wait "$pid" 2>/dev/null || rc=$?
    kill "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true
    # 143 = terminated by SIGTERM, which only the sleeper sends here.
    [[ "$rc" -eq 143 ]] && rc=124
    return "$rc"
}
