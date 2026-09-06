'use strict';
'require baseclass';
'require nym-vpn.components.modal as modal';
'require nym-vpn.components.toast as toast';

// The connect / disconnect / cancel flows and the tunnel-error handling
// around them: validate the picked gateways, save them, ask the daemon
// which pair it would use (tentative_gateways), warn or relax when the pair
// is not independent, issue the connect and follow it to a settled state.
//
// `hero` is the connection card's surface: showConnecting(cancelable),
// showDisconnected(), showDisconnecting(label), focusPickers(). `pickers`
// is the gateway-picker pair.

// Error reason → (severity, heading, detail, target card). Keys match
// rpcd/nym-vpn:emit_account_error(). Missing 'detail' falls back to
// result.error_message from the RPC.
var ERROR_COPY = {
    device_time_desynced:      { sev: 'warning', heading: 'CLOCK DESYNC',           detail: 'Router time is off by more than 60 seconds. Ensure NTP is running.', target: null },
    inactive_subscription:     { sev: 'error',   heading: 'NO ACTIVE SUBSCRIPTION', detail: 'Renew at nymvpn.com to resume service.',                               target: 'account' },
    max_device_reached:        { sev: 'error',   heading: 'DEVICE LIMIT REACHED',   detail: 'This device isn\'t registered. Remove one at nymvpn.com.',             target: 'account' },
    bandwidth_exceeded:        { sev: 'error',   heading: 'DATA LIMIT REACHED',     detail: 'Fair-usage depleted. Resets on billing cycle.',                        target: 'account' },
    account_status_not_active: { sev: 'error',   heading: 'ACCOUNT NOT ACTIVE',     detail: null,                                                                   target: 'account' },
    api_failure:               { sev: 'warning', heading: 'NYM API UNREACHABLE',    detail: null,                                                                   target: null },
    logged_out:                { sev: 'error',   heading: 'NO ACCOUNT CONFIGURED',  detail: 'Add your NymVPN mnemonic in the Account card.',                        target: 'account' }
};

// User-facing copy for tunnel (state-machine) errors. Keyed by the variant
// rpcd parses out of "State: Error state: <Reason>".
var TUNNEL_ERROR_COPY = {
    PerformantEntryGatewayUnavailable: 'Entry gateway unavailable — switch gateways.',
    PerformantExitGatewayUnavailable: 'Exit gateway unavailable — switch gateways.'
};

var INDEPENDENCE_ERROR_COPY = 'The selected entry and exit are not independent. Connect anyway or change servers.';

// Adaptive polling after a connect/disconnect: 250 ms for the first 5 s so
// the UI confirms within one beat of the daemon (~2.5 s connects), then 1 s
// up to the same ~60 s ceiling. A status call is ~10 ms via the Rust rpcd
// bridge, so the fast phase costs nothing.
var MAX_POLLS = 75;
var nextDelay = function(pollCount) { return pollCount < 20 ? 250 : 1000; };

return baseclass.extend({
    ERROR_COPY: ERROR_COPY,
    TUNNEL_ERROR_COPY: TUNNEL_ERROR_COPY,
    INDEPENDENCE_ERROR_COPY: INDEPENDENCE_ERROR_COPY,

    create: function(store, api, hero, pickers) {
        var flow = {};

        // Build a toast for an account error from ERROR_COPY + optional
        // rpcd-supplied error_message. Returns true if one was shown.
        var accountErrorToast = function(result) {
            var reason = result && result.error_reason;
            if (!reason) return false;
            var copy = ERROR_COPY[reason];
            if (copy) {
                var detail = copy.detail || result.error_message || '';
                toast.show(detail ? copy.heading + ' — ' + detail : copy.heading, copy.sev);
            } else {
                toast.show('Account error: ' + reason, 'error');
            }
            return true;
        };

        var connectFailed = function(err) {
            store.setBusy(false);
            toast.show('Connection error: ' + (err && err.message ? err.message : err), 'error');
            store.refreshStatus();
        };

        // Back out of a connect that never reached the daemon (user chose
        // "Change servers"): restore the disconnected hero and hand the user
        // the pickers.
        var abortConnectUi = function() {
            store.setBusy(false);
            hero.showDisconnected();
            store.refreshStatus();
            hero.focusPickers();
        };

        // Same-operator-family confirmation, shared by the pre-connect check
        // and the NeedsRelaxedIndependenceCriteria error state. `tent` is the
        // tentative_gateways reply (names the family when it can) or null.
        // Confirm (red) = connect with the criteria relaxed; the safe green
        // button closes the modal and returns to the pickers.
        var confirmSameFamily = function(tent, onConnectAnyway, onChangeServers) {
            var risk = 'One operator seeing both ends of the tunnel can link your traffic going in and coming out, which defeats the point of two hops.';
            var lead;
            var ef = tent && tent.entry && typeof tent.entry.family === 'string' ? tent.entry.family.trim() : '';
            var xf = tent && tent.exit && typeof tent.exit.family === 'string' ? tent.exit.family.trim() : '';
            if (ef && xf && api.sameFamily(ef, xf)) {
                var en = tent.entry.name ? String(tent.entry.name) : 'gateway';
                var xn = tent.exit.name ? String(tent.exit.name) : 'gateway';
                lead = 'Entry ' + en + ' and exit ' + xn + ' are both run by ' + ef + '.';
            } else if (tent) {
                lead = 'The entry and exit the daemon would pick are not independent — they share an operator family, network or subnet.';
            } else {
                lead = INDEPENDENCE_ERROR_COPY;
            }
            modal.confirm(
                'The selected servers are in the same operator family!',
                lead + ' ' + risk,
                '⚠',
                function() { modal.hide(); if (onConnectAnyway) onConnectAnyway(); },
                function() { if (onChangeServers) onChangeServers(); },
                'Connect anyway',
                'Change servers'
            );
        };

        // Toast (or, for a non-independent pair, the two-way modal) for a
        // tunnel error. Returns true if something was shown. `force`
        // bypasses the once-per-occurrence guard (used in the connect flow,
        // where the user is actively waiting on a result).
        var handleTunnelError = function(result, force) {
            var reason = result && result.tunnel_error;
            if (!reason) return false;
            if (!force && reason === store.prevTunnelError) return false;
            if (api.isIndependenceError(reason)) {
                // Not a dead gateway: the pair is valid but shares an
                // operator family. Offer the same two ways out as the
                // pre-connect check instead of a bare toast.
                confirmSameFamily(null, function() {
                    startConnect(true).catch(connectFailed);
                }, hero.focusPickers);
                return true;
            }
            toast.show(TUNNEL_ERROR_COPY[reason] || 'Tunnel error — switch gateways.', 'error');
            return true;
        };

        // Issue the connect and follow it to a settled state. `relax` sends
        // relax_independence:true — a one-shot for this connect and its
        // automatic reconnects; the persisted setting is untouched.
        var startConnect = function(relax) {
            hero.showConnecting(true);
            return api.connect(relax)
                .then(function(result) {
                    if (!result || !result.success) {
                        toast.show('Connection failed: ' + (result.error || 'Unknown error'), 'error');
                        store.setBusy(false);
                        store.refreshStatus();
                        return;
                    }

                    var pollCount = 0;
                    var settle = function() {
                        store.setBusy(false);
                        store.refreshStatus();
                    };
                    var pollStatus = function() {
                        pollCount++;
                        api.status().then(function(st) {
                            // Account-controller error during a connect
                            // attempt: surface it, then ensure the daemon
                            // comes back to a clean disconnected state
                            // instead of spinning.
                            if (st && st.error_reason) {
                                accountErrorToast(st);
                                api.disconnect().then(settle).catch(settle);
                                return;
                            }
                            // Tunnel bounced to Error during the connect
                            // attempt (e.g. selected gateway unavailable).
                            // Surface it and stop cleanly so the user can
                            // switch gateways.
                            if (st && st.tunnel_error) {
                                handleTunnelError(st, true);
                                store.markTunnelError(st.tunnel_error);
                                settle();
                                return;
                            }
                            if (st && st.state === 'connected') {
                                store.setBusy(false);
                                store.markState('connected');
                                store.refreshStatus();
                            } else if (st && (st.state === 'connecting' || st.state === 'disconnecting')) {
                                if (pollCount < MAX_POLLS) setTimeout(pollStatus, nextDelay(pollCount));
                                else settle();
                            } else {
                                // Disconnected or unknown — give up cleanly
                                settle();
                            }
                        }).catch(function() {
                            if (pollCount < MAX_POLLS) setTimeout(pollStatus, nextDelay(pollCount));
                            else settle();
                        });
                    };

                    setTimeout(pollStatus, 250);
                }).catch(connectFailed);
        };

        var handleConnect = function() {
            // Whatever the pickers show right now is what connects — abort
            // any in-flight prefill so it can't mutate them mid-flow.
            pickers.invalidate();

            var sel = pickers.selection();
            var entry_country = sel.entry_country;
            var exit_country = sel.exit_country;
            var entry_id = sel.entry_id;
            var exit_id = sel.exit_id;

            // Require an explicit choice for both entry and exit. 'none'
            // means the user has not picked anything, and we must not
            // silently fall back to whatever was last saved on the daemon.
            var entryMissing = (entry_country === 'none') && !entry_id;
            var exitMissing = (exit_country === 'none') && !exit_id;
            if (entryMissing || exitMissing) {
                var which;
                if (entryMissing && exitMissing) which = 'entry and exit';
                else if (entryMissing) which = 'entry';
                else which = 'exit';
                toast.show('Please select a country for ' + which + ' before connecting.', 'error');
                return;
            }

            // Nothing has reached the daemon yet, so the button waits
            // disabled through the pre-connect check; startConnect arms
            // Cancel once the connect is actually issued.
            hero.showConnecting(false);

            var entry_random = false;
            var exit_random = false;

            if (entry_country === 'none') entry_country = null;
            if (exit_country === 'none') exit_country = null;
            if (entry_country === 'random') { entry_country = null; entry_id = null; entry_random = true; }
            if (exit_country === 'random') { exit_country = null; exit_id = null; exit_random = true; }
            if (entry_id) entry_country = null;
            if (exit_id) exit_country = null;

            // Save gateway settings, ask the daemon which pair it would
            // pick, then connect — plainly, relaxed, or after the user has
            // agreed.
            api.gatewaySet({
                entry_country: entry_country, exit_country: exit_country,
                entry_id: entry_id, exit_id: exit_id,
                entry_random: entry_random, exit_random: exit_random,
                residential_exit: null
            })
                .then(function(gwResult) {
                    if (!gwResult || !gwResult.success) {
                        console.warn('Gateway config warning:', gwResult ? gwResult.error : 'Unknown');
                    }
                    return api.tentativeGateways();
                })
                .then(function(tent) {
                    var verdict = tent && tent.status;
                    // 'selected', 'none', or no usable answer (older bridge,
                    // error, timeout): connect as before and let the daemon
                    // speak for itself.
                    if (verdict !== 'needs_relaxed') return startConnect(false);
                    if (!store.independence.notifications) {
                        toast.show('Entry and exit share an operator family — gateway independence relaxed for this connection.', 'warning');
                        return startConnect(true);
                    }
                    confirmSameFamily(tent, function() {
                        startConnect(true).catch(connectFailed);
                    }, abortConnectUi);
                })
                .catch(connectFailed);
        };

        var handleCancel = function() {
            store.setBusy(true);
            hero.showDisconnecting('Cancelling');

            api.disconnect().then(function(result) {
                store.setBusy(false);
                if (result && result.success) {
                    toast.show('Connection cancelled', 'warning');
                } else {
                    toast.show('Cancel failed: ' + (result.error || 'Unknown'), 'error');
                }
                store.markState('disconnected');
                store.refreshStatus();
            }).catch(function(err) {
                store.setBusy(false);
                toast.show('Cancel error: ' + err.message, 'error');
                store.refreshStatus();
            });
        };

        var handleDisconnect = function() {
            store.setBusy(true);
            hero.showDisconnecting('Disconnecting');

            api.disconnect().then(function(result) {
                if (!result || !result.success) {
                    store.setBusy(false);
                    toast.show('Disconnect failed: ' + (result ? result.error : 'Unknown'), 'error');
                    store.refreshStatus();
                    return;
                }

                // Poll until the daemon reaches disconnected — same
                // adaptive cadence as the connect path.
                var pollCount = 0;
                var settle = function() {
                    store.setBusy(false);
                    store.refreshStatus();
                };
                var pollDisconnect = function() {
                    pollCount++;
                    api.status().then(function(st) {
                        if (st && st.state === 'disconnected') {
                            store.setBusy(false);
                            store.markState('disconnected');
                            store.refreshStatus();
                        } else if (pollCount < MAX_POLLS) {
                            setTimeout(pollDisconnect, nextDelay(pollCount));
                        } else {
                            settle();
                        }
                    }).catch(function() {
                        if (pollCount < MAX_POLLS) setTimeout(pollDisconnect, nextDelay(pollCount));
                        else settle();
                    });
                };

                setTimeout(pollDisconnect, 250);
            }).catch(function(err) {
                store.setBusy(false);
                toast.show('Disconnect error: ' + err.message, 'error');
                store.refreshStatus();
            });
        };

        flow.handleConnect = handleConnect;
        flow.handleDisconnect = handleDisconnect;
        flow.handleCancel = handleCancel;
        flow.startConnect = startConnect;
        flow.connectFailed = connectFailed;
        flow.handleTunnelError = handleTunnelError;
        flow.accountErrorToast = accountErrorToast;
        return flow;
    }
});
