'use strict';
'require view';
'require ui';
'require poll';
'require dom';
'require nym-vpn.theme as theme';
'require nym-vpn.rpc as rpc';
'require nym-vpn.countries as countries';
'require nym-vpn.assets as assets';
'require nym-vpn.ui as nymUI';

return view.extend({
    load: function() {
        // Single batch RPC call replaces 11 separate calls.
        // Gateway country lists are deferred until user interaction.
        return rpc.init().catch(function(err) {
            console.error('Failed to load Nym VPN data:', err);
            return {};
        });
    },

    render: function(initData) {
        var data = initData || {};
        var status = data.status || {};
        var info = data.info || {};
        var gateway_config = data.gateway_config || {};
        var tunnel_config = data.tunnel_config || {};
        var account_info = data.account || {};
        var network = data.network || {};
        var daemon_status = data.daemon || {};
        var ad_block = data.ad_block || {};
        var stats_config = data.stats || {};
        var dns_config = data.dns || {};
        var watchdog = data.watchdog || {};
        var inbound_exemptions = data.inbound_exemptions || [];
        var split_exclusions = data.split_exclusions || [];
        var split_status = data.split_status || {};
        var lan_clients = data.clients || [];

        var self = this;
        var E = dom.create.bind(dom);
        var svgIcon = function(svg) {
            var el = E('div', { 'class': 'nym-card-icon' });
            el.innerHTML = svg;
            return el;
        };

        // Initialize UI managers
        var modalManager = nymUI.createModalManager();
        var toastManager = nymUI.createToastManager();
        var showToast = toastManager.show.bind(toastManager);
        var showModal = modalManager.show;
        var hideModal = modalManager.hide;
        var fadeOutModal = modalManager.fadeOut;
        var updateModal = modalManager.update;
        var setModalSuccess = modalManager.setSuccess;
        var confirmModal = modalManager.confirm;

        // State references
        var statusHero, statusLabel, uptimeDisplay;
        var actionBtn;
        var entryGatewayDisplay, exitGatewayDisplay, connectionChain, modeLabel;
        var entryCountrySelect, exitCountrySelect;
        var entryGatewayContainer, exitGatewayContainer;
        var isTwoHopMode = tunnel_config.two_hop === 'on';
        var previousState = status.state || 'unknown';
        // Signature of the last connected-state render (gateway identity + hop
        // count). The status poll fires every 5s, but none of this changes for
        // the life of a connection, so we only rebuild the gateway panels and
        // the connection chain when the signature actually changes. This avoids
        // tearing down and recreating the animated chain elements every poll.
        var lastConnectedSig = null;
        // Last account error_reason seen from status polling. When it changes
        // (e.g. a Device-Time-Desynced error clears after recovery) we re-fetch
        // account state and rebuild the card so it doesn't stay stale until a
        // manual page reload.
        var prevErrorReason = (status && status.error_reason) || '';
        // Last tunnel_error seen from status polling, so we notify once per
        // occurrence instead of re-toasting on every 5s poll.
        var prevTunnelError = (status && status.tunnel_error) || '';
        var actionInProgress = false;
        var daemonStatusBadge;
        var daemonStatusBadgeText;
        var serviceInfoFrame;
        var daemonStartBtn;
        var daemonStopBtn;
        // Whether nym-vpnd has its boot symlink. Defaults to true so an older
        // bridge that omits the field never shows a spurious warning.
        var lastDaemonEnabled = daemon_status.enabled !== false;
        // Last account availability seen from status polling, so the Account
        // card is rebuilt when the daemon comes back or goes away.
        var prevAccountUnavailable = (status && status.available === false) || false;
        // Inbound-exemptions section, mounted inside the Tunnel Settings card
        // under the Kill-Switch toggle and shown only while kill-switch is on.
        var inboundMount;
        var splitMount;

        // Uptime tracking
        var connectionStartTime = null;
        var uptimeInterval = null;

        // The session duration is anchored to the router-reported elapsed
        // seconds (status.connected_seconds) instead of a per-browser
        // localStorage timestamp — that old timer drifted between
        // browsers/sessions and was meaningless when the router clock itself
        // was desynced. connectionStartTime is a *virtual* start expressed in
        // the local clock (now - elapsed) used only to drive a smooth 1s tick;
        // the authoritative base comes from the router on every poll.
        var renderUptime = function() {
            if (uptimeDisplay && connectionStartTime) {
                var elapsed = Math.floor((Date.now() - connectionStartTime) / 1000);
                if (elapsed < 0) elapsed = 0;
                uptimeDisplay.textContent = nymUI.formatUptime(elapsed);
            }
        };

        // Re-anchor the virtual start on every poll (cheap), but keep a single
        // 1s ticker for the connection's lifetime instead of tearing it down
        // and rebuilding it each poll (which churned a timer and could stutter
        // the display).
        var syncUptime = function(elapsedSeconds) {
            var base = (typeof elapsedSeconds === 'number' && isFinite(elapsedSeconds) && elapsedSeconds >= 0)
                ? elapsedSeconds : 0;
            connectionStartTime = Date.now() - base * 1000;
            renderUptime();
            if (!uptimeInterval) uptimeInterval = setInterval(renderUptime, 1000);
        };

        var stopUptimeTimer = function() {
            if (uptimeInterval) {
                clearInterval(uptimeInterval);
                uptimeInterval = null;
            }
            connectionStartTime = null;
            nymUI.clearStartTime();
            if (uptimeDisplay) uptimeDisplay.textContent = '--:--';
        };

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

        // Build a toast message for an account error from ERROR_COPY +
        // optional rpcd-supplied error_message.
        var accountErrorToast = function(result) {
            var reason = result && result.error_reason;
            if (!reason) return false;
            var copy = ERROR_COPY[reason];
            if (copy) {
                var detail = copy.detail || result.error_message || '';
                showToast(detail ? copy.heading + ' — ' + detail : copy.heading, copy.sev);
            } else {
                showToast('Account error: ' + reason, 'error');
            }
            return true;
        };

        // User-facing copy for tunnel (state-machine) errors. Keyed by the
        // variant rpcd parses out of "State: Error state: <Reason>".
        var TUNNEL_ERROR_COPY = {
            PerformantEntryGatewayUnavailable: 'Entry gateway unavailable — switch gateways.',
            PerformantExitGatewayUnavailable: 'Exit gateway unavailable — switch gateways.'
        };

        // Toast for a tunnel error. Returns true if one was shown. `force`
        // bypasses the once-per-occurrence guard (used in the connect flow,
        // where the user is actively waiting on a result).
        var tunnelErrorToast = function(result, force) {
            var reason = result && result.tunnel_error;
            if (!reason) return false;
            if (!force && reason === prevTunnelError) return false;
            showToast(TUNNEL_ERROR_COPY[reason] || 'Tunnel error — switch gateways.', 'error');
            return true;
        };

        // Update status display
        var updateStatus = function() {
            // Block background polls while a connect/disconnect action owns the UI
            if (actionInProgress) return Promise.resolve();

            return rpc.status().then(function(result) {
                if (!result) return;

                // Re-check after async gap — action may have started while request was in-flight
                if (actionInProgress) return;

                var state = result.state || 'unknown';

                if (statusHero) {
                    statusHero.className = 'nym-status-hero ' + state;
                }

                if (statusLabel) {
                    if (state === 'connected') {
                        statusLabel.textContent = 'Connected';
                        // Re-anchor to the router's elapsed seconds each poll so
                        // the timer self-corrects and stays consistent across
                        // browsers; falls back to a local count if absent.
                        var secs = parseInt(result.connected_seconds, 10);
                        if (!isNaN(secs)) {
                            syncUptime(secs);
                        } else if (!connectionStartTime) {
                            syncUptime(0);
                        }
                    } else if (state === 'connecting') {
                        statusLabel.textContent = 'Connecting';
                        stopUptimeTimer();
                    } else if (state === 'disconnecting') {
                        // An account-level error often strands the tunnel in
                        // Disconnecting; the error strip shows why, so the
                        // label switches to Halted to stop implying progress.
                        statusLabel.textContent = result.error_reason ? 'Halted' : 'Disconnecting';
                    } else if (result.tunnel_error) {
                        // Persistent cue once the toast has faded: the tunnel
                        // bounced to Error (e.g. gateway unavailable), not a
                        // clean user disconnect.
                        statusLabel.textContent = 'Gateway unavailable';
                        stopUptimeTimer();
                    } else {
                        statusLabel.textContent = 'Disconnected';
                        stopUptimeTimer();
                    }
                }


                if (actionBtn) {
                    if (state === 'connected') {
                        actionBtn.textContent = 'Disconnect';
                        actionBtn.className = 'nym-btn nym-btn-danger';
                        actionBtn.disabled = false;
                        actionBtn.onclick = handleDisconnect;
                    } else if (state === 'disconnected') {
                        actionBtn.textContent = 'Connect';
                        actionBtn.className = 'nym-btn nym-btn-primary';
                        actionBtn.disabled = false;
                        actionBtn.onclick = handleConnect;
                    } else if (state === 'connecting') {
                        actionBtn.textContent = 'Cancel';
                        actionBtn.className = 'nym-btn nym-btn-danger';
                        actionBtn.disabled = false;
                        actionBtn.onclick = handleCancel;
                    } else {
                        // disconnecting — keep disabled
                        actionBtn.textContent = 'Disconnecting';
                        actionBtn.disabled = true;
                    }
                }

                if (state === 'connected') {
                    // Only rebuild the gateway panels and chain when something
                    // actually changed — the poll fires every 5s but this data
                    // is fixed for the connection's lifetime.
                    var hops = isTwoHopMode ? 2 : 5;
                    var sig = [result.entry_name, result.entry_id, result.entry_ip, result.entry_country,
                               result.exit_name, result.exit_id, result.exit_ip, result.exit_country,
                               hops].join('|');
                    if (sig !== lastConnectedSig) {
                        lastConnectedSig = sig;
                        nymUI.renderGatewayInfo(entryGatewayDisplay,
                            result.entry_name,
                            result.entry_id,
                            result.entry_ip,
                            result.entry_country,
                            countries.data);
                        nymUI.renderGatewayInfo(exitGatewayDisplay,
                            result.exit_name,
                            result.exit_id,
                            result.exit_ip,
                            result.exit_country,
                            countries.data);
                        buildConnectionChain(hops);
                    }

                    // The pickers are hidden while connected and their saved
                    // state now lives on the daemon, so any in-flight prefill
                    // is stale and the dirty flag has served its purpose.
                    // Deliberately NOT resetting the picker contents here: they
                    // sit invisibly under the connection info (grid overlay in
                    // theme.js) and blanking them would flash mid-dissolve and
                    // change the panel footprint. The disconnect-time restore
                    // below re-syncs them from the daemon config regardless.
                    restoreGeneration++;
                    pickersDirty = false;
                } else if (state === 'disconnected' || state === 'connecting') {
                    // Only clear gateway info when fully disconnected or connecting fresh
                    if (entryGatewayDisplay) entryGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
                    if (exitGatewayDisplay) exitGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
                    // Force a fresh render on the next connect.
                    lastConnectedSig = null;
                    // The tunnel just dropped: refill the pickers from the
                    // saved daemon config so reconnecting doesn't force a
                    // re-pick of both sides.
                    if (state === 'disconnected' && previousState !== 'disconnected') {
                        restoreGatewaySelection();
                    }
                }
                // Keep gateway info visible during 'disconnecting' state

                // Re-render the account card when the account error situation
                // changes, so a recovered account (or a newly-failed one)
                // reflects live instead of waiting for a page reload.
                var curErrorReason = result.error_reason || '';
                if (curErrorReason !== prevErrorReason) {
                    prevErrorReason = curErrorReason;
                    if (typeof refreshAccountCard === 'function') refreshAccountCard();
                }

                // The daemon appearing or disappearing produces no
                // error_reason of its own, so track it separately: without
                // this the Account card keeps showing the stale panel until
                // the page is reloaded.
                var curUnavailable = result.available === false;
                if (curUnavailable !== prevAccountUnavailable) {
                    prevAccountUnavailable = curUnavailable;
                    if (typeof refreshAccountCard === 'function') refreshAccountCard();
                }

                // Surface tunnel errors (e.g. gateway unavailable) once, when
                // they first appear, so the user knows to switch gateways.
                var curTunnelError = result.tunnel_error || '';
                if (curTunnelError && curTunnelError !== prevTunnelError) {
                    tunnelErrorToast(result);
                }
                prevTunnelError = curTunnelError;

                // Update previous state for next poll
                previousState = state;

            }).catch(function(err) {
                console.error('Status update failed:', err);
            });
        };

        // Build connection chain visualization
        var buildConnectionChain = function(hopCount) {
            if (!connectionChain) return;
            connectionChain.innerHTML = '';

            // Set mode label
            if (modeLabel) {
                modeLabel.textContent = hopCount === 2 ? 'Fast Mode' : 'Anonymous Mode';
            }

            // Entry node
            connectionChain.appendChild(E('div', { 'class': 'nym-chain-node' }));

            if (hopCount === 2) {
                // Two-hop: longer line to match 5-hop total distance
                connectionChain.appendChild(E('div', { 'class': 'nym-chain-line long' }));
            } else {
                // Mixnet (5-hop): 3 middle nodes with lines
                for (var i = 0; i < 3; i++) {
                    connectionChain.appendChild(E('div', { 'class': 'nym-chain-line' }));
                    connectionChain.appendChild(E('div', { 'class': 'nym-chain-node mixnet' }));
                }
                connectionChain.appendChild(E('div', { 'class': 'nym-chain-line' }));
            }

            // Exit node
            connectionChain.appendChild(E('div', { 'class': 'nym-chain-node' }));
        };

        // Connection handlers
        var handleConnect = function() {
            // Whatever the pickers show right now is what connects — abort any
            // in-flight prefill so it can't mutate them mid-flow.
            restoreGeneration++;

            // Get selected gateway settings
            var entry_country = entryCountrySelect ? entryCountrySelect.value : 'none';
            var exit_country = exitCountrySelect ? exitCountrySelect.value : 'none';

            // Get selected gateway IDs from radio buttons
            var entryRadio = entryGatewayContainer ? entryGatewayContainer.querySelector('input[name="entry_gateway_id"]:checked') : null;
            var exitRadio = exitGatewayContainer ? exitGatewayContainer.querySelector('input[name="exit_gateway_id"]:checked') : null;
            var entry_id = entryRadio ? entryRadio.value : null;
            var exit_id = exitRadio ? exitRadio.value : null;

            // Require an explicit choice for both entry and exit. 'none' means
            // the user has not picked anything, and we must not silently fall
            // back to whatever was last saved on the daemon.
            var entryMissing = (entry_country === 'none') && !entry_id;
            var exitMissing = (exit_country === 'none') && !exit_id;
            if (entryMissing || exitMissing) {
                var which;
                if (entryMissing && exitMissing) which = 'entry and exit';
                else if (entryMissing) which = 'entry';
                else which = 'exit';
                showToast('Please select a country for ' + which + ' before connecting.', 'error');
                return;
            }

            actionInProgress = true;
            if (statusHero) statusHero.className = 'nym-status-hero connecting';
            if (statusLabel) statusLabel.textContent = 'Connecting';
            if (actionBtn) {
                actionBtn.textContent = 'Cancel';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.disabled = false;
                actionBtn.onclick = handleCancel;
            }

            var entry_random = false;
            var exit_random = false;

            if (entry_country === 'none') entry_country = null;
            if (exit_country === 'none') exit_country = null;
            if (entry_country === 'random') { entry_country = null; entry_id = null; entry_random = true; }
            if (exit_country === 'random') { exit_country = null; exit_id = null; exit_random = true; }
            if (entry_id) entry_country = null;
            if (exit_id) exit_country = null;

            // Save gateway settings first, then connect
            rpc.gatewaySet(entry_country, exit_country, entry_id || null, exit_id || null, entry_random, exit_random, null)
                .then(function(gwResult) {
                    if (!gwResult || !gwResult.success) {
                        console.warn('Gateway config warning:', gwResult ? gwResult.error : 'Unknown');
                    }
                    return rpc.connect();
                })
                .then(function(result) {
                    if (!result || !result.success) {
                        showToast('Connection failed: ' + (result.error || 'Unknown error'), 'error');
                        actionInProgress = false;
                        updateStatus();
                        return;
                    }

                    // Poll until daemon reaches connected state. Fast cadence
                    // (250ms) for the first 5s so the UI confirms within one
                    // beat of the daemon (~2.5s connects), then 1s up to the
                    // same ~60s ceiling. A status call is ~10ms via the Rust
                    // rpcd bridge, so the fast phase costs nothing.
                    var pollCount = 0;
                    var maxPolls = 75;
                    var nextDelay = function() { return pollCount < 20 ? 250 : 1000; };

                    var pollStatus = function() {
                        pollCount++;
                        rpc.status().then(function(st) {
                            // Account-controller error during a connect attempt:
                            // surface it, then ensure the daemon comes back to
                            // a clean disconnected state instead of spinning.
                            if (st && st.error_reason) {
                                accountErrorToast(st);
                                rpc.disconnect().then(function() {
                                    actionInProgress = false;
                                    updateStatus();
                                }).catch(function() {
                                    actionInProgress = false;
                                    updateStatus();
                                });
                                return;
                            }
                            // Tunnel bounced to Error during the connect attempt
                            // (e.g. selected gateway unavailable). Surface it and
                            // stop cleanly so the user can switch gateways.
                            if (st && st.tunnel_error) {
                                tunnelErrorToast(st, true);
                                prevTunnelError = st.tunnel_error;
                                actionInProgress = false;
                                updateStatus();
                                return;
                            }
                            if (st && st.state === 'connected') {
                                actionInProgress = false;
                                previousState = 'connected';
                                updateStatus();
                            } else if (st && (st.state === 'connecting' || st.state === 'disconnecting')) {
                                if (pollCount < maxPolls) {
                                    setTimeout(pollStatus, nextDelay());
                                } else {
                                    actionInProgress = false;
                                    updateStatus();
                                }
                            } else {
                                // Disconnected or unknown — give up cleanly
                                actionInProgress = false;
                                updateStatus();
                            }
                        }).catch(function() {
                            if (pollCount < maxPolls) setTimeout(pollStatus, nextDelay());
                            else { actionInProgress = false; updateStatus(); }
                        });
                    };

                    setTimeout(pollStatus, 250);
                }).catch(function(err) {
                    actionInProgress = false;
                    showToast('Connection error: ' + err.message, 'error');
                    updateStatus();
                });
        };

        var handleCancel = function() {
            actionInProgress = true;
            if (statusHero) statusHero.className = 'nym-status-hero disconnecting';
            if (statusLabel) statusLabel.textContent = 'Cancelling';
            if (actionBtn) {
                actionBtn.textContent = 'Cancelling';
                actionBtn.disabled = true;
            }

            rpc.disconnect().then(function(result) {
                actionInProgress = false;
                if (result && result.success) {
                    showToast('Connection cancelled', 'warning');
                } else {
                    showToast('Cancel failed: ' + (result.error || 'Unknown'), 'error');
                }
                previousState = 'disconnected';
                updateStatus();
            }).catch(function(err) {
                actionInProgress = false;
                showToast('Cancel error: ' + err.message, 'error');
                updateStatus();
            });
        };

        var handleDisconnect = function() {
            actionInProgress = true;
            if (statusHero) statusHero.className = 'nym-status-hero disconnecting';
            if (statusLabel) statusLabel.textContent = 'Disconnecting';
            if (actionBtn) {
                actionBtn.textContent = 'Disconnecting';
                actionBtn.disabled = true;
            }

            rpc.disconnect().then(function(result) {
                if (!result || !result.success) {
                    actionInProgress = false;
                    showToast('Disconnect failed: ' + (result ? result.error : 'Unknown'), 'error');
                    updateStatus();
                    return;
                }

                // Poll until daemon reaches disconnected state — same adaptive
                // cadence as the connect path.
                var pollCount = 0;
                var maxPolls = 75;
                var nextDelay = function() { return pollCount < 20 ? 250 : 1000; };

                var pollDisconnect = function() {
                    pollCount++;
                    rpc.status().then(function(st) {
                        if (st && st.state === 'disconnected') {
                            actionInProgress = false;
                            previousState = 'disconnected';
                            updateStatus();
                        } else if (pollCount < maxPolls) {
                            setTimeout(pollDisconnect, nextDelay());
                        } else {
                            actionInProgress = false;
                            updateStatus();
                        }
                    }).catch(function() {
                        if (pollCount < maxPolls) setTimeout(pollDisconnect, nextDelay());
                        else { actionInProgress = false; updateStatus(); }
                    });
                };

                setTimeout(pollDisconnect, 250);
            }).catch(function(err) {
                actionInProgress = false;
                showToast('Disconnect error: ' + err.message, 'error');
                updateStatus();
            });
        };

        // Toggle card expand/collapse
        var toggleCard = function(card) {
            card.classList.toggle('expanded');
        };

        // --- Gateway directory (session cache) ---------------------------
        // One gateway_list_full call per type (served by the Rust rpcd
        // bridge from the daemon's directory cache) feeds both the country
        // dropdown and every per-country list for the rest of the session.
        // The old per-country RPCs stay as a fallback for a backend without
        // the bridge, so a version-skewed install degrades instead of dying.
        var gatewayListCache = {};

        var getGatewayList = function(gwType) {
            if (!gatewayListCache[gwType]) {
                gatewayListCache[gwType] = rpc.gatewayListFull(gwType).then(function(result) {
                    if (!result || !Array.isArray(result.gateways))
                        throw new Error((result && result.error) || 'Invalid gateway list');
                    if (result.error && result.gateways.length === 0)
                        throw new Error(result.error);
                    return result.gateways;
                }).catch(function(err) {
                    // Don't cache failure: the next interaction retries.
                    gatewayListCache[gwType] = null;
                    throw err;
                });
            }
            return gatewayListCache[gwType];
        };

        // Warm the picker data shortly after load instead of on first click:
        // the transfer happens while the user is still looking at the
        // dashboard, and a daemon whose directory cache is still cold (e.g.
        // right after a restart) gets its fetch out of the way early. Errors
        // are swallowed — the pickers retry on interaction.
        window.setTimeout(function() {
            getGatewayList('mixnet-entry').catch(function() {});
            getGatewayList('mixnet-exit').catch(function() {});
        }, 1500);

        // Load gateways for selected country
        var loadGatewaysForCountry = function(country, type, container) {
            if (!country || country === 'none') {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country above'));
                return Promise.resolve();
            }

            if (country === 'random') {
                dom.content(container, '');
                return Promise.resolve();
            }

            dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Loading gateways...'));

            return getGatewayList(type).then(function(list) {
                return { gateways: list.filter(function(gw) { return gw.country === country; }) };
            }).catch(function() {
                // Older backend without gateway_list_full: per-country RPC.
                return rpc.gatewayListByCountry(type, country);
            }).then(function(result) {
                if (!result || !result.gateways || result.gateways.length === 0) {
                    dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'No gateways available'));
                    return;
                }

                var inputName = type === 'mixnet-entry' ? 'entry_gateway_id' : 'exit_gateway_id';
                // Circumvention Transports gating: when CT is on, only bridge-
                // capable gateways are valid ENTRY gateways. Read the live toggle
                // (falling back to saved config); for the entry picker only, sink
                // incompatible gateways and disable selecting them below. gw.bridges
                // is only present when the daemon reports it, so treat strictly
                // === false to stay graceful against an older daemon.
                var ctEl = document.getElementById('circumvention-toggle');
                var ctOn = ctEl ? ctEl.checked : (tunnel_config.circumvention_transports === 'on');
                var ctFilter = (inputName === 'entry_gateway_id') && ctOn;

                var perfRank = function(p) {
                    p = p || '';
                    return p.indexOf('High') >= 0 ? 3 :
                           p.indexOf('Medium') >= 0 ? 2 :
                           p.indexOf('Offline') >= 0 ? 0 : 1;
                };
                var sorted = result.gateways.slice().sort(function(a, b) {
                    if (ctFilter) {
                        var ca = (a.bridges === false) ? 1 : 0;
                        var cb = (b.bridges === false) ? 1 : 0;
                        if (ca !== cb) return ca - cb;
                    }
                    return perfRank(b.performance) - perfRank(a.performance);
                });

                var gatewayList = E('div', { 'class': 'nym-gateway-list' });

                var randomOption = E('label', { 'class': 'nym-gateway-option selected' }, [
                    E('input', { 'type': 'radio', 'name': inputName, 'value': '', 'checked': 'checked' }),
                    E('div', { 'class': 'nym-gateway-option-info' }, [
                        E('div', { 'class': 'nym-gateway-option-name' }, '🎲 Any Gateway (Random)')
                    ])
                ]);
                randomOption.addEventListener('click', function() {
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    randomOption.classList.add('selected');
                });
                gatewayList.appendChild(randomOption);

                sorted.forEach(function(gw) {
                    var perf = gw.performance || 'Unknown';
                    var iconDiv = E('div', { 'class': 'nym-gateway-option-icon' });
                    iconDiv.innerHTML = nymUI.getQualityIcon(perf, assets);

                    var ctIncompatible = ctFilter && (gw.bridges === false);

                    var nameChildren = [String(gw.name || 'Unknown')];
                    if (ctIncompatible) {
                        nameChildren.push(E('span', {
                            'style': 'margin-left:6px; padding:1px 5px; border-radius:8px; font-size:9px; text-transform:uppercase; letter-spacing:0.5px; background:var(--danger,#e74c3c); color:#fff; vertical-align:middle'
                        }, 'No CT'));
                    }

                    var inputAttrs = { 'type': 'radio', 'name': inputName, 'value': gw.id || '' };
                    if (ctIncompatible) inputAttrs.disabled = 'disabled';

                    var option = E('label', {
                        'class': 'nym-gateway-option' + (ctIncompatible ? ' disabled' : ''),
                        'style': ctIncompatible ? 'opacity:0.5; cursor:not-allowed' : ''
                    }, [
                        E('input', inputAttrs),
                        iconDiv,
                        E('div', { 'class': 'nym-gateway-option-info' }, [
                            // Array-wrap: gateway name/perf come from the directory
                            // (operator-controlled) and must render as text, not innerHTML.
                            E('div', { 'class': 'nym-gateway-option-name' }, nameChildren),
                            E('div', { 'class': 'nym-gateway-option-perf' }, [String(perf)])
                        ])
                    ]);
                    if (!ctIncompatible) {
                        option.addEventListener('click', function() {
                            container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                                el.classList.remove('selected');
                            });
                            option.classList.add('selected');
                        });
                    }
                    gatewayList.appendChild(option);
                });

                dom.content(container, [
                    E('label', { 'class': 'nym-form-label' }, 'Gateway'),
                    gatewayList,
                    E('div', { 'style': 'font-size: 11px; color: var(--text-muted); margin-top: 8px' },
                        result.gateways.length + ' gateways available')
                ]);
            }).catch(function(err) {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading', 'style': 'color: var(--danger)' },
                    'Error: ' + err.message));
            });
        };

        // Create country select
        var populateCountrySelect = function(select, countryList) {
            while (select.options.length > 0) select.remove(0);
            select.appendChild(E('option', { 'value': 'none' }, '— Select Country —'));
            select.appendChild(E('option', { 'value': 'random' }, '🌐 Random'));
            // The directory returns countries in ISO-code order; sort by the
            // displayed name so the dropdown reads alphabetically.
            var sorted = countryList.slice().sort(function(a, b) {
                return countries.getDisplay(a.code).name.localeCompare(countries.getDisplay(b.code).name);
            });
            sorted.forEach(function(c) {
                var info = countries.getDisplay(c.code);
                select.appendChild(E('option', { 'value': c.code },
                    info.flag + ' ' + info.name + ' (' + c.count + ')'));
            });
        };

        // Cache for loaded country lists
        var countryCache = {};

        var createCountrySelect = function(gwType, name, onSelect) {
            var select = E('select', {
                'class': 'nym-select',
                'name': name,
                'change': onSelect
            }, [E('option', { 'value': 'none' }, '— Select Country —')]);

            // Populate options on demand: first focus, or a programmatic
            // prefill via ensureLoaded(). The promise is cached so the options
            // are only built once; a failed load clears it so the next attempt
            // retries. Countries are derived from the shared full list; the
            // per-country-counts RPC is only a fallback for older backends.
            var loadPromise = null;
            select.ensureLoaded = function() {
                if (!loadPromise) {
                    loadPromise = getGatewayList(gwType).then(function(gateways) {
                        var counts = {};
                        gateways.forEach(function(gw) {
                            if (gw.country) counts[gw.country] = (counts[gw.country] || 0) + 1;
                        });
                        return Object.keys(counts).sort().map(function(code) {
                            return { code: code, count: counts[code] };
                        });
                    }).catch(function() {
                        return countryCache[gwType]
                            ? Promise.resolve(countryCache[gwType])
                            : rpc.gatewayListCountries(gwType).then(function(result) {
                                var list = (result && result.countries) || [];
                                countryCache[gwType] = list;
                                return list;
                            });
                    }).then(function(list) {
                        populateCountrySelect(select, list);
                    }).catch(function() {
                        loadPromise = null;
                        select.options[0].textContent = '— Failed to load —';
                    });
                }
                return loadPromise;
            };
            select.addEventListener('focus', function() { select.ensureLoaded(); });

            return select;
        };

        // --- Remember last gateway selection ---------------------------------
        // The daemon persists entry/exit points across disconnects, but these
        // pickers used to come back empty, forcing a full re-pick before every
        // reconnect. restoreGatewaySelection() prefills them from the saved
        // daemon config, so the explicit-choice guard in handleConnect passes
        // with the previous selection visible instead of silently falling back
        // to invisible state. pickersDirty stops a restore from stomping on
        // picks the user is making right now; restoreGeneration aborts stale
        // in-flight restores when the state moves on (connect, reconnect).
        var pickersDirty = false;
        var restoreGeneration = 0;
        var markPickersDirty = function() { pickersDirty = true; };

        var selectHasOption = function(select, value) {
            for (var i = 0; i < select.options.length; i++)
                if (select.options[i].value === value) return true;
            return false;
        };

        // Prefill one side. saved = {type, country, id} from gateway_get:
        // type 'random' selects the Random option; 'country' opens the saved
        // country with the default "Any Gateway" radio; 'gateway' additionally
        // checks the saved gateway's radio, degrading to country-level when the
        // gateway is gone from the directory or CT-disabled.
        var restoreSide = function(select, container, listType, saved, gen) {
            if (!select || !saved || !saved.type) return Promise.resolve();
            var stale = function() { return gen !== restoreGeneration || pickersDirty; };
            return select.ensureLoaded().then(function() {
                if (stale()) return;
                if (saved.type === 'random') {
                    if (selectHasOption(select, 'random')) {
                        select.value = 'random';
                        return loadGatewaysForCountry('random', listType, container);
                    }
                    return;
                }
                if (!saved.country || !selectHasOption(select, saved.country)) return;
                select.value = saved.country;
                return loadGatewaysForCountry(saved.country, listType, container).then(function() {
                    if (stale() || saved.type !== 'gateway' || !saved.id || !container) return;
                    var radio = container.querySelector('input[value="' + saved.id + '"]');
                    if (!radio || radio.disabled) return;
                    radio.checked = true;
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    var opt = radio.closest('.nym-gateway-option');
                    if (opt) opt.classList.add('selected');
                });
            });
        };

        var restoreGatewaySelection = function() {
            if (pickersDirty) return;
            var gen = ++restoreGeneration;
            rpc.gatewayGet().then(function(cfg) {
                if (!cfg || gen !== restoreGeneration || pickersDirty) return;
                restoreSide(entryCountrySelect, entryGatewayContainer, 'mixnet-entry',
                    { type: cfg.entry_type, country: cfg.entry_country, id: cfg.entry_id }, gen);
                restoreSide(exitCountrySelect, exitGatewayContainer, 'mixnet-exit',
                    { type: cfg.exit_type, country: cfg.exit_country, id: cfg.exit_id }, gen);
            }).catch(function() {});
        };

        // Gateway update handler
        var handleGatewayUpdate = function(ev) {
            ev.preventDefault();
            var form = ev.target;
            var fd = new FormData(form);

            var entry_country = fd.get('entry_country');
            var exit_country = fd.get('exit_country');
            var entry_id = fd.get('entry_gateway_id');
            var exit_id = fd.get('exit_gateway_id');
            var residential = fd.get('residential_exit');

            var entry_random = false;
            var exit_random = false;

            if (entry_country === 'none') entry_country = null;
            if (exit_country === 'none') exit_country = null;
            if (entry_country === 'random') { entry_country = null; entry_id = null; entry_random = true; }
            if (exit_country === 'random') { exit_country = null; exit_id = null; exit_random = true; }
            if (entry_id) entry_country = null;
            if (exit_id) exit_country = null;

            rpc.gatewaySet(entry_country, exit_country, entry_id || null, exit_id || null, entry_random, exit_random, residential || null)
                .then(function(result) {
                    if (result && result.success) {
                        showToast('Gateway configuration saved', 'success');
                    } else {
                        showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                    }
                }).catch(function(err) {
                    showToast('Error: ' + err.message, 'error');
                });
        };

        // Save all tunnel toggles immediately
        var saveTunnelSettings = function() {
            var ipv6El = document.getElementById('ipv6-toggle');
            var twoHopEl = document.getElementById('two-hop-toggle');
            var killswitchEl = document.getElementById('killswitch-toggle');
            var circumventionEl = document.getElementById('circumvention-toggle');
            var legacySplitEl = document.getElementById('legacy-split-toggle');
            var stealthApiEl = document.getElementById('stealth-api-toggle');
            if (!ipv6El || !twoHopEl || !killswitchEl || !circumventionEl) return;

            var ipv6 = ipv6El.checked ? 'on' : 'off';
            var two_hop = twoHopEl.checked ? 'on' : 'off';
            var legacy_split_tunnel = legacySplitEl && legacySplitEl.checked ? 'on' : 'off';
            // Legacy split tunneling and the kill-switch are mutually exclusive.
            // When legacy mode is on the daemon forces the kill-switch off anyway,
            // but send 'off' so the stored value and the (greyed) toggle agree.
            var killswitch = (legacy_split_tunnel === 'on') ? 'off' : (killswitchEl.checked ? 'on' : 'off');
            var circumvention = circumventionEl.checked ? 'on' : 'off';
            var stealth_api = stealthApiEl && stealthApiEl.checked ? 'on' : 'off';

            rpc.tunnelSet(ipv6, two_hop, killswitch, circumvention, legacy_split_tunnel, stealth_api).then(function(result) {
                if (result && result.success) {
                    isTwoHopMode = (two_hop === 'on');
                    showToast('Tunnel settings saved', 'success');
                } else {
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                showToast('Error: ' + err.message, 'error');
            });
        };

        // Save mixnet tuning knobs. Numeric fields are optional: empty input
        // means "leave as-is" (the daemon keeps its current/default value).
        var saveMixnetTuning = function() {
            var poissonEl = document.getElementById('tuning-poisson-toggle');
            var coverEl = document.getElementById('tuning-cover-toggle');
            var loopEl = document.getElementById('tuning-loop-cover');
            var packetEl = document.getElementById('tuning-packet-delay');
            var messageEl = document.getElementById('tuning-message-delay');
            if (!poissonEl || !coverEl) return;

            var inRange = function(el, min, max) {
                if (!el || el.value === '') return '';
                var n = parseInt(el.value, 10);
                if (isNaN(n) || n < min || n > max) return null;
                return String(n);
            };

            var loop_cover = inRange(loopEl, 0, 200);
            var packet = inRange(packetEl, 0, 200);
            var message = inRange(messageEl, 5, 50);
            if (loop_cover === null || packet === null || message === null) {
                showToast('Tuning values out of range (cover 0-200, mixing 0-200, sending 5-50 ms)', 'error');
                return;
            }

            // disable_poisson = toggle says "disable Poisson delays"
            var disable_poisson = poissonEl.checked ? 'on' : 'off';
            var disable_cover = coverEl.checked ? 'on' : 'off';

            rpc.mixnetTuningSet(loop_cover, packet, message, disable_poisson, disable_cover)
                .then(function(result) {
                    if (result && result.success) {
                        showToast('Mixnet tuning saved', 'success');
                    } else {
                        showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                    }
                }).catch(function(err) {
                    showToast('Error: ' + err.message, 'error');
                });
        };

        // Account handlers
        var handleAccountLogin = function(ev) {
            ev.preventDefault();
            var fd = new FormData(ev.target);
            // Collapse whitespace: the field is a textarea, so a pasted phrase
            // can carry newlines and double spaces, and the daemon-side
            // validator only accepts lowercase letters and single spaces.
            var mnemonic = (fd.get('mnemonic') || '').replace(/\s+/g, ' ').trim();
            var mode = fd.get('mode') || 'api';

            if (!mnemonic) {
                showToast('Recovery phrase is required', 'error');
                return;
            }

            showModal('Logging In', 'Configuring account...');

            rpc.accountSet(mnemonic, mode).then(function(result) {
                if (result && result.success) {
                    // Poll for ReadyToConnect status
                    var pollCount = 0;
                    var maxPolls = 30; // 30 seconds max

                    var pollAccountStatus = function() {
                        pollCount++;
                        rpc.accountGet().then(function(accountResult) {
                            var accState = (accountResult && accountResult.state) || '';
                            var accIdentity = (accountResult && accountResult.identity) || '';

                            if (accState === 'ReadyToConnect' || accState.indexOf('Ready') >= 0) {
                                setModalSuccess('Ready', 'Account configured', '✓');
                                setTimeout(function() {
                                    fadeOutModal(function() {
                                        location.reload();
                                    });
                                }, 800);
                            } else if (accState.indexOf('Error') >= 0 || accIdentity.indexOf('Error') >= 0) {
                                hideModal();
                                showToast('Account error: ' + (accState || accIdentity), 'error');
                            } else if (pollCount < maxPolls) {
                                // Update modal message with progress
                                updateModal(accState || 'Please wait...');
                                setTimeout(pollAccountStatus, 1000);
                            } else {
                                hideModal();
                                showToast('Account setup timed out. Please refresh.', 'warning');
                            }
                        }).catch(function() {
                            if (pollCount < maxPolls) {
                                setTimeout(pollAccountStatus, 1000);
                            } else {
                                hideModal();
                                showToast('Account setup timed out', 'warning');
                            }
                        });
                    };

                    // Start polling after a brief delay
                    setTimeout(pollAccountStatus, 1000);
                } else {
                    hideModal();
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                hideModal();
                showToast('Error: ' + err.message, 'error');
            });
        };

        var handleAccountLogout = function() {
            confirmModal(
                'Logout',
                'This will disconnect and remove your account. You will need your recovery phrase to log back in.',
                '⚠',
                function() {
                    // User confirmed - proceed with logout
                    showModal('Logging Out', 'Please wait...');

                    var doLogout = function() {
                        updateModal('Removing account...');
                        rpc.accountForget().then(function(result) {
                            if (result && result.success) {
                                setModalSuccess('Done', 'Account removed', '✓');
                                setTimeout(function() {
                                    fadeOutModal(function() {
                                        location.reload();
                                    });
                                }, 800);
                            } else {
                                hideModal();
                                showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                            }
                        }).catch(function(err) {
                            hideModal();
                            showToast('Error: ' + err.message, 'error');
                        });
                    };

                    // Check if connected, disconnect first
                    rpc.status().then(function(st) {
                        if (st && (st.state === 'connected' || st.state === 'connecting')) {
                            updateModal('Disconnecting...');
                            rpc.disconnect().then(function() {
                                // Poll until disconnected
                                var pollCount = 0;
                                var pollDisconnect = function() {
                                    pollCount++;
                                    rpc.status().then(function(s) {
                                        if (s && s.state === 'disconnected') {
                                            doLogout();
                                        } else if (pollCount < 30) {
                                            setTimeout(pollDisconnect, 500);
                                        } else {
                                            doLogout(); // Try anyway after timeout
                                        }
                                    }).catch(function() {
                                        doLogout();
                                    });
                                };
                                setTimeout(pollDisconnect, 500);
                            }).catch(function() {
                                doLogout(); // Try logout anyway
                            });
                        } else {
                            doLogout();
                        }
                    }).catch(function() {
                        doLogout();
                    });
                }
            );
        };

        // Hard account-state reset for the desync where `forget` can't clear a
        // stranded account. Stops the daemon, wipes the account/key store, and
        // restarts with a delay (the proven manual recovery). Last resort.
        var handleAccountReset = function() {
            confirmModal(
                'Reset account state',
                'Use this only if logging out fails or the account is stuck. It stops the VPN service, erases the stored account and keys on this device, then restarts. Your saved settings are kept, but you will need your recovery phrase to log back in.',
                '⚠',
                function() {
                    showModal('Resetting', 'Stopping service and clearing account state…');
                    rpc.accountReset().then(function(result) {
                        if (result && result.success) {
                            setModalSuccess('Done', 'Account state reset', '✓');
                            setTimeout(function() {
                                fadeOutModal(function() {
                                    location.reload();
                                });
                            }, 900);
                        } else {
                            hideModal();
                            showToast('Reset failed: ' + ((result && result.error) || 'Unknown'), 'error');
                        }
                    }).catch(function(err) {
                        hideModal();
                        showToast('Error: ' + err.message, 'error');
                    });
                }
            );
        };

        var handleRotateKeys = function() {
            rpc.status().then(function(st) {
                if (st && (st.state === 'connected' || st.state === 'connecting')) {
                    showToast('Please disconnect before rotating keys', 'warning');
                    return;
                }

                showModal('Rotating Keys', 'Generating new keys...', '🔑');
                rpc.accountRotateKeys().then(function(result) {
                    hideModal();
                    if (result && result.success) {
                        showToast('Keys rotated successfully', 'success');
                    } else {
                        showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                    }
                }).catch(function(err) {
                    hideModal();
                    showToast('Error: ' + err.message, 'error');
                });
            });
        };

        var copyIdentity = function(text, btn) {
            if (!text) return;
            var flash = function() {
                if (!btn) return;
                btn.classList.add('copied');
                setTimeout(function() { btn.classList.remove('copied'); }, 1400);
            };
            var done = function(ok) {
                if (ok) {
                    flash();
                    showToast('Device identity copied', 'success');
                } else {
                    showToast('Copy failed', 'error');
                }
            };
            if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() { done(true); })
                    .catch(function() { done(legacyCopy(text)); });
                return;
            }
            done(legacyCopy(text));
        };

        // Custom DNS — managed as a list, added/removed one server at a time.
        // The daemon replaces the whole set per call (dns set <list>, or dns
        // clear when empty), so every add/remove re-sends the joined list.
        var dnsServersList = (dns_config.servers || '').split(/\s+/).filter(Boolean);
        var dnsListEl = E('div', { 'class': 'nym-dns-list' });

        // Light client check (IPv4 dotted-quad, or anything colon-bearing for
        // IPv6); the daemon validates strictly before applying.
        var isValidDnsIp = function(s) {
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) {
                return s.split('.').every(function(o) { return +o >= 0 && +o <= 255; });
            }
            return /^[0-9a-fA-F:]+$/.test(s) && s.indexOf(':') >= 0;
        };

        var renderDnsRow = function(ip) {
            return E('div', { 'class': 'nym-dns-row', 'data-ip': ip }, [
                E('div', { 'class': 'nym-dns-ip' }, [String(ip)]),
                E('div', {
                    'class': 'nym-exemption-delete',
                    'title': 'Remove',
                    'click': function() { deleteDnsServer(ip); }
                }, '×')
            ]);
        };

        var redrawDnsList = function() {
            dnsListEl.innerHTML = '';
            if (dnsServersList.length === 0) {
                dnsListEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'Using the VPN default resolvers. Add a server below.'));
                return;
            }
            dnsServersList.forEach(function(ip) { dnsListEl.appendChild(renderDnsRow(ip)); });
        };

        // Push the current enabled state + full server list to the daemon.
        var persistDns = function() {
            var dnsToggle = document.getElementById('dns-toggle');
            var enabled = dnsToggle ? dnsToggle.checked : false;
            return rpc.dnsSet(enabled, dnsServersList.join(' '));
        };

        var addDnsServer = function() {
            var input = document.getElementById('dns-server-input');
            var addBtn = document.getElementById('dns-add-btn');
            if (!input) return;
            var ip = (input.value || '').trim();
            if (!ip) { showToast('Enter a DNS server address', 'error'); return; }
            if (!isValidDnsIp(ip)) { showToast('Not a valid IPv4 or IPv6 address', 'error'); return; }
            if (dnsServersList.indexOf(ip) !== -1) { showToast(ip + ' is already in the list', 'error'); return; }

            dnsServersList.push(ip);
            if (addBtn) { addBtn.disabled = true; addBtn.innerHTML = '<span class="nym-btn-spinner"></span>Adding'; }
            persistDns().then(function(result) {
                if (addBtn) { addBtn.disabled = false; addBtn.textContent = 'Add'; }
                if (result && result.success) {
                    redrawDnsList();
                    input.value = '';
                    showToast('Added ' + ip, 'success');
                } else {
                    dnsServersList.pop();
                    showToast('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                if (addBtn) { addBtn.disabled = false; addBtn.textContent = 'Add'; }
                dnsServersList.pop();
                showToast('Error: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var deleteDnsServer = function(ip) {
            var idx = dnsServersList.indexOf(ip);
            if (idx === -1) return;
            var row = dnsListEl.querySelector('.nym-dns-row[data-ip="' + ip + '"]');
            if (row) row.classList.add('removing');
            dnsServersList.splice(idx, 1);
            persistDns().then(function(result) {
                if (result && result.success) {
                    redrawDnsList();
                    showToast('Removed ' + ip, 'success');
                } else {
                    dnsServersList.splice(idx, 0, ip);
                    if (row) row.classList.remove('removing');
                    showToast('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                dnsServersList.splice(idx, 0, ip);
                if (row) row.classList.remove('removing');
                showToast('Error: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var onDnsKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); addDnsServer(); }
        };

        var handleDnsToggle = function(enabled) {
            persistDns().then(function(result) {
                if (result && result.success) {
                    showToast(enabled ? 'Custom DNS enabled' : 'Custom DNS disabled', 'success');
                } else {
                    showToast('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                    var toggle = document.getElementById('dns-toggle');
                    if (toggle) toggle.checked = !enabled;
                }
            }).catch(function(err) {
                showToast('Error: ' + (err && err.message ? err.message : err), 'error');
                var toggle = document.getElementById('dns-toggle');
                if (toggle) toggle.checked = !enabled;
            });
        };

        // Ad-blocking handler
        var handleAdBlock = function(enabled) {
            rpc.adBlockSet(enabled).then(function(result) {
                if (result && result.success) {
                    showToast(enabled ? 'Ad-blocking enabled' : 'Ad-blocking disabled', 'success');
                    var display = document.getElementById('adblock-status-display');
                    if (display) display.textContent = enabled ? 'Enabled' : 'Disabled';
                    var toggle = document.getElementById('adblock-toggle');
                    if (toggle) toggle.checked = enabled;
                } else {
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                    // Revert toggle
                    var toggle = document.getElementById('adblock-toggle');
                    if (toggle) toggle.checked = !enabled;
                }
            }).catch(function(err) {
                showToast('Error: ' + err.message, 'error');
                var toggle = document.getElementById('adblock-toggle');
                if (toggle) toggle.checked = !enabled;
            });
        };

        // Anonymous statistics handler (Privacy card)
        var handleStatsToggle = function(enabled) {
            var revert = function() {
                var toggle = document.getElementById('stats-toggle');
                if (toggle) toggle.checked = !enabled;
            };
            rpc.statsSet(enabled).then(function(result) {
                if (result && result.success) {
                    showToast(enabled ? 'Anonymous statistics enabled' : 'Anonymous statistics disabled', 'success');
                } else {
                    showToast('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                    revert();
                }
            }).catch(function(err) {
                showToast('Error: ' + (err && err.message ? err.message : err), 'error');
                revert();
            });
        };

        // Derive account flags from an `account get` result. A leftover device
        // identity paired with a LoggedOut/cleared state must NOT read as
        // logged in — that is the 1.27.1 desync where the Account card offered
        // "Sign out" while the status strip simultaneously said "no account
        // configured". State is authoritative; a stale identity does not count.
        var computeAccountFlags = function(acct) {
            acct = acct || {};
            var identity = acct.identity || '';
            var rawState = acct.state || '';
            var state = rawState.replace(/([a-z])([A-Z])/g, '$1 $2');
            var invalidIdentities = ['', 'Not set', 'LoggedOut', 'unset', 'none'];
            // The daemon never answered — either it said so (`available:false`)
            // or, on an older bridge, both fields came back empty, which no
            // real reply produces. This outranks every other flag: showing the
            // login form for a question we never got to ask is what made the
            // 1.33.1 upgrade look like it had wiped the stored account.
            var isUnavailable = acct.available === false || (!identity && !rawState);
            var hasError = state.indexOf('Error') >= 0 || identity.indexOf('Error') >= 0;
            var isLoggedOut = (rawState || '').trim() === 'LoggedOut';
            var isLoggedIn = !isUnavailable && !!identity && invalidIdentities.indexOf(identity) === -1 && !hasError && !isLoggedOut;
            return {
                identity: identity, rawState: rawState, state: state,
                hasError: hasError, isLoggedIn: isLoggedIn, isLoggedOut: isLoggedOut,
                isUnavailable: isUnavailable,
                // Only meaningful while unavailable; absent on a real reply.
                daemonRunning: acct.daemon_running !== false,
                daemonEnabled: acct.daemon_enabled !== false
            };
        };

        var container = E('div', { 'class': 'nym-container' }, [
            E('style', {}, theme.css || ''),

            // Header
            (function() {
                var header = E('div', { 'class': 'nym-header' });
                var logoDiv = E('div', { 'class': 'nym-logo' });
                logoDiv.innerHTML = assets.logo || '';
                header.appendChild(logoDiv);
                return header;
            })(),

            // Status Hero with integrated gateway selection
            statusHero = E('div', { 'class': 'nym-status-hero disconnected' }, [
                // Three-column layout. Each side column hosts BOTH a picker
                // (.nym-panel-picker, shown while disconnected) and the live
                // connection info (.nym-panel-info, shown while connected) for
                // that hop, so the same columns are reused in both states — the
                // connected view fills the width instead of stranding the
                // gateway info in a separate row below the ring.
                E('div', { 'class': 'nym-hero-gateway-row' }, [
                    // LEFT: Entry — picker + connected info
                    E('div', { 'class': 'nym-hero-gateway-panel' }, [
                        E('div', { 'class': 'nym-panel-picker' }, [
                            E('div', { 'class': 'nym-gateway-box-title' }, 'Entry Gateway'),
                            E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' }, [
                                E('label', { 'class': 'nym-form-label' }, 'Country'),
                                entryCountrySelect = createCountrySelect('mixnet-entry', 'entry_country', function(ev) {
                                    markPickersDirty();
                                    loadGatewaysForCountry(ev.target.value, 'mixnet-entry', entryGatewayContainer);
                                })
                            ]),
                            // 'change' only fires on user interaction (radio
                            // clicks bubble; programmatic prefill doesn't), so
                            // it is exactly the dirty signal we want.
                            entryGatewayContainer = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0', 'change': markPickersDirty },
                                E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'))
                        ]),
                        E('div', { 'class': 'nym-panel-info' }, [
                            E('div', { 'class': 'nym-gateway-label' }, 'Entry'),
                            entryGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
                                E('div', { 'class': 'nym-gateway-empty' }, '—')
                            ])
                        ])
                    ]),

                    // CENTER: Status Ring + Uptime + connection chain
                    E('div', { 'class': 'nym-hero-center' }, [
                        E('div', { 'class': 'nym-status-ring' }, [
                            E('div', { 'class': 'nym-status-ring-pulse' }),
                            E('div', { 'class': 'nym-status-ring-outer' }),
                            E('div', { 'class': 'nym-status-ring-inner' }, [
                                statusLabel = E('div', { 'class': 'nym-status-label' }, 'Disconnected')
                            ])
                        ]),
                        E('div', { 'class': 'nym-uptime' }, [
                            uptimeDisplay = E('span', {}, '--:--')
                        ]),
                        E('div', { 'class': 'nym-uptime-label' }, 'Session Duration'),
                        E('div', { 'class': 'nym-connection-wrapper' }, [
                            modeLabel = E('div', { 'class': 'nym-mode-label' }),
                            connectionChain = E('div', { 'class': 'nym-connection-chain' })
                        ])
                    ]),

                    // RIGHT: Exit — picker + connected info
                    E('div', { 'class': 'nym-hero-gateway-panel' }, [
                        E('div', { 'class': 'nym-panel-picker' }, [
                            E('div', { 'class': 'nym-gateway-box-title' }, 'Exit Gateway'),
                            E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' }, [
                                E('label', { 'class': 'nym-form-label' }, 'Country'),
                                exitCountrySelect = createCountrySelect('mixnet-exit', 'exit_country', function(ev) {
                                    markPickersDirty();
                                    loadGatewaysForCountry(ev.target.value, 'mixnet-exit', exitGatewayContainer);
                                })
                            ]),
                            exitGatewayContainer = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0', 'change': markPickersDirty },
                                E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'))
                        ]),
                        E('div', { 'class': 'nym-panel-info' }, [
                            E('div', { 'class': 'nym-gateway-label' }, 'Exit'),
                            exitGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
                                E('div', { 'class': 'nym-gateway-empty' }, '—')
                            ])
                        ])
                    ])
                ]),

                // Action button - no initial click handler to avoid dual handlers
                E('div', { 'class': 'nym-action-buttons' }, [
                    actionBtn = E('button', {
                        'class': 'nym-btn nym-btn-primary'
                    }, 'Connect')
                ])
            ])
        ]);

        // Tunnel Settings Card
        var tunnelCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(tunnelCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconTunnel),
                    'Tunnel Settings'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', {}, [
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'IPv6'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Enable IPv6 connectivity through the tunnel')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'ipv6-toggle',
                                'checked': tunnel_config.ipv6 === 'on' ? 'checked' : null,
                                'change': saveTunnelSettings
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Two-Hop Mode'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Use faster 2-hop routing instead of full mixnet (less private)')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'two-hop-toggle',
                                'checked': tunnel_config.two_hop === 'on' ? 'checked' : null,
                                'change': saveTunnelSettings
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Circumvention Transports'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Wrap the entry gateway connection in a QUIC transport to evade censorship. Applies to two-hop mode.')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'circumvention-toggle',
                                'checked': tunnel_config.circumvention_transports === 'on' ? 'checked' : null,
                                'change': saveTunnelSettings
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Stealth API Connect'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Reach the Nym API through cover domains on every request, not only after a direct request fails. Helps where the API is blocked; API calls get slower. Applies immediately, no reconnect.'),
                            // The daemon reports whether the network environment
                            // publishes cover domains at all; without them the
                            // toggle has nothing to route through.
                            E('div', {
                                'class': 'nym-toggle-warning',
                                'style': 'color: #e67e22; font-size: 11px; margin-top: 4px; display: ' + (tunnel_config.stealth_api_note ? 'block' : 'none')
                            }, 'The current network environment publishes no cover domains, so this setting has no effect right now.')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'stealth-api-toggle',
                                'checked': tunnel_config.stealth_api === 'on' ? 'checked' : null,
                                'change': saveTunnelSettings
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', { 'class': 'nym-toggle-row', 'style': 'flex-wrap: wrap' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Always On'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Automatically reconnect when the VPN tunnel drops. Uses escalating recovery with daemon restart as fallback.'),
                            E('div', {
                                'class': 'nym-toggle-status',
                                'id': 'always-on-status',
                                'style': 'font-size: 11px; margin-top: 4px; color: ' + (watchdog.always_on ? '#27ae60' : '#888')
                            }, watchdog.always_on ? 'Watchdog active' + (watchdog.failures > 0 ? ' (' + watchdog.failures + ' recovery attempts)' : '') : 'Disabled')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'always-on-toggle',
                                'checked': watchdog.always_on ? 'checked' : null,
                                'change': function(ev) {
                                    var enabled = ev.target.checked;
                                    var statusEl = document.getElementById('always-on-status');
                                    var intervalRow = document.getElementById('watchdog-interval-row');
                                    ev.target.disabled = true;

                                    var currentInterval = null;
                                    var activeBtn = intervalRow ? intervalRow.querySelector('.nym-pill.active') : null;
                                    if (activeBtn) currentInterval = parseInt(activeBtn.dataset.value);

                                    rpc.watchdogSet(enabled ? 1 : 0, currentInterval).then(function(result) {
                                        ev.target.disabled = false;
                                        if (result && result.success) {
                                            showToast('Always-on ' + (enabled ? 'enabled' : 'disabled'), 'success');
                                            if (statusEl) {
                                                statusEl.textContent = enabled ? 'Watchdog active' : 'Disabled';
                                                statusEl.style.color = enabled ? '#27ae60' : '#888';
                                            }
                                            if (intervalRow) intervalRow.style.display = enabled ? 'flex' : 'none';
                                        } else {
                                            ev.target.checked = !enabled;
                                            showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                                        }
                                    }).catch(function(err) {
                                        ev.target.disabled = false;
                                        ev.target.checked = !enabled;
                                        showToast('Error: ' + err.message, 'error');
                                    });
                                }
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ]),
                        (function() {
                            var currentInterval = (watchdog.interval || 30).toString();
                            var intervals = [
                                { value: '1', label: '1s' },
                                { value: '5', label: '5s' },
                                { value: '15', label: '15s' },
                                { value: '30', label: '30s' },
                                { value: '60', label: '60s' },
                                { value: '120', label: '2m' }
                            ];
                            var pills = intervals.map(function(opt) {
                                return E('button', {
                                    'class': 'nym-pill' + (opt.value === currentInterval ? ' active' : ''),
                                    'data-value': opt.value,
                                    'click': function(ev) {
                                        ev.preventDefault();
                                        var row = ev.target.closest('#watchdog-interval-row');
                                        row.querySelectorAll('.nym-pill').forEach(function(p) { p.classList.remove('active'); });
                                        ev.target.classList.add('active');
                                        var isEnabled = document.getElementById('always-on-toggle').checked;
                                        rpc.watchdogSet(isEnabled ? 1 : 0, parseInt(opt.value)).then(function(result) {
                                            if (result && result.success) {
                                                showToast('Check interval set to ' + opt.label, 'success');
                                            } else {
                                                showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                                            }
                                        });
                                    }
                                }, opt.label);
                            });
                            return E('div', {
                                'id': 'watchdog-interval-row',
                                'class': 'nym-interval-row',
                                'style': 'display: ' + (watchdog.always_on ? 'flex' : 'none') + '; width: 100%; align-items: center; gap: 10px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-color)'
                            }, [
                                E('span', { 'style': 'font-size: 12px; color: var(--text-muted)' }, 'Check every:'),
                                E('div', { 'class': 'nym-pill-group' }, pills)
                            ]);
                        })()
                    ]),
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Legacy Split Tunneling (PBR)'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Hand routing to luci-app-pbr: only the traffic you select in PBR is sent through the VPN, everything else uses the normal WAN in the clear. Mutually exclusive with the kill-switch and the exclusion list below. Requires reconnect.')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'legacy-split-toggle',
                                'checked': tunnel_config.legacy_split_tunnel === 'on' ? 'checked' : null,
                                'change': function(ev) {
                                    var on = ev.target.checked;
                                    var ksEl = document.getElementById('killswitch-toggle');
                                    var ksRow = document.getElementById('killswitch-row');
                                    if (ksEl) {
                                        ksEl.disabled = on;
                                        if (on) ksEl.checked = false;
                                        var warn = ksRow ? ksRow.querySelector('.nym-toggle-warning') : null;
                                        if (warn) warn.style.display = (on || ksEl.checked) ? 'none' : 'block';
                                    }
                                    if (ksRow) ksRow.style.opacity = on ? '0.5' : '';
                                    if (inboundMount) inboundMount.style.display = (!on && ksEl && ksEl.checked) ? 'block' : 'none';
                                    if (splitMount) splitMount.style.display = on ? 'none' : 'block';
                                    saveTunnelSettings();
                                }
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', {
                        'class': 'nym-toggle-row',
                        'id': 'killswitch-row',
                        'style': tunnel_config.legacy_split_tunnel === 'on' ? 'opacity: 0.5' : ''
                    }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'Kill-Switch'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Block LAN clients from reaching the internet unless the VPN is connected.'),
                            E('div', {
                                'class': 'nym-toggle-warning',
                                'style': 'color: #e67e22; font-size: 11px; margin-top: 4px; display: ' + (tunnel_config.killswitch === 'on' ? 'none' : 'block')
                            }, 'Warning: Traffic may leak outside the VPN when disabled. Requires reconnect.')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'killswitch-toggle',
                                'checked': tunnel_config.killswitch !== 'off' ? 'checked' : null,
                                'disabled': tunnel_config.legacy_split_tunnel === 'on' ? 'disabled' : null,
                                'change': function(ev) {
                                    var warn = ev.target.closest('.nym-toggle-row').querySelector('.nym-toggle-warning');
                                    if (warn) warn.style.display = ev.target.checked ? 'none' : 'block';
                                    if (inboundMount) inboundMount.style.display = ev.target.checked ? 'block' : 'none';
                                    saveTunnelSettings();
                                }
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ])
                ]),
                inboundMount = E('div', {
                    'class': 'nym-inbound-section',
                    'style': 'display: ' + (tunnel_config.killswitch !== 'off' && tunnel_config.legacy_split_tunnel !== 'on' ? 'block' : 'none')
                }),
                splitMount = E('div', {
                    'class': 'nym-split-section',
                    'style': 'display: ' + (tunnel_config.legacy_split_tunnel === 'on' ? 'none' : 'block')
                })
            ])
        ]);
        container.appendChild(tunnelCard);

        // Mixnet Tuning Card — Sphinx traffic knobs (mixnet/5-hop mode).
        // These trade anonymity for performance; the daemon validates ranges.
        var mixnetTuningCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(mixnetTuningCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconSliders),
                    'Mixnet Tuning'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-tuning-warning' },
                    'These settings trade anonymity for performance and only apply to ' +
                    'mixnet (5-hop) mode. Defaults give the strongest privacy; disabling ' +
                    'delays or cover traffic makes traffic analysis easier.'),
                E('div', { 'class': 'nym-toggle-row' }, [
                    E('div', { 'class': 'nym-toggle-info' }, [
                        E('div', { 'class': 'nym-toggle-title' }, 'Disable Poisson Delays'),
                        E('div', { 'class': 'nym-toggle-desc' }, 'Send real traffic immediately instead of on a randomized schedule. Much faster, less private.')
                    ]),
                    E('label', { 'class': 'nym-toggle' }, [
                        E('input', {
                            'type': 'checkbox',
                            'id': 'tuning-poisson-toggle',
                            'checked': tunnel_config.disable_poisson === 'true' ? 'checked' : null,
                            'change': saveMixnetTuning
                        }),
                        E('span', { 'class': 'nym-toggle-slider' })
                    ])
                ]),
                E('div', { 'class': 'nym-toggle-row' }, [
                    E('div', { 'class': 'nym-toggle-info' }, [
                        E('div', { 'class': 'nym-toggle-title' }, 'Disable Background Cover Traffic'),
                        E('div', { 'class': 'nym-toggle-desc' }, 'Stop sending decoy traffic. Saves bandwidth and CPU, less private.')
                    ]),
                    E('label', { 'class': 'nym-toggle' }, [
                        E('input', {
                            'type': 'checkbox',
                            'id': 'tuning-cover-toggle',
                            'checked': tunnel_config.disable_cover === 'true' ? 'checked' : null,
                            'change': saveMixnetTuning
                        }),
                        E('span', { 'class': 'nym-toggle-slider' })
                    ])
                ]),
                E('div', { 'class': 'nym-tuning-grid' }, [
                    E('div', { 'class': 'nym-form-group' }, [
                        E('label', { 'class': 'nym-form-label' }, 'Cover traffic delay (ms, 0-200)'),
                        E('input', {
                            'type': 'number', 'min': '0', 'max': '200',
                            'id': 'tuning-loop-cover', 'class': 'nym-input nym-tuning-num',
                            'value': tunnel_config.loop_cover_delay || '',
                            'placeholder': 'default'
                        })
                    ]),
                    E('div', { 'class': 'nym-form-group' }, [
                        E('label', { 'class': 'nym-form-label' }, 'Mixing delay per hop (ms, 0-200)'),
                        E('input', {
                            'type': 'number', 'min': '0', 'max': '200',
                            'id': 'tuning-packet-delay', 'class': 'nym-input nym-tuning-num',
                            'value': tunnel_config.packet_delay || '',
                            'placeholder': 'default'
                        })
                    ]),
                    E('div', { 'class': 'nym-form-group' }, [
                        E('label', { 'class': 'nym-form-label' }, 'Sending delay (ms, 5-50)'),
                        E('input', {
                            'type': 'number', 'min': '5', 'max': '50',
                            'id': 'tuning-message-delay', 'class': 'nym-input nym-tuning-num',
                            'value': tunnel_config.message_delay || '',
                            'placeholder': 'default'
                        })
                    ])
                ]),
                E('div', { 'class': 'nym-action-buttons' }, [
                    E('button', {
                        'class': 'nym-btn nym-btn-primary',
                        'click': saveMixnetTuning
                    }, 'Apply Tuning')
                ])
            ])
        ]);
        container.appendChild(mixnetTuningCard);

        // Inbound Services Card
        var inboundState = inbound_exemptions.slice();

        var renderExemptionRow = function(ex) {
            var killswitchOn = tunnel_config.killswitch !== 'off';
            var statusClass = killswitchOn ? '' : 'inert';
            var statusText = killswitchOn ? 'Active' : 'Inert';
            return E('div', {
                'class': 'nym-exemption-row',
                'data-proto': ex.proto,
                'data-dport': String(ex.dport)
            }, [
                E('div', { 'class': 'nym-exemption-proto' }, ex.proto.toUpperCase()),
                E('div', { 'class': 'nym-exemption-port' }, String(ex.dport)),
                E('div', { 'class': 'nym-exemption-label' }, ex.label || '—'),
                E('div', { 'class': 'nym-exemption-status ' + statusClass }, statusText),
                E('div', {
                    'class': 'nym-exemption-delete',
                    'title': 'Remove',
                    'click': function() { deleteExemption(ex); }
                }, '×')
            ]);
        };

        var inboundListEl = E('div', { 'class': 'nym-exemption-table' });

        var redrawInboundList = function() {
            inboundListEl.innerHTML = '';
            if (inboundState.length === 0) {
                inboundListEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'No exemptions configured. Add one below.'));
                return;
            }
            inboundListEl.appendChild(E('div', { 'class': 'nym-exemption-header' }, [
                E('div', {}, 'Proto'),
                E('div', {}, 'Port'),
                E('div', {}, 'Label'),
                E('div', {}, 'Status'),
                E('div', {}, '')
            ]));
            inboundState.forEach(function(ex) {
                inboundListEl.appendChild(renderExemptionRow(ex));
            });
        };

        var onAddRowKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); addInbound(); }
        };

        var addInbound = function() {
            var protoSel = document.getElementById('nym-inbound-proto');
            var portInp = document.getElementById('nym-inbound-port');
            var labelInp = document.getElementById('nym-inbound-label');
            var saveBtn = document.getElementById('nym-inbound-save');
            if (!protoSel || !portInp || !saveBtn) return;

            var proto = protoSel.value;
            var dportRaw = (portInp.value || '').trim();
            var label = (labelInp && labelInp.value || '').trim();

            if (!dportRaw) {
                showToast('Port is required', 'error');
                return;
            }
            var dport = parseInt(dportRaw, 10);
            if (isNaN(dport) || dport < 1 || dport > 65535) {
                showToast('Port must be between 1 and 65535', 'error');
                return;
            }
            if (inboundState.some(function(e) { return e.proto === proto && e.dport === dport; })) {
                showToast(proto.toUpperCase() + '/' + dport + ' is already exempted', 'error');
                return;
            }
            if (label.length > 64) {
                showToast('Label too long (max 64 characters)', 'error');
                return;
            }

            var pending = { proto: proto, dport: dport };
            if (label) pending.label = label;

            var pendingRow = renderExemptionRow(pending);
            pendingRow.classList.add('pending');
            if (inboundState.length === 0) inboundListEl.innerHTML = '';
            inboundListEl.appendChild(pendingRow);
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<span class="nym-btn-spinner"></span>Saving';

            rpc.inboundAdd(proto, dport, label || '').then(function(result) {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Add';
                if (result && result.success) {
                    inboundState.push(pending);
                    redrawInboundList();
                    portInp.value = '';
                    if (labelInp) labelInp.value = '';
                    showToast('Added ' + proto.toUpperCase() + '/' + dport, 'success');
                } else {
                    pendingRow.parentNode && pendingRow.parentNode.removeChild(pendingRow);
                    if (inboundState.length === 0) redrawInboundList();
                    showToast((result && result.error) || 'Failed to add exemption', 'error');
                }
            }).catch(function(err) {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Add';
                pendingRow.parentNode && pendingRow.parentNode.removeChild(pendingRow);
                if (inboundState.length === 0) redrawInboundList();
                showToast('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var deleteExemption = function(ex) {
            var row = inboundListEl.querySelector(
                '.nym-exemption-row[data-proto="' + ex.proto + '"][data-dport="' + ex.dport + '"]');
            if (row) row.classList.add('removing');

            rpc.inboundDel(ex.proto, ex.dport).then(function(result) {
                if (result && result.success) {
                    inboundState = inboundState.filter(function(e) {
                        return !(e.proto === ex.proto && e.dport === ex.dport);
                    });
                    redrawInboundList();
                    showToast('Removed ' + ex.proto.toUpperCase() + '/' + ex.dport, 'success');
                } else {
                    if (row) row.classList.remove('removing');
                    showToast((result && result.error) || 'Failed to delete', 'error');
                }
            }).catch(function(err) {
                if (row) row.classList.remove('removing');
                showToast('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        // Inbound exemptions render inside the Tunnel Settings card, beneath the
        // Kill-Switch toggle (they only matter while the kill-switch is on). The
        // daemon stores exemptions independently of the kill-switch, so toggling
        // it off/on never loses them — see handle_inbound_* vs handle_tunnel_set.
        dom.content(inboundMount, [
            E('div', { 'class': 'nym-divider' }),
            E('div', { 'class': 'nym-toggle-title', 'style': 'margin-bottom: 6px' }, 'Inbound Services'),
            E('div', { 'class': 'nym-card-description' },
                'Ports that stay reachable from the WAN while the kill-switch is on ' +
                '(e.g. hosted HTTPS, WireGuard, SSH). For LAN services, add the ' +
                'Network → Firewall port forward first, then the matching port here.'),
            inboundListEl,
            E('div', { 'class': 'nym-exemption-add' }, [
                E('div', { 'class': 'nym-form-label' }, 'Add Exemption'),
                E('div', { 'class': 'nym-exemption-addrow' }, [
                    E('select', { 'class': 'nym-select', 'id': 'nym-inbound-proto' }, [
                        E('option', { 'value': 'tcp' }, 'TCP'),
                        E('option', { 'value': 'udp' }, 'UDP')
                    ]),
                    E('input', {
                        'type': 'text',
                        'class': 'nym-input',
                        'id': 'nym-inbound-port',
                        'placeholder': '1–65535',
                        'inputmode': 'numeric',
                        'maxlength': '5',
                        'keydown': onAddRowKeydown
                    }),
                    E('input', {
                        'type': 'text',
                        'class': 'nym-input',
                        'id': 'nym-inbound-label',
                        'placeholder': 'Label (optional)',
                        'maxlength': '64',
                        'keydown': onAddRowKeydown
                    }),
                    E('button', {
                        'class': 'nym-btn nym-btn-primary',
                        'id': 'nym-inbound-save',
                        'click': addInbound
                    }, 'Add')
                ])
            ])
        ]);
        redrawInboundList();

        // Split Tunneling — carve specific devices/domains out of the tunnel,
        // straight to the WAN. Mounts in the Tunnel Settings card beneath inbound
        // services. Exclusions are marked with fwmark 0x14e and only take effect
        // while the kill-switch is OFF (when ON the firewall drops non-tunnel
        // egress). Stored in UCI independently, so toggling the kill-switch keeps
        // them. See docs/guide/split-tunneling.md and handle_split_* in the rpcd.
        var splitState = split_exclusions.slice();
        var nftsetSupported = !!split_status.nftset_supported;

        var splitValue = function(ex) {
            if (ex.type === 'domain') return ex.domain || '—';
            var c = lan_clients.filter(function(x) { return x.mac === ex.mac; })[0];
            if (c && c.hostname) return c.hostname + ' (' + ex.mac + ')';
            return ex.mac || '—';
        };

        var splitListEl = E('div', { 'class': 'nym-exemption-table' });

        var renderSplitRow = function(ex) {
            var on = ex.enabled !== false && ex.enabled !== 0 && ex.enabled !== '0';
            return E('div', {
                'class': 'nym-split-row' + (on ? '' : ' inert'),
                'data-id': ex.id
            }, [
                E('div', { 'class': 'nym-exemption-proto' }, ex.type === 'domain' ? 'DOMAIN' : 'DEVICE'),
                E('div', { 'class': 'nym-exemption-label' }, splitValue(ex)),
                E('div', { 'class': 'nym-exemption-label' }, ex.label || '—'),
                E('label', { 'class': 'nym-toggle nym-toggle-sm', 'title': on ? 'Enabled' : 'Disabled' }, [
                    E('input', {
                        'type': 'checkbox',
                        'checked': on ? 'checked' : null,
                        'change': function(ev) { toggleSplit(ex, ev.target.checked); }
                    }),
                    E('span', { 'class': 'nym-toggle-slider' })
                ]),
                E('div', {
                    'class': 'nym-exemption-delete',
                    'title': 'Remove',
                    'click': function() { deleteSplit(ex); }
                }, '×')
            ]);
        };

        var redrawSplitList = function() {
            splitListEl.innerHTML = '';
            if (splitState.length === 0) {
                splitListEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'No exclusions configured. Add a device or domain below.'));
                return;
            }
            splitListEl.appendChild(E('div', { 'class': 'nym-split-header' }, [
                E('div', {}, 'Type'),
                E('div', {}, 'Device / Domain'),
                E('div', {}, 'Label'),
                E('div', {}, 'On'),
                E('div', {}, '')
            ]));
            splitState.forEach(function(ex) {
                splitListEl.appendChild(renderSplitRow(ex));
            });
        };

        var deleteSplit = function(ex) {
            var row = splitListEl.querySelector('.nym-split-row[data-id="' + ex.id + '"]');
            if (row) row.classList.add('removing');
            rpc.splitDel(ex.id).then(function(result) {
                if (result && result.success) {
                    splitState = splitState.filter(function(e) { return e.id !== ex.id; });
                    redrawSplitList();
                    showToast('Removed exclusion', 'success');
                } else {
                    if (row) row.classList.remove('removing');
                    showToast((result && result.error) || 'Failed to delete', 'error');
                }
            }).catch(function(err) {
                if (row) row.classList.remove('removing');
                showToast('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var toggleSplit = function(ex, enabled) {
            rpc.splitSetEnabled(ex.id, enabled ? 1 : 0).then(function(result) {
                if (result && result.success) {
                    ex.enabled = enabled ? 1 : 0;
                    redrawSplitList();
                } else {
                    showToast((result && result.error) || 'Failed to update', 'error');
                    redrawSplitList();
                }
            }).catch(function(err) {
                showToast('Failed: ' + (err && err.message ? err.message : err), 'error');
                redrawSplitList();
            });
        };

        var addSplit = function(kind) {
            var labelId = kind === 'domain' ? 'nym-split-domain-label' : 'nym-split-client-label';
            var btnId = kind === 'domain' ? 'nym-split-domain-save' : 'nym-split-client-save';
            var labelInp = document.getElementById(labelId);
            var saveBtn = document.getElementById(btnId);
            var label = (labelInp && labelInp.value || '').trim();
            if (label.length > 64) { showToast('Label too long (max 64 characters)', 'error'); return; }

            var mac = '', domain = '';
            if (kind === 'domain') {
                var domInp = document.getElementById('nym-split-domain');
                domain = (domInp && domInp.value || '').trim().toLowerCase();
                if (!domain) { showToast('Domain is required', 'error'); return; }
                if (splitState.some(function(e) { return e.type === 'domain' && e.domain === domain; })) {
                    showToast(domain + ' is already excluded', 'error'); return;
                }
            } else {
                var sel = document.getElementById('nym-split-client');
                mac = sel && sel.value || '';
                if (!mac) { showToast('Select a device', 'error'); return; }
                if (splitState.some(function(e) { return e.type === 'client' && e.mac === mac; })) {
                    showToast('That device is already excluded', 'error'); return;
                }
            }

            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<span class="nym-btn-spinner"></span>Saving';
            }
            rpc.splitAdd(kind, mac, domain, label || '').then(function(result) {
                if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Add'; }
                if (result && result.success) {
                    var ex = { id: result.id, type: kind, enabled: 1 };
                    if (kind === 'domain') ex.domain = domain; else ex.mac = mac;
                    if (label) ex.label = label;
                    splitState.push(ex);
                    redrawSplitList();
                    if (kind === 'domain') { var di = document.getElementById('nym-split-domain'); if (di) di.value = ''; }
                    if (labelInp) labelInp.value = '';
                    showToast('Added exclusion', 'success');
                } else {
                    showToast((result && result.error) || 'Failed to add exclusion', 'error');
                }
            }).catch(function(err) {
                if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Add'; }
                showToast('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var splitDomainKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); addSplit('domain'); }
        };

        // Device dropdown options from current DHCP leases.
        var clientOptions = [E('option', { 'value': '' }, lan_clients.length ? 'Select a device…' : 'No DHCP leases found')];
        lan_clients.forEach(function(c) {
            var name = (c.hostname ? c.hostname + ' — ' : '') + (c.ip ? c.ip + ' — ' : '') + c.mac;
            clientOptions.push(E('option', { 'value': c.mac }, name));
        });

        // Domain add row — disabled with a hint when dnsmasq lacks nftset support.
        var domainAddRow = nftsetSupported
            ? E('div', { 'class': 'nym-exemption-addrow' }, [
                E('input', {
                    'type': 'text', 'class': 'nym-input', 'id': 'nym-split-domain',
                    'placeholder': 'example.com', 'maxlength': '253', 'keydown': splitDomainKeydown
                }),
                E('input', {
                    'type': 'text', 'class': 'nym-input', 'id': 'nym-split-domain-label',
                    'placeholder': 'Label (optional)', 'maxlength': '64', 'keydown': splitDomainKeydown
                }),
                E('button', {
                    'class': 'nym-btn nym-btn-primary', 'id': 'nym-split-domain-save',
                    'click': function() { addSplit('domain'); }
                }, 'Add')
            ])
            : E('div', { 'class': 'nym-card-description', 'style': 'color: #e67e22' },
                'Domain exclusions require dnsmasq-full (built with nftset support). ' +
                'Install it with: opkg install dnsmasq-full');

        dom.content(splitMount, [
            E('div', { 'class': 'nym-divider' }),
            E('div', { 'class': 'nym-toggle-title', 'style': 'margin-bottom: 6px' }, 'Split Tunneling'),
            E('div', { 'class': 'nym-card-description' },
                'Send specific devices or domains straight to the WAN, bypassing the VPN. ' +
                'Clients must use this router for DNS for domain rules.'),
            splitListEl,
            E('div', { 'class': 'nym-exemption-add' }, [
                E('div', { 'class': 'nym-form-label' }, 'Exclude a Device'),
                E('div', { 'class': 'nym-exemption-addrow' }, [
                    E('select', { 'class': 'nym-select', 'id': 'nym-split-client', 'style': 'flex: 2' }, clientOptions),
                    E('input', {
                        'type': 'text', 'class': 'nym-input', 'id': 'nym-split-client-label',
                        'placeholder': 'Label (optional)', 'maxlength': '64'
                    }),
                    E('button', {
                        'class': 'nym-btn nym-btn-primary', 'id': 'nym-split-client-save',
                        'click': function() { addSplit('client'); }
                    }, 'Add')
                ]),
                E('div', { 'class': 'nym-form-label', 'style': 'margin-top: 10px' }, 'Exclude a Domain'),
                domainAddRow
            ])
        ]);
        redrawSplitList();

        // DNS & Ad Blocking Card
        var adBlockEnabled = ad_block.enabled ? true : false;
        var dnsEnabled = dns_config.enabled ? true : false;

        // The daemon steps aside when dnsmasq has noresolv set (AdGuard Home,
        // https-dns-proxy, stubby), so the servers below are configured but not
        // in force. Say so rather than letting the card imply otherwise.
        var dnsUserManagedNotice = dns_config.user_managed
            ? E('div', { 'class': 'nym-card-description', 'style': 'color: #e67e22' }, [
                E('strong', {}, 'Not in effect: '),
                'dnsmasq has ',
                E('code', {}, 'noresolv'),
                ' set, so you manage upstream DNS. The servers below are ignored — ',
                'your own entries under Network → DNS → Forwards do the resolving, ',
                'and they ride the VPN tunnel while connected. Clear ',
                E('code', {}, 'noresolv'),
                ' if you want the VPN to supply DNS instead.'
            ])
            // null (not '') — LuCI's dom.append skips null children outright
            // rather than inserting an empty text node.
            : null;

        var dnsCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(dnsCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconShield),
                    'DNS & Ad Blocking'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-card-description' },
                    'Configure custom DNS servers and block ads at the DNS level.'),
                dnsUserManagedNotice,

                // Custom DNS toggle
                E('div', { 'class': 'nym-toggle-row' }, [
                    E('div', { 'class': 'nym-toggle-info' }, [
                        E('div', { 'class': 'nym-toggle-title' }, 'Custom DNS'),
                        E('div', { 'class': 'nym-toggle-desc' }, 'Use custom DNS servers instead of the VPN defaults')
                    ]),
                    E('label', { 'class': 'nym-toggle' }, [
                        E('input', {
                            'type': 'checkbox',
                            'id': 'dns-toggle',
                            'checked': dnsEnabled ? 'checked' : null,
                            'change': function(ev) {
                                handleDnsToggle(ev.target.checked);
                            }
                        }),
                        E('span', { 'class': 'nym-toggle-slider' })
                    ])
                ]),

                // Current servers list (above) + single-server add panel (below),
                // mirroring the Inbound exemptions add-one-at-a-time layout.
                dnsListEl,
                E('div', { 'class': 'nym-form-panel' }, [
                    E('div', { 'class': 'nym-form-label' }, 'Add DNS Server'),
                    E('div', { 'class': 'nym-form-row' }, [
                        E('input', {
                            'type': 'text',
                            'id': 'dns-server-input',
                            'class': 'nym-input',
                            'placeholder': 'e.g. 1.1.1.1 or 2606:4700:4700::1111',
                            'autocomplete': 'off',
                            'autocapitalize': 'off',
                            'spellcheck': 'false',
                            'keydown': onDnsKeydown
                        }),
                        E('button', {
                            'class': 'nym-btn nym-btn-primary',
                            'id': 'dns-add-btn',
                            'click': addDnsServer
                        }, 'Add')
                    ])
                ]),

                // Divider
                E('div', { 'class': 'nym-divider' }),

                // Ad Blocking toggle
                E('div', { 'class': 'nym-toggle-row' }, [
                    E('div', { 'class': 'nym-toggle-info' }, [
                        E('div', { 'class': 'nym-toggle-title' }, 'Ad Blocking'),
                        E('div', { 'class': 'nym-toggle-desc' }, 'Block ads, trackers, and malware domains via DNS')
                    ]),
                    E('label', { 'class': 'nym-toggle' }, [
                        E('input', {
                            'type': 'checkbox',
                            'id': 'adblock-toggle',
                            'checked': adBlockEnabled ? 'checked' : null,
                            'change': function(ev) {
                                handleAdBlock(ev.target.checked);
                            }
                        }),
                        E('span', { 'class': 'nym-toggle-slider' })
                    ])
                ])
            ])
        ]);
        container.appendChild(dnsCard);
        redrawDnsList();

        // Privacy Card — the daemon's anonymous statistics switch, CLI-only until
        // now (`nym-vpnc network-stats`). Reports leave only through the tunnel
        // unless disconnected reporting was turned on from the CLI; the card
        // says so when that is the case rather than implying otherwise.
        var statsEnabled = stats_config.enabled ? true : false;
        var statsDesc = stats_config.allow_disconnected
            ? 'Send anonymous, aggregated usage statistics to Nym. Disconnected reporting is on (set from the CLI), so reports can also leave outside the tunnel.'
            : 'Send anonymous, aggregated usage statistics to Nym. Reports only travel through the tunnel while connected; nothing is sent while disconnected.';

        var privacyCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(privacyCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconShield),
                    'Privacy'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-toggle-row' }, [
                    E('div', { 'class': 'nym-toggle-info' }, [
                        E('div', { 'class': 'nym-toggle-title' }, 'Anonymous Statistics'),
                        E('div', { 'class': 'nym-toggle-desc' }, statsDesc)
                    ]),
                    E('label', { 'class': 'nym-toggle' }, [
                        E('input', {
                            'type': 'checkbox',
                            'id': 'stats-toggle',
                            'checked': statsEnabled ? 'checked' : null,
                            'change': function(ev) {
                                handleStatsToggle(ev.target.checked);
                            }
                        }),
                        E('span', { 'class': 'nym-toggle-slider' })
                    ])
                ])
            ])
        ]);
        container.appendChild(privacyCard);

        // Account Card. The body is rebuilt from a fresh `account get` each
        // time refreshAccountCard() runs, so a recovered account clears the
        // error panel without a manual page reload (the 1.27.1 "error stays
        // until refresh" report).
        var accountBodyEl;

        var buildAccountBody = function(flags) {
            var identity = flags.identity;
            var state = flags.state;
            var accountStatusLabel = (state || '').trim() || 'Active';

            // Checked before anything else: with no answer from the daemon we
            // know nothing about the account, so say that instead of guessing.
            if (flags.isUnavailable) {
                var unavailableBody = [
                    E('div', { 'class': 'nym-account-state', 'style': 'background: var(--danger-dim); color: var(--danger)' },
                        flags.daemonRunning ? 'Service not responding' : 'Service not running'),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin: 16px 0' },
                        'The account state is unknown because the VPN service could not be reached. Your recovery phrase is still stored on this device — nothing has been removed.')
                ];
                if (!flags.daemonEnabled) {
                    unavailableBody.push(E('div', { 'class': 'nym-card-description', 'style': 'margin-bottom: 16px; opacity: 0.8' },
                        'nym-vpnd is also not enabled at boot, so it will stay down after a reboot. Enable it from the Service Management card or with: /etc/init.d/nym-vpnd enable'));
                }
                unavailableBody.push(E('button', {
                    'class': 'nym-btn nym-btn-primary',
                    'type': 'button',
                    'style': 'width: 100%',
                    'click': function() { runDaemonAction(flags.daemonRunning ? 'restart' : 'start'); }
                }, flags.daemonRunning ? 'Restart service' : 'Start service'));
                return E('div', { 'class': 'nym-account-logged-in' }, unavailableBody);
            }

            if (flags.isLoggedIn) {
                var copyBtn = E('button', {
                    'class': 'nym-identity-copy',
                    'type': 'button',
                    'title': 'Copy device identity'
                });
                copyBtn.innerHTML = assets.iconCopy;
                copyBtn.addEventListener('click', function(ev) {
                    ev.preventDefault();
                    copyIdentity(identity, copyBtn);
                });

                var rotateBtn = E('button', {
                    'class': 'nym-card-action rotate',
                    'type': 'button',
                    'click': handleRotateKeys
                });
                rotateBtn.innerHTML = assets.iconRefresh + '<span>Rotate keys</span>';

                var signOutBtn = E('button', {
                    'class': 'nym-card-action danger',
                    'type': 'button',
                    'click': handleAccountLogout
                });
                signOutBtn.innerHTML = assets.iconPower + '<span>Sign out</span>';

                return E('div', { 'class': 'nym-account-panel' }, [
                    E('div', { 'class': 'nym-info-frame' }, [
                        E('div', { 'class': 'nym-info-frame-label' }, 'Device Identity'),
                        E('div', { 'class': 'nym-info-frame-main' }, [
                            E('div', { 'class': 'nym-info-frame-id-row' }, [
                                E('div', { 'class': 'nym-info-frame-value' }, identity),
                                copyBtn
                            ]),
                            E('div', { 'class': 'nym-card-status' }, [
                                E('span', { 'class': 'nym-card-status-indicator' }),
                                E('span', { 'class': 'nym-card-status-text' }, accountStatusLabel)
                            ])
                        ])
                    ]),
                    E('div', { 'class': 'nym-card-actions-bar' }, [
                        rotateBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        signOutBtn
                    ])
                ]);
            }

            if (flags.hasError) {
                return E('div', { 'class': 'nym-account-logged-in' }, [
                    E('div', { 'class': 'nym-account-state', 'style': 'background: var(--danger-dim); color: var(--danger)' }, state || identity),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin: 16px 0' }, 'There is an issue with the account. You may need to logout and try again.'),
                    E('button', { 'class': 'nym-btn nym-btn-danger', 'style': 'width: 100%', 'click': handleAccountLogout }, 'Logout'),
                    E('button', { 'class': 'nym-btn nym-btn-secondary', 'style': 'width: 100%; margin-top: 8px', 'click': handleAccountReset }, 'Reset account state'),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin-top: 8px; opacity: 0.7' }, 'If Logout fails or the state is stuck, Reset stops the service and clears the stored account.')
                ]);
            }

            var form = E('form', { 'submit': handleAccountLogin }, [
                E('div', { 'class': 'nym-card-description' },
                    'Enter your Nym account recovery phrase to connect.'),
                E('div', { 'class': 'nym-form-group' }, [
                    E('label', { 'class': 'nym-form-label' }, 'Recovery Phrase'),
                    // A textarea, not a text input: browsers ignore
                    // autocomplete="off" on inputs and helpfully autofill the
                    // saved LuCI login here (users see the word "root" appear
                    // in the field). Password managers do not autofill
                    // textareas, and a 24-word phrase wraps instead of
                    // scrolling. FormData.get('mnemonic') is unchanged.
                    E('textarea', {
                        'class': 'nym-input',
                        'name': 'mnemonic',
                        'rows': '3',
                        'autocomplete': 'off',
                        'autocapitalize': 'off',
                        'autocorrect': 'off',
                        'spellcheck': 'false',
                        'style': 'resize: vertical',
                        'placeholder': 'Enter your recovery phrase...'
                    })
                ]),
                E('button', { 'class': 'nym-btn nym-btn-primary', 'type': 'submit', 'style': 'width: 100%' }, 'Login')
            ]);

            // Desync recovery: the daemon reports LoggedOut yet still has a
            // leftover device identity (the "says not set but won't forget"
            // case). Offer the hard reset so the user isn't stuck.
            if (flags.isLoggedOut && flags.identity) {
                return E('div', {}, [
                    form,
                    E('div', { 'class': 'nym-card-description', 'style': 'margin-top: 16px; opacity: 0.7' }, 'Stale account data detected on this device. If login fails, reset the stored account state.'),
                    E('button', { 'class': 'nym-btn nym-btn-secondary', 'style': 'width: 100%; margin-top: 8px', 'click': handleAccountReset }, 'Reset account state')
                ]);
            }

            return form;
        };

        // Re-fetch live account state and rebuild the card body in place.
        var refreshAccountCard = function() {
            return rpc.accountGet().then(function(acct) {
                if (accountBodyEl) {
                    dom.content(accountBodyEl, buildAccountBody(computeAccountFlags(acct)));
                }
            }).catch(function() { /* leave the existing card on transient errors */ });
        };

        accountBodyEl = E('div', { 'class': 'nym-card-body' }, [
            buildAccountBody(computeAccountFlags(account_info))
        ]);

        var accountCard = E('div', { 'class': 'nym-card', 'id': 'nym-card-account' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(accountCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconUser),
                    'Account'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            accountBodyEl
        ]);
        container.appendChild(accountCard);

        // Daemon action helpers
        // `enabled` is optional: pass undefined to leave the boot-time part of
        // the badge as it was. Running-but-not-enabled is a state users end up
        // in after a bad upgrade and everything looks fine until they reboot,
        // so it gets said out loud rather than inferred.
        var refreshDaemonUi = function(running, enabled) {
            if (enabled !== undefined) lastDaemonEnabled = !!enabled;
            if (daemonStatusBadge) {
                daemonStatusBadge.className = 'nym-card-status' + (running ? '' : ' stopped');
            }
            if (daemonStatusBadgeText) {
                daemonStatusBadgeText.textContent = (running ? 'Running' : 'Stopped') +
                    (lastDaemonEnabled ? '' : ' · not enabled at boot');
            }
            if (serviceInfoFrame) {
                serviceInfoFrame.className = 'nym-info-frame' + (running ? '' : ' stopped');
            }
            if (daemonStartBtn) daemonStartBtn.disabled = running;
            if (daemonStopBtn)  daemonStopBtn.disabled  = !running;
        };

        var DAEMON_ACTIONS = {
            'start':   { label: 'Start',   verb: 'Starting',   pastTense: 'started',   rpcCall: function() { return rpc.daemonStart(); },   needsDisconnect: false },
            'stop':    { label: 'Stop',    verb: 'Stopping',   pastTense: 'stopped',   rpcCall: function() { return rpc.daemonStop(); },    needsDisconnect: true  },
            'restart': { label: 'Restart', verb: 'Restarting', pastTense: 'restarted', rpcCall: function() { return rpc.daemonRestart(); }, needsDisconnect: true  }
        };

        var runDaemonAction = function(action) {
            var info = DAEMON_ACTIONS[action];
            if (!info) return;

            var execute = function() {
                showModal(info.verb + ' Daemon', 'Please wait...');
                info.rpcCall().then(function(result) {
                    var running = result && result.status === 'running';
                    refreshDaemonUi(running, result ? result.enabled : undefined);
                    // The Account card may be sitting on the "service not
                    // reachable" panel; re-ask now that the daemon moved.
                    if (typeof refreshAccountCard === 'function') refreshAccountCard();
                    if (result && result.success) {
                        setModalSuccess('Done', 'Daemon ' + info.pastTense, '✓');
                        setTimeout(fadeOutModal, 1500);
                    } else {
                        hideModal();
                        showToast(info.label + ' failed: ' + ((result && result.error) || 'Unknown'), 'error');
                    }
                }).catch(function(err) {
                    hideModal();
                    showToast('Error: ' + err.message, 'error');
                });
            };

            if (!info.needsDisconnect) {
                execute();
                return;
            }

            rpc.status().then(function(st) {
                if (st && (st.state === 'connected' || st.state === 'connecting')) {
                    confirmModal(
                        info.label + ' Daemon',
                        'The VPN is currently connected. ' + info.verb + ' the daemon will disconnect you.',
                        '⚠',
                        function() {
                            showModal('Disconnecting', 'Please wait...');
                            rpc.disconnect().then(function() {
                                updateModal(info.verb + ' daemon...');
                                setTimeout(execute, 1000);
                            }).catch(execute);
                        },
                        null,
                        info.label
                    );
                } else {
                    execute();
                }
            }).catch(execute);
        };

        // Update daemon status display (called by status poller)
        var updateDaemonStatus = function() {
            return rpc.daemonStatus().then(function(result) {
                if (!result) return;
                refreshDaemonUi(!!result.running, result.enabled);
            }).catch(function(err) {
                console.error('Daemon status update failed:', err);
            });
        };

        // Service Management Card
        var initialDaemonRunning = !!daemon_status.running;

        daemonStartBtn = E('button', {
            'class': 'nym-card-action success',
            'type': 'button',
            'click': function() { runDaemonAction('start'); }
        });
        daemonStartBtn.innerHTML = assets.iconStart + '<span>Start</span>';
        daemonStartBtn.disabled = initialDaemonRunning;

        var daemonRestartBtn = E('button', {
            'class': 'nym-card-action rotate',
            'type': 'button',
            'click': function() { runDaemonAction('restart'); }
        });
        daemonRestartBtn.innerHTML = assets.iconRefresh + '<span>Restart</span>';

        daemonStopBtn = E('button', {
            'class': 'nym-card-action danger',
            'type': 'button',
            'click': function() { runDaemonAction('stop'); }
        });
        daemonStopBtn.innerHTML = assets.iconStop + '<span>Stop</span>';
        daemonStopBtn.disabled = !initialDaemonRunning;

        daemonStatusBadgeText = E('span', { 'class': 'nym-card-status-text' },
            (initialDaemonRunning ? 'Running' : 'Stopped') +
            (lastDaemonEnabled ? '' : ' · not enabled at boot'));
        daemonStatusBadge = E('div', {
            'class': 'nym-card-status' + (initialDaemonRunning ? '' : ' stopped')
        }, [
            E('span', { 'class': 'nym-card-status-indicator' }),
            daemonStatusBadgeText
        ]);

        serviceInfoFrame = E('div', {
            'class': 'nym-info-frame' + (initialDaemonRunning ? '' : ' stopped')
        }, [
            E('div', { 'class': 'nym-info-frame-label' }, 'Daemon'),
            E('div', { 'class': 'nym-info-frame-main' }, [
                E('div', { 'class': 'nym-info-frame-value' }, 'nym-vpnd'),
                daemonStatusBadge
            ])
        ]);

        var serviceCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(serviceCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconService),
                    'Service Management'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-account-panel' }, [
                    serviceInfoFrame,
                    E('div', { 'class': 'nym-card-actions-bar' }, [
                        daemonStartBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        daemonRestartBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        daemonStopBtn
                    ])
                ])
            ])
        ]);
        container.appendChild(serviceCard);

        // Logs Card — tail of `logread -e nym-vpn`. Auto-refreshes every 5s
        // while the card is expanded and not paused by the user.
        var logViewer = E('div', { 'class': 'nym-log-viewer empty' }, 'Expand to load logs.');
        var logLinesSelect = E('select', { 'class': 'nym-select' }, [
            E('option', { 'value': '100' }, '100 lines'),
            E('option', { 'value': '200', 'selected': 'selected' }, '200 lines'),
            E('option', { 'value': '500' }, '500 lines'),
            E('option', { 'value': '1000' }, '1000 lines')
        ]);
        var logIntervalSelect = E('select', { 'class': 'nym-select' }, [
            E('option', { 'value': '2' }, 'Every 2s'),
            E('option', { 'value': '5', 'selected': 'selected' }, 'Every 5s'),
            E('option', { 'value': '10' }, 'Every 10s'),
            E('option', { 'value': '30' }, 'Every 30s')
        ]);
        // Error-context filter: collapse the buffer to just error/warn lines
        // plus a window of surrounding lines, so info/debug noise is only kept
        // where it gives context to a failure.
        var logFilterSelect = E('select', { 'class': 'nym-select', 'title': 'Filter log level' }, [
            E('option', { 'value': 'all', 'selected': 'selected' }, 'All levels'),
            E('option', { 'value': 'err0' }, 'Errors only'),
            E('option', { 'value': 'err10' }, 'Errors ±10'),
            E('option', { 'value': 'err30' }, 'Errors ±30')
        ]);
        var logStatus = E('span', { 'class': 'nym-log-status paused' }, 'paused');
        var logPauseBtn = E('button', { 'class': 'nym-btn nym-btn-secondary nym-btn-icon', 'type': 'button', 'title': 'Play' });
        logPauseBtn.innerHTML = assets.iconPlay;
        var logCopyBtn = E('button', { 'class': 'nym-btn nym-btn-secondary nym-btn-icon', 'type': 'button', 'title': 'Copy to clipboard' });
        logCopyBtn.innerHTML = assets.iconClipboard;

        var logsExpanded = false;
        var logsPaused = true;
        var logsFetching = false;
        var lastLogsClean = '';
        var logTimer = null;

        var setLogStatus = function(text, cls) {
            logStatus.textContent = text;
            logStatus.className = 'nym-log-status ' + cls;
        };

        // ANSI escape stripping (server already does this, kept as a safety net).
        var ansiRe = /\x1b\[[0-9;]*m/g;
        var escapeHtml = function(s) {
            return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        };
        // Match the tracing level keyword that follows an ISO-8601 timestamp.
        // Anchoring on the timestamp keeps us from accidentally coloring the
        // word "INFO" / "ERROR" if it happens to appear inside a message body.
        var levelRe = /(\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+)(INFO|WARN|WARNING|ERROR|DEBUG|TRACE)\b/;
        var levelClass = { INFO: 'info', WARN: 'warn', WARNING: 'warn', ERROR: 'error', DEBUG: 'debug', TRACE: 'trace' };
        var renderColoredLogs = function(cleaned) {
            var parts = cleaned.split('\n');
            var out = '';
            for (var i = 0; i < parts.length; i++) {
                var safe = escapeHtml(parts[i]);
                var m = safe.match(levelRe);
                if (m) {
                    var cls = levelClass[m[2]];
                    var idx = m.index + m[1].length;
                    safe = safe.slice(0, idx) +
                           '<span class="nym-log-' + cls + '">' + m[2] + '</span>' +
                           safe.slice(idx + m[2].length);
                }
                out += safe;
                if (i < parts.length - 1) out += '\n';
            }
            return out;
        };

        // A line is an "error anchor" if it carries an ERROR/WARN tracing level
        // (after the ISO-8601 timestamp) or a syslog daemon.{err,warn,crit,…}
        // facility from logread. Anchoring avoids matching the words in a body.
        var errLineRe = /\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+(?:ERROR|WARN(?:ING)?)\b|daemon\.(?:err(?:or)?|warn(?:ing)?|crit|alert|emerg)\b/;
        var lastLogsDisplay = '';

        // Reduce the buffer to error/warn lines plus a +/-N line context window.
        // Skipped runs are collapsed to a single ellipsis marker. mode is one of
        // all | err0 | err10 | err30.
        var applyLogFilter = function(text) {
            var mode = logFilterSelect.value;
            if (mode === 'all') return text;
            var ctx = mode === 'err30' ? 30 : (mode === 'err10' ? 10 : 0);
            var lines = text.split('\n');
            var keep = new Array(lines.length);
            var anyErr = false;
            for (var i = 0; i < lines.length; i++) {
                if (errLineRe.test(lines[i])) {
                    anyErr = true;
                    var lo = Math.max(0, i - ctx), hi = Math.min(lines.length - 1, i + ctx);
                    for (var j = lo; j <= hi; j++) keep[j] = true;
                }
            }
            if (!anyErr) return '';
            var out = [], skipping = false;
            for (var k = 0; k < lines.length; k++) {
                if (keep[k]) {
                    if (skipping) { out.push('        ⋯'); skipping = false; }
                    out.push(lines[k]);
                } else {
                    skipping = true;
                }
            }
            return out.join('\n');
        };

        // Render lastLogsClean through the active filter. Called both on fetch
        // and on filter change (no refetch needed — filtering is client-side).
        var renderLogView = function(cleaned) {
            var display = applyLogFilter(cleaned);
            lastLogsDisplay = display;
            var shouldAutoscroll = (logViewer.scrollTop + logViewer.clientHeight) >= (logViewer.scrollHeight - 8);
            if (cleaned.length === 0) {
                logViewer.className = 'nym-log-viewer empty';
                logViewer.textContent = 'No nym-vpn log entries in the system buffer.';
            } else if (display.length === 0) {
                logViewer.className = 'nym-log-viewer empty';
                logViewer.textContent = 'No error or warning entries in the current buffer.';
            } else {
                logViewer.className = 'nym-log-viewer';
                logViewer.innerHTML = renderColoredLogs(display);
                if (shouldAutoscroll) logViewer.scrollTop = logViewer.scrollHeight;
            }
        };

        var fetchLogs = function() {
            if (logsFetching) return;
            logsFetching = true;
            var lines = parseInt(logLinesSelect.value, 10) || 200;
            rpc.logsGet(lines).then(function(result) {
                logsFetching = false;
                if (!result || result.success !== true) {
                    logViewer.className = 'nym-log-viewer empty';
                    logViewer.textContent = (result && result.error) || 'Failed to read logs.';
                    return;
                }
                var raw = result.logs || '';
                var cleaned = raw.replace(ansiRe, '');
                lastLogsClean = cleaned;
                renderLogView(cleaned);
            }).catch(function(err) {
                logsFetching = false;
                logViewer.className = 'nym-log-viewer empty';
                logViewer.textContent = 'Log fetch error: ' + (err && err.message ? err.message : err);
            });
        };

        var copyLogs = function() {
            // Copy what's shown — when a filter is active this is the focused
            // error-context view, which is what users want to share.
            var text = lastLogsDisplay || lastLogsClean || '';
            if (!text) {
                showToast('No logs to copy', 'warning');
                return;
            }
            var done = function(ok) {
                showToast(ok ? 'Logs copied to clipboard' : 'Copy failed', ok ? 'success' : 'error');
            };
            // Prefer the async clipboard API (HTTPS / localhost). Fall back to
            // the legacy textarea + execCommand path for plain-HTTP LuCI.
            if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() { done(true); })
                    .catch(function() { done(legacyCopy(text)); });
                return;
            }
            done(legacyCopy(text));
        };
        var legacyCopy = function(text) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.top = '0';
            ta.style.left = '0';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
            document.body.removeChild(ta);
            return ok;
        };

        var startLogTimer = function() {
            stopLogTimer();
            var seconds = parseInt(logIntervalSelect.value, 10) || 5;
            logTimer = setInterval(function() {
                if (logsExpanded && !logsPaused) fetchLogs();
            }, seconds * 1000);
        };
        var stopLogTimer = function() {
            if (logTimer) { clearInterval(logTimer); logTimer = null; }
        };
        var setPlayPauseUi = function() {
            if (logsPaused) {
                logPauseBtn.innerHTML = assets.iconPlay;
                logPauseBtn.setAttribute('title', 'Play');
                setLogStatus('paused', 'paused');
            } else {
                logPauseBtn.innerHTML = assets.iconPause;
                logPauseBtn.setAttribute('title', 'Pause');
                setLogStatus('live', 'live');
            }
        };

        logCopyBtn.onclick = copyLogs;
        logPauseBtn.onclick = function() {
            logsPaused = !logsPaused;
            setPlayPauseUi();
            if (!logsPaused) { fetchLogs(); startLogTimer(); }
            else { stopLogTimer(); }
        };
        logLinesSelect.addEventListener('change', function() { if (!logsPaused) fetchLogs(); });
        logIntervalSelect.addEventListener('change', function() { if (!logsPaused) startLogTimer(); });
        // Re-filter in place from the buffer we already have — no refetch.
        logFilterSelect.addEventListener('change', function() { renderLogView(lastLogsClean); });

        var logsCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() {
                toggleCard(logsCard);
                logsExpanded = logsCard.classList.contains('expanded');
                if (logsExpanded) {
                    // Start live by default when the user opens the card.
                    logsPaused = false;
                    setPlayPauseUi();
                    fetchLogs();
                    startLogTimer();
                } else {
                    logsPaused = true;
                    setPlayPauseUi();
                    stopLogTimer();
                }
            } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconLogs),
                    'Daemon Logs'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-card-description' },
                    'Live tail of nym-vpnd log entries from the system log.'),
                E('div', { 'class': 'nym-log-controls' }, [
                    logLinesSelect,
                    logIntervalSelect,
                    logFilterSelect,
                    logPauseBtn,
                    logCopyBtn,
                    logStatus
                ]),
                logViewer
            ])
        ]);
        // Troubleshooting group appended last (Diagnostics → Logs); logsCard is
        // appended after diagCard below.

        // Diagnostics Card — surfaces the daemon's connectivity self-test
        // (`nym-vpnc diagnostic run`): DNS resolution, VPN API reachability over
        // HTTP, and the selected gateway's TCP/WebSocket handshake. The report is
        // rendered as PASS/FAIL rows; the JSON is treated as opaque so new daemon
        // probes appear automatically without touching this view.
        var diagResults = E('div', { 'class': 'nym-diag-results empty' },
            'Run a diagnostic to test DNS, API, and gateway connectivity.');
        var diagSkipDns = E('input', { 'type': 'checkbox', 'id': 'diag-skip-dns' });
        var diagSkipHttp = E('input', { 'type': 'checkbox', 'id': 'diag-skip-http' });
        var diagRunBtn = E('button', { 'class': 'nym-btn nym-btn-primary nym-btn-small', 'type': 'button' }, 'Run Diagnostic');
        var diagRunning = false;

        var diagChip = function(ok) {
            return E('span', { 'class': 'nym-diag-chip ' + (ok ? 'ok' : 'fail') }, ok ? 'PASS' : 'FAIL');
        };
        var diagRow = function(label, ok, detail) {
            return E('div', { 'class': 'nym-diag-row' }, [
                diagChip(ok),
                E('div', { 'class': 'nym-diag-row-body' }, [
                    // Array-wrap so LuCI's dom.append renders these as text nodes
                    // (createTextNode); a bare string child is assigned via innerHTML,
                    // which would execute markup in untrusted report fields (gateway
                    // operator name, X-Cable-Routing-Id, daemon error strings).
                    E('div', { 'class': 'nym-diag-row-label' }, [String(label)]),
                    detail ? E('div', { 'class': 'nym-diag-row-detail' }, [String(detail)]) : ''
                ])
            ]);
        };
        var diagGroup = function(title, rows) {
            if (!rows.length) rows = [E('div', { 'class': 'nym-diag-empty' }, 'No results.')];
            return E('div', { 'class': 'nym-diag-group' },
                [E('div', { 'class': 'nym-diag-group-title' }, [String(title)])].concat(rows));
        };
        var diagDnsRow = function(label, r) {
            var res = r.resolution || {};
            var detail;
            if (res.ok)
                detail = r.hostname + ' → ' + (res.value || []).join(', ') +
                    ' (' + r.resolution_duration_ms + 'ms)';
            else
                detail = r.hostname + ' → ' + (res.error || 'failed');
            return diagRow(label, !!res.ok, detail);
        };
        var renderDiagnosticReport = function(report) {
            var groups = [];

            // DNS resolution — host resolvers plus each configured nameserver.
            if (report.dns) {
                var dnsRows = [];
                var sys = report.dns.system;
                if (sys) {
                    if (sys.ok && sys.value)
                        sys.value.forEach(function(r) { dnsRows.push(diagDnsRow('System resolvers', r)); });
                    else
                        dnsRows.push(diagRow('System resolvers', false, sys.error || 'failed'));
                }
                (report.dns.by_nameserver || []).forEach(function(r) {
                    dnsRows.push(diagDnsRow(r.nameservers || 'nameserver', r));
                });
                groups.push(diagGroup('DNS Resolution', dnsRows));
            }

            // HTTP — VPN API time skew, health endpoint, node count.
            if (report.http) {
                var httpRows = [];
                var h = report.http;
                if (h.ok && h.value) {
                    var v = h.value;
                    if (v.remote_time) {
                        var rt = v.remote_time;
                        httpRows.push(diagRow('API time skew',
                            !!(rt.ok && rt.value && rt.value.accetably_synced),
                            rt.ok && rt.value
                                ? ('local ' + rt.value.local_time + ' / remote ' + rt.value.estimated_remote_time)
                                : (rt.error || 'failed')));
                    }
                    if (v.health_response) {
                        var hr = v.health_response;
                        httpRows.push(diagRow('API health', !!hr.ok,
                            hr.ok && hr.value ? (hr.value.status + ' @ ' + hr.value.timestamp_utc)
                                : (hr.error || 'failed')));
                    }
                    if (v.nb_nymnodes) {
                        var nn = v.nb_nymnodes;
                        httpRows.push(diagRow('Nym nodes reachable', !!nn.ok,
                            nn.ok ? (nn.value + ' nodes') : (nn.error || 'failed')));
                    }
                } else {
                    httpRows.push(diagRow('VPN API', false, h.error || 'failed'));
                }
                groups.push(diagGroup('VPN API (HTTP)', httpRows));

                // Per-endpoint reachability, incl. domain-fronted probes (#5300).
                if (h.ok && h.value && (h.value.by_endpoint || []).length) {
                    var epRows = h.value.by_endpoint.map(function(ep) {
                        if (ep.ok && ep.value) {
                            var u = ep.value.url || {};
                            var fronted = !!(u.front_hosts && u.front_hosts.length);
                            return diagRow((u.url || 'endpoint') + (fronted ? ' [fronted]' : ''),
                                true,
                                'status: ' + ep.value.status +
                                    (fronted ? ' · via ' + u.front_hosts.join(', ') : ''));
                        }
                        return diagRow('endpoint', false, ep.error || 'failed');
                    });
                    groups.push(diagGroup('API Endpoints', epRows));
                }
            }

            // Gateway — selection plus TCP/WebSocket reachability.
            if (report.gateway) {
                var gwRows = [];
                var g = report.gateway;
                if (g.gateway) {
                    var sel = g.gateway;
                    var val = sel.value || {};
                    var gwName = val.name || val.identity_key || val.identityKey || 'selected';
                    gwRows.push(diagRow('Gateway selection', !!sel.ok,
                        sel.ok ? gwName : (sel.error || 'failed')));
                }
                if (g.tcp)
                    gwRows.push(diagRow('TCP reachability', !!g.tcp.ok,
                        g.tcp.ok ? 'connected' : (g.tcp.error || 'failed')));
                if (g.websocket)
                    gwRows.push(diagRow('WebSocket handshake', !!g.websocket.ok,
                        g.websocket.ok ? 'connected' : (g.websocket.error || 'failed')));
                if (g.websocket_request)
                    gwRows.push(diagRow('WebSocket request', !!g.websocket_request.ok,
                        g.websocket_request.ok ? (g.websocket_request.value || 'ok')
                            : (g.websocket_request.error || 'failed')));
                groups.push(diagGroup('Gateway', gwRows));
            }

            // Hybrid Transport — CTAP 2.2 relay reachability canary (#5314).
            // Omitted from the JSON when --skip-hybrid-transport was passed.
            if (report.hybrid_transport) {
                var ht = report.hybrid_transport;
                groups.push(diagGroup('Hybrid Transport', [
                    diagRow('CTAP relay (cable.ua5v.com)', !!ht.ok,
                        ht.ok && ht.value
                            ? ('routing-id ' + ht.value.routing_id + ' (' + ht.value.handshake_duration_ms + 'ms)')
                            : (ht.error || 'failed'))
                ]));
            }

            if (!groups.length)
                groups.push(E('div', { 'class': 'nym-diag-empty' }, 'Diagnostic returned no sections.'));
            return groups;
        };

        var runDiagnostic = function() {
            if (diagRunning) return;
            diagRunning = true;
            diagRunBtn.disabled = true;
            diagRunBtn.textContent = 'Running…';
            diagResults.className = 'nym-diag-results empty';
            diagResults.textContent = 'Running diagnostic — this may take a few seconds…';

            var reset = function() {
                diagRunning = false;
                diagRunBtn.disabled = false;
                diagRunBtn.textContent = 'Run Diagnostic';
            };

            rpc.diagnosticRun(diagSkipDns.checked, diagSkipHttp.checked, '').then(function(result) {
                reset();
                if (!result || result.success !== true) {
                    diagResults.className = 'nym-diag-results empty';
                    diagResults.textContent = (result && result.error) || 'Diagnostic failed.';
                    return;
                }
                var report;
                try { report = JSON.parse(result.report); }
                catch (e) {
                    diagResults.className = 'nym-diag-results empty';
                    diagResults.textContent = 'Could not parse diagnostic report.';
                    return;
                }
                diagResults.className = 'nym-diag-results';
                dom.content(diagResults, renderDiagnosticReport(report));
            }).catch(function(err) {
                reset();
                diagResults.className = 'nym-diag-results empty';
                diagResults.textContent = 'Diagnostic error: ' + (err && err.message ? err.message : err);
            });
        };
        diagRunBtn.onclick = runDiagnostic;

        var diagCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(diagCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconDiagnostic),
                    'Diagnostics'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-card-description' },
                    'Run a connectivity self-test against DNS, the Nym VPN API, and the selected gateway.'),
                E('div', { 'class': 'nym-diag-controls' }, [
                    diagRunBtn,
                    E('label', { 'class': 'nym-diag-check' }, [diagSkipDns, ' Skip DNS']),
                    E('label', { 'class': 'nym-diag-check' }, [diagSkipHttp, ' Skip HTTP'])
                ]),
                diagResults
            ])
        ]);
        container.appendChild(diagCard);
        container.appendChild(logsCard);

        // Footer
        var footer = E('div', { 'class': 'nym-footer' }, [
            E('div', { 'class': 'nym-footer-info' }, [
                E('div', { 'class': 'nym-footer-item' }, [
                    'Version: ',
                    E('span', {}, info.version || 'Unknown')
                ]),
                E('div', { 'class': 'nym-footer-item' }, [
                    'Network: ',
                    E('span', {}, network.network || 'mainnet')
                ])
            ])
        ]);
        container.appendChild(footer);

        // Set initial status and button handler
        if (status.state) {
            statusHero.className = 'nym-status-hero ' + status.state;
            statusLabel.textContent = status.state.charAt(0).toUpperCase() + status.state.slice(1);

            if (status.state === 'connected') {
                nymUI.renderGatewayInfo(entryGatewayDisplay,
                    status.entry_name,
                    status.entry_id,
                    status.entry_ip,
                    status.entry_country,
                    countries.data);
                nymUI.renderGatewayInfo(exitGatewayDisplay,
                    status.exit_name,
                    status.exit_id,
                    status.exit_ip,
                    status.exit_country,
                    countries.data);
                buildConnectionChain(isTwoHopMode ? 2 : 5);

                actionBtn.textContent = 'Disconnect';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.onclick = handleDisconnect;
            } else if (status.state === 'connecting') {
                actionBtn.textContent = 'Cancel';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.onclick = handleCancel;
            } else {
                // Disconnected or other state - set Connect handler
                actionBtn.textContent = 'Connect';
                actionBtn.className = 'nym-btn nym-btn-primary';
                actionBtn.onclick = handleConnect;
            }
        } else {
            // No status yet - default to Connect
            actionBtn.onclick = handleConnect;
        }

        // Start uptime if connected, anchored to the router's elapsed seconds.
        if (status.state === 'connected') {
            var initSecs = parseInt(status.connected_seconds, 10);
            syncUptime(isNaN(initSecs) ? 0 : initSecs);
        }

        // Prefill the pickers from the saved daemon config on first render.
        // While connected/connecting they are hidden and reset anyway; the
        // poll's disconnected transition handles later drops.
        if (!status.state || status.state === 'disconnected' || status.state === 'unknown') {
            restoreGatewaySelection();
        }

        // Start polling
        poll.add(updateStatus, 5);
        poll.add(updateDaemonStatus, 10);

        return container;
    }
});
