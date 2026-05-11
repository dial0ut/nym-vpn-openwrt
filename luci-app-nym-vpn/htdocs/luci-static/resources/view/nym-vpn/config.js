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
        var dns_config = data.dns || {};
        var watchdog = data.watchdog || {};

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
        var actionInProgress = false;
        var daemonStatusDisplay;

        // Uptime tracking
        var connectionStartTime = null;
        var uptimeInterval = null;

        var startUptimeTimer = function(existingStartTime) {
            if (uptimeInterval) clearInterval(uptimeInterval);

            connectionStartTime = existingStartTime || Date.now();
            nymUI.saveStartTime(connectionStartTime);

            var updateDisplay = function() {
                if (uptimeDisplay && connectionStartTime) {
                    var elapsed = Math.floor((Date.now() - connectionStartTime) / 1000);
                    uptimeDisplay.textContent = nymUI.formatUptime(elapsed);
                }
            };

            updateDisplay();
            uptimeInterval = setInterval(updateDisplay, 1000);
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
                        if (!connectionStartTime) {
                            startUptimeTimer(nymUI.getStoredStartTime());
                        }
                    } else if (state === 'connecting') {
                        statusLabel.textContent = 'Connecting';
                        stopUptimeTimer();
                    } else if (state === 'disconnecting') {
                        // An account-level error often strands the tunnel in
                        // Disconnecting; the error strip shows why, so the
                        // label switches to Halted to stop implying progress.
                        statusLabel.textContent = result.error_reason ? 'Halted' : 'Disconnecting';
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
                    buildConnectionChain(isTwoHopMode ? 2 : 5);

                    // Reset gateway selectors to default state only on state change to connected
                    if (previousState !== 'connected') {
                        if (entryCountrySelect) entryCountrySelect.value = 'none';
                        if (exitCountrySelect) exitCountrySelect.value = 'none';
                        if (entryGatewayContainer) dom.content(entryGatewayContainer, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'));
                        if (exitGatewayContainer) dom.content(exitGatewayContainer, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'));
                    }
                } else if (state === 'disconnected' || state === 'connecting') {
                    // Only clear gateway info when fully disconnected or connecting fresh
                    if (entryGatewayDisplay) entryGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
                    if (exitGatewayDisplay) exitGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
                }
                // Keep gateway info visible during 'disconnecting' state

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

                    // Poll until daemon reaches connected state
                    var pollCount = 0;
                    var maxPolls = 60;

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
                            if (st && st.state === 'connected') {
                                actionInProgress = false;
                                previousState = 'connected';
                                updateStatus();
                            } else if (st && (st.state === 'connecting' || st.state === 'disconnecting')) {
                                if (pollCount < maxPolls) {
                                    setTimeout(pollStatus, 1000);
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
                            if (pollCount < maxPolls) setTimeout(pollStatus, 1000);
                            else { actionInProgress = false; updateStatus(); }
                        });
                    };

                    setTimeout(pollStatus, 1000);
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

                // Poll until daemon reaches disconnected state
                var pollCount = 0;
                var maxPolls = 60;

                var pollDisconnect = function() {
                    pollCount++;
                    rpc.status().then(function(st) {
                        if (st && st.state === 'disconnected') {
                            actionInProgress = false;
                            previousState = 'disconnected';
                            updateStatus();
                        } else if (pollCount < maxPolls) {
                            setTimeout(pollDisconnect, 1000);
                        } else {
                            actionInProgress = false;
                            updateStatus();
                        }
                    }).catch(function() {
                        if (pollCount < maxPolls) setTimeout(pollDisconnect, 1000);
                        else { actionInProgress = false; updateStatus(); }
                    });
                };

                setTimeout(pollDisconnect, 500);
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

        // Load gateways for selected country
        var loadGatewaysForCountry = function(country, type, container) {
            if (!country || country === 'none') {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country above'));
                return;
            }

            if (country === 'random') {
                dom.content(container, '');
                return;
            }

            dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Loading gateways...'));

            rpc.gatewayListByCountry(type, country).then(function(result) {
                if (!result || !result.gateways || result.gateways.length === 0) {
                    dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'No gateways available'));
                    return;
                }

                var sorted = result.gateways.slice().sort(function(a, b) {
                    var scoreA = (a.performance || '').indexOf('High') >= 0 ? 3 :
                                 (a.performance || '').indexOf('Medium') >= 0 ? 2 :
                                 (a.performance || '').indexOf('Offline') >= 0 ? 0 : 1;
                    var scoreB = (b.performance || '').indexOf('High') >= 0 ? 3 :
                                 (b.performance || '').indexOf('Medium') >= 0 ? 2 :
                                 (b.performance || '').indexOf('Offline') >= 0 ? 0 : 1;
                    return scoreB - scoreA;
                });

                var inputName = type === 'mixnet-entry' ? 'entry_gateway_id' : 'exit_gateway_id';
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

                    var option = E('label', { 'class': 'nym-gateway-option' }, [
                        E('input', { 'type': 'radio', 'name': inputName, 'value': gw.id || '' }),
                        iconDiv,
                        E('div', { 'class': 'nym-gateway-option-info' }, [
                            E('div', { 'class': 'nym-gateway-option-name' }, gw.name || 'Unknown'),
                            E('div', { 'class': 'nym-gateway-option-perf' }, perf)
                        ])
                    ]);
                    option.addEventListener('click', function() {
                        container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                            el.classList.remove('selected');
                        });
                        option.classList.add('selected');
                    });
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
            countryList.forEach(function(c) {
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

            // Lazy-load country list on first focus
            var loaded = false;
            select.addEventListener('focus', function() {
                if (loaded) return;
                loaded = true;

                if (countryCache[gwType]) {
                    populateCountrySelect(select, countryCache[gwType]);
                    return;
                }

                rpc.gatewayListCountries(gwType).then(function(result) {
                    var list = (result && result.countries) || [];
                    countryCache[gwType] = list;
                    populateCountrySelect(select, list);
                }).catch(function() {
                    select.options[0].textContent = '— Failed to load —';
                });
            });

            return select;
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
            if (!ipv6El || !twoHopEl || !killswitchEl) return;

            var ipv6 = ipv6El.checked ? 'on' : 'off';
            var two_hop = twoHopEl.checked ? 'on' : 'off';
            var killswitch = killswitchEl.checked ? 'on' : 'off';

            rpc.tunnelSet(ipv6, two_hop, killswitch).then(function(result) {
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

        // Account handlers
        var handleAccountLogin = function(ev) {
            ev.preventDefault();
            var fd = new FormData(ev.target);
            var mnemonic = fd.get('mnemonic');
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

        // Custom DNS handler
        var handleDnsToggle = function(enabled) {
            var serversInput = document.getElementById('dns-servers-input');
            var servers = serversInput ? serversInput.value.trim() : null;
            rpc.dnsSet(enabled, servers || null).then(function(result) {
                if (result && result.success) {
                    showToast(enabled ? 'Custom DNS enabled' : 'Custom DNS disabled', 'success');
                } else {
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                    var toggle = document.getElementById('dns-toggle');
                    if (toggle) toggle.checked = !enabled;
                }
            }).catch(function(err) {
                showToast('Error: ' + err.message, 'error');
                var toggle = document.getElementById('dns-toggle');
                if (toggle) toggle.checked = !enabled;
            });
        };

        var handleDnsSave = function() {
            var serversInput = document.getElementById('dns-servers-input');
            var dnsToggle = document.getElementById('dns-toggle');
            var servers = serversInput ? serversInput.value.trim() : '';
            var enabled = dnsToggle ? dnsToggle.checked : false;
            rpc.dnsSet(enabled, servers || null).then(function(result) {
                if (result && result.success) {
                    showToast('DNS servers updated', 'success');
                } else {
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                showToast('Error: ' + err.message, 'error');
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

        // Check if logged in
        var identity = account_info.identity || '';
        var rawState = account_info.state || '';
        var state = rawState.replace(/([a-z])([A-Z])/g, '$1 $2');
        var invalidIdentities = ['', 'Not set', 'LoggedOut', 'unset', 'none'];
        var hasError = state.indexOf('Error') >= 0 || identity.indexOf('Error') >= 0;
        var isLoggedIn = identity && invalidIdentities.indexOf(identity) === -1 && !hasError;

        var container = E('div', { 'class': 'nym-container' }, [
            E('style', {}, theme.css || ''),

            // Header
            (function() {
                var header = E('div', { 'class': 'nym-header' });
                var logoDiv = E('div', { 'class': 'nym-logo' });
                logoDiv.innerHTML = assets.logo || '';
                header.appendChild(logoDiv);
                header.appendChild(E('div', { 'class': 'nym-subtitle' }, 'The world\'s most private VPN'));
                return header;
            })(),

            // Status Hero with integrated gateway selection
            statusHero = E('div', { 'class': 'nym-status-hero disconnected' }, [
                // Three-column layout: Entry selector | Status ring | Exit selector
                E('div', { 'class': 'nym-hero-gateway-row' }, [
                    // LEFT: Entry Gateway Selection
                    E('div', { 'class': 'nym-hero-gateway-panel' }, [
                        E('div', { 'class': 'nym-gateway-box-title' }, 'Entry Gateway'),
                        E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' }, [
                            E('label', { 'class': 'nym-form-label' }, 'Country'),
                            entryCountrySelect = createCountrySelect('mixnet-entry', 'entry_country', function(ev) {
                                loadGatewaysForCountry(ev.target.value, 'mixnet-entry', entryGatewayContainer);
                            })
                        ]),
                        entryGatewayContainer = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' },
                            E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'))
                    ]),

                    // CENTER: Status Ring + Uptime
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
                        E('div', { 'class': 'nym-uptime-label' }, 'Session Duration')
                    ]),

                    // RIGHT: Exit Gateway Selection
                    E('div', { 'class': 'nym-hero-gateway-panel' }, [
                        E('div', { 'class': 'nym-gateway-box-title' }, 'Exit Gateway'),
                        E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' }, [
                            E('label', { 'class': 'nym-form-label' }, 'Country'),
                            exitCountrySelect = createCountrySelect('mixnet-exit', 'exit_country', function(ev) {
                                loadGatewaysForCountry(ev.target.value, 'mixnet-exit', exitGatewayContainer);
                            })
                        ]),
                        exitGatewayContainer = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' },
                            E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'))
                    ])
                ]),

                // Gateway info display (shown when connected)
                E('div', { 'class': 'nym-gateway-display' }, [
                    E('div', { 'class': 'nym-gateway-item' }, [
                        E('div', { 'class': 'nym-gateway-label' }, 'Entry'),
                        entryGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
                            E('div', { 'class': 'nym-gateway-empty' }, '—')
                        ])
                    ]),
                    E('div', { 'class': 'nym-connection-wrapper' }, [
                        modeLabel = E('div', { 'class': 'nym-mode-label' }),
                        connectionChain = E('div', { 'class': 'nym-connection-chain' })
                    ]),
                    E('div', { 'class': 'nym-gateway-item' }, [
                        E('div', { 'class': 'nym-gateway-label' }, 'Exit'),
                        exitGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
                            E('div', { 'class': 'nym-gateway-empty' }, '—')
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
                                'change': function(ev) {
                                    var warn = ev.target.closest('.nym-toggle-row').querySelector('.nym-toggle-warning');
                                    if (warn) warn.style.display = ev.target.checked ? 'none' : 'block';
                                    saveTunnelSettings();
                                }
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ])
                ]),
            ])
        ]);
        container.appendChild(tunnelCard);

        // DNS & Ad Blocking Card
        var adBlockEnabled = ad_block.enabled ? true : false;
        var dnsEnabled = dns_config.enabled ? true : false;
        var dnsServers = dns_config.servers || '';
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

                // DNS servers input
                E('div', { 'style': 'margin-top: 12px' }, [
                    E('div', { 'class': 'nym-toggle-desc', 'style': 'margin-bottom: 8px' },
                        'Space-separated IP addresses (e.g. 1.1.1.1 8.8.8.8)'),
                    E('div', { 'style': 'display: flex; gap: 8px' }, [
                        E('input', {
                            'type': 'text',
                            'id': 'dns-servers-input',
                            'class': 'nym-input',
                            'placeholder': '1.1.1.1 8.8.8.8',
                            'value': dnsServers,
                            'style': 'flex: 1'
                        }),
                        E('button', {
                            'class': 'nym-btn nym-btn-primary nym-btn-small',
                            'click': handleDnsSave
                        }, 'Save')
                    ])
                ]),

                // Divider
                E('div', { 'style': 'border-top: 1px solid var(--border-color); margin: 16px 0' }),

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

        // Account Card
        var accountCard = E('div', { 'class': 'nym-card', 'id': 'nym-card-account' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(accountCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconUser),
                    'Account'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                isLoggedIn ? E('div', { 'class': 'nym-account-logged-in' }, [
                    E('div', { 'class': 'nym-account-state' }, state),
                    E('div', { 'class': 'nym-account-id' }, identity),
                    E('div', { 'class': 'nym-account-actions nym-account-actions-stacked' }, [
                        E('button', { 'class': 'nym-btn nym-btn-secondary nym-btn-small', 'click': handleRotateKeys }, 'Rotate Keys'),
                        E('button', { 'class': 'nym-btn nym-btn-danger nym-btn-small', 'click': handleAccountLogout }, 'Logout')
                    ])
                ]) : hasError ? E('div', { 'class': 'nym-account-logged-in' }, [
                    E('div', { 'class': 'nym-account-state', 'style': 'background: var(--danger-dim); color: var(--danger)' }, state || identity),
                    E('div', { 'class': 'nym-card-description', 'style': 'margin: 16px 0' }, 'There is an issue with the account. You may need to logout and try again.'),
                    E('button', { 'class': 'nym-btn nym-btn-danger', 'style': 'width: 100%', 'click': handleAccountLogout }, 'Logout')
                ]) : E('form', { 'submit': handleAccountLogin }, [
                    E('div', { 'class': 'nym-card-description' },
                        'Enter your Nym account recovery phrase to connect.'),
                    E('div', { 'class': 'nym-form-group' }, [
                        E('label', { 'class': 'nym-form-label' }, 'Recovery Phrase'),
                        E('input', {
                            'class': 'nym-input',
                            'type': 'text',
                            'name': 'mnemonic',
                            'autocomplete': 'off',
                            'autocapitalize': 'off',
                            'autocorrect': 'off',
                            'spellcheck': 'false',
                            'placeholder': 'Enter your recovery phrase...'
                        })
                    ]),
                    E('button', { 'class': 'nym-btn nym-btn-primary', 'type': 'submit', 'style': 'width: 100%' }, 'Login')
                ])
            ])
        ]);
        container.appendChild(accountCard);

        // Daemon restart handler
        var handleDaemonRestart = function() {
            var doRestart = function() {
                showModal('Restarting Daemon', 'Please wait...');

                rpc.daemonRestart().then(function(result) {
                    if (result && result.success) {
                        setModalSuccess('Done', 'Daemon restarted', '✓');
                        // Update daemon status display
                        if (daemonStatusDisplay) {
                            daemonStatusDisplay.textContent = 'Running';
                            daemonStatusDisplay.className = 'nym-daemon-status running';
                        }
                        setTimeout(function() {
                            fadeOutModal();
                        }, 1500);
                    } else {
                        hideModal();
                        showToast('Restart failed: ' + (result.error || 'Unknown'), 'error');
                        if (daemonStatusDisplay) {
                            daemonStatusDisplay.textContent = 'Stopped';
                            daemonStatusDisplay.className = 'nym-daemon-status stopped';
                        }
                    }
                }).catch(function(err) {
                    hideModal();
                    showToast('Error: ' + err.message, 'error');
                });
            };

            // Check if VPN is connected - warn user
            rpc.status().then(function(st) {
                if (st && (st.state === 'connected' || st.state === 'connecting')) {
                    confirmModal(
                        'Restart Daemon',
                        'The VPN is currently connected. Restarting the daemon will disconnect you.',
                        '⚠',
                        function() {
                            // User confirmed - disconnect first, then restart
                            showModal('Disconnecting', 'Please wait...');
                            rpc.disconnect().then(function() {
                                updateModal('Restarting daemon...');
                                setTimeout(doRestart, 1000);
                            }).catch(function() {
                                doRestart(); // Try restart anyway
                            });
                        },
                        null,
                        'Restart'
                    );
                } else {
                    // Not connected - just show spinner modal and restart
                    doRestart();
                }
            }).catch(function() {
                doRestart();
            });
        };

        // Update daemon status display
        var updateDaemonStatus = function() {
            return rpc.daemonStatus().then(function(result) {
                if (!result || !daemonStatusDisplay) return;

                if (result.running) {
                    daemonStatusDisplay.textContent = 'Running';
                    daemonStatusDisplay.className = 'nym-daemon-status running';
                } else {
                    daemonStatusDisplay.textContent = 'Stopped';
                    daemonStatusDisplay.className = 'nym-daemon-status stopped';
                }
            }).catch(function(err) {
                console.error('Daemon status update failed:', err);
            });
        };

        // Service Management Card
        var serviceCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(serviceCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    svgIcon(assets.iconService),
                    'Service Management'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-card-description' },
                    'Manage the Nym VPN daemon service running on this router.'),
                E('div', { 'class': 'nym-service-status-row' }, [
                    E('div', { 'class': 'nym-service-info' }, [
                        E('div', { 'class': 'nym-service-label' }, 'Daemon Status'),
                        daemonStatusDisplay = E('div', {
                            'class': 'nym-daemon-status ' + (daemon_status.running ? 'running' : 'stopped')
                        }, daemon_status.running ? 'Running' : 'Stopped')
                    ])
                ]),
                E('div', { 'class': 'nym-text-center nym-mt-16' }, [
                    E('button', {
                        'class': 'nym-btn nym-btn-danger',
                        'click': handleDaemonRestart
                    }, 'Restart Daemon')
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
                var shouldAutoscroll = (logViewer.scrollTop + logViewer.clientHeight) >= (logViewer.scrollHeight - 8);
                if (cleaned.length === 0) {
                    logViewer.className = 'nym-log-viewer empty';
                    logViewer.textContent = 'No nym-vpn log entries in the system buffer.';
                } else {
                    logViewer.className = 'nym-log-viewer';
                    logViewer.innerHTML = renderColoredLogs(cleaned);
                    if (shouldAutoscroll) logViewer.scrollTop = logViewer.scrollHeight;
                }
            }).catch(function(err) {
                logsFetching = false;
                logViewer.className = 'nym-log-viewer empty';
                logViewer.textContent = 'Log fetch error: ' + (err && err.message ? err.message : err);
            });
        };

        var copyLogs = function() {
            var text = lastLogsClean || '';
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
                    logPauseBtn,
                    logCopyBtn,
                    logStatus
                ]),
                logViewer
            ])
        ]);
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

        // Start uptime if connected
        if (status.state === 'connected') {
            var storedTime = nymUI.getStoredStartTime();
            startUptimeTimer(storedTime);
        }

        // Start polling
        poll.add(updateStatus, 5);
        poll.add(updateDaemonStatus, 10);

        return container;
    }
});
