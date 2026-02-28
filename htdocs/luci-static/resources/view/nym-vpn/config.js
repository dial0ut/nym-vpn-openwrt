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
        return Promise.all([
            rpc.status(),
            rpc.info(),
            rpc.gatewayGet(),
            rpc.gatewayListCountries('mixnet-entry'),
            rpc.gatewayListCountries('mixnet-exit'),
            rpc.tunnelGet(),
            rpc.accountGet(),
            rpc.networkGet(),
            rpc.lanGet(),
            rpc.daemonStatus()
        ]).catch(function(err) {
            console.error('Failed to load Nym VPN data:', err);
            return [null, null, null, [], [], null, null, null, null, null];
        });
    },

    render: function(data) {
        var status = data[0] || {};
        var info = data[1] || {};
        var gateway_config = data[2] || {};
        var entry_countries = (data[3] && data[3].countries) || [];
        var exit_countries = (data[4] && data[4].countries) || [];
        var tunnel_config = data[5] || {};
        var account_info = data[6] || {};
        var network = data[7] || {};
        var lan_policy = data[8] || {};
        var daemon_status = data[9] || {};

        var self = this;
        var E = dom.create.bind(dom);

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

        // Update status display
        var updateStatus = function() {
            return rpc.status().then(function(result) {
                if (!result) return;

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
                        statusLabel.textContent = 'Disconnecting';
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
                    } else {
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
            if (statusHero) statusHero.className = 'nym-status-hero connecting';
            if (statusLabel) statusLabel.textContent = 'Connecting';
            if (actionBtn) actionBtn.disabled = true;

            // Get selected gateway settings
            var entry_country = entryCountrySelect ? entryCountrySelect.value : 'none';
            var exit_country = exitCountrySelect ? exitCountrySelect.value : 'none';

            // Get selected gateway IDs from radio buttons
            var entryRadio = entryGatewayContainer ? entryGatewayContainer.querySelector('input[name="entry_gateway_id"]:checked') : null;
            var exitRadio = exitGatewayContainer ? exitGatewayContainer.querySelector('input[name="exit_gateway_id"]:checked') : null;
            var entry_id = entryRadio ? entryRadio.value : null;
            var exit_id = exitRadio ? exitRadio.value : null;

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
                        updateStatus();
                        return;
                    }

                    var pollCount = 0;
                    var maxPolls = 60;

                    var pollStatus = function() {
                        pollCount++;
                        rpc.status().then(function(st) {
                            if (st && st.state === 'connected') {
                                updateStatus();
                            } else if (st && st.state === 'connecting') {
                                if (pollCount < maxPolls) {
                                    setTimeout(pollStatus, 1000);
                                } else {
                                    updateStatus();
                                }
                            } else {
                                updateStatus();
                            }
                        }).catch(function() {
                            if (pollCount < maxPolls) setTimeout(pollStatus, 1000);
                            else updateStatus();
                        });
                    };

                    setTimeout(pollStatus, 1000);
                }).catch(function(err) {
                    showToast('Connection error: ' + err.message, 'error');
                    updateStatus();
                });
        };

        var handleDisconnect = function() {
            if (statusHero) statusHero.className = 'nym-status-hero disconnecting';
            if (statusLabel) statusLabel.textContent = 'Disconnecting';
            if (actionBtn) actionBtn.disabled = true;

            rpc.disconnect().then(function(result) {
                if (result && result.success) {
                    updateStatus();
                } else {
                    showToast('Disconnect failed: ' + (result.error || 'Unknown'), 'error');
                    updateStatus();
                }
            }).catch(function(err) {
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
                dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, '🌐 Random gateway will be selected'));
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
        var createCountrySelect = function(countryList, name, onSelect) {
            var options = [E('option', { 'value': 'none' }, '— Select Country —')];
            options.push(E('option', { 'value': 'random' }, '🌐 Random'));

            countryList.forEach(function(c) {
                var info = countries.getDisplay(c.code);
                options.push(E('option', { 'value': c.code },
                    info.flag + ' ' + info.name + ' (' + c.count + ')'));
            });

            return E('select', {
                'class': 'nym-select',
                'name': name,
                'change': onSelect
            }, options);
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

        // Tunnel update handler
        var handleTunnelUpdate = function(ev) {
            ev.preventDefault();
            var ipv6 = ev.target.querySelector('#ipv6-toggle').checked ? 'on' : 'off';
            var two_hop = ev.target.querySelector('#two-hop-toggle').checked ? 'on' : 'off';

            rpc.tunnelSet(ipv6, two_hop).then(function(result) {
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

        // LAN policy handler
        var handleLanPolicy = function(policy) {
            rpc.lanSet(policy).then(function(result) {
                if (result && result.success) {
                    showToast('LAN policy set to: ' + policy, 'success');
                    var display = document.getElementById('lan-policy-display');
                    if (display) display.textContent = policy;
                } else {
                    showToast('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                showToast('Error: ' + err.message, 'error');
            });
        };

        // Check if logged in
        var identity = account_info.identity || '';
        var state = account_info.state || '';
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
                            entryCountrySelect = createCountrySelect(entry_countries, 'entry_country', function(ev) {
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
                            exitCountrySelect = createCountrySelect(exit_countries, 'exit_country', function(ev) {
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
                    E('div', { 'class': 'nym-card-icon' }, '⚙'),
                    'Tunnel Settings'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('form', { 'submit': handleTunnelUpdate }, [
                    E('div', { 'class': 'nym-toggle-row' }, [
                        E('div', { 'class': 'nym-toggle-info' }, [
                            E('div', { 'class': 'nym-toggle-title' }, 'IPv6'),
                            E('div', { 'class': 'nym-toggle-desc' }, 'Enable IPv6 connectivity through the tunnel')
                        ]),
                        E('label', { 'class': 'nym-toggle' }, [
                            E('input', {
                                'type': 'checkbox',
                                'id': 'ipv6-toggle',
                                'checked': tunnel_config.ipv6 === 'on' ? 'checked' : null
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
                                'checked': tunnel_config.two_hop === 'on' ? 'checked' : null
                            }),
                            E('span', { 'class': 'nym-toggle-slider' })
                        ])
                    ]),
                    E('div', { 'class': 'nym-text-center nym-mt-16' }, [
                        E('button', { 'class': 'nym-btn nym-btn-primary', 'type': 'submit' }, 'Save Tunnel Settings')
                    ])
                ])
            ])
        ]);
        container.appendChild(tunnelCard);

        // Local Network Card
        var lanCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(lanCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    E('div', { 'class': 'nym-card-icon' }, '🔒'),
                    'Local Network'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                E('div', { 'class': 'nym-card-description' },
                    'Control whether local network devices can be accessed while connected to the VPN.'),
                E('div', { 'class': 'nym-info-item', 'style': 'margin-bottom: 16px' }, [
                    E('div', { 'class': 'nym-info-label' }, 'Current Policy'),
                    E('div', { 'class': 'nym-info-value', 'id': 'lan-policy-display' }, lan_policy.policy || 'Not set')
                ]),
                E('div', { 'style': 'display: flex; gap: 12px; justify-content: center' }, [
                    E('button', {
                        'class': 'nym-btn nym-btn-primary',
                        'click': function() { handleLanPolicy('allow'); }
                    }, 'Allow LAN'),
                    E('button', {
                        'class': 'nym-btn nym-btn-danger',
                        'click': function() { handleLanPolicy('block'); }
                    }, 'Block LAN')
                ])
            ])
        ]);
        container.appendChild(lanCard);

        // Account Card
        var accountCard = E('div', { 'class': 'nym-card' }, [
            E('div', { 'class': 'nym-card-header', 'click': function() { toggleCard(accountCard); } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    E('div', { 'class': 'nym-card-icon' }, '👤'),
                    'Account'
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            E('div', { 'class': 'nym-card-body' }, [
                isLoggedIn ? E('div', { 'class': 'nym-account-logged-in' }, [
                    E('div', { 'class': 'nym-account-id' }, identity),
                    E('div', { 'class': 'nym-account-state' }, state),
                    E('div', { 'class': 'nym-account-actions' }, [
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
                            'type': 'password',
                            'name': 'mnemonic',
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
                    E('div', { 'class': 'nym-card-icon' }, '🔧'),
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
