'use strict';
'require baseclass';
'require dom';
'require nym-vpn.countries as countries';
'require nym-vpn.ui as nymUI';
'require nym-vpn.components.gateway-picker as gatewayPicker';
'require nym-vpn.flows.connect as connectFlow';

// The status hero: entry/exit pickers (while disconnected) or connected
// gateway info (while connected) in the side columns, the status ring,
// session duration and hop chain in the middle, and the action button.

var E = dom.create.bind(dom);

return baseclass.extend({
    render: function(store, api) {
        var status = store.data.status;
        var pickers = gatewayPicker.create(store, api);

        var statusHero, statusLabel, uptimeDisplay, actionBtn;
        var entryGatewayDisplay, exitGatewayDisplay, connectionChain, modeLabel;
        // Signature of the last connected-state render (gateway identity +
        // hop count). The status poll fires every 5s, but none of this
        // changes for the life of a connection, so we only rebuild the
        // gateway panels and the connection chain when the signature
        // actually changes. This avoids tearing down and recreating the
        // animated chain elements every poll.
        var lastConnectedSig = null;

        // --- uptime ------------------------------------------------------
        // The session duration is anchored to the router-reported elapsed
        // seconds (status.connected_seconds) instead of a per-browser
        // localStorage timestamp — that old timer drifted between
        // browsers/sessions and was meaningless when the router clock itself
        // was desynced. connectionStartTime is a *virtual* start expressed
        // in the local clock (now - elapsed) used only to drive a smooth 1s
        // tick; the authoritative base comes from the router on every poll.
        var connectionStartTime = null;
        var uptimeInterval = null;

        var renderUptime = function() {
            if (uptimeDisplay && connectionStartTime) {
                var elapsed = Math.floor((Date.now() - connectionStartTime) / 1000);
                if (elapsed < 0) elapsed = 0;
                uptimeDisplay.textContent = nymUI.formatUptime(elapsed);
            }
        };

        // Re-anchor the virtual start on every poll (cheap), but keep a
        // single 1s ticker for the connection's lifetime instead of tearing
        // it down and rebuilding it each poll.
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

        // --- connected gateway panels -------------------------------------
        // Operator family (and the same-family warning) under a connected
        // gateway panel. DOM nodes, not innerHTML: the family name comes from
        // the directory and must render as text.
        var appendFamilyInfo = function(container, family, same) {
            if (!container || !family) return;
            container.appendChild(E('div', {
                'class': 'nym-gateway-family' + (same ? ' same' : ''),
                'title': 'Operator family'
            }, [family]));
            if (same) {
                container.appendChild(E('div', { 'class': 'nym-gateway-family-warn' }, '⚠ Same operator family'));
            }
        };
        var renderConnectedGateways = function(st) {
            var ef = api.familyOf(st, 'entry');
            var xf = api.familyOf(st, 'exit');
            var same = api.sameFamily(ef, xf);
            nymUI.renderGatewayInfo(entryGatewayDisplay, st.entry_name, st.entry_id, st.entry_ip, st.entry_country, countries.data);
            appendFamilyInfo(entryGatewayDisplay, ef, same);
            nymUI.renderGatewayInfo(exitGatewayDisplay, st.exit_name, st.exit_id, st.exit_ip, st.exit_country, countries.data);
            appendFamilyInfo(exitGatewayDisplay, xf, same);
        };
        var clearGatewayPanels = function() {
            if (entryGatewayDisplay) entryGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
            if (exitGatewayDisplay) exitGatewayDisplay.innerHTML = '<div class="nym-gateway-empty">—</div>';
        };

        var buildConnectionChain = function(hopCount) {
            if (!connectionChain) return;
            connectionChain.innerHTML = '';

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

        // --- action button ------------------------------------------------
        var flow;
        var setAction = function(kind, text) {
            if (!actionBtn) return;
            switch (kind) {
            case 'connect':
                actionBtn.textContent = 'Connect';
                actionBtn.className = 'nym-btn nym-btn-primary';
                actionBtn.disabled = false;
                actionBtn.onclick = flow.handleConnect;
                break;
            case 'disconnect':
                actionBtn.textContent = 'Disconnect';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.disabled = false;
                actionBtn.onclick = flow.handleDisconnect;
                break;
            case 'cancel':
                actionBtn.textContent = 'Cancel';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.disabled = false;
                actionBtn.onclick = flow.handleCancel;
                break;
            case 'connecting':
                // Before the connect has been sent there is nothing to
                // cancel, so the button sits disabled.
                actionBtn.textContent = 'Connecting';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.disabled = true;
                actionBtn.onclick = null;
                break;
            case 'wait':
                // Disconnecting / cancelling — keep the look, disable.
                actionBtn.textContent = text;
                actionBtn.disabled = true;
                break;
            }
        };

        // The surface the connect flow drives.
        var hero = {
            // Put the hero into its connecting look. `cancelable` arms the
            // Cancel button.
            showConnecting: function(cancelable) {
                store.setBusy(true);
                if (statusHero) statusHero.className = 'nym-status-hero connecting';
                if (statusLabel) statusLabel.textContent = 'Connecting';
                setAction(cancelable ? 'cancel' : 'connecting');
            },
            showDisconnected: function() {
                if (statusHero) statusHero.className = 'nym-status-hero disconnected';
                if (statusLabel) statusLabel.textContent = 'Disconnected';
                setAction('connect');
            },
            showDisconnecting: function(label) {
                if (statusHero) statusHero.className = 'nym-status-hero disconnecting';
                if (statusLabel) statusLabel.textContent = label;
                setAction('wait', label);
            },
            focusPickers: function() {
                if (statusHero && statusHero.scrollIntoView) {
                    statusHero.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
                pickers.focus();
            }
        };
        flow = connectFlow.create(store, api, hero, pickers);

        // --- DOM -----------------------------------------------------------
        // Three-column layout. Each side column hosts BOTH a picker
        // (.nym-panel-picker, shown while disconnected) and the live
        // connection info (.nym-panel-info, shown while connected) for that
        // hop, so the same columns are reused in both states — the connected
        // view fills the width instead of stranding the gateway info in a
        // separate row below the ring.
        var sidePanel = function(title, side, infoLabel, infoDisplay) {
            return E('div', { 'class': 'nym-hero-gateway-panel' }, [
                E('div', { 'class': 'nym-panel-picker' }, [
                    E('div', { 'class': 'nym-gateway-box-title' }, title),
                    E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0' }, [
                        E('label', { 'class': 'nym-form-label' }, 'Country'),
                        side.select
                    ]),
                    side.list
                ]),
                E('div', { 'class': 'nym-panel-info' }, [
                    E('div', { 'class': 'nym-gateway-label' }, infoLabel),
                    infoDisplay
                ])
            ]);
        };

        entryGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
            E('div', { 'class': 'nym-gateway-empty' }, '—')
        ]);
        exitGatewayDisplay = E('div', { 'class': 'nym-gateway-value' }, [
            E('div', { 'class': 'nym-gateway-empty' }, '—')
        ]);

        statusHero = E('div', { 'class': 'nym-status-hero disconnected' }, [
            E('div', { 'class': 'nym-hero-gateway-row' }, [
                sidePanel('Entry Gateway', pickers.entry, 'Entry', entryGatewayDisplay),

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

                sidePanel('Exit Gateway', pickers.exit, 'Exit', exitGatewayDisplay)
            ]),

            // Action button - no initial click handler to avoid dual handlers
            E('div', { 'class': 'nym-action-buttons' }, [
                actionBtn = E('button', {
                    'class': 'nym-btn nym-btn-primary'
                }, 'Connect')
            ])
        ]);

        // --- status updates -----------------------------------------------
        var onStatus = function(ev) {
            var result = ev.status;
            var state = ev.state;

            statusHero.className = 'nym-status-hero ' + state;

            if (state === 'connected') {
                statusLabel.textContent = 'Connected';
                // Re-anchor to the router's elapsed seconds each poll so the
                // timer self-corrects and stays consistent across browsers;
                // falls back to a local count if absent.
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
                // Disconnecting; the error strip shows why, so the label
                // switches to Halted to stop implying progress.
                statusLabel.textContent = result.error_reason ? 'Halted' : 'Disconnecting';
            } else if (result.tunnel_error) {
                // Persistent cue once the toast has faded: the tunnel bounced
                // to Error (e.g. gateway unavailable), not a clean user
                // disconnect.
                statusLabel.textContent = api.isIndependenceError(result.tunnel_error)
                    ? 'Not independent' : 'Gateway unavailable';
                stopUptimeTimer();
            } else {
                statusLabel.textContent = 'Disconnected';
                stopUptimeTimer();
            }

            if (state === 'connected') setAction('disconnect');
            else if (state === 'disconnected') setAction('connect');
            else if (state === 'connecting') setAction('cancel');
            else setAction('wait', 'Disconnecting');

            if (state === 'connected') {
                // Only rebuild the gateway panels and chain when something
                // actually changed — the poll fires every 5s but this data is
                // fixed for the connection's lifetime.
                var hops = store.hops();
                var sig = [result.entry_name, result.entry_id, result.entry_ip, result.entry_country,
                           result.exit_name, result.exit_id, result.exit_ip, result.exit_country,
                           api.familyOf(result, 'entry'), api.familyOf(result, 'exit'),
                           hops].join('|');
                if (sig !== lastConnectedSig) {
                    lastConnectedSig = sig;
                    renderConnectedGateways(result);
                    buildConnectionChain(hops);
                }

                // The pickers are hidden while connected and their saved
                // state now lives on the daemon, so any in-flight prefill is
                // stale and the dirty flag has served its purpose.
                // Deliberately NOT resetting the picker contents here: they
                // sit invisibly under the connection info (grid overlay in
                // theme.js) and blanking them would flash mid-dissolve and
                // change the panel footprint. The disconnect-time restore
                // below re-syncs them from the daemon config regardless.
                pickers.invalidate();
                pickers.settle();
            } else if (state === 'disconnected' || state === 'connecting') {
                // Only clear gateway info when fully disconnected or
                // connecting fresh; keep it visible during 'disconnecting'.
                clearGatewayPanels();
                // Force a fresh render on the next connect.
                lastConnectedSig = null;
                // The tunnel just dropped: refill the pickers from the saved
                // daemon config so reconnecting doesn't force a re-pick of
                // both sides.
                if (ev.becameDisconnected) pickers.restore();
            }

            // Surface tunnel errors (e.g. gateway unavailable) once, when
            // they first appear, so the user knows to switch gateways. The
            // store has already recorded the reason, hence `force`.
            if (ev.newTunnelError) flow.handleTunnelError(result, true);
        };

        // --- initial state --------------------------------------------------
        if (status.state) {
            statusHero.className = 'nym-status-hero ' + status.state;
            statusLabel.textContent = status.state.charAt(0).toUpperCase() + status.state.slice(1);

            if (status.state === 'connected') {
                renderConnectedGateways(status);
                buildConnectionChain(store.hops());
                actionBtn.textContent = 'Disconnect';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.onclick = flow.handleDisconnect;
            } else if (status.state === 'connecting') {
                actionBtn.textContent = 'Cancel';
                actionBtn.className = 'nym-btn nym-btn-danger';
                actionBtn.onclick = flow.handleCancel;
            } else {
                actionBtn.textContent = 'Connect';
                actionBtn.className = 'nym-btn nym-btn-primary';
                actionBtn.onclick = flow.handleConnect;
            }
        } else {
            actionBtn.onclick = flow.handleConnect;
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
            pickers.restore();
        }

        store.on('status', onStatus);

        return statusHero;
    }
});
