'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';
'require nym-vpn.cards.inbound-services as inboundServices';
'require nym-vpn.cards.split-tunneling as splitTunneling';

// Tunnel Settings — the daemon's tunnel switches (IPv6, two-hop,
// circumvention transports, stealth API, gateway independence, family
// reminders, always-on watchdog, legacy split tunnelling, kill-switch), with
// the Inbound Services and Split Tunneling sections mounted underneath.

var E = dom.create.bind(dom);

var WATCHDOG_INTERVALS = [
    { value: '1', label: '1s' },
    { value: '5', label: '5s' },
    { value: '15', label: '15s' },
    { value: '30', label: '30s' },
    { value: '60', label: '60s' },
    { value: '120', label: '2m' }
];

return baseclass.extend({
    render: function(store, api) {
        var tunnel_config = store.data.tunnel_config;
        var watchdog = store.data.watchdog;

        var ipv6El, twoHopEl, killswitchEl, circumventionEl, legacySplitEl, stealthApiEl;
        var killswitchRow, killswitchWarn, inboundMount, splitMount;

        // Save all tunnel toggles immediately.
        var saveTunnelSettings = function() {
            if (!ipv6El || !twoHopEl || !killswitchEl || !circumventionEl) return;

            var ipv6 = ipv6El.checked ? 'on' : 'off';
            var two_hop = twoHopEl.checked ? 'on' : 'off';
            var legacy_split_tunnel = legacySplitEl && legacySplitEl.checked ? 'on' : 'off';
            // Legacy split tunneling and the kill-switch are mutually
            // exclusive. When legacy mode is on the daemon forces the
            // kill-switch off anyway, but send 'off' so the stored value and
            // the (greyed) toggle agree.
            var killswitch = (legacy_split_tunnel === 'on') ? 'off' : (killswitchEl.checked ? 'on' : 'off');
            var circumvention = circumventionEl.checked ? 'on' : 'off';
            var stealth_api = stealthApiEl && stealthApiEl.checked ? 'on' : 'off';

            api.tunnelSet({
                ipv6: ipv6, two_hop: two_hop, killswitch: killswitch,
                circumvention: circumvention, legacy_split_tunnel: legacy_split_tunnel, stealth_api: stealth_api
            }).then(function(result) {
                if (result && result.success) {
                    store.setTwoHop(two_hop === 'on');
                    toast.show('Tunnel settings saved', 'success');
                } else {
                    toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                toast.show('Error: ' + err.message, 'error');
            });
        };

        // --- plain daemon switches ---------------------------------------
        var ipv6Row = toggle.row({
            id: 'ipv6-toggle',
            title: 'IPv6',
            desc: 'Enable IPv6 connectivity through the tunnel',
            checked: tunnel_config.ipv6 === 'on',
            onChange: saveTunnelSettings
        });
        ipv6El = ipv6Row.querySelector('input');

        var twoHopRow = toggle.row({
            id: 'two-hop-toggle',
            title: 'Two-Hop Mode',
            desc: 'Use faster 2-hop routing instead of full mixnet (less private)',
            checked: tunnel_config.two_hop === 'on',
            onChange: saveTunnelSettings
        });
        twoHopEl = twoHopRow.querySelector('input');

        var circumventionRow = toggle.row({
            id: 'circumvention-toggle',
            title: 'Circumvention Transports',
            desc: 'Wrap the entry gateway connection in a QUIC transport to evade censorship. Applies to two-hop mode.',
            checked: tunnel_config.circumvention_transports === 'on',
            onChange: function(ev) {
                // The gateway picker gates entry gateways on this while the
                // list is built, so it follows the switch, saved or not.
                store.setCircumvention(ev.target.checked);
                saveTunnelSettings();
            }
        });
        circumventionEl = circumventionRow.querySelector('input');

        var stealthRow = toggle.row({
            id: 'stealth-api-toggle',
            title: 'Stealth API Connect',
            desc: 'Reach the Nym API through cover domains on every request, not only after a direct request fails. Helps where the API is blocked; API calls get slower. Applies immediately, no reconnect.',
            // The daemon reports whether the network environment publishes
            // cover domains at all; without them the toggle has nothing to
            // route through.
            extra: [E('div', {
                'class': 'nym-toggle-warning',
                'style': 'color: #e67e22; font-size: 11px; margin-top: 4px; display: ' + (tunnel_config.stealth_api_note ? 'block' : 'none')
            }, 'The current network environment publishes no cover domains, so this setting has no effect right now.')],
            checked: tunnel_config.stealth_api === 'on',
            onChange: saveTunnelSettings
        });
        stealthApiEl = stealthRow.querySelector('input');

        // --- gateway independence ----------------------------------------
        // Both switches ride on tunnel_set with only the changed key
        // present, so the daemon leaves the other alone; a failed save
        // reverts the switch. Independence itself applies on the next
        // connect; reminders are consulted by the connect flow before each
        // connect, so they take effect at once.
        var independenceSaver = function(key) {
            return toggle.saver({
                save: function(enabled) { return api.independenceSet(key, enabled); },
                onSuccess: function(enabled) {
                    var ind = { enabled: store.independence.enabled, notifications: store.independence.notifications };
                    ind[key] = enabled;
                    store.setIndependence(ind);
                    toast.show(key === 'enabled'
                        ? 'Gateway independence ' + (enabled ? 'enabled' : 'disabled') + ' — applies on reconnect'
                        : 'Server family reminders ' + (enabled ? 'enabled' : 'disabled'), 'success');
                }
            });
        };

        var independenceNote = E('div', {
            'class': 'nym-toggle-warning',
            'id': 'gw-independence-note',
            'style': 'color: #e67e22; font-size: 11px; margin-top: 4px; display: none'
        }, 'The installed daemon does not report gateway independence; these switches have no effect until it is updated.');

        var independenceRow = toggle.row({
            rowId: 'gw-independence-row',
            id: 'gw-independence-toggle',
            title: 'Gateway Independence',
            desc: 'Entry and exit must be run by different operators, in different networks and subnets. Requires reconnect.',
            // Shown only when a real tunnel_get reply lacks the field, i.e.
            // the daemon predates the feature.
            extra: [independenceNote],
            checked: store.independence.enabled,
            onChange: independenceSaver('enabled')
        });
        var remindersRow = toggle.row({
            rowId: 'family-reminders-row',
            id: 'family-reminders-toggle',
            title: 'Server Family Reminders',
            desc: 'Warn before connecting when the chosen entry and exit are in the same operator family. Off, the connection goes ahead with independence relaxed and a notice is shown instead. Applies immediately.',
            checked: store.independence.notifications,
            onChange: independenceSaver('notifications')
        });
        var independenceEl = independenceRow.querySelector('input');
        var remindersEl = remindersRow.querySelector('input');

        // Sync the independence switches from a tunnel_get reply. Called
        // when the init batch did not carry the field: an older bridge
        // answers without it, in which case the switches are greyed out
        // rather than left pretending. A degraded reply (daemon unreachable,
        // every field '') proves nothing, so it changes nothing.
        var applyIndependenceConfig = function(cfg) {
            var ind = api.readIndependence(cfg && cfg.gateway_independence);
            if (ind) {
                store.setIndependence(ind);
                independenceEl.checked = ind.enabled;
                independenceEl.disabled = false;
                remindersEl.checked = ind.notifications;
                remindersEl.disabled = false;
                independenceRow.style.opacity = '';
                remindersRow.style.opacity = '';
                independenceNote.style.display = 'none';
                return;
            }
            if (!store.independenceKnown && api.isRealTunnelReply(cfg)) {
                independenceEl.disabled = true;
                remindersEl.disabled = true;
                independenceRow.style.opacity = '0.5';
                remindersRow.style.opacity = '0.5';
                independenceNote.style.display = 'block';
            }
        };

        // --- always on ----------------------------------------------------
        var alwaysOnStatus = E('div', {
            'class': 'nym-toggle-status',
            'id': 'always-on-status',
            'style': 'font-size: 11px; margin-top: 4px; color: ' + (watchdog.always_on ? '#27ae60' : '#888')
        }, watchdog.always_on ? 'Watchdog active' + (watchdog.failures > 0 ? ' (' + watchdog.failures + ' recovery attempts)' : '') : 'Disabled');

        var currentInterval = (watchdog.interval || 30).toString();
        var intervalRow;
        var alwaysOnEl;
        var pills = WATCHDOG_INTERVALS.map(function(opt) {
            return E('button', {
                'class': 'nym-pill' + (opt.value === currentInterval ? ' active' : ''),
                'data-value': opt.value,
                'click': function(ev) {
                    ev.preventDefault();
                    intervalRow.querySelectorAll('.nym-pill').forEach(function(p) { p.classList.remove('active'); });
                    ev.target.classList.add('active');
                    var isEnabled = alwaysOnEl.checked;
                    api.watchdogSet(isEnabled ? 1 : 0, parseInt(opt.value)).then(function(result) {
                        if (result && result.success) {
                            toast.show('Check interval set to ' + opt.label, 'success');
                        } else {
                            toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                        }
                    });
                }
            }, opt.label);
        });
        intervalRow = E('div', {
            'id': 'watchdog-interval-row',
            'class': 'nym-interval-row',
            'style': 'display: ' + (watchdog.always_on ? 'flex' : 'none') + '; width: 100%; align-items: center; gap: 10px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-color)'
        }, [
            E('span', { 'style': 'font-size: 12px; color: var(--text-muted)' }, 'Check every:'),
            E('div', { 'class': 'nym-pill-group' }, pills)
        ]);

        var alwaysOnRow = toggle.row({
            rowStyle: 'flex-wrap: wrap',
            id: 'always-on-toggle',
            title: 'Always On',
            desc: 'Automatically reconnect when the VPN tunnel drops. Uses escalating recovery with daemon restart as fallback.',
            extra: [alwaysOnStatus],
            after: [intervalRow],
            checked: !!watchdog.always_on,
            onChange: toggle.saver({
                disableWhileSaving: true,
                save: function(enabled) {
                    var interval = null;
                    var activeBtn = intervalRow.querySelector('.nym-pill.active');
                    if (activeBtn) interval = parseInt(activeBtn.dataset.value);
                    return api.watchdogSet(enabled ? 1 : 0, interval);
                },
                onSuccess: function(enabled) {
                    toast.show('Always-on ' + (enabled ? 'enabled' : 'disabled'), 'success');
                    alwaysOnStatus.textContent = enabled ? 'Watchdog active' : 'Disabled';
                    alwaysOnStatus.style.color = enabled ? '#27ae60' : '#888';
                    intervalRow.style.display = enabled ? 'flex' : 'none';
                }
            })
        });
        alwaysOnEl = alwaysOnRow.querySelector('input');

        // --- legacy split tunnelling / kill-switch ------------------------
        var legacyOn = tunnel_config.legacy_split_tunnel === 'on';
        var killswitchOn = tunnel_config.killswitch !== 'off';

        var legacyRow = toggle.row({
            id: 'legacy-split-toggle',
            title: 'Legacy Split Tunneling (PBR)',
            desc: 'Hand routing to luci-app-pbr: only the traffic you select in PBR is sent through the VPN, everything else uses the normal WAN in the clear. Mutually exclusive with the kill-switch and the exclusion list below. Requires reconnect.',
            checked: legacyOn,
            onChange: function(ev) {
                var on = ev.target.checked;
                if (killswitchEl) {
                    killswitchEl.disabled = on;
                    if (on) killswitchEl.checked = false;
                    if (killswitchWarn) killswitchWarn.style.display = (on || killswitchEl.checked) ? 'none' : 'block';
                }
                if (killswitchRow) killswitchRow.style.opacity = on ? '0.5' : '';
                if (inboundMount) inboundMount.style.display = (!on && killswitchEl && killswitchEl.checked) ? 'block' : 'none';
                if (splitMount) splitMount.style.display = on ? 'none' : 'block';
                saveTunnelSettings();
            }
        });
        legacySplitEl = legacyRow.querySelector('input');

        killswitchWarn = E('div', {
            'class': 'nym-toggle-warning',
            'style': 'color: #e67e22; font-size: 11px; margin-top: 4px; display: ' + (tunnel_config.killswitch === 'on' ? 'none' : 'block')
        }, 'Warning: Traffic may leak outside the VPN when disabled. Requires reconnect.');

        killswitchRow = toggle.row({
            rowId: 'killswitch-row',
            rowStyle: legacyOn ? 'opacity: 0.5' : null,
            id: 'killswitch-toggle',
            title: 'Kill-Switch',
            desc: 'Block LAN clients from reaching the internet unless the VPN is connected.',
            extra: [killswitchWarn],
            checked: killswitchOn,
            disabled: legacyOn,
            onChange: function(ev) {
                if (killswitchWarn) killswitchWarn.style.display = ev.target.checked ? 'none' : 'block';
                if (inboundMount) inboundMount.style.display = ev.target.checked ? 'block' : 'none';
                saveTunnelSettings();
            }
        });
        killswitchEl = killswitchRow.querySelector('input');

        // --- sections under the switches ----------------------------------
        // Inbound exemptions only matter while the kill-switch is on; the
        // exclusion list is replaced by PBR under legacy split tunnelling.
        inboundMount = inboundServices.render(store, api);
        inboundMount.style.display = (killswitchOn && !legacyOn) ? 'block' : 'none';
        splitMount = splitTunneling.render(store, api);
        splitMount.style.display = legacyOn ? 'none' : 'block';

        var el = card.create({
            icon: assets.iconTunnel,
            title: 'Tunnel Settings',
            body: [
                E('div', {}, [
                    ipv6Row,
                    twoHopRow,
                    circumventionRow,
                    stealthRow,
                    independenceRow,
                    remindersRow,
                    alwaysOnRow,
                    legacyRow,
                    killswitchRow
                ]),
                inboundMount,
                splitMount
            ]
        }).el;

        // The init batch may predate the independence field; one tunnel_get
        // settles whether the daemon has it (and its current values).
        if (!store.independenceKnown) {
            api.tunnelGet().then(applyIndependenceConfig).catch(function() {});
        }

        return el;
    }
});
