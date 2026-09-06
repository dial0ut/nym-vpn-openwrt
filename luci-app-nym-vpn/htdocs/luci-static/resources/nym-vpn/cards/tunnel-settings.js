'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';
'require nym-vpn.flows.tunnel as tunnelFlow';
'require nym-vpn.cards.inbound-services as inboundServices';

// Tunnel Settings — the daemon's tunnel switches in three groups:
//
//   Protection  kill-switch (first: it decides whether anything leaks),
//               with its inbound-service exceptions nested beneath it,
//               then gateway independence, the family reminders and the
//               always-on watchdog with its check interval
//   Transport   two-hop, circumvention transports, stealth API, IPv6
//
// Each row states what the switch does in one clause; the full explanation
// sits behind the row's (i) button (components/details via toggle.row's
// `more`), with a Learn more link into the LuCI guide. Switches that only
// apply on the next connect carry a 'reconnect' tag. The legacy PBR switch
// lives in the Split Tunneling card; its effect on the kill-switch arrives
// through the store's 'tunnel-switch' event.

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
        var switches = store.tunnelSwitches;

        // Every switch saves at once; the flow re-sends the full set.
        var saveSwitch = function(key) {
            return function(ev) { tunnelFlow.setSwitch(store, api, key, ev.target.checked); };
        };

        // --- protection: kill-switch ----------------------------------------
        var legacyOn = switches.legacy_split_tunnel;
        var killswitchOn = switches.killswitch;

        var killswitchWarn = E('div', {
            'class': 'nym-toggle-warning',
            'style': 'display: ' + (killswitchOn ? 'none' : 'block')
        }, 'Off: LAN traffic can leave the router outside the VPN whenever the tunnel is down.');

        var killswitchRow = toggle.row({
            rowId: 'killswitch-row',
            rowStyle: legacyOn ? 'opacity: 0.5' : null,
            id: 'killswitch-toggle',
            title: 'Kill-Switch',
            tag: 'reconnect',
            desc: 'Blocks all traffic outside the tunnel.',
            more: 'A firewall block only: traffic is routed into the tunnel whenever connected regardless of this setting. Off, LAN traffic falls back to the WAN in the clear while the tunnel is down. Split-tunnel exclusions work with it on. Greyed while the legacy PBR switch owns the routing.',
            docs: 'kill-switch',
            extra: [killswitchWarn],
            checked: killswitchOn,
            disabled: legacyOn,
            onChange: saveSwitch('killswitch')
        });
        var killswitchEl = killswitchRow.querySelector('input');

        // The exceptions to the block, nested under the switch they belong
        // to; shown only while there is a block to be exempt from.
        var inboundMount = inboundServices.render(store, api);
        inboundMount.classList.add('nym-subpanel');

        // Reflect the store: the kill-switch is greyed and forced off while
        // legacy split tunnelling (Split Tunneling card) owns the routing.
        var syncProtection = function() {
            var legacy = switches.legacy_split_tunnel;
            var ks = switches.killswitch && !legacy;
            killswitchEl.disabled = legacy;
            killswitchEl.checked = ks;
            killswitchRow.style.opacity = legacy ? '0.5' : '';
            killswitchWarn.style.display = (legacy || ks) ? 'none' : 'block';
            inboundMount.style.display = ks ? 'block' : 'none';
        };
        syncProtection();
        store.on('tunnel-switch', syncProtection);

        // --- protection: gateway independence ------------------------------
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
            'style': 'display: none'
        }, 'The installed daemon does not report gateway independence; these switches have no effect until it is updated.');

        var independenceRow = toggle.row({
            rowId: 'gw-independence-row',
            id: 'gw-independence-toggle',
            title: 'Gateway Independence',
            tag: 'reconnect',
            desc: 'Requires entry and exit from different operators.',
            more: 'Entry and exit must be run by different operators (node families), in different networks (ASNs) and different subnets, so no single operator sees both ends of the tunnel. On by default; the daemon refuses a pair that fails. Off allows any combination.',
            docs: 'gateway-independence',
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
            desc: 'Warns before connecting through one operator family.',
            more: 'Before connecting, the page asks the daemon which entry/exit pair your selection resolves to. If they share an operator family you can connect anyway (criteria relaxed for that connection only) or change servers. Off, the connection goes ahead relaxed and a notice says so.',
            docs: 'server-family-reminders',
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

        // --- transport ------------------------------------------------------
        var twoHopRow = toggle.row({
            id: 'two-hop-toggle',
            title: 'Two-Hop Mode',
            tag: 'reconnect',
            desc: 'Faster 2-hop WireGuard instead of the 5-hop mixnet.',
            more: '2-hop WireGuard skips the mixnet: no per-hop delays or cover traffic, so it is much faster but offers weaker protection against traffic analysis. The two hops still hide your address from the exit.',
            docs: 'two-hop-mode',
            checked: switches.two_hop,
            onChange: saveSwitch('two_hop')
        });

        var circumventionRow = toggle.row({
            id: 'circumvention-toggle',
            title: 'Circumvention Transports',
            tag: 'reconnect',
            desc: 'Wraps the entry connection to get past censorship.',
            more: 'Wraps the entry gateway connection in a QUIC transport. Two-hop mode only. While on, entry gateways that cannot carry it are greyed in the picker with a No CT tag and cannot be selected.',
            docs: 'circumvention-transports',
            checked: switches.circumvention,
            onChange: saveSwitch('circumvention')
        });

        var stealthRow = toggle.row({
            id: 'stealth-api-toggle',
            title: 'Stealth API Connect',
            desc: 'Reaches the Nym API through cover domains.',
            more: 'The daemon normally reaches the Nym API (account, gateway directory, discovery) directly and only falls back to cover domains — domain fronting through a CDN — when a direct request fails. On, every API request goes through them from the start. Use it where the API hosts are blocked; API calls get slower. Applies at once.',
            docs: 'stealth-api-connect',
            // The daemon reports whether the network environment publishes
            // cover domains at all; without them the toggle has nothing to
            // route through.
            extra: [E('div', {
                'class': 'nym-toggle-warning',
                'style': 'display: ' + (tunnel_config.stealth_api_note ? 'block' : 'none')
            }, 'The current network environment publishes no cover domains, so this setting has no effect right now.')],
            checked: switches.stealth_api,
            onChange: saveSwitch('stealth_api')
        });

        var ipv6Row = toggle.row({
            id: 'ipv6-toggle',
            title: 'IPv6',
            tag: 'reconnect',
            desc: 'Routes IPv6 through the tunnel.',
            more: 'Off by default: most exit gateways have no IPv6 egress, and IPv6 that is tunnelled and then dropped makes dual-stack clients stall on every new connection. Turn it on only if your exit demonstrably carries IPv6.',
            docs: 'ipv6',
            checked: switches.ipv6,
            onChange: saveSwitch('ipv6')
        });

        // --- protection: always on -------------------------------------------
        var alwaysOnStatus = E('div', {
            'class': 'nym-toggle-status' + (watchdog.always_on ? ' active' : ''),
            'id': 'always-on-status'
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
            'style': 'display: ' + (watchdog.always_on ? 'flex' : 'none')
        }, [
            E('span', { 'class': 'nym-interval-label' }, 'Check every'),
            E('div', { 'class': 'nym-pill-group' }, pills)
        ]);

        var alwaysOnRow = toggle.row({
            rowStyle: 'flex-wrap: wrap',
            id: 'always-on-toggle',
            title: 'Always On',
            desc: 'Reconnects when the tunnel drops.',
            more: 'A watchdog: soft reconnects first, then a daemon restart with growing backoff. It checks at the chosen interval and is also woken by WAN link events, so the tunnel is re-checked as soon as the WAN comes back. Its log lines are tagged nym-watchdog.',
            docs: 'always-on',
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
                    alwaysOnStatus.className = 'nym-toggle-status' + (enabled ? ' active' : '');
                    intervalRow.style.display = enabled ? 'flex' : 'none';
                }
            })
        });
        alwaysOnEl = alwaysOnRow.querySelector('input');

        var el = card.create({
            icon: assets.iconTunnel,
            title: 'Tunnel Settings',
            body: [
                card.group({
                    title: 'Protection',
                    body: [
                        E('div', { 'class': 'nym-row-with-sub' }, [killswitchRow, inboundMount]),
                        independenceRow,
                        remindersRow,
                        alwaysOnRow
                    ]
                }),
                card.group({
                    title: 'Transport',
                    body: [twoHopRow, circumventionRow, stealthRow, ipv6Row]
                })
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
