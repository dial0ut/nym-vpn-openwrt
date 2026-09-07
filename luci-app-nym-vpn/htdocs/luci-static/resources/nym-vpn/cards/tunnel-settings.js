'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';
'require nym-vpn.flows.tunnel as tunnelFlow';
'require nym-vpn.flows.connect as connectFlow';
'require nym-vpn.cards.inbound-services as inboundServices';

// Tunnel Settings — the daemon's tunnel switches in three groups:
//
//   Protection  Always On first (whose status line follows the daemon's
//               supervisor), then the kill-switch with its inbound-service
//               exceptions nested beneath it, gateway independence and the
//               family reminders
//   Transport   two-hop, circumvention transports, stealth API, IPv6
//
// Each row states what the switch does in one clause; the full explanation
// sits behind the row's (i) button (components/details via toggle.row's
// `more`), with a Learn more link into the LuCI guide. Switches that only
// apply on the next connect carry a 'reconnect' tag. The legacy PBR switch
// lives in the Split Tunneling card; its effect on the kill-switch arrives
// through the store's 'tunnel-switch' event.

var E = dom.create.bind(dom);

// Copy for the terminal errors Always On latches on, keyed by the daemon's
// error ident (status.always_on.latched). Account errors reuse the connect
// flow's headings so the strip and this line agree.
var LATCHED_COPY = {
    NeedsRelaxedIndependenceCriteria: connectFlow.INDEPENDENCE_ERROR_COPY,
    SameEntryAndExitGateway: 'Entry and exit are the same gateway',
    InvalidEntryGatewayIdentity: 'The pinned entry gateway is not available',
    InvalidExitGatewayIdentity: 'The pinned exit gateway is not available',
    InvalidEntryGatewayCountry: 'No entry gateway in the selected country',
    InvalidExitGatewayCountry: 'No exit gateway in the selected country',
    Ipv6Unavailable: 'IPv6 is unavailable on this router',
    InactiveAccount: connectFlow.ERROR_COPY.account_status_not_active.heading,
    InactiveSubscription: connectFlow.ERROR_COPY.inactive_subscription.heading,
    MaxDevicesReached: connectFlow.ERROR_COPY.max_device_reached.heading,
    DeviceLoggedOut: connectFlow.ERROR_COPY.logged_out.heading
};

// The status line under the Always On row, from the bridge's
// status.always_on (see rpcd always_on_json) and the tunnel state. `on` is
// the switch as the page shows it, for when the status carries no
// supervisor view (older daemon, daemon unreachable).
// Returns {text, active}.
function alwaysOnStatus(status, on) {
    var ao = status && status.always_on;
    if (!ao) return { text: on ? 'Active' : 'Off', active: on };
    if (!ao.enabled) return { text: 'Off', active: false };
    if (ao.paused) return { text: 'Paused — disconnected by you', active: false };
    if (ao.latched) {
        return { text: 'Stopped: ' + (LATCHED_COPY[ao.latched] || ao.latched) + ' — fix and connect', active: false };
    }
    if (ao.next_retry_secs !== null && ao.next_retry_secs !== undefined) {
        return { text: 'Retrying in ' + ao.next_retry_secs + ' s (attempt ' + ao.attempt + ')', active: false };
    }
    if (status.state === 'offline') return { text: 'Waiting for network', active: false };
    return { text: 'Active', active: true };
}

return baseclass.extend({
    alwaysOnStatus: alwaysOnStatus,

    render: function(store, api) {
        var tunnel_config = store.data.tunnel_config;
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
        // A plain tunnel switch: the daemon persists it and does the work
        // (connect at start once a default route exists, retry error states,
        // pause on a user disconnect). The line under the row shows what its
        // supervisor is doing, refreshed by the 5 s status poll.
        var alwaysOnLine = E('div', { 'class': 'nym-toggle-status', 'id': 'always-on-status' });
        var syncAlwaysOn = function(status) {
            var view = alwaysOnStatus(status, switches.always_on);
            alwaysOnLine.textContent = view.text;
            alwaysOnLine.className = 'nym-toggle-status' + (view.active ? ' active' : '');
        };
        syncAlwaysOn(store.status);
        store.on('status', function(ev) { syncAlwaysOn(ev.status); });
        // The switch just moved: say so at once rather than after the next
        // poll, ignoring a stale supervisor view.
        store.on('tunnel-switch', function(ev) {
            if (ev.key === 'always_on') syncAlwaysOn(null);
        });

        var alwaysOnRow = toggle.row({
            id: 'always-on-toggle',
            title: 'Always On',
            desc: 'Keeps the tunnel up while the router is on.',
            more: 'The daemon connects when it starts — waiting for a default route rather than polling for one — reconnects after drops and WAN outages, retries error states with growing backoff (moving off gateways that keep failing) and re-selects gateways if a connect drags on. Disconnecting pauses it until you connect again or the router reboots; the setting stays on. Terminal errors (account, an impossible gateway pair) stop the retries until you change something. Log lines are tagged always-on in the daemon log.',
            docs: 'always-on',
            extra: [alwaysOnLine],
            checked: switches.always_on,
            onChange: saveSwitch('always_on')
        });

        var el = card.create({
            icon: assets.iconTunnel,
            title: 'Tunnel Settings',
            body: [
                card.group({
                    title: 'Protection',
                    body: [
                        alwaysOnRow,
                        E('div', { 'class': 'nym-row-with-sub' }, [killswitchRow, inboundMount]),
                        independenceRow,
                        remindersRow
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
