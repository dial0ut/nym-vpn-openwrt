'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.select as select';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';
'require nym-vpn.flows.tunnel as tunnelFlow';

// Split Tunneling — the two ways of sending some traffic around the VPN.
//
// Exclusions (the built-in way): specific devices or domains go straight to
// the WAN, everything else stays in the tunnel and the kill-switch keeps
// covering it. Marked with fwmark 0x14e and stored in UCI independently of
// the kill-switch. An entry routed via the mixnet instead (fwmark 0x14f)
// goes through the dual tunnel's mixnet side, which the bridge switches on
// while such an entry exists. See docs/guide/split-tunneling.md,
// docs/guide/dual-tunnel.md and split_* in the rpcd bridge.
//
// Policy-based routing (legacy): routing is handed to luci-app-pbr; only
// the traffic PBR selects goes through the VPN. It is mutually exclusive
// with the kill-switch and the exclusion list, so switching it on greys the
// kill-switch in Tunnel Settings (through the store's 'tunnel-switch'
// event) and hides the exclusions here.

var E = dom.create.bind(dom);

// The bridge replies {success: false, saved: true, error} when the change
// reached UCI but the firewall or dnsmasq did not take it: the list follows
// what is stored and the toast carries the error.
var stored = function(result) {
    return !!(result && (result.success || result.saved));
};

// An entry's route: the bridge's `via`.
var ROUTES = [
    { via: 'wan', label: 'Bypass VPN' },
    { via: 'mixnet', label: 'Mixnet' }
];

var viaOf = function(ex) { return ex.via === 'mixnet' ? 'mixnet' : 'wan'; };

var isOn = function(ex) {
    return ex.enabled !== false && ex.enabled !== 0 && ex.enabled !== '0';
};

var routeSelect = function(attrs, via) {
    return select.create(attrs, ROUTES.map(function(r) {
        return { value: r.via, label: r.label, selected: r.via === via };
    }));
};

// What the mixnet routes have right now, from the live status.
var mixnetRouteNote = function(status) {
    var st = status || {};
    var side = st.side_tunnel;
    if (!st.connected)
        return { warn: true, text: 'Mixnet routes have no connection while the VPN is disconnected.' };
    if (st.mode === 'mixnet')
        return { warn: false, text: 'Mixnet mode: all traffic already goes through the mixnet.' };
    if (side && side.state === 'up') {
        var exit = side.exit && (side.exit.name || side.exit.country);
        return { warn: false, text: 'Mixnet tunnel up' + (exit ? ', exiting via ' + exit : '') + '.' };
    }
    if (side && side.state === 'connecting') {
        var retry = side.retry_attempt ? ' (retry ' + side.retry_attempt + ')' : '';
        return { warn: true, text: 'Mixnet tunnel connecting' + retry + '. Mixnet routes have no connection until it is up.' };
    }
    return { warn: true, text: 'The mixnet tunnel is not running; mixnet routes have no connection.' };
};

return baseclass.extend({
    // The exclusion list plus the add-device / add-domain forms. Returns the
    // section element (.nym-split-section); the card controls its
    // visibility.
    renderExclusions: function(store, api) {
        var state = store.data.split_exclusions.slice();
        var clients = store.data.clients;
        var nftsetSupported = !!store.data.split_status.nftset_supported;

        var valueOf = function(ex) {
            if (ex.type === 'domain') return ex.domain || '—';
            var c = clients.filter(function(x) { return x.mac === ex.mac; })[0];
            if (c && c.hostname) return c.hostname + ' (' + ex.mac + ')';
            return ex.mac || '—';
        };

        var listEl = E('div', { 'class': 'nym-exemption-table' });
        var clientSel, clientRoute, clientLabel, clientSave;
        var domainInp, domainRoute, domainLabel, domainSave;

        var mixnetNote = E('div', { 'class': 'nym-note', 'id': 'nym-split-mixnet-note' });
        var updateMixnetNote = function() {
            var routed = state.some(function(ex) { return isOn(ex) && viaOf(ex) === 'mixnet'; });
            mixnetNote.style.display = routed ? 'block' : 'none';
            if (!routed) return;
            var note = mixnetRouteNote(store.status);
            mixnetNote.className = 'nym-note' + (note.warn ? ' nym-note-warn' : '');
            mixnetNote.textContent = note.text;
        };
        store.on('status', updateMixnetNote);

        var renderRow = function(ex) {
            var on = isOn(ex);
            return E('div', {
                'class': 'nym-split-row' + (on ? '' : ' inert'),
                'data-id': ex.id
            }, [
                E('div', { 'class': 'nym-exemption-proto' }, ex.type === 'domain' ? 'DOMAIN' : 'DEVICE'),
                // UCI values and lease hostnames: text, never markup.
                E('div', { 'class': 'nym-exemption-label' }, [String(valueOf(ex))]),
                routeSelect({
                    'class': 'nym-select nym-split-via',
                    'title': 'Route',
                    'change': function(ev) { setVia(ex, ev.target.value); }
                }, viaOf(ex)),
                E('div', { 'class': 'nym-exemption-label' }, [String(ex.label || '—')]),
                E('label', { 'class': 'nym-toggle nym-toggle-sm', 'title': on ? 'Enabled' : 'Disabled' }, [
                    E('input', {
                        'type': 'checkbox',
                        'checked': on ? 'checked' : null,
                        'change': function(ev) { setEnabled(ex, ev.target.checked); }
                    }),
                    E('span', { 'class': 'nym-toggle-slider' })
                ]),
                E('div', {
                    'class': 'nym-exemption-delete',
                    'title': 'Remove',
                    'click': function() { remove(ex); }
                }, '×')
            ]);
        };

        var redraw = function() {
            listEl.innerHTML = '';
            // The hero greys the mixnet pins in the Fast picker while a
            // mixnet route exists.
            store.data.split_exclusions = state;
            store.emit('split', state);
            updateMixnetNote();
            if (state.length === 0) {
                listEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'No exclusions yet. Add a device or domain below.'));
                return;
            }
            listEl.appendChild(E('div', { 'class': 'nym-split-header' }, [
                E('div', {}, 'Type'),
                E('div', {}, 'Device / Domain'),
                E('div', {}, 'Route'),
                E('div', {}, 'Label'),
                E('div', {}, 'On'),
                E('div', {}, '')
            ]));
            state.forEach(function(ex) { listEl.appendChild(renderRow(ex)); });
        };

        var remove = function(ex) {
            var row = listEl.querySelector('.nym-split-row[data-id="' + ex.id + '"]');
            if (row) row.classList.add('removing');
            api.splitDel(ex.id).then(function(result) {
                if (stored(result)) {
                    state = state.filter(function(e) { return e.id !== ex.id; });
                    redraw();
                } else if (row) {
                    row.classList.remove('removing');
                }
                if (result && result.success) toast.show('Removed exclusion', 'success');
                else toast.show((result && result.error) || 'Failed to delete', 'error');
            }).catch(function(err) {
                if (row) row.classList.remove('removing');
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var setEnabled = function(ex, enabled) {
            api.splitSetEnabled(ex.id, enabled ? 1 : 0).then(function(result) {
                if (stored(result)) ex.enabled = enabled ? 1 : 0;
                if (!(result && result.success)) toast.show((result && result.error) || 'Failed to update', 'error');
                redraw();
            }).catch(function(err) {
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
                redraw();
            });
        };

        var setVia = function(ex, via) {
            api.splitSetVia(ex.id, via).then(function(result) {
                if (stored(result)) ex.via = via;
                if (!(result && result.success)) toast.show((result && result.error) || 'Failed to update', 'error');
                redraw();
            }).catch(function(err) {
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
                redraw();
            });
        };

        var add = function(kind) {
            var labelInp = kind === 'domain' ? domainLabel : clientLabel;
            var saveBtn = kind === 'domain' ? domainSave : clientSave;
            var routeSel = kind === 'domain' ? domainRoute : clientRoute;
            var via = routeSel && routeSel.value === 'mixnet' ? 'mixnet' : 'wan';
            var label = (labelInp && labelInp.value || '').trim();
            if (label.length > 64) { toast.show('Label too long (max 64 characters)', 'error'); return; }

            var mac = '', domain = '';
            if (kind === 'domain') {
                domain = (domainInp && domainInp.value || '').trim().toLowerCase();
                if (!domain) { toast.show('Domain is required', 'error'); return; }
                if (state.some(function(e) { return e.type === 'domain' && e.domain === domain; })) {
                    toast.show(domain + ' is already in the list', 'error'); return;
                }
            } else {
                mac = clientSel && clientSel.value || '';
                if (!mac) { toast.show('Select a device', 'error'); return; }
                if (state.some(function(e) { return e.type === 'client' && e.mac === mac; })) {
                    toast.show('That device is already in the list', 'error'); return;
                }
            }

            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<span class="nym-btn-spinner"></span>Saving';
            }
            api.splitAdd(kind, mac, domain, label || '', via).then(function(result) {
                if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Add'; }
                if (stored(result)) {
                    var ex = { id: result.id, type: kind, enabled: 1, via: via };
                    if (kind === 'domain') ex.domain = domain; else ex.mac = mac;
                    if (label) ex.label = label;
                    state.push(ex);
                    redraw();
                    if (kind === 'domain' && domainInp) domainInp.value = '';
                    if (labelInp) labelInp.value = '';
                }
                if (result && result.success) toast.show(via === 'mixnet' ? 'Added mixnet route' : 'Added exclusion', 'success');
                else toast.show((result && result.error) || 'Failed to add exclusion', 'error');
            }).catch(function(err) {
                if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Add'; }
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var domainKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); add('domain'); }
        };

        // Device dropdown options from current DHCP leases.
        var clientOptions = [E('option', { 'value': '' }, clients.length ? 'Select a device…' : 'No DHCP leases found')];
        clients.forEach(function(c) {
            var name = (c.hostname ? c.hostname + ' — ' : '') + (c.ip ? c.ip + ' — ' : '') + c.mac;
            clientOptions.push(E('option', { 'value': c.mac }, [name]));
        });

        clientSel = E('select', { 'class': 'nym-select', 'id': 'nym-split-client', 'style': 'flex: 2' }, clientOptions);
        clientRoute = routeSelect({ 'id': 'nym-split-client-route', 'title': 'Route' }, 'wan');
        clientLabel = E('input', {
            'type': 'text', 'class': 'nym-input', 'id': 'nym-split-client-label',
            'placeholder': 'Label (optional)', 'maxlength': '64'
        });
        clientSave = E('button', {
            'class': 'nym-btn nym-btn-primary', 'id': 'nym-split-client-save',
            'click': function() { add('client'); }
        }, 'Add');

        // Domain add row — replaced by a hint when dnsmasq lacks nftset
        // support.
        var domainAddRow;
        if (nftsetSupported) {
            domainInp = E('input', {
                'type': 'text', 'class': 'nym-input', 'id': 'nym-split-domain',
                'placeholder': 'example.com', 'maxlength': '253', 'keydown': domainKeydown
            });
            domainRoute = routeSelect({ 'id': 'nym-split-domain-route', 'title': 'Route' }, 'wan');
            domainLabel = E('input', {
                'type': 'text', 'class': 'nym-input', 'id': 'nym-split-domain-label',
                'placeholder': 'Label (optional)', 'maxlength': '64', 'keydown': domainKeydown
            });
            domainSave = E('button', {
                'class': 'nym-btn nym-btn-primary', 'id': 'nym-split-domain-save',
                'click': function() { add('domain'); }
            }, 'Add');
            domainAddRow = E('div', { 'class': 'nym-exemption-addrow' }, [domainInp, domainRoute, domainLabel, domainSave]);
        } else {
            domainAddRow = E('div', { 'class': 'nym-note nym-note-warn' },
                'Domain exclusions need dnsmasq-full (built with nftset support): ' +
                'opkg install dnsmasq-full');
        }

        var section = E('div', { 'class': 'nym-split-section' }, [
            card.group({
                title: 'Exclusions',
                moreId: 'exclusions',
                more: 'Chosen devices or domains leave the tunnel. Bypass VPN sends them straight to the WAN; everything else stays in the tunnel and the kill-switch keeps covering it. Mixnet sends them through the mixnet while fast mode carries everything else (dual tunnel): they never fall back to the fast tunnel or the WAN, and have no connection until the mixnet tunnel is up. Where routes overlap the mixnet wins, so a bypass domain does not apply to a mixnet device. Devices are matched by MAC address, so they survive an IP change. Domain rules need clients to use this router for DNS. A bypassed device\'s own DNS still goes through the tunnel; a mixnet device\'s goes through the mixnet.',
                docs: 'exclusions',
                body: [
                    mixnetNote,
                    listEl,
                    E('div', { 'class': 'nym-exemption-add' }, [
                        E('div', { 'class': 'nym-form-label' }, 'Add a Device'),
                        E('div', { 'class': 'nym-exemption-addrow' }, [clientSel, clientRoute, clientLabel, clientSave]),
                        E('div', { 'class': 'nym-form-label', 'style': 'margin-top: 14px' }, 'Add a Domain'),
                        domainAddRow
                    ])
                ]
            })
        ]);
        redraw();
        return section;
    },

    render: function(store, api) {
        var legacyOn = store.tunnelSwitches.legacy_split_tunnel;

        var splitMount = this.renderExclusions(store, api);
        splitMount.style.display = legacyOn ? 'none' : 'block';

        // Stands in for the exclusion list while PBR owns the routing.
        var legacyNote = E('div', {
            'class': 'nym-note nym-note-warn',
            'id': 'legacy-split-note',
            'style': 'display: ' + (legacyOn ? 'block' : 'none')
        }, 'Routing is handled by luci-app-pbr. The exclusion list and the kill-switch are off until this is switched back.');

        var legacyRow = toggle.row({
            id: 'legacy-split-toggle',
            title: 'Legacy Split Tunneling (PBR)',
            tag: 'reconnect',
            desc: 'Hands routing to luci-app-pbr.',
            more: 'Only the traffic PBR selects goes through the VPN; everything else uses the WAN in the clear. Mutually exclusive with the kill-switch and the exclusion list: both are off while this is on, and the kill-switch stays off until you turn it back on yourself.',
            docs: 'legacy-split-tunneling-pbr',
            checked: legacyOn,
            onChange: function(ev) {
                var on = ev.target.checked;
                splitMount.style.display = on ? 'none' : 'block';
                legacyNote.style.display = on ? 'block' : 'none';
                tunnelFlow.setSwitch(store, api, 'legacy_split_tunnel', on);
            }
        });

        return card.create({
            icon: assets.iconSplit,
            title: 'Split Tunneling',
            body: [
                legacyNote,
                splitMount,
                card.group({
                    title: 'Policy-based routing',
                    body: [legacyRow]
                })
            ]
        }).el;
    }
});
