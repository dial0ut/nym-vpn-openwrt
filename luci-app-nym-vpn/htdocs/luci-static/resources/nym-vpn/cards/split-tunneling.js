'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';
'require nym-vpn.flows.tunnel as tunnelFlow';

// Split Tunneling — the two ways of sending some traffic around the VPN.
//
// Exclusions (the built-in way): specific devices or domains go straight to
// the WAN, everything else stays in the tunnel and the kill-switch keeps
// covering it. Marked with fwmark 0x14e and stored in UCI independently of
// the kill-switch. See docs/guide/split-tunneling.md and handle_split_* in
// the rpcd bridge.
//
// Policy-based routing (legacy): routing is handed to luci-app-pbr; only
// the traffic PBR selects goes through the VPN. It is mutually exclusive
// with the kill-switch and the exclusion list, so switching it on greys the
// kill-switch in Tunnel Settings (through the store's 'tunnel-switch'
// event) and hides the exclusions here.

var E = dom.create.bind(dom);

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
        var clientSel, clientLabel, clientSave, domainInp, domainLabel, domainSave;

        var renderRow = function(ex) {
            var on = ex.enabled !== false && ex.enabled !== 0 && ex.enabled !== '0';
            return E('div', {
                'class': 'nym-split-row' + (on ? '' : ' inert'),
                'data-id': ex.id
            }, [
                E('div', { 'class': 'nym-exemption-proto' }, ex.type === 'domain' ? 'DOMAIN' : 'DEVICE'),
                E('div', { 'class': 'nym-exemption-label' }, valueOf(ex)),
                E('div', { 'class': 'nym-exemption-label' }, ex.label || '—'),
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
            if (state.length === 0) {
                listEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'No exclusions yet. Add a device or domain below.'));
                return;
            }
            listEl.appendChild(E('div', { 'class': 'nym-split-header' }, [
                E('div', {}, 'Type'),
                E('div', {}, 'Device / Domain'),
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
                if (result && result.success) {
                    state = state.filter(function(e) { return e.id !== ex.id; });
                    redraw();
                    toast.show('Removed exclusion', 'success');
                } else {
                    if (row) row.classList.remove('removing');
                    toast.show((result && result.error) || 'Failed to delete', 'error');
                }
            }).catch(function(err) {
                if (row) row.classList.remove('removing');
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var setEnabled = function(ex, enabled) {
            api.splitSetEnabled(ex.id, enabled ? 1 : 0).then(function(result) {
                if (result && result.success) {
                    ex.enabled = enabled ? 1 : 0;
                    redraw();
                } else {
                    toast.show((result && result.error) || 'Failed to update', 'error');
                    redraw();
                }
            }).catch(function(err) {
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
                redraw();
            });
        };

        var add = function(kind) {
            var labelInp = kind === 'domain' ? domainLabel : clientLabel;
            var saveBtn = kind === 'domain' ? domainSave : clientSave;
            var label = (labelInp && labelInp.value || '').trim();
            if (label.length > 64) { toast.show('Label too long (max 64 characters)', 'error'); return; }

            var mac = '', domain = '';
            if (kind === 'domain') {
                domain = (domainInp && domainInp.value || '').trim().toLowerCase();
                if (!domain) { toast.show('Domain is required', 'error'); return; }
                if (state.some(function(e) { return e.type === 'domain' && e.domain === domain; })) {
                    toast.show(domain + ' is already excluded', 'error'); return;
                }
            } else {
                mac = clientSel && clientSel.value || '';
                if (!mac) { toast.show('Select a device', 'error'); return; }
                if (state.some(function(e) { return e.type === 'client' && e.mac === mac; })) {
                    toast.show('That device is already excluded', 'error'); return;
                }
            }

            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<span class="nym-btn-spinner"></span>Saving';
            }
            api.splitAdd(kind, mac, domain, label || '').then(function(result) {
                if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Add'; }
                if (result && result.success) {
                    var ex = { id: result.id, type: kind, enabled: 1 };
                    if (kind === 'domain') ex.domain = domain; else ex.mac = mac;
                    if (label) ex.label = label;
                    state.push(ex);
                    redraw();
                    if (kind === 'domain' && domainInp) domainInp.value = '';
                    if (labelInp) labelInp.value = '';
                    toast.show('Added exclusion', 'success');
                } else {
                    toast.show((result && result.error) || 'Failed to add exclusion', 'error');
                }
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
            clientOptions.push(E('option', { 'value': c.mac }, name));
        });

        clientSel = E('select', { 'class': 'nym-select', 'id': 'nym-split-client', 'style': 'flex: 2' }, clientOptions);
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
            domainLabel = E('input', {
                'type': 'text', 'class': 'nym-input', 'id': 'nym-split-domain-label',
                'placeholder': 'Label (optional)', 'maxlength': '64', 'keydown': domainKeydown
            });
            domainSave = E('button', {
                'class': 'nym-btn nym-btn-primary', 'id': 'nym-split-domain-save',
                'click': function() { add('domain'); }
            }, 'Add');
            domainAddRow = E('div', { 'class': 'nym-exemption-addrow' }, [domainInp, domainLabel, domainSave]);
        } else {
            domainAddRow = E('div', { 'class': 'nym-note nym-note-warn' },
                'Domain exclusions need dnsmasq-full (built with nftset support): ' +
                'opkg install dnsmasq-full');
        }

        var section = E('div', { 'class': 'nym-split-section' }, [
            card.group({
                title: 'Exclusions',
                desc: 'Devices are matched by MAC address, so they survive an IP change. ' +
                    'Domain rules need clients to use this router for DNS.',
                body: [
                    listEl,
                    E('div', { 'class': 'nym-exemption-add' }, [
                        E('div', { 'class': 'nym-form-label' }, 'Exclude a Device'),
                        E('div', { 'class': 'nym-exemption-addrow' }, [clientSel, clientLabel, clientSave]),
                        E('div', { 'class': 'nym-form-label', 'style': 'margin-top: 14px' }, 'Exclude a Domain'),
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
            desc: 'Hand routing to luci-app-pbr: only the traffic PBR selects goes through the VPN, everything else uses the WAN in the clear. Turns the kill-switch and the exclusion list off.',
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
                E('div', { 'class': 'nym-card-description' },
                    'Send chosen devices or domains straight to the WAN instead of through the VPN. ' +
                    'Everything else stays in the tunnel, and the kill-switch keeps covering it.'),
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
