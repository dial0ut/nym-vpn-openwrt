'use strict';
'require baseclass';
'require dom';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toast as toast';

// Inbound Services — ports whose reply traffic bypasses the tunnel so a
// service on the router or LAN stays reachable from the WAN with the
// kill-switch on. Renders inside the Tunnel Settings card as the block
// nested under the Kill-Switch row; the daemon stores exemptions
// independently of the kill-switch, so toggling it off/on never loses them.

var E = dom.create.bind(dom);

return baseclass.extend({
    // Returns the section element (.nym-inbound-section); the caller
    // controls its visibility.
    render: function(store, api) {
        var state = store.data.inbound_exemptions.slice();
        var listEl = E('div', { 'class': 'nym-exemption-table' });
        var protoSel, portInp, labelInp, saveBtn;

        var renderRow = function(ex) {
            var killswitchOn = store.tunnelSwitches.killswitch && !store.tunnelSwitches.legacy_split_tunnel;
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

        var redraw = function() {
            listEl.innerHTML = '';
            if (state.length === 0) {
                listEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'No exemptions configured.'));
                return;
            }
            listEl.appendChild(E('div', { 'class': 'nym-exemption-header' }, [
                E('div', {}, 'Proto'),
                E('div', {}, 'Port'),
                E('div', {}, 'Label'),
                E('div', {}, 'Status'),
                E('div', {}, '')
            ]));
            state.forEach(function(ex) { listEl.appendChild(renderRow(ex)); });
        };

        var onKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); add(); }
        };

        var add = function() {
            if (!protoSel || !portInp || !saveBtn) return;

            var proto = protoSel.value;
            var dportRaw = (portInp.value || '').trim();
            var label = (labelInp && labelInp.value || '').trim();

            if (!dportRaw) {
                toast.show('Port is required', 'error');
                return;
            }
            var dport = parseInt(dportRaw, 10);
            if (isNaN(dport) || dport < 1 || dport > 65535) {
                toast.show('Port must be between 1 and 65535', 'error');
                return;
            }
            if (state.some(function(e) { return e.proto === proto && e.dport === dport; })) {
                toast.show(proto.toUpperCase() + '/' + dport + ' is already exempted', 'error');
                return;
            }
            if (label.length > 64) {
                toast.show('Label too long (max 64 characters)', 'error');
                return;
            }

            var pending = { proto: proto, dport: dport };
            if (label) pending.label = label;

            var pendingRow = renderRow(pending);
            pendingRow.classList.add('pending');
            if (state.length === 0) listEl.innerHTML = '';
            listEl.appendChild(pendingRow);
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<span class="nym-btn-spinner"></span>Saving';

            var rollback = function() {
                pendingRow.parentNode && pendingRow.parentNode.removeChild(pendingRow);
                if (state.length === 0) redraw();
            };

            api.inboundAdd(proto, dport, label || '').then(function(result) {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Add';
                if (result && result.success) {
                    state.push(pending);
                    redraw();
                    portInp.value = '';
                    if (labelInp) labelInp.value = '';
                    toast.show('Added ' + proto.toUpperCase() + '/' + dport, 'success');
                } else {
                    rollback();
                    toast.show((result && result.error) || 'Failed to add exemption', 'error');
                }
            }).catch(function(err) {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Add';
                rollback();
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var deleteExemption = function(ex) {
            var row = listEl.querySelector(
                '.nym-exemption-row[data-proto="' + ex.proto + '"][data-dport="' + ex.dport + '"]');
            if (row) row.classList.add('removing');

            api.inboundDel(ex.proto, ex.dport).then(function(result) {
                if (result && result.success) {
                    state = state.filter(function(e) {
                        return !(e.proto === ex.proto && e.dport === ex.dport);
                    });
                    redraw();
                    toast.show('Removed ' + ex.proto.toUpperCase() + '/' + ex.dport, 'success');
                } else {
                    if (row) row.classList.remove('removing');
                    toast.show((result && result.error) || 'Failed to delete', 'error');
                }
            }).catch(function(err) {
                if (row) row.classList.remove('removing');
                toast.show('Failed: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        protoSel = E('select', { 'class': 'nym-select', 'id': 'nym-inbound-proto' }, [
            E('option', { 'value': 'tcp' }, 'TCP'),
            E('option', { 'value': 'udp' }, 'UDP')
        ]);
        portInp = E('input', {
            'type': 'text',
            'class': 'nym-input',
            'id': 'nym-inbound-port',
            'placeholder': '1–65535',
            'inputmode': 'numeric',
            'maxlength': '5',
            'keydown': onKeydown
        });
        labelInp = E('input', {
            'type': 'text',
            'class': 'nym-input',
            'id': 'nym-inbound-label',
            'placeholder': 'Label (optional)',
            'maxlength': '64',
            'keydown': onKeydown
        });
        saveBtn = E('button', {
            'class': 'nym-btn nym-btn-primary',
            'id': 'nym-inbound-save',
            'click': add
        }, 'Add');

        // The add form is on demand once there is a list to look at: a small
        // opener in the group head reveals it (and hands focus to the port
        // field). With no exemptions yet the form is open from the start, so
        // the feature never looks inert. The form is in the DOM either way.
        var addPanel = E('div', { 'class': 'nym-exemption-add', 'id': 'nym-inbound-add' }, [
            E('div', { 'class': 'nym-form-label' }, 'Add Exemption'),
            E('div', { 'class': 'nym-exemption-addrow' }, [protoSel, portInp, labelInp, saveBtn])
        ]);
        var opener = E('button', {
            'type': 'button',
            'class': 'nym-add-open',
            'id': 'nym-inbound-add-open',
            'aria-controls': 'nym-inbound-add',
            'aria-expanded': 'false',
            'click': function() {
                addPanel.hidden = false;
                opener.hidden = true;
                opener.setAttribute('aria-expanded', 'true');
                try { portInp.focus(); } catch (e) {}
            }
        }, '+ Add exemption');
        if (state.length > 0) {
            addPanel.hidden = true;
        } else {
            opener.hidden = true;
            opener.setAttribute('aria-expanded', 'true');
        }

        var section = E('div', { 'class': 'nym-inbound-section' }, [
            card.group({
                title: 'Inbound Services',
                moreId: 'inbound-services',
                more: 'Ports whose reply traffic bypasses the tunnel, so a service on the router (LuCI, SSH) or on the LAN stays reachable from the WAN with the kill-switch on. Rows read Active while the kill-switch is on and Inert when it is off. For a LAN service, add the port forward under Network → Firewall first, then the same WAN-side port here.',
                docs: 'inbound-services',
                action: opener,
                body: [listEl, addPanel]
            })
        ]);
        redraw();
        return section;
    }
});
