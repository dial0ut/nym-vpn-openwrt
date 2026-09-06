'use strict';
'require baseclass';
'require dom';
'require nym-vpn.components.toast as toast';

// Inbound Services — ports whose reply traffic bypasses the tunnel so a
// service on the router or LAN stays reachable from the WAN with the
// kill-switch on. Renders inside the Tunnel Settings card beneath the
// Kill-Switch toggle; the daemon stores exemptions independently of the
// kill-switch, so toggling it off/on never loses them.

var E = dom.create.bind(dom);

return baseclass.extend({
    // Returns the section element (.nym-inbound-section); the caller
    // controls its visibility.
    render: function(store, api) {
        var state = store.data.inbound_exemptions.slice();
        var listEl = E('div', { 'class': 'nym-exemption-table' });
        var protoSel, portInp, labelInp, saveBtn;

        var renderRow = function(ex) {
            var killswitchOn = store.data.tunnel_config.killswitch !== 'off';
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
                    'No exemptions configured. Add one below.'));
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

        var section = E('div', { 'class': 'nym-inbound-section' }, [
            E('div', { 'class': 'nym-divider' }),
            E('div', { 'class': 'nym-toggle-title', 'style': 'margin-bottom: 6px' }, 'Inbound Services'),
            E('div', { 'class': 'nym-card-description' },
                'Ports that stay reachable from the WAN while the kill-switch is on ' +
                '(e.g. hosted HTTPS, WireGuard, SSH). For LAN services, add the ' +
                'Network → Firewall port forward first, then the matching port here.'),
            listEl,
            E('div', { 'class': 'nym-exemption-add' }, [
                E('div', { 'class': 'nym-form-label' }, 'Add Exemption'),
                E('div', { 'class': 'nym-exemption-addrow' }, [protoSel, portInp, labelInp, saveBtn])
            ])
        ]);
        redraw();
        return section;
    }
});
