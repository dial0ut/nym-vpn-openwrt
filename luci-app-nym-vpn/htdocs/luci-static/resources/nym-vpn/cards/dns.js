'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';

// DNS & Ad Blocking — custom resolvers managed as a list (the daemon
// replaces the whole set per call, so every add/remove re-sends the joined
// list) and the DNS-level ad-blocking switch.

var E = dom.create.bind(dom);

// Light client check (IPv4 dotted-quad, or anything colon-bearing for IPv6);
// the daemon validates strictly before applying.
var isValidDnsIp = function(s) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) {
        return s.split('.').every(function(o) { return +o >= 0 && +o <= 255; });
    }
    return /^[0-9a-fA-F:]+$/.test(s) && s.indexOf(':') >= 0;
};

return baseclass.extend({
    isValidDnsIp: isValidDnsIp,

    render: function(store, api) {
        var dns_config = store.data.dns;
        var ad_block = store.data.ad_block;

        var servers = (dns_config.servers || '').split(/\s+/).filter(Boolean);
        var listEl = E('div', { 'class': 'nym-dns-list' });
        var dnsToggle, serverInput, addBtn, adblockToggle;

        var renderRow = function(ip) {
            return E('div', { 'class': 'nym-dns-row', 'data-ip': ip }, [
                E('div', { 'class': 'nym-dns-ip' }, [String(ip)]),
                E('div', {
                    'class': 'nym-exemption-delete',
                    'title': 'Remove',
                    'click': function() { deleteServer(ip); }
                }, '×')
            ]);
        };

        var redraw = function() {
            listEl.innerHTML = '';
            if (servers.length === 0) {
                listEl.appendChild(E('div', { 'class': 'nym-exemption-empty' },
                    'Using the VPN default resolvers. Add a server below.'));
                return;
            }
            servers.forEach(function(ip) { listEl.appendChild(renderRow(ip)); });
        };

        // Push the current enabled state + full server list to the daemon.
        var persist = function() {
            var enabled = dnsToggle ? dnsToggle.checked : false;
            return api.dnsSet(enabled, servers.join(' '));
        };

        var addServer = function() {
            if (!serverInput) return;
            var ip = (serverInput.value || '').trim();
            if (!ip) { toast.show('Enter a DNS server address', 'error'); return; }
            if (!isValidDnsIp(ip)) { toast.show('Not a valid IPv4 or IPv6 address', 'error'); return; }
            if (servers.indexOf(ip) !== -1) { toast.show(ip + ' is already in the list', 'error'); return; }

            servers.push(ip);
            if (addBtn) { addBtn.disabled = true; addBtn.innerHTML = '<span class="nym-btn-spinner"></span>Adding'; }
            persist().then(function(result) {
                if (addBtn) { addBtn.disabled = false; addBtn.textContent = 'Add'; }
                if (result && result.success) {
                    redraw();
                    serverInput.value = '';
                    toast.show('Added ' + ip, 'success');
                } else {
                    servers.pop();
                    toast.show('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                if (addBtn) { addBtn.disabled = false; addBtn.textContent = 'Add'; }
                servers.pop();
                toast.show('Error: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var deleteServer = function(ip) {
            var idx = servers.indexOf(ip);
            if (idx === -1) return;
            var row = listEl.querySelector('.nym-dns-row[data-ip="' + ip + '"]');
            if (row) row.classList.add('removing');
            servers.splice(idx, 1);
            persist().then(function(result) {
                if (result && result.success) {
                    redraw();
                    toast.show('Removed ' + ip, 'success');
                } else {
                    servers.splice(idx, 0, ip);
                    if (row) row.classList.remove('removing');
                    toast.show('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                servers.splice(idx, 0, ip);
                if (row) row.classList.remove('removing');
                toast.show('Error: ' + (err && err.message ? err.message : err), 'error');
            });
        };

        var onKeydown = function(ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); addServer(); }
        };

        // The daemon steps aside when dnsmasq has noresolv set (AdGuard Home,
        // https-dns-proxy, stubby), so the servers below are configured but
        // not in force. Say so rather than letting the card imply otherwise.
        var userManagedNotice = dns_config.user_managed
            ? E('div', { 'class': 'nym-note nym-note-warn' }, [
                E('strong', {}, 'Not in effect: '),
                'dnsmasq has ',
                E('code', {}, 'noresolv'),
                ' set, so you manage upstream DNS. The servers below are ignored — ',
                'your own entries under Network → DNS → Forwards do the resolving, ',
                'and they ride the VPN tunnel while connected. Clear ',
                E('code', {}, 'noresolv'),
                ' if you want the VPN to supply DNS instead.'
            ])
            // null (not '') — LuCI's dom.append skips null children outright
            // rather than inserting an empty text node.
            : null;

        var dnsRow = toggle.row({
            id: 'dns-toggle',
            title: 'Custom DNS',
            desc: 'Uses your own resolvers instead of the VPN\'s.',
            more: 'Add servers one at a time; they replace the VPN\'s default resolvers for every client that uses the router for DNS, and the queries ride the tunnel while connected. If dnsmasq is set to noresolv (AdGuard Home, https-dns-proxy, stubby) the daemon steps aside and the card says so.',
            docs: 'custom-dns',
            checked: !!dns_config.enabled,
            onChange: toggle.saver({
                save: function() { return persist(); },
                onSuccess: function(enabled) {
                    toast.show(enabled ? 'Custom DNS enabled' : 'Custom DNS disabled', 'success');
                }
            })
        });
        dnsToggle = dnsRow.querySelector('input');

        var adblockStatus = null;
        var adblockRow = toggle.row({
            id: 'adblock-toggle',
            title: 'Ad Blocking',
            desc: 'Blocks ads, trackers and malware domains via DNS.',
            more: 'DNS-level blocking on the resolvers the tunnel uses: blocked domains simply fail to resolve, so pages load without them.',
            docs: 'ad-blocking',
            checked: !!ad_block.enabled,
            onChange: toggle.saver({
                save: function(enabled) { return api.adBlockSet(enabled); },
                onSuccess: function(enabled) {
                    toast.show(enabled ? 'Ad-blocking enabled' : 'Ad-blocking disabled', 'success');
                    if (adblockStatus) adblockStatus.textContent = enabled ? 'Enabled' : 'Disabled';
                    if (adblockToggle) adblockToggle.checked = enabled;
                }
            })
        });
        adblockToggle = adblockRow.querySelector('input');

        serverInput = E('input', {
            'type': 'text',
            'id': 'dns-server-input',
            'class': 'nym-input',
            'placeholder': 'e.g. 1.1.1.1 or 2606:4700:4700::1111',
            'autocomplete': 'off',
            'autocapitalize': 'off',
            'spellcheck': 'false',
            'keydown': onKeydown
        });
        addBtn = E('button', {
            'class': 'nym-btn nym-btn-primary',
            'id': 'dns-add-btn',
            'click': addServer
        }, 'Add');

        var el = card.create({
            icon: assets.iconShield,
            title: 'DNS & Ad Blocking',
            body: [
                userManagedNotice,
                dnsRow,
                // Current servers list (above) + single-server add panel
                // (below), mirroring the inbound exemptions layout.
                listEl,
                E('div', { 'class': 'nym-form-panel' }, [
                    E('div', { 'class': 'nym-form-label' }, 'Add DNS Server'),
                    E('div', { 'class': 'nym-form-row' }, [serverInput, addBtn])
                ]),
                E('div', { 'class': 'nym-divider' }),
                adblockRow
            ]
        }).el;
        redraw();
        return el;
    }
});
