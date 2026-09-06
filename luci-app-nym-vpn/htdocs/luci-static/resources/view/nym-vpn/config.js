'use strict';
'require view';
'require ui';
'require poll';
'require dom';
'require nym-vpn.theme as theme';
'require nym-vpn.assets as assets';
'require nym-vpn.api as api';
'require nym-vpn.store as store';
'require nym-vpn.cards.connection as connectionCard';
'require nym-vpn.cards.tunnel-settings as tunnelSettingsCard';
'require nym-vpn.cards.mixnet-tuning as mixnetTuningCard';
'require nym-vpn.cards.dns as dnsCard';
'require nym-vpn.cards.account as accountCard';
'require nym-vpn.cards.service as serviceCard';
'require nym-vpn.cards.diagnostics as diagnosticsCard';
'require nym-vpn.cards.logs as logsCard';

// The NymVPN page: loads the init batch, seeds the store, and composes the
// cards in order. Everything else lives in the nym-vpn/ module tree — api
// (rpc + normalisation), store (state + polling), components, flows, cards.

var E = dom.create.bind(dom);

return view.extend({
    load: function() {
        // Single batch RPC call replaces a dozen separate calls. Gateway
        // country lists are deferred until user interaction.
        return api.init().catch(function(err) {
            console.error('Failed to load Nym VPN data:', err);
            return {};
        });
    },

    render: function(initData) {
        store.seed(initData, api);

        var header = E('div', { 'class': 'nym-header' });
        var logo = E('div', { 'class': 'nym-logo' });
        logo.innerHTML = assets.logo || '';
        header.appendChild(logo);

        var container = E('div', { 'class': 'nym-container' }, [
            E('style', {}, theme.css || ''),
            header,
            connectionCard.render(store, api)
        ]);

        // Settings, then account and service, then the troubleshooting
        // group (Diagnostics → Logs).
        [
            tunnelSettingsCard,
            mixnetTuningCard,
            dnsCard,
            accountCard,
            serviceCard,
            diagnosticsCard,
            logsCard
        ].forEach(function(c) {
            container.appendChild(c.render(store, api));
        });

        container.appendChild(E('div', { 'class': 'nym-footer' }, [
            E('div', { 'class': 'nym-footer-info' }, [
                E('div', { 'class': 'nym-footer-item' }, [
                    'Version: ',
                    E('span', {}, store.data.info.version || 'Unknown')
                ]),
                E('div', { 'class': 'nym-footer-item' }, [
                    'Network: ',
                    E('span', {}, store.data.network.network || 'mainnet')
                ])
            ])
        ]));

        store.startPolling(poll);

        return container;
    }
});
