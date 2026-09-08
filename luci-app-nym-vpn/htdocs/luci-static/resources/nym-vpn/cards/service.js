'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.flows.daemon as daemonFlow';

// Service Management — whether nym-vpnd is running (and enabled at boot),
// with Start / Restart / Stop.

var E = dom.create.bind(dom);

return baseclass.extend({
    render: function(store, api) {
        var running = store.daemonRunning;

        var startBtn = E('button', {
            'class': 'nym-card-action success',
            'type': 'button',
            'click': function() { daemonFlow.run('start', store, api); }
        });
        startBtn.innerHTML = assets.iconStart + '<span>Start</span>';
        startBtn.disabled = running;

        var restartBtn = E('button', {
            'class': 'nym-card-action rotate',
            'type': 'button',
            'click': function() { daemonFlow.run('restart', store, api); }
        });
        restartBtn.innerHTML = assets.iconRefresh + '<span>Restart</span>';

        var stopBtn = E('button', {
            'class': 'nym-card-action danger',
            'type': 'button',
            'click': function() { daemonFlow.run('stop', store, api); }
        });
        stopBtn.innerHTML = assets.iconStop + '<span>Stop</span>';
        stopBtn.disabled = !running;

        var badgeText = function(isRunning, enabled) {
            return (isRunning ? 'Running' : 'Stopped') + (enabled ? '' : ' · not enabled at boot');
        };

        var statusText = E('span', { 'class': 'nym-card-status-text' }, badgeText(running, store.daemonEnabled));
        var statusBadge = E('div', {
            'class': 'nym-card-status' + (running ? '' : ' stopped')
        }, [
            E('span', { 'class': 'nym-card-status-indicator' }),
            statusText
        ]);

        var infoFrame = E('div', {
            'class': 'nym-info-frame' + (running ? '' : ' stopped')
        }, [
            E('div', { 'class': 'nym-info-frame-label' }, 'Daemon'),
            E('div', { 'class': 'nym-info-frame-main' }, [
                E('div', { 'class': 'nym-info-frame-value' }, 'nym-vpnd'),
                statusBadge
            ])
        ]);

        store.on('daemon', function(d) {
            statusBadge.className = 'nym-card-status' + (d.running ? '' : ' stopped');
            statusText.textContent = badgeText(d.running, d.enabled);
            infoFrame.className = 'nym-info-frame' + (d.running ? '' : ' stopped');
            startBtn.disabled = d.running;
            stopBtn.disabled = !d.running;
        });

        return card.create({
            icon: assets.iconService,
            title: 'Service Management',
            body: [
                E('div', { 'class': 'nym-account-panel' }, [
                    infoFrame,
                    E('div', { 'class': 'nym-card-actions-bar' }, [
                        startBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        restartBtn,
                        E('div', { 'class': 'nym-card-action-divider' }),
                        stopBtn
                    ])
                ])
            ]
        }).el;
    }
});
