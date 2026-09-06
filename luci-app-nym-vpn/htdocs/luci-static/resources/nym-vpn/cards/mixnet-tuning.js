'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';
'require nym-vpn.components.toggle as toggle';
'require nym-vpn.components.toast as toast';

// Mixnet Tuning — Sphinx traffic knobs (mixnet/5-hop mode). These trade
// anonymity for performance; the daemon validates ranges.

var E = dom.create.bind(dom);

return baseclass.extend({
    render: function(store, api) {
        var tunnel_config = store.data.tunnel_config;

        var poissonEl, coverEl, loopEl, packetEl, messageEl;

        // Numeric fields are optional: empty input means "leave as-is" (the
        // daemon keeps its current/default value).
        var save = function() {
            if (!poissonEl || !coverEl) return;

            var inRange = function(el, min, max) {
                if (!el || el.value === '') return '';
                var n = parseInt(el.value, 10);
                if (isNaN(n) || n < min || n > max) return null;
                return String(n);
            };

            var loop_cover = inRange(loopEl, 0, 200);
            var packet = inRange(packetEl, 0, 200);
            var message = inRange(messageEl, 5, 50);
            if (loop_cover === null || packet === null || message === null) {
                toast.show('Tuning values out of range (cover 0-200, mixing 0-200, sending 5-50 ms)', 'error');
                return;
            }

            api.mixnetTuningSet({
                loop_cover_delay: loop_cover,
                packet_delay: packet,
                message_delay: message,
                // disable_poisson = toggle says "disable Poisson delays"
                disable_poisson: poissonEl.checked ? 'on' : 'off',
                disable_cover: coverEl.checked ? 'on' : 'off'
            }).then(function(result) {
                if (result && result.success) {
                    toast.show('Mixnet tuning saved', 'success');
                } else {
                    toast.show('Failed: ' + (result.error || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                toast.show('Error: ' + err.message, 'error');
            });
        };

        var numField = function(label, id, min, max, value) {
            var input = E('input', {
                'type': 'number', 'min': String(min), 'max': String(max),
                'id': id, 'class': 'nym-input nym-tuning-num',
                'value': value || '',
                'placeholder': 'default'
            });
            return {
                input: input,
                el: E('div', { 'class': 'nym-form-group' }, [
                    E('label', { 'class': 'nym-form-label' }, label),
                    input
                ])
            };
        };

        var poissonRow = toggle.row({
            id: 'tuning-poisson-toggle',
            title: 'Disable Poisson Delays',
            desc: 'Send real traffic immediately instead of on a randomized schedule. Much faster, less private.',
            checked: tunnel_config.disable_poisson === 'true',
            onChange: save
        });
        var coverRow = toggle.row({
            id: 'tuning-cover-toggle',
            title: 'Disable Background Cover Traffic',
            desc: 'Stop sending decoy traffic. Saves bandwidth and CPU, less private.',
            checked: tunnel_config.disable_cover === 'true',
            onChange: save
        });
        poissonEl = poissonRow.querySelector('input');
        coverEl = coverRow.querySelector('input');

        var loop = numField('Cover traffic delay (ms, 0-200)', 'tuning-loop-cover', 0, 200, tunnel_config.loop_cover_delay);
        var packet = numField('Mixing delay per hop (ms, 0-200)', 'tuning-packet-delay', 0, 200, tunnel_config.packet_delay);
        var message = numField('Sending delay (ms, 5-50)', 'tuning-message-delay', 5, 50, tunnel_config.message_delay);
        loopEl = loop.input;
        packetEl = packet.input;
        messageEl = message.input;

        return card.create({
            icon: assets.iconSliders,
            title: 'Mixnet Tuning',
            body: [
                E('div', { 'class': 'nym-tuning-warning' },
                    'These settings trade anonymity for performance and only apply to ' +
                    'mixnet (5-hop) mode. Defaults give the strongest privacy; disabling ' +
                    'delays or cover traffic makes traffic analysis easier.'),
                poissonRow,
                coverRow,
                E('div', { 'class': 'nym-tuning-grid' }, [loop.el, packet.el, message.el]),
                E('div', { 'class': 'nym-action-buttons' }, [
                    E('button', {
                        'class': 'nym-btn nym-btn-primary',
                        'click': save
                    }, 'Apply Tuning')
                ])
            ]
        }).el;
    }
});
