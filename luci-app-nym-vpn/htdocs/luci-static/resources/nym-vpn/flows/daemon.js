'use strict';
'require baseclass';
'require nym-vpn.components.modal as modal';
'require nym-vpn.components.toast as toast';

// Start / stop / restart nym-vpnd, asking first when the VPN is up since the
// action drops the tunnel. Used by the Service Management card and by the
// Account card's "service not reachable" panel.

var ACTIONS = {
    'start':   { label: 'Start',   verb: 'Starting',   pastTense: 'started',   call: function(api) { return api.daemonStart(); },   needsDisconnect: false },
    'stop':    { label: 'Stop',    verb: 'Stopping',   pastTense: 'stopped',   call: function(api) { return api.daemonStop(); },    needsDisconnect: true  },
    'restart': { label: 'Restart', verb: 'Restarting', pastTense: 'restarted', call: function(api) { return api.daemonRestart(); }, needsDisconnect: true  }
};

return baseclass.extend({
    ACTIONS: ACTIONS,

    run: function(action, store, api) {
        var info = ACTIONS[action];
        if (!info) return;

        var execute = function() {
            modal.show(info.verb + ' Daemon', 'Please wait...');
            info.call(api).then(function(result) {
                var running = result && result.status === 'running';
                store.setDaemon(running, result ? result.enabled : undefined);
                // The Account card may be sitting on the "service not
                // reachable" panel; re-ask now that the daemon moved.
                store.emit('account-recheck');
                if (result && result.success) {
                    modal.setSuccess('Done', 'Daemon ' + info.pastTense, '✓');
                    setTimeout(function() { modal.fadeOut(); }, 1500);
                } else {
                    modal.hide();
                    toast.show(info.label + ' failed: ' + ((result && result.error) || 'Unknown'), 'error');
                }
            }).catch(function(err) {
                modal.hide();
                toast.show('Error: ' + err.message, 'error');
            });
        };

        if (!info.needsDisconnect) {
            execute();
            return;
        }

        api.status().then(function(st) {
            if (st && (st.state === 'connected' || st.state === 'connecting')) {
                modal.confirm(
                    info.label + ' Daemon',
                    'The VPN is currently connected. ' + info.verb + ' the daemon will disconnect you.',
                    '⚠',
                    function() {
                        modal.show('Disconnecting', 'Please wait...');
                        api.disconnect().then(function() {
                            modal.update(info.verb + ' daemon...');
                            setTimeout(execute, 1000);
                        }).catch(execute);
                    },
                    null,
                    info.label
                );
            } else {
                execute();
            }
        }).catch(execute);
    }
});
