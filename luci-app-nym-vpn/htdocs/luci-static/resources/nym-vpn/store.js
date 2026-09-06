'use strict';
'require baseclass';

// Single page state: the init batch, the live status, the daemon state and
// the handful of settings other parts of the page consult, plus the status
// poll. No DOM in here — cards subscribe with on() and render themselves.
//
// Events:
//   'status'       {status, state, prevState, becameDisconnected,
//                   errorReasonChanged, availabilityChanged, newTunnelError}
//   'daemon'       {running, enabled}
//   'account-recheck'  the account card should re-ask the daemon

return baseclass.extend({
    __init__: function() {
        this.api = null;
        this.data = {};
        this.listeners = {};

        this.status = {};
        // A connect/disconnect action owns the UI: background polls stand
        // aside until it settles.
        this.busy = false;
        // Previous poll's state, so a transition to disconnected can refill
        // the gateway pickers.
        this.prevState = 'unknown';
        // Last tunnel_error / error_reason / availability seen, so the page
        // reacts once per change instead of on every 5 s poll.
        this.prevTunnelError = '';
        this.prevErrorReason = '';
        this.prevUnavailable = false;

        this.twoHop = false;
        this.circumvention = false;
        this.independence = { enabled: true, notifications: true };
        // Whether any bridge reply has carried the independence field yet;
        // the init batch may predate it.
        this.independenceKnown = false;

        this.daemonRunning = false;
        // Whether nym-vpnd has its boot symlink. Defaults to true so an older
        // bridge that omits the field never shows a spurious warning.
        this.daemonEnabled = true;
    },

    // Seed from the init batch (rpc init) and remember the api for polling.
    seed: function(initData, api) {
        var data = initData || {};
        this.api = api;
        this.data = {
            status: data.status || {},
            info: data.info || {},
            tunnel_config: data.tunnel_config || {},
            account: data.account || {},
            network: data.network || {},
            daemon: data.daemon || {},
            ad_block: data.ad_block || {},
            dns: data.dns || {},
            watchdog: data.watchdog || {},
            inbound_exemptions: data.inbound_exemptions || [],
            split_exclusions: data.split_exclusions || [],
            split_status: data.split_status || {},
            clients: data.clients || []
        };
        var status = this.data.status;
        var tunnel = this.data.tunnel_config;
        this.status = status;
        this.prevState = status.state || 'unknown';
        this.prevErrorReason = status.error_reason || '';
        this.prevTunnelError = status.tunnel_error || '';
        this.prevUnavailable = status.available === false;
        this.twoHop = tunnel.two_hop === 'on';
        this.circumvention = tunnel.circumvention_transports === 'on';
        var ind = api.readIndependence(tunnel.gateway_independence);
        this.independence = ind || { enabled: true, notifications: true };
        this.independenceKnown = !!ind;
        this.daemonRunning = !!this.data.daemon.running;
        this.daemonEnabled = this.data.daemon.enabled !== false;
    },

    // --- events -------------------------------------------------------------
    on: function(event, fn) {
        var list = this.listeners[event] || (this.listeners[event] = []);
        list.push(fn);
        return function() {
            var i = list.indexOf(fn);
            if (i !== -1) list.splice(i, 1);
        };
    },

    emit: function(event, payload) {
        (this.listeners[event] || []).slice().forEach(function(fn) { fn(payload); });
    },

    // --- status -------------------------------------------------------------
    setBusy: function(busy) { this.busy = !!busy; },
    isBusy: function() { return this.busy; },

    // Flows that already know where the daemon ended up (a connect or
    // disconnect they drove) pre-set the previous state so the next poll is
    // not read as a transition.
    markState: function(state) { this.prevState = state; },
    markTunnelError: function(reason) { this.prevTunnelError = reason || ''; },

    hops: function() { return this.twoHop ? 2 : 5; },

    applyStatus: function(result) {
        var state = result.state || 'unknown';
        var curErrorReason = result.error_reason || '';
        var curUnavailable = result.available === false;
        var curTunnelError = result.tunnel_error || '';
        var ev = {
            status: result,
            state: state,
            prevState: this.prevState,
            becameDisconnected: state === 'disconnected' && this.prevState !== 'disconnected',
            errorReasonChanged: curErrorReason !== this.prevErrorReason,
            availabilityChanged: curUnavailable !== this.prevUnavailable,
            newTunnelError: (curTunnelError && curTunnelError !== this.prevTunnelError) ? curTunnelError : ''
        };
        this.status = result;
        this.prevErrorReason = curErrorReason;
        this.prevUnavailable = curUnavailable;
        this.prevTunnelError = curTunnelError;
        this.prevState = state;
        this.emit('status', ev);
    },

    // One status poll. Skipped while an action owns the UI, re-checked after
    // the async gap since the action may have started mid-request.
    refreshStatus: function() {
        if (this.busy) return Promise.resolve();
        var self = this;
        return this.api.status().then(function(result) {
            if (!result) return;
            if (self.busy) return;
            self.applyStatus(result);
        }).catch(function(err) {
            console.error('Status update failed:', err);
        });
    },

    // --- daemon -------------------------------------------------------------
    // `enabled` is optional: pass undefined to leave the boot-time flag as it
    // was. Running-but-not-enabled is a state users end up in after a bad
    // upgrade and everything looks fine until they reboot, so it is tracked
    // rather than inferred.
    setDaemon: function(running, enabled) {
        if (enabled !== undefined) this.daemonEnabled = !!enabled;
        this.daemonRunning = !!running;
        this.emit('daemon', { running: this.daemonRunning, enabled: this.daemonEnabled });
    },

    refreshDaemon: function() {
        var self = this;
        return this.api.daemonStatus().then(function(result) {
            if (!result) return;
            self.setDaemon(!!result.running, result.enabled);
        }).catch(function(err) {
            console.error('Daemon status update failed:', err);
        });
    },

    // --- settings -----------------------------------------------------------
    setTwoHop: function(on) { this.twoHop = !!on; },
    setCircumvention: function(on) { this.circumvention = !!on; },

    // Consulted by the connect flow (notifications) before each connect.
    setIndependence: function(ind) {
        this.independence = { enabled: !!ind.enabled, notifications: !!ind.notifications };
        this.independenceKnown = true;
    },

    // --- polling ------------------------------------------------------------
    startPolling: function(poll) {
        var self = this;
        poll.add(function() { return self.refreshStatus(); }, 5);
        poll.add(function() { return self.refreshDaemon(); }, 10);
    }
});
