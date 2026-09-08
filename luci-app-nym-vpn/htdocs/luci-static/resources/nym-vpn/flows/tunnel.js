'use strict';
'require baseclass';
'require nym-vpn.components.toast as toast';

// Saving the tunnel switches. tunnel_set takes all seven as one payload, and
// two cards drive them (Tunnel Settings owns six, Split Tunneling owns the
// legacy PBR switch), so the values live in the store and every change
// re-sends the whole set from there. A failed save leaves the switch where
// the user put it and toasts; the next change re-sends the lot.

return baseclass.extend({
    // Record `key` = `on` and save. Resolves true when the daemon accepted
    // the set.
    setSwitch: function(store, api, key, on) {
        store.setTunnelSwitch(key, on);
        // The gateway picker gates entry gateways on this while a list is
        // built, so it follows the switch at once, saved or not.
        if (key === 'circumvention') store.setCircumvention(on);
        return api.tunnelSet(store.tunnelSetPayload()).then(function(result) {
            if (result && result.success) {
                // The hop count drawn in the hero follows the saved value.
                if (key === 'two_hop') store.setTwoHop(on);
                toast.show('Tunnel settings saved', 'success');
                return true;
            }
            toast.show('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
            return false;
        }).catch(function(err) {
            toast.show('Error: ' + (err && err.message ? err.message : err), 'error');
            return false;
        });
    }
});
