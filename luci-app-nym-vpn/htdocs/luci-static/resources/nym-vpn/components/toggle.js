'use strict';
'require baseclass';
'require dom';
'require nym-vpn.components.toast as toast';

// Labelled switch row (title, description, optional notes under it, the
// switch) and the save-or-revert behaviour most switches on the page share.

var E = dom.create.bind(dom);

return baseclass.extend({
    // opts: {id, title, desc, checked, disabled, onChange(ev), extra
    // (children after the description), after (children after the switch),
    // rowId, rowStyle}
    row: function(opts) {
        var info = [
            E('div', { 'class': 'nym-toggle-title' }, opts.title),
            E('div', { 'class': 'nym-toggle-desc' }, opts.desc)
        ].concat(opts.extra || []);
        var rowAttrs = { 'class': 'nym-toggle-row' };
        if (opts.rowId) rowAttrs.id = opts.rowId;
        if (opts.rowStyle) rowAttrs.style = opts.rowStyle;
        var inputAttrs = {
            'type': 'checkbox',
            'id': opts.id,
            'checked': opts.checked ? 'checked' : null,
            'disabled': opts.disabled ? 'disabled' : null,
            'change': opts.onChange
        };
        return E('div', rowAttrs, [
            E('div', { 'class': 'nym-toggle-info' }, info),
            E('label', { 'class': 'nym-toggle' }, [
                E('input', inputAttrs),
                E('span', { 'class': 'nym-toggle-slider' })
            ])
        ].concat(opts.after || []));
    },

    // Change handler that saves and reverts the switch when the save fails.
    // opts: {save(enabled) -> Promise<result>, onSuccess(enabled, result),
    // disableWhileSaving}. A result without success:true toasts
    // 'Failed: <error>'; a rejection toasts 'Error: <message>'.
    saver: function(opts) {
        return function(ev) {
            var input = ev.target;
            var enabled = input.checked;
            var revert = function() { input.checked = !enabled; };
            var settle = function() { if (opts.disableWhileSaving) input.disabled = false; };
            if (opts.disableWhileSaving) input.disabled = true;
            opts.save(enabled).then(function(result) {
                settle();
                if (result && result.success) {
                    if (opts.onSuccess) opts.onSuccess(enabled, result);
                } else {
                    toast.show('Failed: ' + ((result && result.error) || 'Unknown'), 'error');
                    revert();
                }
            }).catch(function(err) {
                settle();
                toast.show('Error: ' + (err && err.message ? err.message : err), 'error');
                revert();
            });
        };
    }
});
