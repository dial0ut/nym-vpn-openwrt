'use strict';
'require baseclass';
'require dom';
'require nym-vpn.components.toast as toast';
'require nym-vpn.components.details as details';

// Labelled switch row (title, description, optional notes under it, the
// switch) and the save-or-revert behaviour most switches on the page share.

var E = dom.create.bind(dom);

var TAG_TITLES = { reconnect: 'Takes effect on the next connect' };

return baseclass.extend({
    // opts: {id, title, desc, tag, checked, disabled, onChange(ev), extra
    // (children after the description), after (children after the switch),
    // rowId, rowStyle, more, docs, moreId}. `tag` is a short marker beside
    // the title ('reconnect' for switches that apply on the next connect);
    // it sits next to the title element, not inside it, so the title text
    // stays the bare name. `desc` is one short clause; the full explanation
    // goes in `more` (string or children) behind an (i) button, with `docs`
    // naming the LuCI-guide anchor its Learn more link points at.
    row: function(opts) {
        var head = [E('div', { 'class': 'nym-toggle-title' }, opts.title)];
        if (opts.tag) {
            var tagAttrs = { 'class': 'nym-toggle-tag' };
            if (TAG_TITLES[opts.tag]) tagAttrs.title = TAG_TITLES[opts.tag];
            head.push(E('span', tagAttrs, opts.tag));
        }
        var more = null;
        if (opts.more) {
            more = details.create({
                id: opts.moreId || opts.id,
                label: opts.title,
                text: opts.more,
                docs: opts.docs
            });
            head.push(more.button);
        }
        var info = [
            E('div', { 'class': 'nym-toggle-head' }, head),
            E('div', { 'class': 'nym-toggle-desc' }, opts.desc)
        ];
        if (more) info.push(more.panel);
        info = info.concat(opts.extra || []);
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
