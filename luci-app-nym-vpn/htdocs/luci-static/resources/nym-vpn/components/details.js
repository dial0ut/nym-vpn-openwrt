'use strict';
'require baseclass';
'require dom';

// Progressive disclosure for the settings cards. A row or group shows one
// short clause; the full explanation sits behind a small (i) button that
// expands it inline, closed by default, remembered per row in localStorage,
// and ends in a "Learn more" link into the matching section of the LuCI
// guide on the docs site.

var E = dom.create.bind(dom);

var DOCS_BASE = 'https://docs.dial0ut.org/guide/luci/';
var STORAGE_PREFIX = 'nym-more:';

var ICON = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">' +
    '<circle cx="8" cy="8" r="6.6" fill="none" stroke="currentColor" stroke-width="1.3"/>' +
    '<circle cx="8" cy="5" r="0.9" fill="currentColor"/>' +
    '<path d="M8 7.4v4.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';

var remembered = function(id) {
    try { return localStorage.getItem(STORAGE_PREFIX + id) === '1'; } catch (e) { return false; }
};
var remember = function(id, open) {
    try {
        if (open) localStorage.setItem(STORAGE_PREFIX + id, '1');
        else localStorage.removeItem(STORAGE_PREFIX + id);
    } catch (e) { /* private mode, quota: the row still toggles */ }
};

return baseclass.extend({
    DOCS_BASE: DOCS_BASE,
    STORAGE_PREFIX: STORAGE_PREFIX,

    // opts: {id (storage key, also the panel's element id suffix), label
    // (what the button describes, for aria-label), text (string, or an
    // array of strings/elements), docs (anchor in the LuCI guide, without
    // '#'), open (initial state; the remembered state wins)}.
    // Returns {button, panel, isOpen(), set(open)}.
    create: function(opts) {
        var panelId = 'nym-more-' + opts.id;
        var open = remembered(opts.id) || !!opts.open;

        var body = Array.isArray(opts.text) ? opts.text.slice() : [String(opts.text || '')];
        var children = [E('div', { 'class': 'nym-more-text' }, body)];
        if (opts.docs) {
            children.push(E('a', {
                'class': 'nym-learn-more',
                'href': DOCS_BASE + '#' + opts.docs,
                'target': '_blank',
                'rel': 'noopener'
            }, 'Learn more ↗'));
        }
        var panel = E('div', { 'class': 'nym-more', 'id': panelId }, children);
        panel.hidden = !open;

        var button = E('button', {
            'type': 'button',
            'class': 'nym-info-btn' + (open ? ' open' : ''),
            'aria-expanded': open ? 'true' : 'false',
            'aria-controls': panelId,
            'aria-label': 'More about ' + (opts.label || 'this setting'),
            'title': open ? 'Hide details' : 'Details'
        });
        button.innerHTML = ICON;

        var set = function(next) {
            open = !!next;
            panel.hidden = !open;
            button.setAttribute('aria-expanded', open ? 'true' : 'false');
            button.title = open ? 'Hide details' : 'Details';
            button.classList.toggle('open', open);
            remember(opts.id, open);
        };
        button.addEventListener('click', function(ev) {
            // Rows are <label>s wrapping the switch: stop the click from
            // reaching them and flipping the setting.
            ev.preventDefault();
            ev.stopPropagation();
            set(!open);
        });

        return { button: button, panel: panel, isOpen: function() { return open; }, set: set };
    }
});
