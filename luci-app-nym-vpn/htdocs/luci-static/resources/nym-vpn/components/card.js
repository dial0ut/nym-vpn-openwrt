'use strict';
'require baseclass';
'require dom';

// Expandable settings card: header (icon, title, chevron) that toggles the
// 'expanded' class, and a body.

var E = dom.create.bind(dom);

return baseclass.extend({
    // A card header icon from an inline SVG string.
    svgIcon: function(svg) {
        var el = E('div', { 'class': 'nym-card-icon' });
        el.innerHTML = svg;
        return el;
    },

    // opts: {icon (svg string), title, id, body (children), onToggle(expanded)}
    // Returns {el, body} so the caller can rebuild the body in place.
    create: function(opts) {
        var body = E('div', { 'class': 'nym-card-body' }, opts.body || []);
        var attrs = { 'class': 'nym-card' };
        if (opts.id) attrs.id = opts.id;
        var el = E('div', attrs, [
            E('div', { 'class': 'nym-card-header', 'click': function() {
                el.classList.toggle('expanded');
                if (opts.onToggle) opts.onToggle(el.classList.contains('expanded'));
            } }, [
                E('div', { 'class': 'nym-card-title' }, [
                    this.svgIcon(opts.icon),
                    opts.title
                ]),
                E('div', { 'class': 'nym-card-chevron' }, '▼')
            ]),
            body
        ]);
        return { el: el, body: body };
    }
});
