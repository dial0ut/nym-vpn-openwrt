'use strict';
'require baseclass';
'require dom';
'require nym-vpn.components.details as details';

// Expandable settings card: header (icon, title, chevron) that toggles the
// 'expanded' class, and a body. group() is the sub-heading used to break a
// long body into named runs (Protection / Transport / …).

var E = dom.create.bind(dom);

// Card and group bodies are built from arrays that may hold null for an
// element that is not shown (a notice, an optional row). LuCI's dom.append
// renders non-element children as text, so a null would show up on the page
// as the word "null"; drop those before handing the list over.
function children(list) {
    return (list || []).filter(function(c) { return c !== null && c !== undefined; });
}

return baseclass.extend({
    // A titled run inside a card body. opts: {title, desc, body (children),
    // id, cls, more, moreId, docs, action}. The title is a muted micro-label,
    // so a card reads as a few short groups instead of one wall of rows.
    // `desc` is for live state only; standing advice goes in `more`, behind
    // the same (i) button the switch rows use. `action` is an element placed
    // at the right end of the title bar (an "Add" opener, say).
    group: function(opts) {
        var attrs = { 'class': 'nym-group' + (opts.cls ? ' ' + opts.cls : '') };
        if (opts.id) attrs.id = opts.id;
        var titleChildren = [E('span', {}, opts.title)];
        var more = null;
        if (opts.more) {
            more = details.create({
                id: opts.moreId || (opts.id || String(opts.title).toLowerCase().replace(/[^a-z0-9]+/g, '-')),
                label: opts.title,
                text: opts.more,
                docs: opts.docs
            });
            titleChildren.push(more.button);
        }
        var titleBar = [E('div', { 'class': 'nym-group-title' }, titleChildren)];
        if (opts.action) titleBar.push(opts.action);
        var head = [E('div', { 'class': 'nym-group-titlebar' }, titleBar)];
        if (opts.desc) head.push(E('div', { 'class': 'nym-group-desc' }, opts.desc));
        if (more) head.push(more.panel);
        return E('div', attrs, [
            E('div', { 'class': 'nym-group-head' }, head)
        ].concat(children(opts.body)));
    },

    // A card header icon from an inline SVG string.
    svgIcon: function(svg) {
        var el = E('div', { 'class': 'nym-card-icon' });
        el.innerHTML = svg;
        return el;
    },

    // opts: {icon (svg string), title, id, body (children), onToggle(expanded)}
    // Returns {el, body} so the caller can rebuild the body in place.
    create: function(opts) {
        var body = E('div', { 'class': 'nym-card-body' }, children(opts.body));
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
