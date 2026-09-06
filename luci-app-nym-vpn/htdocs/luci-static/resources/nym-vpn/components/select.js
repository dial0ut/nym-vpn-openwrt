'use strict';
'require baseclass';
'require dom';

// Plain <select class="nym-select"> from a list of options.

var E = dom.create.bind(dom);

return baseclass.extend({
    // attrs: extra attributes (id, style, title, change...); options:
    // [{value, label, selected}]
    create: function(attrs, options) {
        var a = Object.assign({ 'class': 'nym-select' }, attrs || {});
        return E('select', a, (options || []).map(function(o) {
            var oa = { 'value': o.value };
            if (o.selected) oa.selected = 'selected';
            return E('option', oa, o.label);
        }));
    }
});
