'use strict';
'require baseclass';
'require dom';

// Bottom-corner toasts that dismiss themselves after four seconds.

var E = dom.create.bind(dom);

return baseclass.extend({
    __init__: function() {
        this.container = null;
    },

    ensureContainer: function() {
        if (!this.container || !this.container.parentNode) {
            this.container = E('div', { 'class': 'nym-toast-container' });
            document.body.appendChild(this.container);
        }
        return this.container;
    },

    remove: function(toast) {
        if (toast && toast.parentNode) {
            toast.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(function() {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }
    },

    // type: 'success' (default), 'error' or 'warning'
    show: function(message, type) {
        var self = this;
        var container = this.ensureContainer();
        var icons = { success: '✓', error: '✕', warning: '⚠' };
        var toast = E('div', { 'class': 'nym-toast ' + (type || 'success') }, [
            E('span', { 'class': 'nym-toast-icon' }, icons[type] || '✓'),
            E('span', { 'class': 'nym-toast-message' }, message),
            E('button', { 'class': 'nym-toast-close', 'click': function() { self.remove(toast); } }, '×')
        ]);
        container.appendChild(toast);
        setTimeout(function() { self.remove(toast); }, 4000);
    }
});
