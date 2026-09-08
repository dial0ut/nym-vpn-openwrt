'use strict';
'require baseclass';
'require dom';

// Page-wide modal: progress (show/update/setSuccess/fadeOut) and confirm.
// LuCI instantiates the module once, so every card shares the same overlay.

var E = dom.create.bind(dom);

return baseclass.extend({
    __init__: function() {
        this.activeModal = null;
    },

    hide: function() {
        if (this.activeModal && this.activeModal.parentNode) {
            this.activeModal.parentNode.removeChild(this.activeModal);
            this.activeModal = null;
        }
    },

    show: function(title, message, icon) {
        this.hide();
        this.activeModal = E('div', { 'class': 'nym-modal-overlay' }, [
            E('div', { 'class': 'nym-modal' }, [
                E('div', { 'class': 'nym-modal-ring' }, [
                    E('div', { 'class': 'nym-modal-ring-outer' }),
                    E('div', { 'class': 'nym-modal-ring-inner' }, [
                        E('div', { 'class': 'nym-modal-icon' }, icon || '◐')
                    ])
                ]),
                E('div', { 'class': 'nym-modal-title' }, title),
                E('div', { 'class': 'nym-modal-message' }, message)
            ])
        ]);
        document.body.appendChild(this.activeModal);
    },

    fadeOut: function(callback) {
        var self = this;
        if (this.activeModal) {
            this.activeModal.classList.add('fade-out');
            setTimeout(function() {
                self.hide();
                if (callback) callback();
            }, 500);
        } else if (callback) {
            callback();
        }
    },

    update: function(message) {
        if (this.activeModal) {
            var msgEl = this.activeModal.querySelector('.nym-modal-message');
            if (msgEl) msgEl.textContent = message;
        }
    },

    setSuccess: function(title, message, icon) {
        if (this.activeModal) {
            this.activeModal.classList.add('success');
            var titleEl = this.activeModal.querySelector('.nym-modal-title');
            var msgEl = this.activeModal.querySelector('.nym-modal-message');
            var iconEl = this.activeModal.querySelector('.nym-modal-icon');
            if (titleEl && title) titleEl.textContent = title;
            if (msgEl && message) msgEl.textContent = message;
            if (iconEl && icon) iconEl.textContent = icon;
        }
    },

    // The safe (green) button hides the modal and runs onCancel; the red one
    // runs onConfirm and leaves hiding to the caller. cancelText relabels
    // the safe button; it defaults to 'Cancel'.
    confirm: function(title, message, icon, onConfirm, onCancel, confirmText, cancelText) {
        var self = this;
        this.hide();
        this.activeModal = E('div', { 'class': 'nym-modal-overlay' }, [
            E('div', { 'class': 'nym-modal' }, [
                E('div', { 'class': 'nym-modal-ring' }, [
                    E('div', { 'class': 'nym-modal-ring-outer nym-modal-ring-static' }),
                    E('div', { 'class': 'nym-modal-ring-inner' }, [
                        E('div', { 'class': 'nym-modal-icon' }, icon || '⚠')
                    ])
                ]),
                E('div', { 'class': 'nym-modal-title' }, title),
                E('div', { 'class': 'nym-modal-message' }, message),
                E('div', { 'class': 'nym-modal-buttons' }, [
                    E('button', {
                        'class': 'nym-btn nym-btn-primary',
                        'click': function() { self.hide(); if (onCancel) onCancel(); }
                    }, cancelText || 'Cancel'),
                    E('button', {
                        'class': 'nym-btn nym-btn-danger',
                        'click': function() { if (onConfirm) onConfirm(); }
                    }, confirmText || 'Confirm')
                ])
            ])
        ]);
        document.body.appendChild(this.activeModal);
    }
});
