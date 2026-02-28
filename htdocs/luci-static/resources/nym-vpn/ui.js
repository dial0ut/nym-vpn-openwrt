'use strict';
'require baseclass';
'require dom';

return baseclass.extend({
    UPTIME_STORAGE_KEY: 'nym_vpn_connection_start',
    formatUptime: function(seconds) {
        var hours = Math.floor(seconds / 3600);
        var minutes = Math.floor((seconds % 3600) / 60);
        var secs = seconds % 60;

        var pad = function(n) { return n < 10 ? '0' + n : n; };

        if (hours > 0) {
            return pad(hours) + ':' + pad(minutes) + ':' + pad(secs);
        } else {
            return pad(minutes) + ':' + pad(secs);
        }
    },

    getStoredStartTime: function() {
        try {
            var stored = localStorage.getItem(this.UPTIME_STORAGE_KEY);
            return stored ? parseInt(stored, 10) : null;
        } catch (e) { return null; }
    },

    saveStartTime: function(time) {
        try {
            localStorage.setItem(this.UPTIME_STORAGE_KEY, time.toString());
        } catch (e) {}
    },

    clearStartTime: function() {
        try {
            localStorage.removeItem(this.UPTIME_STORAGE_KEY);
        } catch (e) {}
    },

    getQualityIcon: function(performance, assets) {
        var perf = (performance || '').toLowerCase();
        if (perf.indexOf('high') >= 0) return assets.qualityHigh;
        if (perf.indexOf('medium') >= 0) return assets.qualityMedium;
        if (perf.indexOf('offline') >= 0) return assets.qualityOffline;
        return assets.qualityLow;
    },

    renderGatewayInfo: function(container, name, id, ip, country, countryData) {
        if (!container) return;
        if (!name && !ip && !id) {
            container.innerHTML = '<div class="nym-gateway-empty">—</div>';
            return;
        }
        var flag = country ? (countryData[country] || {}).flag || '🌐' : '🌐';
        var html = '<div class="nym-gateway-flag">' + flag + '</div>';
        if (name) html += '<div class="nym-gateway-name" title="' + (name || '') + '">' + name + '</div>';
        if (id) html += '<div class="nym-gateway-id">' + id + '</div>';
        if (ip) html += '<div class="nym-gateway-ip">' + ip + '</div>';
        container.innerHTML = html;
    },

    createCountrySelect: function(countries, name, onSelect, getCountryDisplay) {
        var E = dom.create.bind(dom);
        var options = [E('option', { 'value': 'none' }, '— Select Country —')];
        options.push(E('option', { 'value': 'random' }, '🌐 Random'));

        countries.forEach(function(c) {
            var info = getCountryDisplay(c.code);
            options.push(E('option', { 'value': c.code },
                info.flag + ' ' + info.name + ' (' + c.count + ')'));
        });

        return E('select', {
            'class': 'nym-select',
            'name': name,
            'change': onSelect
        }, options);
    },

    createModalManager: function() {
        var activeModal = null;
        var E = dom.create.bind(dom);

        var hide = function() {
            if (activeModal && activeModal.parentNode) {
                activeModal.parentNode.removeChild(activeModal);
                activeModal = null;
            }
        };

        var show = function(title, message, icon) {
            hide();
            activeModal = E('div', { 'class': 'nym-modal-overlay' }, [
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
            document.body.appendChild(activeModal);
        };

        var fadeOut = function(callback) {
            if (activeModal) {
                activeModal.classList.add('fade-out');
                setTimeout(function() {
                    hide();
                    if (callback) callback();
                }, 500);
            } else if (callback) {
                callback();
            }
        };

        var update = function(message) {
            if (activeModal) {
                var msgEl = activeModal.querySelector('.nym-modal-message');
                if (msgEl) msgEl.textContent = message;
            }
        };

        var setSuccess = function(title, message, icon) {
            if (activeModal) {
                activeModal.classList.add('success');
                var titleEl = activeModal.querySelector('.nym-modal-title');
                var msgEl = activeModal.querySelector('.nym-modal-message');
                var iconEl = activeModal.querySelector('.nym-modal-icon');
                if (titleEl && title) titleEl.textContent = title;
                if (msgEl && message) msgEl.textContent = message;
                if (iconEl && icon) iconEl.textContent = icon;
            }
        };

        var confirm = function(title, message, icon, onConfirm, onCancel, confirmText) {
            hide();
            activeModal = E('div', { 'class': 'nym-modal-overlay' }, [
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
                            'click': function() { hide(); if (onCancel) onCancel(); }
                        }, 'Cancel'),
                        E('button', {
                            'class': 'nym-btn nym-btn-danger',
                            'click': function() { if (onConfirm) onConfirm(); }
                        }, confirmText || 'Confirm')
                    ])
                ])
            ]);
            document.body.appendChild(activeModal);
        };

        return { show: show, hide: hide, fadeOut: fadeOut, update: update, setSuccess: setSuccess, confirm: confirm };
    },

    createToastManager: function() {
        var toastContainer = null;
        var E = dom.create.bind(dom);

        var ensureContainer = function() {
            if (!toastContainer || !toastContainer.parentNode) {
                toastContainer = E('div', { 'class': 'nym-toast-container' });
                document.body.appendChild(toastContainer);
            }
            return toastContainer;
        };

        var removeToast = function(toast) {
            if (toast && toast.parentNode) {
                toast.style.animation = 'slideOut 0.3s ease forwards';
                setTimeout(function() {
                    if (toast.parentNode) toast.parentNode.removeChild(toast);
                }, 300);
            }
        };

        return {
            show: function(message, type) {
                var container = ensureContainer();
                var icons = { success: '✓', error: '✕', warning: '⚠' };
                var toast = E('div', { 'class': 'nym-toast ' + (type || 'success') }, [
                    E('span', { 'class': 'nym-toast-icon' }, icons[type] || '✓'),
                    E('span', { 'class': 'nym-toast-message' }, message),
                    E('button', { 'class': 'nym-toast-close', 'click': function() { removeToast(toast); } }, '×')
                ]);
                container.appendChild(toast);
                setTimeout(function() { removeToast(toast); }, 4000);
            }
        };
    }
});
