'use strict';
'require baseclass';

// Small presentational helpers shared by the cards: uptime formatting, the
// legacy uptime storage key, quality icons, the connected-gateway panel and
// clipboard copy.

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
        // Curated flag if we have one; otherwise derive it from the ISO code
        // (Regional Indicator Symbols) so any country still shows a flag.
        var flag = '🌐';
        if (country) {
            var entry = countryData[country] || {};
            if (entry.flag) {
                flag = entry.flag;
            } else if (/^[A-Za-z]{2}$/.test(country)) {
                var cc = country.toUpperCase();
                flag = String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65,
                                            0x1F1E6 + cc.charCodeAt(1) - 65);
            }
        }
        var html = '<div class="nym-gateway-flag">' + flag + '</div>';
        if (name) html += '<div class="nym-gateway-name" title="' + (name || '') + '">' + name + '</div>';
        if (id) html += '<div class="nym-gateway-id">' + id + '</div>';
        if (ip) html += '<div class="nym-gateway-ip">' + ip + '</div>';
        container.innerHTML = html;
    },

    // Copy `text` to the clipboard and call done(ok). Prefers the async
    // clipboard API (HTTPS / localhost) and falls back to the legacy
    // textarea + execCommand path for plain-HTTP LuCI.
    copyText: function(text, done) {
        var self = this;
        if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function() { done(true); })
                .catch(function() { done(self.legacyCopy(text)); });
            return;
        }
        done(this.legacyCopy(text));
    },

    legacyCopy: function(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '0';
        ta.style.left = '0';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        return ok;
    }
});
