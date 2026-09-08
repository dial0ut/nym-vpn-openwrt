'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.ui as nymUI';
'require nym-vpn.components.card as card';
'require nym-vpn.components.select as select';
'require nym-vpn.components.toast as toast';

// Daemon Logs — tail of `logread -e nym-vpn`. Auto-refreshes while the card
// is expanded and not paused by the user; the level filter runs
// client-side on the buffer already fetched.

var E = dom.create.bind(dom);

// ANSI escape stripping (server already does this, kept as a safety net).
var ansiRe = /\x1b\[[0-9;]*m/g;
var escapeHtml = function(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
};
// Match the tracing level keyword that follows an ISO-8601 timestamp.
// Anchoring on the timestamp keeps us from accidentally coloring the word
// "INFO" / "ERROR" if it happens to appear inside a message body.
var levelRe = /(\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+)(INFO|WARN|WARNING|ERROR|DEBUG|TRACE)\b/;
var levelClass = { INFO: 'info', WARN: 'warn', WARNING: 'warn', ERROR: 'error', DEBUG: 'debug', TRACE: 'trace' };
var renderColoredLogs = function(cleaned) {
    var parts = cleaned.split('\n');
    var out = '';
    for (var i = 0; i < parts.length; i++) {
        var safe = escapeHtml(parts[i]);
        var m = safe.match(levelRe);
        if (m) {
            var cls = levelClass[m[2]];
            var idx = m.index + m[1].length;
            safe = safe.slice(0, idx) +
                   '<span class="nym-log-' + cls + '">' + m[2] + '</span>' +
                   safe.slice(idx + m[2].length);
        }
        out += safe;
        if (i < parts.length - 1) out += '\n';
    }
    return out;
};

// A line is an "error anchor" if it carries an ERROR/WARN tracing level
// (after the ISO-8601 timestamp) or a syslog daemon.{err,warn,crit,…}
// facility from logread. Anchoring avoids matching the words in a body.
var errLineRe = /\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+(?:ERROR|WARN(?:ING)?)\b|daemon\.(?:err(?:or)?|warn(?:ing)?|crit|alert|emerg)\b/;

// Reduce the buffer to error/warn lines plus a +/-N line context window.
// Skipped runs are collapsed to a single ellipsis marker. mode is one of
// all | err0 | err10 | err30.
var applyLogFilter = function(text, mode) {
    if (mode === 'all') return text;
    var ctx = mode === 'err30' ? 30 : (mode === 'err10' ? 10 : 0);
    var lines = text.split('\n');
    var keep = new Array(lines.length);
    var anyErr = false;
    for (var i = 0; i < lines.length; i++) {
        if (errLineRe.test(lines[i])) {
            anyErr = true;
            var lo = Math.max(0, i - ctx), hi = Math.min(lines.length - 1, i + ctx);
            for (var j = lo; j <= hi; j++) keep[j] = true;
        }
    }
    if (!anyErr) return '';
    var out = [], skipping = false;
    for (var k = 0; k < lines.length; k++) {
        if (keep[k]) {
            if (skipping) { out.push('        ⋯'); skipping = false; }
            out.push(lines[k]);
        } else {
            skipping = true;
        }
    }
    return out.join('\n');
};

return baseclass.extend({
    applyLogFilter: applyLogFilter,
    renderColoredLogs: renderColoredLogs,

    render: function(store, api) {
        var viewer = E('div', { 'class': 'nym-log-viewer empty' }, 'Expand to load logs.');
        var linesSelect = select.create({}, [
            { value: '100', label: '100 lines' },
            { value: '200', label: '200 lines', selected: true },
            { value: '500', label: '500 lines' },
            { value: '1000', label: '1000 lines' }
        ]);
        var intervalSelect = select.create({}, [
            { value: '2', label: 'Every 2s' },
            { value: '5', label: 'Every 5s', selected: true },
            { value: '10', label: 'Every 10s' },
            { value: '30', label: 'Every 30s' }
        ]);
        var filterSelect = select.create({ 'title': 'Filter log level' }, [
            { value: 'all', label: 'All levels', selected: true },
            { value: 'err0', label: 'Errors only' },
            { value: 'err10', label: 'Errors ±10' },
            { value: 'err30', label: 'Errors ±30' }
        ]);
        var status = E('span', { 'class': 'nym-log-status paused' }, 'paused');
        var pauseBtn = E('button', { 'class': 'nym-btn nym-btn-secondary nym-btn-icon', 'type': 'button', 'title': 'Play' });
        pauseBtn.innerHTML = assets.iconPlay;
        var copyBtn = E('button', { 'class': 'nym-btn nym-btn-secondary nym-btn-icon', 'type': 'button', 'title': 'Copy to clipboard' });
        copyBtn.innerHTML = assets.iconClipboard;

        var expanded = false;
        var paused = true;
        var fetching = false;
        var lastClean = '';
        var lastDisplay = '';
        var timer = null;

        var setStatus = function(text, cls) {
            status.textContent = text;
            status.className = 'nym-log-status ' + cls;
        };

        // Render lastClean through the active filter. Called both on fetch
        // and on filter change (no refetch needed — filtering is client-side).
        var renderView = function(cleaned) {
            var display = applyLogFilter(cleaned, filterSelect.value);
            lastDisplay = display;
            var shouldAutoscroll = (viewer.scrollTop + viewer.clientHeight) >= (viewer.scrollHeight - 8);
            if (cleaned.length === 0) {
                viewer.className = 'nym-log-viewer empty';
                viewer.textContent = 'No nym-vpn log entries in the system buffer.';
            } else if (display.length === 0) {
                viewer.className = 'nym-log-viewer empty';
                viewer.textContent = 'No error or warning entries in the current buffer.';
            } else {
                viewer.className = 'nym-log-viewer';
                viewer.innerHTML = renderColoredLogs(display);
                if (shouldAutoscroll) viewer.scrollTop = viewer.scrollHeight;
            }
        };

        var fetchLogs = function() {
            if (fetching) return;
            fetching = true;
            var lines = parseInt(linesSelect.value, 10) || 200;
            api.logsGet(lines).then(function(result) {
                fetching = false;
                if (!result || result.success !== true) {
                    viewer.className = 'nym-log-viewer empty';
                    viewer.textContent = (result && result.error) || 'Failed to read logs.';
                    return;
                }
                var raw = result.logs || '';
                var cleaned = raw.replace(ansiRe, '');
                lastClean = cleaned;
                renderView(cleaned);
            }).catch(function(err) {
                fetching = false;
                viewer.className = 'nym-log-viewer empty';
                viewer.textContent = 'Log fetch error: ' + (err && err.message ? err.message : err);
            });
        };

        var copyLogs = function() {
            // Copy what's shown — when a filter is active this is the focused
            // error-context view, which is what users want to share.
            var text = lastDisplay || lastClean || '';
            if (!text) {
                toast.show('No logs to copy', 'warning');
                return;
            }
            nymUI.copyText(text, function(ok) {
                toast.show(ok ? 'Logs copied to clipboard' : 'Copy failed', ok ? 'success' : 'error');
            });
        };

        var stopTimer = function() {
            if (timer) { clearInterval(timer); timer = null; }
        };
        var startTimer = function() {
            stopTimer();
            var seconds = parseInt(intervalSelect.value, 10) || 5;
            timer = setInterval(function() {
                if (expanded && !paused) fetchLogs();
            }, seconds * 1000);
        };
        var setPlayPauseUi = function() {
            if (paused) {
                pauseBtn.innerHTML = assets.iconPlay;
                pauseBtn.setAttribute('title', 'Play');
                setStatus('paused', 'paused');
            } else {
                pauseBtn.innerHTML = assets.iconPause;
                pauseBtn.setAttribute('title', 'Pause');
                setStatus('live', 'live');
            }
        };

        copyBtn.onclick = copyLogs;
        pauseBtn.onclick = function() {
            paused = !paused;
            setPlayPauseUi();
            if (!paused) { fetchLogs(); startTimer(); }
            else { stopTimer(); }
        };
        linesSelect.addEventListener('change', function() { if (!paused) fetchLogs(); });
        intervalSelect.addEventListener('change', function() { if (!paused) startTimer(); });
        // Re-filter in place from the buffer we already have — no refetch.
        filterSelect.addEventListener('change', function() { renderView(lastClean); });

        return card.create({
            icon: assets.iconLogs,
            title: 'Daemon Logs',
            onToggle: function(isExpanded) {
                expanded = isExpanded;
                if (expanded) {
                    // Start live by default when the user opens the card.
                    paused = false;
                    setPlayPauseUi();
                    fetchLogs();
                    startTimer();
                } else {
                    paused = true;
                    setPlayPauseUi();
                    stopTimer();
                }
            },
            body: [
                E('div', { 'class': 'nym-log-controls' }, [
                    linesSelect,
                    intervalSelect,
                    filterSelect,
                    pauseBtn,
                    copyBtn,
                    status
                ]),
                viewer
            ]
        }).el;
    }
});
