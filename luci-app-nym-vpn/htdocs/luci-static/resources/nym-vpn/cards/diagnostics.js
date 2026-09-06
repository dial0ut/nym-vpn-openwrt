'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.components.card as card';

// Diagnostics — the daemon's connectivity self-test (`nym-vpnc diagnostic
// run`): DNS resolution, VPN API reachability over HTTP, and the selected
// gateway's TCP/WebSocket handshake. The report is rendered as PASS/FAIL
// rows; the JSON is treated as opaque so new daemon probes appear
// automatically without touching this card.

var E = dom.create.bind(dom);

var chip = function(ok) {
    return E('span', { 'class': 'nym-diag-chip ' + (ok ? 'ok' : 'fail') }, ok ? 'PASS' : 'FAIL');
};
var row = function(label, ok, detail) {
    return E('div', { 'class': 'nym-diag-row' }, [
        chip(ok),
        E('div', { 'class': 'nym-diag-row-body' }, [
            // Array-wrap so LuCI's dom.append renders these as text nodes
            // (createTextNode); a bare string child is assigned via innerHTML,
            // which would execute markup in untrusted report fields (gateway
            // operator name, X-Cable-Routing-Id, daemon error strings).
            E('div', { 'class': 'nym-diag-row-label' }, [String(label)]),
            detail ? E('div', { 'class': 'nym-diag-row-detail' }, [String(detail)]) : ''
        ])
    ]);
};
var group = function(title, rows) {
    if (!rows.length) rows = [E('div', { 'class': 'nym-diag-empty' }, 'No results.')];
    return E('div', { 'class': 'nym-diag-group' },
        [E('div', { 'class': 'nym-diag-group-title' }, [String(title)])].concat(rows));
};
var dnsRow = function(label, r) {
    var res = r.resolution || {};
    var detail;
    if (res.ok)
        detail = r.hostname + ' → ' + (res.value || []).join(', ') +
            ' (' + r.resolution_duration_ms + 'ms)';
    else
        detail = r.hostname + ' → ' + (res.error || 'failed');
    return row(label, !!res.ok, detail);
};

var renderReport = function(report) {
    var groups = [];

    // DNS resolution — host resolvers plus each configured nameserver.
    if (report.dns) {
        var dnsRows = [];
        var sys = report.dns.system;
        if (sys) {
            if (sys.ok && sys.value)
                sys.value.forEach(function(r) { dnsRows.push(dnsRow('System resolvers', r)); });
            else
                dnsRows.push(row('System resolvers', false, sys.error || 'failed'));
        }
        (report.dns.by_nameserver || []).forEach(function(r) {
            dnsRows.push(dnsRow(r.nameservers || 'nameserver', r));
        });
        groups.push(group('DNS Resolution', dnsRows));
    }

    // HTTP — VPN API time skew, health endpoint, node count.
    if (report.http) {
        var httpRows = [];
        var h = report.http;
        if (h.ok && h.value) {
            var v = h.value;
            if (v.remote_time) {
                var rt = v.remote_time;
                httpRows.push(row('API time skew',
                    !!(rt.ok && rt.value && rt.value.accetably_synced),
                    rt.ok && rt.value
                        ? ('local ' + rt.value.local_time + ' / remote ' + rt.value.estimated_remote_time)
                        : (rt.error || 'failed')));
            }
            if (v.health_response) {
                var hr = v.health_response;
                httpRows.push(row('API health', !!hr.ok,
                    hr.ok && hr.value ? (hr.value.status + ' @ ' + hr.value.timestamp_utc)
                        : (hr.error || 'failed')));
            }
            if (v.nb_nymnodes) {
                var nn = v.nb_nymnodes;
                httpRows.push(row('Nym nodes reachable', !!nn.ok,
                    nn.ok ? (nn.value + ' nodes') : (nn.error || 'failed')));
            }
        } else {
            httpRows.push(row('VPN API', false, h.error || 'failed'));
        }
        groups.push(group('VPN API (HTTP)', httpRows));

        // Per-endpoint reachability, incl. domain-fronted probes (#5300).
        if (h.ok && h.value && (h.value.by_endpoint || []).length) {
            var epRows = h.value.by_endpoint.map(function(ep) {
                if (ep.ok && ep.value) {
                    var u = ep.value.url || {};
                    var fronted = !!(u.front_hosts && u.front_hosts.length);
                    return row((u.url || 'endpoint') + (fronted ? ' [fronted]' : ''),
                        true,
                        'status: ' + ep.value.status +
                            (fronted ? ' · via ' + u.front_hosts.join(', ') : ''));
                }
                return row('endpoint', false, ep.error || 'failed');
            });
            groups.push(group('API Endpoints', epRows));
        }
    }

    // Gateway — selection plus TCP/WebSocket reachability.
    if (report.gateway) {
        var gwRows = [];
        var g = report.gateway;
        if (g.gateway) {
            var sel = g.gateway;
            var val = sel.value || {};
            var gwName = val.name || val.identity_key || val.identityKey || 'selected';
            gwRows.push(row('Gateway selection', !!sel.ok,
                sel.ok ? gwName : (sel.error || 'failed')));
        }
        if (g.tcp)
            gwRows.push(row('TCP reachability', !!g.tcp.ok,
                g.tcp.ok ? 'connected' : (g.tcp.error || 'failed')));
        if (g.websocket)
            gwRows.push(row('WebSocket handshake', !!g.websocket.ok,
                g.websocket.ok ? 'connected' : (g.websocket.error || 'failed')));
        if (g.websocket_request)
            gwRows.push(row('WebSocket request', !!g.websocket_request.ok,
                g.websocket_request.ok ? (g.websocket_request.value || 'ok')
                    : (g.websocket_request.error || 'failed')));
        groups.push(group('Gateway', gwRows));
    }

    // Hybrid Transport — CTAP 2.2 relay reachability canary (#5314).
    // Omitted from the JSON when --skip-hybrid-transport was passed.
    if (report.hybrid_transport) {
        var ht = report.hybrid_transport;
        groups.push(group('Hybrid Transport', [
            row('CTAP relay (cable.ua5v.com)', !!ht.ok,
                ht.ok && ht.value
                    ? ('routing-id ' + ht.value.routing_id + ' (' + ht.value.handshake_duration_ms + 'ms)')
                    : (ht.error || 'failed'))
        ]));
    }

    if (!groups.length)
        groups.push(E('div', { 'class': 'nym-diag-empty' }, 'Diagnostic returned no sections.'));
    return groups;
};

return baseclass.extend({
    renderReport: renderReport,

    render: function(store, api) {
        var results = E('div', { 'class': 'nym-diag-results empty' },
            'Run a diagnostic to test DNS, API, and gateway connectivity.');
        var skipDns = E('input', { 'type': 'checkbox', 'id': 'diag-skip-dns' });
        var skipHttp = E('input', { 'type': 'checkbox', 'id': 'diag-skip-http' });
        var runBtn = E('button', { 'class': 'nym-btn nym-btn-primary nym-btn-small', 'type': 'button' }, 'Run Diagnostic');
        var running = false;

        var run = function() {
            if (running) return;
            running = true;
            runBtn.disabled = true;
            runBtn.textContent = 'Running…';
            results.className = 'nym-diag-results empty';
            results.textContent = 'Running diagnostic — this may take a few seconds…';

            var reset = function() {
                running = false;
                runBtn.disabled = false;
                runBtn.textContent = 'Run Diagnostic';
            };

            api.diagnosticRun(skipDns.checked, skipHttp.checked, '').then(function(result) {
                reset();
                if (!result || result.success !== true) {
                    results.className = 'nym-diag-results empty';
                    results.textContent = (result && result.error) || 'Diagnostic failed.';
                    return;
                }
                var report;
                try { report = JSON.parse(result.report); }
                catch (e) {
                    results.className = 'nym-diag-results empty';
                    results.textContent = 'Could not parse diagnostic report.';
                    return;
                }
                results.className = 'nym-diag-results';
                dom.content(results, renderReport(report));
            }).catch(function(err) {
                reset();
                results.className = 'nym-diag-results empty';
                results.textContent = 'Diagnostic error: ' + (err && err.message ? err.message : err);
            });
        };
        runBtn.onclick = run;

        return card.create({
            icon: assets.iconDiagnostic,
            title: 'Diagnostics',
            body: [
                E('div', { 'class': 'nym-card-description' },
                    'Run a connectivity self-test against DNS, the Nym VPN API, and the selected gateway.'),
                E('div', { 'class': 'nym-diag-controls' }, [
                    runBtn,
                    E('label', { 'class': 'nym-diag-check' }, [skipDns, ' Skip DNS']),
                    E('label', { 'class': 'nym-diag-check' }, [skipHttp, ' Skip HTTP'])
                ]),
                results
            ]
        }).el;
    }
});
