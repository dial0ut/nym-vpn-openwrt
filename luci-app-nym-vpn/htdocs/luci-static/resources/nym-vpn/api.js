'use strict';
'require baseclass';
'require nym-vpn.rpc as rpc';

// Everything the page asks the rpcd bridge, plus the normalisation of what
// comes back: 'on'/'off' vs booleans, the flat entry_family / nested
// entry.family shapes, replies that are not objects at all. Cards and flows
// talk to this module and never parse raw bridge JSON themselves.

var onish = function(v) { return v === true || v === 'on' || v === 'true' || v === 1; };

// Gateway independence (upstream calls it node families). tunnel_get
// reports {enabled, notifications, different_node_family, different_asn,
// different_subnet}; the bridge may emit booleans or 'on'/'off', and an
// older bridge emits nothing, so read it defensively. Defaults mirror the
// daemon's: criteria enforced, reminders on.
var readIndependence = function(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        enabled: raw.enabled === undefined ? true : onish(raw.enabled),
        notifications: raw.notifications === undefined ? true : onish(raw.notifications)
    };
};

// A tunnel_get reply that actually came from the daemon, as opposed to the
// degraded all-empty reply the bridge emits when the daemon is unreachable.
var isRealTunnelReply = function(cfg) {
    return !!cfg && (cfg.two_hop === 'on' || cfg.two_hop === 'off');
};

// Operator family of one side of a status reply. Flat entry_family /
// exit_family like the other entry_*/exit_* fields; a nested
// {entry: {family}} shape is accepted too.
var familyOf = function(st, side) {
    if (!st) return '';
    var v = st[side + '_family'];
    if ((v === undefined || v === null) && st[side] && typeof st[side] === 'object') v = st[side].family;
    return (typeof v === 'string') ? v.trim() : '';
};

var sameFamily = function(a, b) {
    return !!a && !!b && a.toLowerCase() === b.toLowerCase();
};

// LuCI's rpc.js bounds every request at L.env.rpctimeout (20 s) with no
// per-call option, but reads it per request: raise it around one call and
// put it back once the reply is in. The daemon stop/restart/reset methods
// block for the init script's real stop (disconnect, SIGTERM, wait for the
// pid: up to ~35 s with a hung daemon); 60 s is uhttpd's own ubus bound.
var SLOW_CALL_TIMEOUT_S = 60;
var withSlowCallTimeout = function(call) {
    var env = (typeof L !== 'undefined' && L && L.env) ? L.env : null;
    if (!env) return call();
    var had = Object.prototype.hasOwnProperty.call(env, 'rpctimeout');
    var prev = env.rpctimeout;
    var restore = function() {
        if (had) env.rpctimeout = prev; else delete env.rpctimeout;
    };
    env.rpctimeout = Math.max(prev || 0, SLOW_CALL_TIMEOUT_S);
    var pending;
    try {
        pending = Promise.resolve(call());
    } catch (e) {
        restore();
        return Promise.reject(e);
    }
    return pending.then(function(v) { restore(); return v; }, function(e) { restore(); throw e; });
};

// The daemon's error-state reason for a non-independent pair. The bridge
// passes the variant name through (error_reason_ident), so match case- and
// separator-insensitively: both NeedsRelaxedIndependenceCriteria and
// NEEDS_RELAXED_INDEPENDENCE_CRITERIA hit.
var isIndependenceError = function(reason) {
    return typeof reason === 'string' &&
        reason.replace(/[^a-z]/gi, '').toLowerCase() === 'needsrelaxedindependencecriteria';
};

// Derive account flags from an `account get` result. A leftover device
// identity paired with a LoggedOut/cleared state must NOT read as logged
// in — that is the 1.27.1 desync where the Account card offered "Sign out"
// while the status strip simultaneously said "no account configured".
// State is authoritative; a stale identity does not count.
var computeAccountFlags = function(acct) {
    acct = acct || {};
    var identity = acct.identity || '';
    var rawState = acct.state || '';
    var state = rawState.replace(/([a-z])([A-Z])/g, '$1 $2');
    var invalidIdentities = ['', 'Not set', 'LoggedOut', 'unset', 'none'];
    // The daemon never answered — either it said so (`available:false`) or,
    // on an older bridge, both fields came back empty, which no real reply
    // produces. This outranks every other flag: showing the login form for
    // a question we never got to ask is what made the 1.33.1 upgrade look
    // like it had wiped the stored account.
    var isUnavailable = acct.available === false || (!identity && !rawState);
    var hasError = state.indexOf('Error') >= 0 || identity.indexOf('Error') >= 0;
    var isLoggedOut = (rawState || '').trim() === 'LoggedOut';
    var isLoggedIn = !isUnavailable && !!identity && invalidIdentities.indexOf(identity) === -1 && !hasError && !isLoggedOut;
    return {
        identity: identity, rawState: rawState, state: state,
        hasError: hasError, isLoggedIn: isLoggedIn, isLoggedOut: isLoggedOut,
        isUnavailable: isUnavailable,
        // Only meaningful while unavailable; absent on a real reply.
        daemonRunning: acct.daemon_running !== false,
        daemonEnabled: acct.daemon_enabled !== false
    };
};

return baseclass.extend({
    __init__: function() {
        // One gateway_list_full call per type (served by the Rust rpcd
        // bridge from the daemon's directory cache) feeds both the country
        // dropdown and every per-country list for the rest of the session.
        this.gatewayListCache = {};
        this.countryCache = {};
    },

    onish: onish,
    readIndependence: readIndependence,
    isRealTunnelReply: isRealTunnelReply,
    familyOf: familyOf,
    sameFamily: sameFamily,
    isIndependenceError: isIndependenceError,
    computeAccountFlags: computeAccountFlags,

    // Client-side bound on the pre-connect check; the daemon bounds it too.
    TENTATIVE_TIMEOUT_MS: 6000,

    // --- session / status ------------------------------------------------
    init: function() { return rpc.init(); },
    status: function() { return rpc.status(); },
    disconnect: function() { return rpc.disconnect(); },

    // `relax` sends relax_independence:true — a one-shot for this connect
    // and its automatic reconnects; the persisted setting is untouched. Left
    // out entirely otherwise so an older bridge sees the same request as
    // before.
    connect: function(relax) {
        return relax ? rpc.connect(true) : rpc.connect();
    },

    // Ask the daemon which entry/exit pair the saved selection resolves to
    // and whether it passes the independence criteria. Resolves to the reply
    // object or null — never rejects — and gives up after 6 s so a slow
    // directory can't stall the Connect button. An rpc.js that predates the
    // declaration resolves to null as well.
    tentativeGateways: function() {
        if (typeof rpc.tentativeGateways !== 'function') return Promise.resolve(null);
        var timeoutMs = this.TENTATIVE_TIMEOUT_MS;
        return new Promise(function(resolve) {
            var settled = false;
            var finish = function(value) {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                resolve(value && typeof value === 'object' && !Array.isArray(value) ? value : null);
            };
            var timer = setTimeout(function() { finish(null); }, timeoutMs);
            try {
                rpc.tentativeGateways().then(finish, function() { finish(null); });
            } catch (e) {
                finish(null);
            }
        });
    },

    // --- gateways ----------------------------------------------------------
    gatewayGet: function() { return rpc.gatewayGet(); },

    // sel: {entry_country, exit_country, entry_id, exit_id, entry_random,
    // exit_random, residential_exit}; missing keys are sent as null.
    gatewaySet: function(sel) {
        sel = sel || {};
        var nul = function(v) { return v === undefined ? null : v; };
        return rpc.gatewaySet(nul(sel.entry_country), nul(sel.exit_country), sel.entry_id || null, sel.exit_id || null,
            !!sel.entry_random, !!sel.exit_random, nul(sel.residential_exit));
    },

    // Full list for one gateway type, cached for the session. Rejects when
    // the bridge cannot serve it (older backend); the failure is not cached
    // so the next interaction retries.
    gatewayList: function(gwType) {
        var self = this;
        if (!this.gatewayListCache[gwType]) {
            this.gatewayListCache[gwType] = rpc.gatewayListFull(gwType).then(function(result) {
                if (!result || !Array.isArray(result.gateways))
                    throw new Error((result && result.error) || 'Invalid gateway list');
                if (result.error && result.gateways.length === 0)
                    throw new Error(result.error);
                return result.gateways;
            }).catch(function(err) {
                self.gatewayListCache[gwType] = null;
                throw err;
            });
        }
        return this.gatewayListCache[gwType];
    },

    // [{code, count}] derived from the full list; the per-country-counts RPC
    // is only a fallback for older backends (cached once it answers).
    gatewayCountries: function(gwType) {
        var self = this;
        return this.gatewayList(gwType).then(function(gateways) {
            var counts = {};
            gateways.forEach(function(gw) {
                if (gw.country) counts[gw.country] = (counts[gw.country] || 0) + 1;
            });
            return Object.keys(counts).sort().map(function(code) {
                return { code: code, count: counts[code] };
            });
        }).catch(function() {
            return self.countryCache[gwType]
                ? Promise.resolve(self.countryCache[gwType])
                : rpc.gatewayListCountries(gwType).then(function(result) {
                    var list = (result && result.countries) || [];
                    self.countryCache[gwType] = list;
                    return list;
                });
        });
    },

    // {gateways: [...]} for one country, from the full list or the older
    // per-country RPC.
    gatewaysForCountry: function(gwType, country) {
        return this.gatewayList(gwType).then(function(list) {
            return { gateways: list.filter(function(gw) { return gw.country === country; }) };
        }).catch(function() {
            return rpc.gatewayListByCountry(gwType, country);
        });
    },

    // --- tunnel settings ---------------------------------------------------
    tunnelGet: function() { return rpc.tunnelGet(); },

    // cfg: {ipv6, two_hop, killswitch, circumvention, legacy_split_tunnel,
    // stealth_api, always_on} as 'on'/'off'.
    tunnelSet: function(cfg) {
        return rpc.tunnelSet(cfg.ipv6, cfg.two_hop, cfg.killswitch, cfg.circumvention, cfg.legacy_split_tunnel, cfg.stealth_api, cfg.always_on);
    },

    // key is 'enabled' (gateway_independence) or 'notifications'
    // (family_reminders); only that key is sent so the daemon leaves the
    // other alone.
    independenceSet: function(key, enabled) {
        var value = enabled ? 'on' : 'off';
        return key === 'enabled'
            ? rpc.gatewayIndependenceSet(value, undefined)
            : rpc.gatewayIndependenceSet(undefined, value);
    },

    // t: {loop_cover_delay, packet_delay, message_delay} as strings ('' =
    // leave as is) and {disable_poisson, disable_cover} as 'on'/'off'.
    mixnetTuningSet: function(t) {
        return rpc.mixnetTuningSet(t.loop_cover_delay, t.packet_delay, t.message_delay, t.disable_poisson, t.disable_cover);
    },

    // --- inbound services / split tunneling --------------------------------
    inboundAdd: function(proto, dport, label) { return rpc.inboundAdd(proto, dport, label); },
    inboundDel: function(proto, dport) { return rpc.inboundDel(proto, dport); },
    splitAdd: function(kind, mac, domain, label) { return rpc.splitAdd(kind, mac, domain, label); },
    splitDel: function(id) { return rpc.splitDel(id); },
    splitSetEnabled: function(id, enabled) { return rpc.splitSetEnabled(id, enabled); },

    // --- DNS ---------------------------------------------------------------
    dnsSet: function(enabled, servers) { return rpc.dnsSet(enabled, servers); },
    adBlockSet: function(enabled) { return rpc.adBlockSet(enabled); },

    // --- account -----------------------------------------------------------
    accountGet: function() { return rpc.accountGet(); },
    accountSet: function(mnemonic, mode) { return rpc.accountSet(mnemonic, mode); },
    accountForget: function() { return rpc.accountForget(); },
    accountReset: function() { return withSlowCallTimeout(function() { return rpc.accountReset(); }); },
    accountRotateKeys: function() { return rpc.accountRotateKeys(); },

    // --- daemon ------------------------------------------------------------
    SLOW_CALL_TIMEOUT_S: SLOW_CALL_TIMEOUT_S,
    daemonStatus: function() { return rpc.daemonStatus(); },
    daemonStart: function() { return rpc.daemonStart(); },
    daemonStop: function() { return withSlowCallTimeout(function() { return rpc.daemonStop(); }); },
    daemonRestart: function() { return withSlowCallTimeout(function() { return rpc.daemonRestart(); }); },

    // --- troubleshooting ---------------------------------------------------
    logsGet: function(lines) { return rpc.logsGet(lines); },
    diagnosticRun: function(skipDns, skipHttp, gateway) { return rpc.diagnosticRun(skipDns, skipHttp, gateway); }
});
