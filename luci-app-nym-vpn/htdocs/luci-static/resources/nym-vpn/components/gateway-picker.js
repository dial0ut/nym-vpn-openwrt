'use strict';
'require baseclass';
'require dom';
'require nym-vpn.countries as countries';
'require nym-vpn.components.details as details';

// The two gateway pickers (entry and exit): a country dropdown filled on
// first focus (Random and All countries on top), a search box that narrows
// the list, the gateway list itself (two lines per gateway: the name and
// its tier, then a telemetry line with the No CT marker at its end,
// explained by an (i) legend under the list), and the restore of the
// daemon's saved selection after a disconnect.

var E = dom.create.bind(dom);

// The bridge reports performance as one string, "High (load: Low, uptime:
// 95%)" (or "N/A"). The tier is the leading score word only: the load in
// the parentheses uses the same words, so a match anywhere in the string
// would read "Low (load: High, ...)" as High.
var TIERS = { high: 'High', medium: 'Medium', low: 'Low', offline: 'Offline' };
var RANKS = { high: 3, medium: 2, low: 1, unknown: 1, offline: 0 };
var tierOf = function(p) {
    var m = /^\s*(\w+)/.exec(String(p || ''));
    var word = m ? m[1].toLowerCase() : '';
    return TIERS.hasOwnProperty(word) ? word : 'unknown';
};
var perfRank = function(p) { return RANKS[tierOf(p)]; };

// Split the string into the tier and its two components so the row can
// show the tier as a label and the rest as telemetry; anything that does
// not match keeps the raw string as its telemetry line.
var parsePerformance = function(raw) {
    var s = String(raw || '').trim();
    var m = /^(\w+)\s*\(load:\s*(\w+),\s*uptime:\s*(\d+)%\)$/i.exec(s);
    var tier = tierOf(s);
    if (!m) {
        // Only a known tier word is a real tier; "N/A"/"Unknown" is neither.
        var known = tier !== 'unknown';
        var shown = s && !known && !/^n\/?a$/i.test(s) ? s : '';
        return { tier: tier, label: known ? TIERS[tier] : 'N/A', telemetry: shown, raw: s };
    }
    return {
        tier: tier,
        label: TIERS[tier] || m[1],
        telemetry: 'load ' + m[2].toLowerCase() + ' · uptime ' + m[3] + '%',
        raw: s
    };
};

var selectHasOption = function(select, value) {
    for (var i = 0; i < select.options.length; i++)
        if (select.options[i].value === value) return true;
    return false;
};

// Whitespace-separated terms, all of which must appear in a row's search
// text (name, identity key, city, operator family, country).
var searchTerms = function(input) {
    var q = String(input.value || '').trim().toLowerCase();
    return q ? q.split(/\s+/) : [];
};

return baseclass.extend({
    // Returns the picker pair. Each side exposes {select, list}; the pair
    // exposes markDirty/invalidate/settle/restore/selection.
    create: function(store, api) {
        // The daemon persists entry/exit points across disconnects; restore()
        // prefills the pickers from that saved config so the explicit-choice
        // guard in the connect flow passes with the previous selection
        // visible. dirty stops a restore from stomping on picks the user is
        // making right now; generation aborts stale in-flight restores when
        // the state moves on (connect, reconnect).
        var dirty = false;
        var generation = 0;
        var markDirty = function() { dirty = true; };

        var populateCountrySelect = function(select, countryList) {
            while (select.options.length > 0) select.remove(0);
            select.appendChild(E('option', { 'value': 'none' }, '— Select Country —'));
            select.appendChild(E('option', { 'value': 'random' }, '🌐 Random'));
            // Every gateway in one list, for finding one by name without
            // knowing its country. A view, not a location: selection()
            // reports a pick from it by gateway id, or as Random.
            var total = countryList.reduce(function(n, c) { return n + (c.count || 0); }, 0);
            if (total) select.appendChild(E('option', { 'value': 'all' }, ['🗺️ All countries (' + total + ')']));
            // The directory returns countries in ISO-code order; sort by the
            // displayed name so the dropdown reads alphabetically.
            var sorted = countryList.slice().sort(function(a, b) {
                return countries.getDisplay(a.code).name.localeCompare(countries.getDisplay(b.code).name);
            });
            sorted.forEach(function(c) {
                var info = countries.getDisplay(c.code);
                // An unknown code is shown as-is, so it is text too.
                select.appendChild(E('option', { 'value': c.code },
                    [info.flag + ' ' + info.name + ' (' + c.count + ')']));
            });
        };

        var createCountrySelect = function(gwType, name, onSelect) {
            var select = E('select', {
                'class': 'nym-select',
                'name': name,
                'change': onSelect
            }, [E('option', { 'value': 'none' }, '— Select Country —')]);

            // Populate options on demand: first focus, or a programmatic
            // prefill via ensureLoaded(). The promise is cached so the options
            // are only built once; a failed load clears it so the next attempt
            // retries.
            var loadPromise = null;
            select.ensureLoaded = function() {
                if (!loadPromise) {
                    loadPromise = api.gatewayCountries(gwType).then(function(list) {
                        populateCountrySelect(select, list);
                    }).catch(function() {
                        loadPromise = null;
                        select.options[0].textContent = '— Failed to load —';
                    });
                }
                return loadPromise;
            };
            select.addEventListener('focus', function() { select.ensureLoaded(); });
            return select;
        };

        // Show the rows matching the side's search box and update the count
        // under the list. The checked row stays visible whatever the query,
        // so the pick that will connect is never hidden.
        var applyFilter = function(side) {
            var list = side.list.querySelector('.nym-gateway-list');
            if (!list) return;
            var terms = searchTerms(side.search);
            var shown = 0, total = 0;
            Array.prototype.forEach.call(list.querySelectorAll('.nym-gateway-option'), function(opt) {
                var radio = opt.querySelector('input');
                var isGateway = opt.searchText !== undefined;
                var match = isGateway && terms.every(function(t) { return opt.searchText.indexOf(t) !== -1; });
                opt.hidden = terms.length > 0 && !match && !(radio && radio.checked);
                if (!isGateway) return;
                total++;
                if (match) shown++;
            });
            var empty = side.list.querySelector('.nym-gateway-nomatch');
            if (empty) {
                empty.hidden = !terms.length || shown > 0;
                empty.textContent = 'No gateway matches "' + side.search.value.trim() + '"';
            }
            var count = side.list.querySelector('.nym-gateway-count');
            if (count) count.textContent = terms.length ? shown + ' of ' + total + ' gateways' : total + ' gateways available';
        };

        var loadGatewaysForCountry = function(side, country) {
            var type = side.type, container = side.list;
            if (!country || country === 'none') {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country, or search by name'));
                return Promise.resolve();
            }
            if (country === 'random') {
                dom.content(container, '');
                return Promise.resolve();
            }

            dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Loading gateways...'));

            return api.gatewaysForCountry(type, country).then(function(result) {
                if (!result || !result.gateways || result.gateways.length === 0) {
                    dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'No gateways available'));
                    return;
                }

                var inputName = type === 'mixnet-entry' ? 'entry_gateway_id' : 'exit_gateway_id';
                // Circumvention Transports gating: when CT is on, only bridge-
                // capable gateways are valid ENTRY gateways. For the entry
                // picker only, sink incompatible gateways and disable selecting
                // them. gw.bridges is only present when the daemon reports it,
                // so treat strictly === false to stay graceful against an
                // older daemon.
                var ctFilter = (inputName === 'entry_gateway_id') && store.circumvention;

                var sorted = result.gateways.slice().sort(function(a, b) {
                    if (ctFilter) {
                        var ca = (a.bridges === false) ? 1 : 0;
                        var cb = (b.bridges === false) ? 1 : 0;
                        if (ca !== cb) return ca - cb;
                    }
                    return perfRank(b.performance) - perfRank(a.performance);
                });

                var gatewayList = E('div', { 'class': 'nym-gateway-list' });
                var allCountries = country === 'all';

                var selectOption = function(option) {
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    option.classList.add('selected');
                };

                // One row per gateway, two lines on a two-column grid. Line
                // 1: the name (one line, ellipsised, full text in its title)
                // and the tier. Line 2: the telemetry (load, uptime, operator
                // family, city) and the No CT marker. The side
                // columns are sized by their content, so a marker can never
                // be pushed under the name's ellipsis. Every row is the same
                // height, so the list shows as many as fit.
                // Every string here comes from the directory (operator-
                // controlled) and is array-wrapped so it renders as text.
                //   row: {name, value, checked, disabled, perf, city, family,
                //         flag, search, noCt, note, index}
                var buildRow = function(row) {
                    var inputAttrs = { 'type': 'radio', 'name': inputName, 'value': row.value };
                    if (row.checked) inputAttrs.checked = 'checked';
                    if (row.disabled) inputAttrs.disabled = 'disabled';

                    var name = String(row.name || 'Unknown');
                    var meta = [];
                    if (row.perf && row.perf.telemetry) {
                        // The parsed "load · uptime" pair, or the raw string
                        // for a bridge whose format the parser does not know.
                        // "N/A" has nothing to say here and is skipped (the
                        // tier label already reads N/A).
                        meta.push(E('span', { 'class': 'nym-gateway-option-perf' }, [row.perf.telemetry]));
                    }
                    // Family before city: the family is what gateway
                    // independence checks, the city the token to lose if the
                    // line clips.
                    if (row.family) meta.push(E('span', { 'class': 'nym-gateway-option-family' }, [row.family]));
                    if (row.city) meta.push(E('span', { 'class': 'nym-gateway-option-city' }, [row.city]));
                    if (row.note) meta.push(E('span', { 'class': 'nym-gateway-option-note' }, [row.note]));
                    var metaText = meta.map(function(el) { return el.textContent; }).join(' · ');

                    var tags = [];
                    if (row.noCt) {
                        tags.push(E('span', {
                            'class': 'nym-gateway-ct-tag',
                            'title': 'No circumvention transport: not selectable while Circumvention Transports is on'
                        }, 'No CT'));
                    }

                    var children = [
                        E('input', inputAttrs),
                        E('div', { 'class': 'nym-gateway-option-name', 'title': name },
                            row.flag ? [E('span', { 'class': 'nym-gateway-option-flag' }, [row.flag]), name] : [name])
                    ];
                    if (row.perf) {
                        children.push(E('span', {
                            'class': 'nym-gateway-tier ' + row.perf.tier,
                            'title': row.perf.raw
                        }, [row.perf.label]));
                    }
                    children.push(E('div', { 'class': 'nym-gateway-option-meta', 'title': metaText }, meta));
                    if (tags.length) children.push(E('div', { 'class': 'nym-gateway-option-tags' }, tags));

                    var option = E('label', {
                        'class': 'nym-gateway-option' + (tags.length ? ' tagged' : '') + (row.checked ? ' selected' : '') + (row.disabled ? ' disabled' : ''),
                        // Staggered entrance; capped so a long list settles quickly.
                        'style': '--i:' + Math.min(row.index || 0, 10)
                    }, children);
                    // Only gateway rows are searchable; Any Gateway has none.
                    if (row.search !== undefined) option.searchText = row.search;
                    if (!row.disabled) {
                        option.addEventListener('click', function() { selectOption(option); });
                    }
                    return option;
                };

                gatewayList.appendChild(buildRow({
                    name: '🎲 Any Gateway (Random)',
                    value: '',
                    checked: true,
                    note: 'picked by the daemon at connect',
                    index: 0
                }));

                sorted.forEach(function(gw, i) {
                    var ctIncompatible = ctFilter && (gw.bridges === false);
                    // Operator family is null or absent on gateways without
                    // one and on an older bridge; city likewise.
                    var family = (typeof gw.family === 'string' && gw.family.trim()) ? gw.family.trim() : '';
                    var city = (typeof gw.city === 'string' && gw.city.trim()) ? gw.city.trim() : '';
                    var where = gw.country ? countries.getDisplay(gw.country) : null;
                    gatewayList.appendChild(buildRow({
                        name: gw.name,
                        value: gw.id || '',
                        disabled: ctIncompatible,
                        noCt: ctIncompatible,
                        perf: parsePerformance(gw.performance),
                        city: city,
                        family: family,
                        // The country is the dropdown's in a per-country
                        // list; in All countries each row shows its own.
                        flag: allCountries && where ? where.flag : '',
                        search: [gw.name, gw.id, city, family, gw.country, where && where.name]
                            .filter(function(v) { return typeof v === 'string' && v; })
                            .join(' ').toLowerCase(),
                        index: i + 1
                    }));
                });

                var legend = details.create({
                    id: 'gateway-tags-' + (container.getAttribute('data-side') || 'list'),
                    label: 'the gateway tags',
                    text: [
                        E('div', {}, ['HIGH, MEDIUM, LOW and OFFLINE are the gateway\'s performance tier; the line under the name shows its load, 24-hour uptime, operator family and city.']),
                        E('div', {}, ['No CT: cannot carry Circumvention Transports, so it cannot be picked while that switch is on.'])
                    ],
                    docs: 'gateway-tags'
                });
                dom.content(container, [
                    gatewayList,
                    E('div', { 'class': 'nym-gateway-nomatch', 'hidden': 'hidden' }),
                    E('div', { 'class': 'nym-gateway-list-footer' }, [
                        E('span', { 'class': 'nym-gateway-count' }),
                        legend.button
                    ]),
                    legend.panel
                ]);
                applyFilter(side);
            }).catch(function(err) {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading', 'style': 'color: var(--danger)' },
                    ['Error: ' + (err && err.message ? err.message : err)]));
            });
        };

        // Typing with no list on screen (no country yet, or Random) opens
        // All countries, so a gateway can be found by name alone.
        var onSearch = function(side) {
            var current = side.select.value;
            if (!searchTerms(side.search).length || (current !== 'none' && current !== 'random')) {
                applyFilter(side);
                return;
            }
            side.select.ensureLoaded().then(function() {
                if (side.select.value !== current || !selectHasOption(side.select, 'all')) return;
                markDirty();
                side.select.value = 'all';
                loadGatewaysForCountry(side, 'all');
            });
        };

        var makeSide = function(gwType, selectName) {
            var side = { type: gwType };
            side.select = createCountrySelect(gwType, selectName, function(ev) {
                markDirty();
                loadGatewaysForCountry(side, ev.target.value);
            });
            // type=text, not search: LuCI's bootstrap theme gives
            // input[type=search] content-box sizing, which outranks
            // .nym-input and pushes the box out of the panel.
            side.search = E('input', {
                'type': 'text',
                'enterkeyhint': 'search',
                'class': 'nym-input nym-gateway-search',
                'placeholder': 'Search by name, city or operator',
                'aria-label': (gwType === 'mixnet-entry' ? 'Entry' : 'Exit') + ' gateway search',
                'autocomplete': 'off',
                'spellcheck': 'false',
                'input': function() { onSearch(side); },
                'keydown': function(ev) {
                    // Enter would submit LuCI's page form; Escape clears.
                    if (ev.key === 'Enter') {
                        ev.preventDefault();
                    } else if (ev.key === 'Escape' && side.search.value) {
                        ev.preventDefault();
                        side.search.value = '';
                        applyFilter(side);
                    }
                }
            });
            // 'change' only fires on user interaction (radio clicks bubble;
            // programmatic prefill doesn't), so it is exactly the dirty
            // signal we want.
            side.list = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0', 'change': markDirty,
                'data-side': selectName.split('_')[0] },
                E('div', { 'class': 'nym-gateway-loading' }, 'Select a country, or search by name'));
            return side;
        };

        var entry = makeSide('mixnet-entry', 'entry_country');
        var exit = makeSide('mixnet-exit', 'exit_country');

        // Prefill one side. saved = {type, country, id} from gateway_get:
        // type 'random' selects the Random option; 'country' opens the saved
        // country with the default "Any Gateway" radio; 'gateway' additionally
        // checks the saved gateway's radio, degrading to country-level when
        // the gateway is gone from the directory or CT-disabled.
        var restoreSide = function(side, saved, gen) {
            var select = side.select, container = side.list;
            if (!select || !saved || !saved.type) return Promise.resolve();
            var stale = function() { return gen !== generation || dirty; };
            return select.ensureLoaded().then(function() {
                if (stale()) return;
                if (saved.type === 'random') {
                    if (selectHasOption(select, 'random')) {
                        select.value = 'random';
                        return loadGatewaysForCountry(side, 'random');
                    }
                    return;
                }
                if (!saved.country || !selectHasOption(select, saved.country)) return;
                select.value = saved.country;
                return loadGatewaysForCountry(side, saved.country).then(function() {
                    if (stale() || saved.type !== 'gateway' || !saved.id || !container) return;
                    var radio = container.querySelector('input[value="' + saved.id + '"]');
                    if (!radio || radio.disabled) return;
                    radio.checked = true;
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    var opt = radio.closest('.nym-gateway-option');
                    if (opt) opt.classList.add('selected');
                    applyFilter(side);
                });
            });
        };

        var checkedId = function(side, name) {
            var radio = side.list ? side.list.querySelector('input[name="' + name + '"]:checked') : null;
            return radio ? radio.value : null;
        };

        // Warm the picker data shortly after load instead of on first click:
        // the transfer happens while the user is still looking at the
        // dashboard, and a daemon whose directory cache is still cold (e.g.
        // right after a restart) gets its fetch out of the way early. Errors
        // are swallowed — the pickers retry on interaction.
        window.setTimeout(function() {
            api.gatewayList('mixnet-entry').catch(function() {});
            api.gatewayList('mixnet-exit').catch(function() {});
        }, 1500);

        return {
            entry: entry,
            exit: exit,
            markDirty: markDirty,
            // Abort any in-flight restore: what the pickers show now stands.
            invalidate: function() { generation++; },
            // The picks have reached the daemon; the dirty flag has served
            // its purpose.
            settle: function() { dirty = false; },
            restore: function() {
                if (dirty) return;
                var gen = ++generation;
                api.gatewayGet().then(function(cfg) {
                    if (!cfg || gen !== generation || dirty) return;
                    restoreSide(entry, { type: cfg.entry_type, country: cfg.entry_country, id: cfg.entry_id }, gen);
                    restoreSide(exit, { type: cfg.exit_type, country: cfg.exit_country, id: cfg.exit_id }, gen);
                }).catch(function() {});
            },
            // Raw picker state: country values ('none', 'random' or a code)
            // and the checked gateway ids (null when none). All countries
            // is not a location: a gateway picked from it goes by its id,
            // and its Any Gateway row is plain Random.
            selection: function() {
                var entryId = checkedId(entry, 'entry_gateway_id');
                var exitId = checkedId(exit, 'exit_gateway_id');
                var country = function(side, id) {
                    var v = side.select ? side.select.value : 'none';
                    return v === 'all' && !id ? 'random' : v;
                };
                return {
                    entry_country: country(entry, entryId),
                    exit_country: country(exit, exitId),
                    entry_id: entryId,
                    exit_id: exitId
                };
            },
            focus: function() {
                if (entry.select) {
                    try { entry.select.focus({ preventScroll: true }); } catch (e) { entry.select.focus(); }
                }
            }
        };
    }
});
