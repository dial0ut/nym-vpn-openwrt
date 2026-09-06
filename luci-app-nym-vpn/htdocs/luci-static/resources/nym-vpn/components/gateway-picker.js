'use strict';
'require baseclass';
'require dom';
'require nym-vpn.assets as assets';
'require nym-vpn.countries as countries';
'require nym-vpn.ui as nymUI';

// The two gateway pickers (entry and exit): a country dropdown filled on
// first focus, a per-country server list with performance indicators and
// the operator-family chip, and the restore of the daemon's saved selection
// after a disconnect.

var E = dom.create.bind(dom);

var perfRank = function(p) {
    p = p || '';
    return p.indexOf('High') >= 0 ? 3 :
           p.indexOf('Medium') >= 0 ? 2 :
           p.indexOf('Offline') >= 0 ? 0 : 1;
};

var selectHasOption = function(select, value) {
    for (var i = 0; i < select.options.length; i++)
        if (select.options[i].value === value) return true;
    return false;
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
            // The directory returns countries in ISO-code order; sort by the
            // displayed name so the dropdown reads alphabetically.
            var sorted = countryList.slice().sort(function(a, b) {
                return countries.getDisplay(a.code).name.localeCompare(countries.getDisplay(b.code).name);
            });
            sorted.forEach(function(c) {
                var info = countries.getDisplay(c.code);
                select.appendChild(E('option', { 'value': c.code },
                    info.flag + ' ' + info.name + ' (' + c.count + ')'));
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

        var loadGatewaysForCountry = function(country, type, container) {
            if (!country || country === 'none') {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading' }, 'Select a country above'));
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

                var selectOption = function(option) {
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    option.classList.add('selected');
                };

                var randomOption = E('label', { 'class': 'nym-gateway-option selected' }, [
                    E('input', { 'type': 'radio', 'name': inputName, 'value': '', 'checked': 'checked' }),
                    E('div', { 'class': 'nym-gateway-option-info' }, [
                        E('div', { 'class': 'nym-gateway-option-name' }, '🎲 Any Gateway (Random)')
                    ])
                ]);
                randomOption.addEventListener('click', function() { selectOption(randomOption); });
                gatewayList.appendChild(randomOption);

                sorted.forEach(function(gw) {
                    var perf = gw.performance || 'Unknown';
                    var iconDiv = E('div', { 'class': 'nym-gateway-option-icon' });
                    iconDiv.innerHTML = nymUI.getQualityIcon(perf, assets);

                    var ctIncompatible = ctFilter && (gw.bridges === false);

                    var nameChildren = [String(gw.name || 'Unknown')];
                    if (ctIncompatible) {
                        nameChildren.push(E('span', {
                            'style': 'margin-left:6px; padding:1px 5px; border-radius:8px; font-size:9px; text-transform:uppercase; letter-spacing:0.5px; background:var(--danger,#e74c3c); color:#fff; vertical-align:middle'
                        }, 'No CT'));
                    }

                    var inputAttrs = { 'type': 'radio', 'name': inputName, 'value': gw.id || '' };
                    if (ctIncompatible) inputAttrs.disabled = 'disabled';

                    // Array-wrap: gateway name/perf come from the directory
                    // (operator-controlled) and must render as text, not innerHTML.
                    var infoChildren = [
                        E('div', { 'class': 'nym-gateway-option-name' }, nameChildren),
                        E('div', { 'class': 'nym-gateway-option-perf' }, [String(perf)])
                    ];
                    // Operator family chip; the field is null or absent on
                    // gateways without one and on an older bridge.
                    if (typeof gw.family === 'string' && gw.family.trim()) {
                        infoChildren.push(E('div', { 'class': 'nym-gateway-option-family' }, [
                            E('span', { 'class': 'nym-family-chip', 'title': 'Operator family' }, [gw.family.trim()])
                        ]));
                    }

                    var option = E('label', {
                        'class': 'nym-gateway-option' + (ctIncompatible ? ' disabled' : ''),
                        'style': ctIncompatible ? 'opacity:0.5; cursor:not-allowed' : ''
                    }, [
                        E('input', inputAttrs),
                        iconDiv,
                        E('div', { 'class': 'nym-gateway-option-info' }, infoChildren)
                    ]);
                    if (!ctIncompatible) {
                        option.addEventListener('click', function() { selectOption(option); });
                    }
                    gatewayList.appendChild(option);
                });

                dom.content(container, [
                    E('label', { 'class': 'nym-form-label' }, 'Gateway'),
                    gatewayList,
                    E('div', { 'style': 'font-size: 11px; color: var(--text-muted); margin-top: 8px' },
                        result.gateways.length + ' gateways available')
                ]);
            }).catch(function(err) {
                dom.content(container, E('div', { 'class': 'nym-gateway-loading', 'style': 'color: var(--danger)' },
                    'Error: ' + err.message));
            });
        };

        var makeSide = function(gwType, selectName) {
            var side = { type: gwType };
            side.select = createCountrySelect(gwType, selectName, function(ev) {
                markDirty();
                loadGatewaysForCountry(ev.target.value, gwType, side.list);
            });
            // 'change' only fires on user interaction (radio clicks bubble;
            // programmatic prefill doesn't), so it is exactly the dirty
            // signal we want.
            side.list = E('div', { 'class': 'nym-form-group', 'style': 'margin-bottom: 0', 'change': markDirty },
                E('div', { 'class': 'nym-gateway-loading' }, 'Select a country'));
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
                        return loadGatewaysForCountry('random', side.type, container);
                    }
                    return;
                }
                if (!saved.country || !selectHasOption(select, saved.country)) return;
                select.value = saved.country;
                return loadGatewaysForCountry(saved.country, side.type, container).then(function() {
                    if (stale() || saved.type !== 'gateway' || !saved.id || !container) return;
                    var radio = container.querySelector('input[value="' + saved.id + '"]');
                    if (!radio || radio.disabled) return;
                    radio.checked = true;
                    container.querySelectorAll('.nym-gateway-option').forEach(function(el) {
                        el.classList.remove('selected');
                    });
                    var opt = radio.closest('.nym-gateway-option');
                    if (opt) opt.classList.add('selected');
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
            // and the checked gateway ids (null when none).
            selection: function() {
                return {
                    entry_country: entry.select ? entry.select.value : 'none',
                    exit_country: exit.select ? exit.select.value : 'none',
                    entry_id: checkedId(entry, 'entry_gateway_id'),
                    exit_id: checkedId(exit, 'exit_gateway_id')
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
