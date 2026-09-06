'use strict';
// Behavioural checks for the NymVPN LuCI view. Loads the real modules through
// the LuCI emulation in luci-env.js with a scripted rpc, drives the DOM the
// way a user would, and asserts on what the page does. Run with `npm test`.
const { createEnv } = require('./luci-env');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
let total = 0;
function check(cond, msg) {
  total++;
  console.log((cond ? '  ok   ' : '  FAIL ') + msg);
  if (!cond) failures++;
}
function section(name) {
  console.log('\n# ' + name);
}
function eq(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ---------------------------------------------------------------- fixtures
const GATEWAYS = [
  { id: 'A1', name: 'alpha-entry', country: 'DE', performance: 'High (load: Low, uptime: 99%)', bridges: true, family: 'Acme Ops' },
  { id: 'A2', name: 'alpha-two', country: 'DE', performance: 'Medium (load: Low, uptime: 98%)', bridges: false, family: null },
  { id: 'B1', name: 'beta-exit', country: 'FR', performance: 'High (load: Low, uptime: 99%)', bridges: true, family: 'Acme Ops' },
];
const CONNECTED = {
  state: 'connected', connected: true, connected_seconds: 5,
  entry_name: 'alpha-entry', entry_id: 'A1', entry_ip: '1.1.1.1', entry_country: 'DE', entry_family: 'Acme Ops',
  exit_name: 'beta-exit', exit_id: 'B1', exit_ip: '2.2.2.2', exit_country: 'FR', exit_family: 'Acme Ops',
};
const TUNNEL = { ipv6: 'off', two_hop: 'on', killswitch: 'on', circumvention_transports: 'off', legacy_split_tunnel: 'off', stealth_api: 'off',
  gateway_independence: { enabled: true, notifications: true } };

function baseInit(extra) {
  return Object.assign({
    status: { state: 'disconnected' },
    info: { version: '1.2.3' },
    tunnel_config: Object.assign({}, TUNNEL),
    account: { identity: 'DEVICE1', state: 'Active' },
    network: { network: 'mainnet' },
    daemon: { running: true, enabled: true },
    ad_block: { enabled: false },
    dns: { enabled: false, servers: '' },
    watchdog: { always_on: 0, interval: 30 },
    inbound_exemptions: [],
    split_exclusions: [],
    split_status: { nftset_supported: true },
    clients: [{ mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.1.50', hostname: 'laptop' }],
  }, extra || {});
}

function setup(opts) {
  opts = opts || {};
  const env = createEnv(opts);
  const view = env.require('view.nym-vpn.config');
  const container = view.render(opts.init || baseInit());
  env.document.body.appendChild(container);
  return Object.assign(env, { view, container });
}

// ----------------------------------------------------------------- helpers
const q = (t, sel) => t.document.querySelector(sel);
const qa = (t, sel) => Array.from(t.document.querySelectorAll(sel));
const byId = (t, id) => t.document.getElementById(id);
const cardTitles = (t) => qa(t, '.nym-card .nym-card-title').map((e) => e.textContent.trim());
const card = (t, title) => qa(t, '.nym-card').find((c) => c.querySelector('.nym-card-title').textContent.trim() === title);
const modal = (t) => q(t, '.nym-modal-overlay');
const modalButtons = (t) => qa(t, '.nym-modal-buttons button').map((b) => b.textContent);
const clickModalButton = (t, text) => qa(t, '.nym-modal-buttons button').find((b) => b.textContent === text).click();
const toasts = (t) => qa(t, '.nym-toast-message').map((e) => e.textContent);
const callsTo = (t, method) => t.calls.filter((c) => c.method === method).map((c) => c.params);
const actionBtn = (t) => t.container.querySelector('.nym-status-hero .nym-action-buttons button');
const statusLabel = (t) => t.container.querySelector('.nym-status-label').textContent;
function fire(t, el, type) {
  el.dispatchEvent(new t.window.Event(type, { bubbles: true, cancelable: true }));
}
function setToggle(t, id, checked) {
  const el = byId(t, id);
  el.checked = checked;
  fire(t, el, 'change');
  return el;
}
async function pickGateways(t, entry, exit) {
  const entrySel = q(t, 'select[name="entry_country"]');
  const exitSel = q(t, 'select[name="exit_country"]');
  await entrySel.ensureLoaded();
  await exitSel.ensureLoaded();
  entrySel.value = entry || 'DE';
  fire(t, entrySel, 'change');
  exitSel.value = exit || 'FR';
  fire(t, exitSel, 'change');
  await sleep(30);
}
function connectEnv(overrides, initExtra) {
  let st = { state: 'disconnected' };
  const rpc = Object.assign({
    status: () => st,
    gateway_list_full: { gateways: GATEWAYS },
    connect: () => { st = CONNECTED; return { success: true }; },
  }, overrides || {});
  const t = setup({ rpc, init: baseInit(initExtra), undeclared: (overrides && overrides.__undeclared) || [] });
  t.setStatus = (s) => { st = s; };
  return t;
}

// --------------------------------------------------------------- scenarios
async function scenarioStructure() {
  section('page structure');
  const t = setup();
  check(eq(cardTitles(t), ['Tunnel Settings', 'Split Tunneling', 'Mixnet Tuning', 'DNS & Ad Blocking', 'Account', 'Service Management', 'Diagnostics', 'Daemon Logs']),
    'card order: ' + JSON.stringify(cardTitles(t)));
  check(!card(t, 'Privacy') && !byId(t, 'stats-toggle'), 'no Privacy card / statistics toggle');
  check(t.declared.indexOf('stats_get') === -1 && t.declared.indexOf('stats_set') === -1, 'stats_get / stats_set never declared');
  check(!t.calls.some((c) => /^stats_/.test(c.method)), 'no stats_* rpc call issued');
  const rows = Array.from(card(t, 'Tunnel Settings').querySelectorAll('.nym-toggle-row .nym-toggle-title')).map((e) => e.textContent);
  check(rows[0] === 'Kill-Switch', 'kill-switch is the first Tunnel Settings row: ' + JSON.stringify(rows));
  check(eq(rows.slice().sort(), ['Always On', 'Circumvention Transports', 'Gateway Independence', 'IPv6', 'Kill-Switch', 'Server Family Reminders', 'Stealth API Connect', 'Two-Hop Mode'].sort()),
    'all eight tunnel rows present, legacy split moved out');
  const splitCard = card(t, 'Split Tunneling');
  check(!!splitCard && splitCard.contains(byId(t, 'legacy-split-toggle')) && splitCard.contains(q(t, '.nym-split-section')), 'Split Tunneling card holds the legacy PBR switch and the exclusions');
  check(card(t, 'Tunnel Settings').contains(q(t, '.nym-inbound-section')), 'inbound services stay in Tunnel Settings');
  const groups = Array.from(card(t, 'Tunnel Settings').querySelectorAll('.nym-group-title')).map((e) => e.textContent);
  check(eq(groups, ['Protection', 'Inbound Services', 'Transport', 'Resilience']), 'Tunnel Settings grouped: ' + JSON.stringify(groups));
  const protection = card(t, 'Tunnel Settings').querySelector('.nym-group');
  check(protection.contains(byId(t, 'killswitch-toggle')) && protection.contains(q(t, '.nym-inbound-section')) && protection.contains(byId(t, 'gw-independence-toggle')) && protection.contains(byId(t, 'family-reminders-toggle')),
    'Protection holds kill-switch, its inbound exceptions, independence and reminders');
  check(q(t, '.nym-inbound-section').previousElementSibling === byId(t, 'killswitch-row'), 'inbound services sit directly under the kill-switch row');
  const tagged = qa(t, '.nym-toggle-row').filter((r) => r.querySelector('.nym-toggle-tag')).map((r) => r.querySelector('.nym-toggle-title').textContent);
  check(eq(tagged, ['Kill-Switch', 'Gateway Independence', 'Two-Hop Mode', 'Circumvention Transports', 'IPv6', 'Legacy Split Tunneling (PBR)']), 'reconnect tag on exactly the switches that apply on the next connect: ' + JSON.stringify(tagged));
  check(!qa(t, '.nym-toggle-desc').some((d) => /requires reconnect|applies immediately|no reconnect/i.test(d.textContent)), 'no row description repeats the reconnect note');
  check(byId(t, 'legacy-split-note').style.display === 'none', 'legacy note hidden while legacy split is off');
  check(q(t, '.nym-footer').textContent.indexOf('1.2.3') !== -1 && q(t, '.nym-footer').textContent.indexOf('mainnet') !== -1, 'footer shows version and network');
  check(q(t, '.nym-inbound-section').style.display === 'block' && q(t, '.nym-split-section').style.display === 'block', 'inbound and split sections shown (killswitch on, legacy off)');
  check(t.poll.queue.some((e) => e.i === 5) && t.poll.queue.some((e) => e.i === 10), 'status (5s) and daemon (10s) polls registered');

  const loaded = await t.view.load();
  check(t.calls.some((c) => c.method === 'init') && loaded && loaded.success === true, 'load() batches everything through init');

  // Legacy split on at load: killswitch greyed, sections hidden.
  const t2 = setup({ init: baseInit({ tunnel_config: Object.assign({}, TUNNEL, { legacy_split_tunnel: 'on', killswitch: 'off' }) }) });
  check(byId(t2, 'killswitch-toggle').disabled && byId(t2, 'killswitch-row').style.opacity === '0.5', 'legacy split on: kill-switch disabled and dimmed');
  check(q(t2, '.nym-inbound-section').style.display === 'none' && q(t2, '.nym-split-section').style.display === 'none', 'legacy split on: inbound and split sections hidden');
  check(byId(t2, 'legacy-split-note').style.display === 'block' && /luci-app-pbr/.test(byId(t2, 'legacy-split-note').textContent), 'legacy split on: PBR note stands in for the exclusions');
}

async function scenarioTunnelToggles() {
  section('tunnel settings toggles save the full set');
  const t = setup();
  setToggle(t, 'ipv6-toggle', true);
  await sleep(10);
  let sets = callsTo(t, 'tunnel_set');
  check(sets.length === 1 && eq(sets[0], { ipv6: 'on', two_hop: 'on', killswitch: 'on', circumvention: 'off', legacy_split_tunnel: 'off', stealth_api: 'off' }),
    'ipv6 change -> tunnel_set with all six fields: ' + JSON.stringify(sets[0]));
  check(toasts(t).indexOf('Tunnel settings saved') !== -1, 'saved toast');

  setToggle(t, 'legacy-split-toggle', true);
  await sleep(10);
  const ks = byId(t, 'killswitch-toggle');
  sets = callsTo(t, 'tunnel_set');
  check(ks.disabled && !ks.checked, 'legacy split on (Split Tunneling card): kill-switch in Tunnel Settings unchecked and disabled');
  check(byId(t, 'killswitch-row').style.opacity === '0.5' && byId(t, 'legacy-split-note').style.display === 'block', 'kill-switch row dimmed, PBR note shown');
  check(sets[1].killswitch === 'off' && sets[1].legacy_split_tunnel === 'on', 'legacy split forces killswitch=off in the request');
  check(q(t, '.nym-inbound-section').style.display === 'none' && q(t, '.nym-split-section').style.display === 'none', 'sections hidden while legacy split is on');
  check(byId(t, 'killswitch-row').querySelector('.nym-toggle-warning').style.display === 'none', 'kill-switch leak warning hidden under legacy split');

  setToggle(t, 'legacy-split-toggle', false);
  await sleep(10);
  check(!ks.disabled && q(t, '.nym-split-section').style.display === 'block' && byId(t, 'legacy-split-note').style.display === 'none', 'legacy off: kill-switch enabled, split section back, note gone');
  check(callsTo(t, 'tunnel_set')[2].killswitch === 'off' && callsTo(t, 'tunnel_set')[2].legacy_split_tunnel === 'off', 'legacy off leaves the kill-switch off until the user re-enables it');
  check(byId(t, 'killswitch-row').querySelector('.nym-toggle-warning').style.display === 'block', 'kill-switch off -> leak warning visible');
  setToggle(t, 'killswitch-toggle', true);
  await sleep(10);
  check(q(t, '.nym-inbound-section').style.display === 'block' && byId(t, 'killswitch-row').querySelector('.nym-toggle-warning').style.display === 'none', 'kill-switch on -> inbound section shown, warning hidden');
  sets = callsTo(t, 'tunnel_set');
  check(sets[sets.length - 1].killswitch === 'on', 'kill-switch saved on');

  // Two-hop change flips the hop count used by the chain.
  const t2 = connectEnv({}, { tunnel_config: Object.assign({}, TUNNEL, { two_hop: 'off' }) });
  setToggle(t2, 'two-hop-toggle', true);
  await sleep(10);
  await pickGateways(t2);
  actionBtn(t2).click();
  await sleep(400);
  check(t2.container.querySelectorAll('.nym-chain-node').length === 2 && q(t2, '.nym-mode-label').textContent === 'Fast Mode', 'saved two-hop -> 2-node chain, Fast Mode');

  // Save failure keeps the toggle where the user put it and toasts.
  const t3 = setup({ rpc: { tunnel_set: { success: false, error: 'nope' } } });
  setToggle(t3, 'stealth-api-toggle', true);
  await sleep(10);
  check(toasts(t3).indexOf('Failed: nope') !== -1, 'failed tunnel_set toasts the error');
  const t4 = setup({ init: baseInit({ tunnel_config: Object.assign({}, TUNNEL, { stealth_api_note: true }) }) });
  check(byId(t4, 'stealth-api-toggle').closest('.nym-toggle-row').querySelector('.nym-toggle-warning').style.display === 'block', 'stealth API note shown when the environment has no cover domains');
}

async function scenarioIndependenceToggles() {
  section('independence toggles bound to tunnel_get.gateway_independence');
  const t = setup({ init: baseInit({ tunnel_config: { two_hop: 'off', gateway_independence: { enabled: false, notifications: true } } }) });
  const ind = byId(t, 'gw-independence-toggle');
  const rem = byId(t, 'family-reminders-toggle');
  check(ind && !ind.checked, 'independence toggle reflects enabled:false');
  check(rem && rem.checked, 'reminders toggle reflects notifications:true');
  check(byId(t, 'gw-independence-note').style.display === 'none', 'unsupported note hidden');
  check(!t.calls.some((c) => c.method === 'tunnel_get'), 'no tunnel_get fallback when init carried the field');
  setToggle(t, 'gw-independence-toggle', true);
  setToggle(t, 'family-reminders-toggle', false);
  await sleep(20);
  const sets = callsTo(t, 'tunnel_set');
  check(sets.length === 2 && eq(sets[0], { gateway_independence: 'on' }) && eq(sets[1], { family_reminders: 'off' }),
    'tunnel_set called with only the changed key each time: ' + JSON.stringify(sets));
  check(toasts(t).some((m) => /independence enabled/.test(m)) && toasts(t).some((m) => /reminders disabled/.test(m)), 'toasts for both saves');

  const t2 = setup({
    init: baseInit({ tunnel_config: { two_hop: 'off', gateway_independence: { enabled: 'on', notifications: 'off' } } }),
    rpc: { tunnel_set: { success: false, error: 'nope' } },
  });
  const ind2 = byId(t2, 'gw-independence-toggle');
  check(ind2.checked && !byId(t2, 'family-reminders-toggle').checked, "'on'/'off' string form accepted");
  setToggle(t2, 'gw-independence-toggle', false);
  await sleep(20);
  check(ind2.checked === true, 'failed save reverts the switch');
  check(toasts(t2).some((m) => /Failed: nope/.test(m)), 'failure toast shown');

  const t3 = setup({ init: baseInit({ tunnel_config: { two_hop: 'off', gateway_independence: { enabled: true, notifications: true } } }), rpc: { tunnel_set: () => { throw new Error('boom'); } } });
  setToggle(t3, 'family-reminders-toggle', false);
  await sleep(20);
  check(byId(t3, 'family-reminders-toggle').checked === true && toasts(t3).some((m) => /Error: boom/.test(m)), 'rejected save reverts and toasts Error');
}

async function scenarioFallbackTunnelGet() {
  section('init without the field -> tunnel_get fallback');
  const t = setup({ init: baseInit({ tunnel_config: { two_hop: 'off' } }), rpc: { tunnel_get: { two_hop: 'off', gateway_independence: { enabled: false, notifications: false } } } });
  await sleep(20);
  check(t.calls.some((c) => c.method === 'tunnel_get'), 'tunnel_get requested');
  check(!byId(t, 'gw-independence-toggle').checked && !byId(t, 'family-reminders-toggle').checked, 'switches synced from tunnel_get');

  const t2 = setup({ init: baseInit({ tunnel_config: { two_hop: 'off' } }), rpc: { tunnel_get: { two_hop: 'off', stealth_api: 'off' } } });
  await sleep(20);
  check(byId(t2, 'gw-independence-toggle').disabled && byId(t2, 'gw-independence-note').style.display === 'block' && byId(t2, 'gw-independence-row').style.opacity === '0.5', 'older daemon: switches greyed with note');

  const t3 = setup({ init: baseInit({ tunnel_config: { two_hop: '' } }), rpc: { tunnel_get: { two_hop: '', raw_config: 'daemon down' } } });
  await sleep(20);
  check(!byId(t3, 'gw-independence-toggle').disabled && byId(t3, 'gw-independence-note').style.display === 'none', 'degraded reply (daemon down) changes nothing');

  // Reminders resolved from the fallback are what the connect flow consults.
  const t4 = connectEnv({ tunnel_get: { two_hop: 'on', gateway_independence: { enabled: true, notifications: false } }, tentative_gateways: { status: 'needs_relaxed' } },
    { tunnel_config: { two_hop: 'on' } });
  await sleep(20);
  await pickGateways(t4);
  actionBtn(t4).click();
  await sleep(400);
  check(!modal(t4) && eq(callsTo(t4, 'connect'), [{ relax_independence: true }]), 'reminders=off learned from tunnel_get -> relaxed connect without modal');
}

async function scenarioPickers() {
  section('gateway pickers');
  const t = setup({ rpc: { gateway_list_full: { gateways: GATEWAYS } } });
  await pickGateways(t);
  check(callsTo(t, 'gateway_list_full').length === 2, 'one gateway_list_full per type (warm-up + pickers share the cache)');
  const rows = qa(t, '.nym-gateway-option');
  const chips = qa(t, '.nym-family-chip').map((c) => c.textContent);
  check(rows.length === 5, 'entry (3 incl. random) + exit (2 incl. random) rows rendered: ' + rows.length);
  check(chips.length === 2 && chips.every((c) => c === 'Acme Ops'), 'chips only on rows with a family: ' + JSON.stringify(chips));
  check(qa(t, '.nym-gateway-option-perf').length === 3, 'performance lines intact');
  const entrySel = q(t, 'select[name="entry_country"]');
  check(Array.from(entrySel.options).some((o) => o.value === 'DE' && /\(2\)/.test(o.textContent)), 'country dropdown counts intact');
  check(Array.from(entrySel.options).map((o) => o.value).slice(0, 2).join(',') === 'none,random', 'placeholder and Random options first');
  const names = qa(t, '.nym-gateway-option-name').map((e) => e.textContent);
  check(names[1] === 'alpha-entry' && names[2] === 'alpha-two', 'entry list sorted by performance (High before Medium)');
  check(qa(t, 'input[name="entry_gateway_id"]:checked')[0].value === '', 'Random radio checked by default');
  qa(t, '.nym-gateway-option')[1].click();
  check(qa(t, '.nym-gateway-option')[1].classList.contains('selected') && !qa(t, '.nym-gateway-option')[0].classList.contains('selected'), 'clicking a row moves the selected class');

  // Circumvention transports on: non-bridge entry gateways sink and are disabled.
  const t2 = setup({ rpc: { gateway_list_full: { gateways: GATEWAYS } } });
  setToggle(t2, 'circumvention-toggle', true);
  await pickGateways(t2);
  const entryRows = Array.from(q(t2, 'select[name="entry_country"]').closest('.nym-panel-picker').querySelectorAll('.nym-gateway-option'));
  const last = entryRows[entryRows.length - 1];
  check(last.classList.contains('disabled') && last.querySelector('input').disabled && /No CT/.test(last.textContent), 'CT on: bridges:false entry gateway disabled with No CT badge');
  const exitRows = Array.from(q(t2, 'select[name="exit_country"]').closest('.nym-panel-picker').querySelectorAll('.nym-gateway-option'));
  check(exitRows.every((r) => !r.classList.contains('disabled')), 'CT gating applies to the entry side only');

  // Restore from the saved daemon selection on first render.
  const t3 = setup({ rpc: { gateway_list_full: { gateways: GATEWAYS }, gateway_get: { entry_type: 'gateway', entry_country: 'DE', entry_id: 'A2', exit_type: 'random' } } });
  await sleep(60);
  check(q(t3, 'select[name="entry_country"]').value === 'DE' && q(t3, 'input[name="entry_gateway_id"][value="A2"]').checked, 'saved gateway restored into the entry picker');
  check(q(t3, 'select[name="exit_country"]').value === 'random', 'saved random exit restored');

  // Fallback to the per-country RPCs when the full list is unavailable.
  const t4 = setup({ rpc: { gateway_list_full: { error: 'no bridge' }, gateway_list_countries: { countries: [{ code: 'DE', count: 1 }] }, gateway_list_by_country: { gateways: [GATEWAYS[0]] } } });
  await pickGateways(t4, 'DE', 'DE');
  check(callsTo(t4, 'gateway_list_countries').length >= 1 && callsTo(t4, 'gateway_list_by_country').length >= 1 && qa(t4, '.nym-gateway-option').length === 4, 'older backend: per-country fallback used');
  const t5 = setup({ rpc: { gateway_list_full: { error: 'no bridge' }, gateway_list_countries: { countries: [{ code: 'DE', count: 1 }] }, gateway_list_by_country: { gateways: [] } } });
  await pickGateways(t5, 'DE', 'DE');
  check(qa(t5, '.nym-gateway-loading').filter((e) => e.textContent === 'No gateways available').length === 2, 'empty country shows No gateways available');
  const t6 = setup({ rpc: { gateway_list_full: { error: 'no bridge' }, gateway_list_countries: () => { throw new Error('down'); } } });
  await q(t6, 'select[name="entry_country"]').ensureLoaded();
  check(q(t6, 'select[name="entry_country"]').options[0].textContent === '— Failed to load —', 'country load failure shows in the placeholder');
}

async function scenarioConnectSelectionGuard() {
  section('connect: explicit selection required');
  const t = connectEnv();
  actionBtn(t).click();
  await sleep(20);
  check(toasts(t).indexOf('Please select a country for entry and exit before connecting.') !== -1, 'both sides missing -> toast');
  check(callsTo(t, 'gateway_set').length === 0 && callsTo(t, 'connect').length === 0, 'nothing sent to the daemon');
  const t2 = connectEnv();
  await pickGateways(t2, 'DE', 'none');
  actionBtn(t2).click();
  await sleep(20);
  check(toasts(t2).indexOf('Please select a country for exit before connecting.') !== -1, 'exit missing -> names the exit');
}

async function scenarioConnectPlain() {
  section("connect: 'selected' / 'none' -> plain connect, gateway_set first");
  for (const status of ['selected', 'none']) {
    const t = connectEnv({ tentative_gateways: { status } });
    await pickGateways(t);
    actionBtn(t).click();
    await sleep(400);
    const gs = callsTo(t, 'gateway_set');
    check(gs.length === 1 && eq(gs[0], { entry_country: 'DE', exit_country: 'FR', entry_id: null, exit_id: null, entry_random: false, exit_random: false, residential_exit: null }),
      status + ': gateway_set carries the picked countries: ' + JSON.stringify(gs[0]));
    check(t.calls.findIndex((c) => c.method === 'gateway_set') < t.calls.findIndex((c) => c.method === 'tentative_gateways') && t.calls.findIndex((c) => c.method === 'tentative_gateways') < t.calls.findIndex((c) => c.method === 'connect'),
      status + ': gateway_set -> tentative_gateways -> connect order');
    check(eq(callsTo(t, 'connect'), [{}]), status + ': connect() without relax flag');
    check(!modal(t), status + ': no modal');
    check(statusLabel(t) === 'Connected' && actionBtn(t).textContent === 'Disconnect', status + ': reached Connected, button flipped');
    check(q(t, '.nym-uptime span').textContent === '00:05', status + ': uptime anchored to connected_seconds');
  }
  // Random + specific gateway id mapping.
  const t = connectEnv({ tentative_gateways: { status: 'selected' } });
  await pickGateways(t, 'random', 'FR');
  q(t, 'input[name="exit_gateway_id"][value="B1"]').click();
  actionBtn(t).click();
  await sleep(400);
  check(eq(callsTo(t, 'gateway_set')[0], { entry_country: null, exit_country: null, entry_id: null, exit_id: 'B1', entry_random: true, exit_random: false, residential_exit: null }),
    'random entry + specific exit id: ' + JSON.stringify(callsTo(t, 'gateway_set')[0]));
}

async function scenarioNeedsRelaxed() {
  section('connect: needs_relaxed + reminders on -> modal');
  const t = connectEnv({ tentative_gateways: { status: 'needs_relaxed', entry: { id: 'A1', name: 'alpha-entry', country: 'DE', family: 'Acme Ops' }, exit: { id: 'B1', name: 'beta-exit', country: 'FR', family: 'Acme Ops' } } });
  await pickGateways(t);
  const btn = actionBtn(t);
  btn.click();
  await sleep(50);
  check(callsTo(t, 'connect').length === 0, 'no connect yet while modal open');
  check(btn.disabled && btn.textContent === 'Connecting', 'action button parked disabled during the check/modal');
  const m = modal(t);
  check(!!m && m.querySelector('.nym-modal-title').textContent === 'The selected servers are in the same operator family!', 'modal title');
  check(m && /alpha-entry.*beta-exit.*Acme Ops/.test(m.querySelector('.nym-modal-message').textContent), 'message names both gateways and the family');
  check(eq(modalButtons(t), ['Change servers', 'Connect anyway']), 'buttons: ' + JSON.stringify(modalButtons(t)));
  clickModalButton(t, 'Connect anyway');
  await sleep(400);
  check(!modal(t), 'modal closed');
  check(eq(callsTo(t, 'connect'), [{ relax_independence: true }]), 'connect(relax_independence=true)');
  check(statusLabel(t) === 'Connected', 'reached Connected');
  const fam = qa(t, '.nym-gateway-family').map((e) => e.textContent);
  check(fam.length === 2 && fam.every((f) => f === 'Acme Ops'), 'family under entry and exit: ' + JSON.stringify(fam));
  check(qa(t, '.nym-gateway-family.same').length === 2 && qa(t, '.nym-gateway-family-warn').length === 2, 'same-family warning on both sides');
  check(btn.textContent === 'Disconnect', 'button flipped to Disconnect');

  section('connect: needs_relaxed -> Change servers');
  const t2 = connectEnv({ tentative_gateways: { status: 'needs_relaxed' } });
  await pickGateways(t2);
  actionBtn(t2).click();
  await sleep(50);
  check(!!modal(t2) && /not independent/.test(modal(t2).querySelector('.nym-modal-message').textContent), 'generic message when families unknown');
  clickModalButton(t2, 'Change servers');
  await sleep(50);
  check(!modal(t2) && callsTo(t2, 'connect').length === 0, 'modal closed, no connect issued');
  check(actionBtn(t2).textContent === 'Connect' && !actionBtn(t2).disabled, 'button back to Connect');
  check(q(t2, '.nym-status-hero').className === 'nym-status-hero disconnected', 'hero back to disconnected');
  check(t2.document.activeElement === q(t2, 'select[name="entry_country"]'), 'entry picker focused');

  section('connect: needs_relaxed + reminders off -> relaxed connect + toast');
  const t3 = connectEnv({ tentative_gateways: { status: 'needs_relaxed' } }, { tunnel_config: Object.assign({}, TUNNEL, { gateway_independence: { enabled: true, notifications: false } }) });
  await pickGateways(t3);
  actionBtn(t3).click();
  await sleep(400);
  check(!modal(t3) && eq(callsTo(t3, 'connect'), [{ relax_independence: true }]), 'no modal, connect(true)');
  check(toasts(t3).some((m) => /relaxed/.test(m)), 'relaxed toast: ' + JSON.stringify(toasts(t3)));
}

async function scenarioTentativeDegraded() {
  section('connect: tentative missing / rejecting / non-object / hanging -> plain connect');
  const cases = [
    ['undeclared method', { __undeclared: ['tentative_gateways'] }],
    ['rejecting method', { tentative_gateways: () => { throw new Error('Object not found'); } }],
    ['ubus status code reply', { tentative_gateways: 2 }],
    ['array reply', { tentative_gateways: [1] }],
  ];
  for (const [label, rpc] of cases) {
    const t = connectEnv(rpc);
    await pickGateways(t);
    actionBtn(t).click();
    await sleep(400);
    check(eq(callsTo(t, 'connect'), [{}]) && statusLabel(t) === 'Connected', label + ': plain connect');
  }
  const t = connectEnv({ tentative_gateways: () => new Promise(() => {}) });
  await pickGateways(t);
  const t0 = Date.now();
  actionBtn(t).click();
  await sleep(5500);
  check(callsTo(t, 'connect').length === 0 && actionBtn(t).disabled, 'hanging check: still waiting at 5.5 s');
  await sleep(1200);
  check(eq(callsTo(t, 'connect'), [{}]), 'hanging check: plain connect after ~6 s (' + (Date.now() - t0) + ' ms)');
}

async function scenarioConnectFailures() {
  section('connect: daemon-side failures');
  const t = connectEnv({ tentative_gateways: { status: 'selected' }, connect: { success: false, error: 'no account' } });
  await pickGateways(t);
  actionBtn(t).click();
  await sleep(100);
  check(toasts(t).indexOf('Connection failed: no account') !== -1, 'connect failure toast');
  check(actionBtn(t).textContent === 'Connect' && !actionBtn(t).disabled, 'button back to Connect after failure');

  const t2 = connectEnv({ tentative_gateways: { status: 'selected' }, connect: () => { t2.setStatus({ state: 'connecting' }); setTimeout(() => t2.setStatus({ state: 'disconnected', tunnel_error: 'PerformantExitGatewayUnavailable' }), 300); return { success: true }; } });
  await pickGateways(t2);
  actionBtn(t2).click();
  await sleep(100);
  check(actionBtn(t2).textContent === 'Cancel' && !actionBtn(t2).disabled && statusLabel(t2) === 'Connecting', 'Cancel armed once the connect is issued');
  await sleep(700);
  check(toasts(t2).some((m) => /Exit gateway unavailable/.test(m)), 'tunnel error during connect toasts once');
  check(statusLabel(t2) === 'Gateway unavailable' && actionBtn(t2).textContent === 'Connect', "label 'Gateway unavailable', button Connect");
  await t2.poll.fire(5);
  check(toasts(t2).filter((m) => /Exit gateway unavailable/.test(m)).length === 1, 'background poll does not re-toast the same error');

  const t3 = connectEnv({ tentative_gateways: { status: 'selected' }, connect: () => { t3.setStatus({ state: 'connecting', error_reason: 'logged_out' }); return { success: true }; } });
  await pickGateways(t3);
  actionBtn(t3).click();
  await sleep(500);
  check(toasts(t3).some((m) => /NO ACCOUNT CONFIGURED/.test(m)), 'account error during connect toasts the ERROR_COPY heading');
  check(callsTo(t3, 'disconnect').length === 1, 'and disconnects to leave a clean state');
}

async function scenarioDisconnectAndCancel() {
  section('disconnect and cancel');
  let st = CONNECTED;
  const t = setup({ init: baseInit({ status: CONNECTED }), rpc: { status: () => st, disconnect: () => { st = { state: 'disconnected' }; return { success: true }; } } });
  check(statusLabel(t) === 'Connected' && actionBtn(t).textContent === 'Disconnect', 'initial connected render');
  check(qa(t, '.nym-gateway-name').map((e) => e.textContent).join(',') === 'alpha-entry,beta-exit', 'gateway names rendered');
  actionBtn(t).click();
  check(statusLabel(t) === 'Disconnecting' && actionBtn(t).disabled, 'disconnecting look while the call is in flight');
  await sleep(400);
  check(eq(callsTo(t, 'disconnect'), [{}]) && statusLabel(t) === 'Disconnected' && actionBtn(t).textContent === 'Connect', 'settled at Disconnected');
  check(q(t, '.nym-uptime span').textContent === '--:--', 'uptime reset');
  check(qa(t, '.nym-gateway-empty').length === 2, 'gateway panels cleared');

  const t2 = setup({ init: baseInit({ status: { state: 'connecting' } }), rpc: { status: { state: 'disconnected' }, disconnect: { success: true } } });
  check(actionBtn(t2).textContent === 'Cancel', 'connecting at load -> Cancel');
  actionBtn(t2).click();
  check(statusLabel(t2) === 'Cancelling', 'cancelling label');
  await sleep(50);
  check(toasts(t2).indexOf('Connection cancelled') !== -1 && actionBtn(t2).textContent === 'Connect', 'cancel -> toast, back to Connect');
}

async function scenarioErrorState() {
  section('error state NEEDS_RELAXED_INDEPENDENCE_CRITERIA from the background poll');
  for (const ident of ['NeedsRelaxedIndependenceCriteria', 'NEEDS_RELAXED_INDEPENDENCE_CRITERIA']) {
    const t = connectEnv();
    t.setStatus({ state: 'disconnected', tunnel_error: ident });
    await t.poll.fire(5);
    await sleep(20);
    const m = modal(t);
    check(!!m, ident + ': modal offered');
    check(m && m.querySelector('.nym-modal-message').textContent.indexOf('The selected entry and exit are not independent. Connect anyway or change servers.') === 0, ident + ': friendly message');
    check(statusLabel(t) === 'Not independent', ident + ": status label 'Not independent'");
    await t.poll.fire(5);
    check(qa(t, '.nym-modal-overlay').length === 1, ident + ': not re-offered on the next poll');
    clickModalButton(t, 'Connect anyway');
    await sleep(400);
    check(eq(callsTo(t, 'connect'), [{ relax_independence: true }]), ident + ': Connect anyway -> connect(true)');
    check(statusLabel(t) === 'Connected', ident + ': reached Connected');
  }
  const t = connectEnv();
  t.setStatus({ state: 'disconnected', tunnel_error: 'PerformantExitGatewayUnavailable' });
  await t.poll.fire(5);
  check(!modal(t) && toasts(t).some((m) => /Exit gateway unavailable/.test(m)), 'other tunnel errors keep the toast');
  check(statusLabel(t) === 'Gateway unavailable', "label 'Gateway unavailable'");
  t.setStatus({ state: 'disconnecting', error_reason: 'api_failure' });
  await t.poll.fire(5);
  check(statusLabel(t) === 'Halted' && actionBtn(t).disabled, "disconnecting with an error reason -> 'Halted', button disabled");
}

async function scenarioConnectedFamilies() {
  section('initial render while connected, families');
  const st = Object.assign({}, CONNECTED, { exit_family: 'Other Org' });
  const t = setup({ init: baseInit({ status: st }), rpc: { status: st } });
  const fam = qa(t, '.nym-gateway-family').map((e) => e.textContent);
  check(eq(fam, ['Acme Ops', 'Other Org']), 'families rendered: ' + JSON.stringify(fam));
  check(qa(t, '.nym-gateway-family-warn').length === 0, 'no warning when families differ');
  check(t.container.querySelectorAll('.nym-chain-node').length === 2, 'two-hop chain has two nodes');
  const st2 = { state: 'connected', connected_seconds: 1, entry_name: 'a', entry_id: 'A', exit_name: 'b', exit_id: 'B', entry: { family: 'X' }, exit: { family: 'x' } };
  const t2 = setup({ init: baseInit({ status: st2 }), rpc: { status: st2 } });
  check(qa(t2, '.nym-gateway-family.same').length === 2, 'nested {entry:{family}} shape, case-insensitive match');
  const st3 = { state: 'connected', connected_seconds: 1, entry_name: 'a', entry_id: 'A', exit_name: 'b', exit_id: 'B' };
  const t3 = setup({ init: baseInit({ status: st3, tunnel_config: Object.assign({}, TUNNEL, { two_hop: 'off' }) }), rpc: { status: st3 } });
  check(qa(t3, '.nym-gateway-family').length === 0 && q(t3, '.nym-gateway-name').textContent === 'a', 'older bridge without family: panels unchanged');
  check(t3.container.querySelectorAll('.nym-chain-node').length === 5 && q(t3, '.nym-mode-label').textContent === 'Anonymous Mode', 'five-hop chain, Anonymous Mode');
  const chain = q(t3, '.nym-connection-chain').innerHTML;
  await t3.poll.fire(5);
  check(q(t3, '.nym-connection-chain').innerHTML === chain && qa(t3, '.nym-gateway-name').length === 2, 'unchanged status poll does not rebuild the chain');
}

async function scenarioInbound() {
  section('inbound services');
  const t = setup({ init: baseInit({ inbound_exemptions: [{ proto: 'tcp', dport: 443, label: 'https' }] }), rpc: { inbound_add: { success: true }, inbound_del: { success: true } } });
  check(qa(t, '.nym-exemption-row').length === 1 && q(t, '.nym-exemption-status').textContent === 'Active', 'existing exemption rendered Active (kill-switch on)');
  byId(t, 'nym-inbound-port').value = '70000';
  byId(t, 'nym-inbound-save').click();
  check(toasts(t).indexOf('Port must be between 1 and 65535') !== -1 && callsTo(t, 'inbound_add').length === 0, 'port range validated client-side');
  byId(t, 'nym-inbound-port').value = '443';
  byId(t, 'nym-inbound-save').click();
  check(toasts(t).indexOf('TCP/443 is already exempted') !== -1, 'duplicate rejected');
  byId(t, 'nym-inbound-proto').value = 'udp';
  byId(t, 'nym-inbound-port').value = '51820';
  byId(t, 'nym-inbound-label').value = 'wg';
  fire(t, byId(t, 'nym-inbound-label'), 'keydown');
  byId(t, 'nym-inbound-label').dispatchEvent(new t.window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
  await sleep(20);
  check(eq(callsTo(t, 'inbound_add'), [{ proto: 'udp', dport: 51820, label: 'wg' }]), 'Enter adds: inbound_add(udp, 51820, wg)');
  check(qa(t, '.nym-exemption-row').length === 2 && byId(t, 'nym-inbound-port').value === '', 'row appended, inputs cleared');
  check(toasts(t).indexOf('Added UDP/51820') !== -1, 'added toast');
  qa(t, '.nym-exemption-delete')[0].click();
  await sleep(20);
  check(eq(callsTo(t, 'inbound_del'), [{ proto: 'tcp', dport: 443 }]) && qa(t, '.nym-exemption-row').length === 1, 'delete removes the row');
  const t2 = setup({ init: baseInit({ tunnel_config: Object.assign({}, TUNNEL, { killswitch: 'off' }), inbound_exemptions: [{ proto: 'tcp', dport: 22 }] }) });
  check(q(t2, '.nym-exemption-status').textContent === 'Inert' && q(t2, '.nym-inbound-section').style.display === 'none', 'kill-switch off: rows Inert and section hidden');
  const t3 = setup({ rpc: { inbound_add: { success: false, error: 'denied' } } });
  byId(t3, 'nym-inbound-port').value = '80';
  byId(t3, 'nym-inbound-save').click();
  await sleep(20);
  check(toasts(t3).indexOf('denied') !== -1 && qa(t3, '.nym-exemption-row').length === 0 && q(t3, '.nym-exemption-empty'), 'failed add: pending row removed, empty state back');
}

async function scenarioSplit() {
  section('split tunneling');
  const t = setup({ init: baseInit({ split_exclusions: [{ id: 'x1', type: 'client', mac: 'aa:bb:cc:dd:ee:ff', enabled: 1 }] }), rpc: { split_add: { success: true, id: 'x2' }, split_del: { success: true }, split_set_enabled: { success: true } } });
  check(qa(t, '.nym-split-row').length === 1 && /laptop \(aa:bb:cc:dd:ee:ff\)/.test(q(t, '.nym-split-row').textContent), 'client exclusion shows hostname (mac)');
  byId(t, 'nym-split-client-save').click();
  check(toasts(t).indexOf('Select a device') !== -1, 'device required');
  byId(t, 'nym-split-client').value = 'aa:bb:cc:dd:ee:ff';
  byId(t, 'nym-split-client-save').click();
  check(toasts(t).indexOf('That device is already excluded') !== -1, 'duplicate device rejected');
  byId(t, 'nym-split-domain').value = 'Example.COM';
  byId(t, 'nym-split-domain-label').value = 'ex';
  byId(t, 'nym-split-domain-save').click();
  await sleep(20);
  check(eq(callsTo(t, 'split_add'), [{ type: 'domain', mac: '', domain: 'example.com', label: 'ex' }]), 'domain lower-cased: ' + JSON.stringify(callsTo(t, 'split_add')));
  check(qa(t, '.nym-split-row').length === 2 && byId(t, 'nym-split-domain').value === '', 'row added and input cleared');
  const sw = qa(t, '.nym-split-row input[type="checkbox"]')[0];
  sw.checked = false;
  fire(t, sw, 'change');
  await sleep(20);
  check(eq(callsTo(t, 'split_set_enabled'), [{ id: 'x1', enabled: 0 }]) && qa(t, '.nym-split-row')[0].classList.contains('inert'), 'toggle off -> split_set_enabled(id, 0), row inert');
  qa(t, '.nym-split-row .nym-exemption-delete')[1].click();
  await sleep(20);
  check(eq(callsTo(t, 'split_del'), [{ id: 'x2' }]) && qa(t, '.nym-split-row').length === 1, 'delete by id');
  const t2 = setup({ init: baseInit({ split_status: { nftset_supported: false }, clients: [] }) });
  check(!byId(t2, 'nym-split-domain') && /dnsmasq-full/.test(q(t2, '.nym-split-section').textContent), 'no nftset: domain row replaced by the dnsmasq-full hint');
  check(byId(t2, 'nym-split-client').options[0].textContent === 'No DHCP leases found', 'no leases placeholder');
}

async function scenarioDns() {
  section('DNS and ad blocking');
  const t = setup({ init: baseInit({ dns: { enabled: true, servers: '1.1.1.1 9.9.9.9' }, ad_block: { enabled: true } }), rpc: { dns_set: { success: true }, ad_block_set: { success: true } } });
  check(qa(t, '.nym-dns-row').length === 2 && byId(t, 'dns-toggle').checked && byId(t, 'adblock-toggle').checked, 'servers and toggles from init');
  byId(t, 'dns-server-input').value = '999.1.1.1';
  byId(t, 'dns-add-btn').click();
  check(toasts(t).indexOf('Not a valid IPv4 or IPv6 address') !== -1 && callsTo(t, 'dns_set').length === 0, 'invalid address rejected client-side');
  byId(t, 'dns-server-input').value = '1.1.1.1';
  byId(t, 'dns-add-btn').click();
  check(toasts(t).indexOf('1.1.1.1 is already in the list') !== -1, 'duplicate rejected');
  byId(t, 'dns-server-input').value = '2606:4700:4700::1111';
  byId(t, 'dns-add-btn').click();
  await sleep(20);
  check(eq(callsTo(t, 'dns_set'), [{ enabled: true, servers: '1.1.1.1 9.9.9.9 2606:4700:4700::1111' }]), 'add re-sends the whole list: ' + JSON.stringify(callsTo(t, 'dns_set')));
  check(qa(t, '.nym-dns-row').length === 3, 'row added');
  qa(t, '.nym-dns-row .nym-exemption-delete')[0].click();
  await sleep(20);
  check(callsTo(t, 'dns_set')[1].servers === '9.9.9.9 2606:4700:4700::1111' && qa(t, '.nym-dns-row').length === 2, 'remove re-sends without it');
  setToggle(t, 'dns-toggle', false);
  await sleep(20);
  check(callsTo(t, 'dns_set')[2].enabled === false && toasts(t).indexOf('Custom DNS disabled') !== -1, 'dns toggle -> dns_set(false, list)');
  setToggle(t, 'adblock-toggle', false);
  await sleep(20);
  check(eq(callsTo(t, 'ad_block_set'), [{ enabled: false }]) && toasts(t).indexOf('Ad-blocking disabled') !== -1, 'adblock toggle -> ad_block_set(false)');

  const t2 = setup({ rpc: { dns_set: { success: false, error: 'bad' }, ad_block_set: () => { throw new Error('down'); } } });
  setToggle(t2, 'dns-toggle', true);
  setToggle(t2, 'adblock-toggle', true);
  await sleep(20);
  check(!byId(t2, 'dns-toggle').checked && toasts(t2).indexOf('Failed: bad') !== -1, 'failed dns_set reverts the toggle');
  check(!byId(t2, 'adblock-toggle').checked && toasts(t2).indexOf('Error: down') !== -1, 'rejected ad_block_set reverts the toggle');
  byId(t2, 'dns-server-input').value = '8.8.8.8';
  byId(t2, 'dns-add-btn').click();
  await sleep(20);
  check(qa(t2, '.nym-dns-row').length === 0 && q(t2, '.nym-exemption-empty'), 'failed add rolls the list back');
  const t3 = setup({ init: baseInit({ dns: { enabled: true, servers: '', user_managed: true } }) });
  check(/noresolv/.test(card(t3, 'DNS & Ad Blocking').textContent), 'user-managed dnsmasq notice shown');
}

async function scenarioMixnetTuning() {
  section('mixnet tuning');
  const t = setup({ init: baseInit({ tunnel_config: Object.assign({}, TUNNEL, { disable_poisson: 'true', loop_cover_delay: '50' }) }) });
  check(byId(t, 'tuning-poisson-toggle').checked && !byId(t, 'tuning-cover-toggle').checked && byId(t, 'tuning-loop-cover').value === '50', 'init values bound');
  byId(t, 'tuning-message-delay').value = '3';
  card(t, 'Mixnet Tuning').querySelector('.nym-card-actions button').click();
  check(qa(t, '.nym-action-buttons').length === 1 && q(t, '.nym-status-hero').contains(q(t, '.nym-action-buttons')), 'only the hero carries the centred action button');
  check(toasts(t).some((m) => /out of range/.test(m)) && callsTo(t, 'tunnel_set').length === 0, 'out-of-range sending delay rejected without rpc');
  byId(t, 'tuning-message-delay').value = '';
  byId(t, 'tuning-packet-delay').value = '120';
  setToggle(t, 'tuning-cover-toggle', true);
  await sleep(20);
  check(eq(callsTo(t, 'tunnel_set'), [{ loop_cover_delay: '50', packet_delay: '120', message_delay: '', disable_poisson: 'on', disable_cover: 'on' }]),
    'tunnel_set with tuning fields, blanks left as-is: ' + JSON.stringify(callsTo(t, 'tunnel_set')));
  check(toasts(t).indexOf('Mixnet tuning saved') !== -1, 'saved toast');
}

async function scenarioAccount() {
  section('account card states');
  const t = setup();
  const body = card(t, 'Account');
  check(/DEVICE1/.test(body.textContent) && /Rotate keys/.test(body.textContent) && /Sign out/.test(body.textContent), 'logged in: identity, rotate, sign out');
  check(body.querySelector('.nym-card-status-text').textContent === 'Active', 'account state label');
  const t2 = setup({ init: baseInit({ account: { identity: '', state: 'LoggedOut' } }) });
  check(!!card(t2, 'Account').querySelector('textarea[name="mnemonic"]') && !card(t2, 'Account').querySelector('.nym-btn-secondary'), 'logged out: recovery phrase form, no reset button');
  const t3 = setup({ init: baseInit({ account: { identity: 'OLD', state: 'LoggedOut' } }) });
  check(!!card(t3, 'Account').querySelector('textarea') && /Stale account data/.test(card(t3, 'Account').textContent), 'stale identity while LoggedOut: form plus reset hint');
  const t4 = setup({ init: baseInit({ account: { available: false, daemon_running: false, daemon_enabled: false } }) });
  check(/Service not running/.test(card(t4, 'Account').textContent) && /not enabled at boot/.test(card(t4, 'Account').textContent) && card(t4, 'Account').querySelector('button').textContent === 'Start service', 'daemon unavailable: says so, offers Start service');
  const t5 = setup({ init: baseInit({ account: { identity: 'X', state: 'ErrorSomething' } }) });
  check(/Error Something/.test(card(t5, 'Account').textContent) && /Reset account state/.test(card(t5, 'Account').textContent), 'error state: camel-case split, Logout + Reset offered');
  const t6 = setup({ init: baseInit({ account: { identity: '', state: '' } }) });
  check(/Service not responding/.test(card(t6, 'Account').textContent), 'empty reply from an older bridge reads as unavailable');

  section('account flows');
  const t7 = setup({ init: baseInit({ account: { identity: '', state: 'LoggedOut' } }), rpc: { account_set: { success: true }, account_get: { identity: 'NEW', state: 'ReadyToConnect' } } });
  const form = card(t7, 'Account').querySelector('form');
  form.querySelector('textarea').value = ' word1  word2\nword3 ';
  form.querySelector('button[type="submit"]').click();
  await sleep(20);
  check(eq(callsTo(t7, 'account_set'), [{ mnemonic: 'word1 word2 word3', mode: 'api' }]), 'login collapses whitespace: ' + JSON.stringify(callsTo(t7, 'account_set')));
  check(!!modal(t7) && modal(t7).querySelector('.nym-modal-title').textContent === 'Logging In', 'progress modal shown');
  await sleep(1100);
  check(modal(t7) && modal(t7).classList.contains('success') && modal(t7).querySelector('.nym-modal-title').textContent === 'Ready', 'ReadyToConnect -> success modal');
  const t8 = setup({ rpc: { status: { state: 'connected' } } });
  card(t8, 'Account').querySelector('.nym-card-action.rotate').click();
  await sleep(20);
  check(toasts(t8).indexOf('Please disconnect before rotating keys') !== -1 && callsTo(t8, 'account_rotate_keys').length === 0, 'rotate refused while connected');
  const t9 = setup({ rpc: { status: { state: 'disconnected' }, account_rotate_keys: { success: true } } });
  card(t9, 'Account').querySelector('.nym-card-action.rotate').click();
  await sleep(20);
  check(callsTo(t9, 'account_rotate_keys').length === 1 && toasts(t9).indexOf('Keys rotated successfully') !== -1, 'rotate keys while disconnected');
  card(t9, 'Account').querySelector('.nym-card-action.danger').click();
  check(!!modal(t9) && modal(t9).querySelector('.nym-modal-title').textContent === 'Logout', 'sign out asks for confirmation');
  clickModalButton(t9, 'Cancel');
  check(!modal(t9) && callsTo(t9, 'account_forget').length === 0, 'cancel leaves the account alone');

  section('account card refresh on status changes');
  let st = { state: 'disconnected' };
  const t10 = setup({ rpc: { status: () => st, account_get: { identity: '', state: 'LoggedOut' } } });
  st = { state: 'disconnected', error_reason: 'logged_out' };
  await t10.poll.fire(5);
  await sleep(20);
  check(callsTo(t10, 'account_get').length === 1 && !!card(t10, 'Account').querySelector('textarea'), 'error_reason change re-fetches the account and rebuilds the card');
  await t10.poll.fire(5);
  check(callsTo(t10, 'account_get').length === 1, 'same reason on the next poll: no refetch');
  st = { state: 'disconnected', error_reason: 'logged_out', available: false };
  await t10.poll.fire(5);
  check(callsTo(t10, 'account_get').length === 2, 'availability change refetches too');
}

async function scenarioService() {
  section('service management');
  const t = setup({ init: baseInit({ daemon: { running: false, enabled: false } }), rpc: { daemon_status: { running: true, enabled: true }, daemon_start: { success: true, status: 'running', enabled: true } } });
  const svc = card(t, 'Service Management');
  check(svc.querySelector('.nym-card-status-text').textContent === 'Stopped · not enabled at boot' && svc.querySelector('.nym-card-status').classList.contains('stopped'), 'stopped + not enabled badge');
  const [startBtn, restartBtn, stopBtn] = Array.from(svc.querySelectorAll('.nym-card-action'));
  check(!startBtn.disabled && stopBtn.disabled, 'Start enabled, Stop disabled while stopped');
  await t.poll.fire(10);
  check(svc.querySelector('.nym-card-status-text').textContent === 'Running' && startBtn.disabled && !stopBtn.disabled, 'daemon_status poll flips the badge and buttons');
  const t2 = setup({ init: baseInit({ daemon: { running: false } }), rpc: { daemon_start: { success: true, status: 'running' }, account_get: { identity: 'D', state: 'Active' } } });
  card(t2, 'Service Management').querySelector('.nym-card-action.success').click();
  await sleep(20);
  check(callsTo(t2, 'daemon_start').length === 1 && callsTo(t2, 'account_get').length === 1, 'start -> daemon_start, account card re-asked');
  check(!!modal(t2) && modal(t2).classList.contains('success'), 'success modal');
  const t3 = setup({ rpc: { status: { state: 'connected' } } });
  Array.from(card(t3, 'Service Management').querySelectorAll('.nym-card-action'))[1].click();
  await sleep(20);
  check(!!modal(t3) && /disconnect you/.test(modal(t3).querySelector('.nym-modal-message').textContent) && eq(modalButtons(t3), ['Cancel', 'Restart']), 'restart while connected asks first');
  clickModalButton(t3, 'Cancel');
  check(callsTo(t3, 'daemon_restart').length === 0, 'cancelled restart does nothing');
}

async function scenarioAlwaysOn() {
  section('always on watchdog');
  const t = setup({ init: baseInit({ watchdog: { always_on: 1, interval: 60, failures: 2 } }), rpc: { watchdog_set: { success: true } } });
  check(byId(t, 'always-on-toggle').checked && byId(t, 'always-on-status').textContent === 'Watchdog active (2 recovery attempts)', 'active status with failures');
  check(byId(t, 'watchdog-interval-row').style.display === 'flex' && q(t, '.nym-pill.active').textContent === '60s', 'interval row visible, 60s active');
  q(t, '.nym-pill[data-value="15"]').click();
  await sleep(20);
  check(eq(callsTo(t, 'watchdog_set'), [{ always_on: 1, interval: 15 }]) && toasts(t).indexOf('Check interval set to 15s') !== -1, 'pill -> watchdog_set(1, 15)');
  setToggle(t, 'always-on-toggle', false);
  await sleep(20);
  check(eq(callsTo(t, 'watchdog_set')[1], { always_on: 0, interval: 15 }) && byId(t, 'watchdog-interval-row').style.display === 'none' && byId(t, 'always-on-status').textContent === 'Disabled', 'toggle off -> watchdog_set(0, current), row hidden');
  const t2 = setup({ rpc: { watchdog_set: { success: false, error: 'no' } } });
  setToggle(t2, 'always-on-toggle', true);
  await sleep(20);
  check(!byId(t2, 'always-on-toggle').checked && !byId(t2, 'always-on-toggle').disabled, 'failed save reverts and re-enables the switch');
}

async function scenarioLogsAndDiagnostics() {
  section('daemon logs');
  const logs = '2026-09-06T10:00:00Z  INFO nym: up\n2026-09-06T10:00:01Z ERROR nym: <b>bad</b>\n2026-09-06T10:00:02Z  INFO nym: fine';
  const t = setup({ rpc: { logs_get: { success: true, logs: logs } } });
  const logsCard = card(t, 'Daemon Logs');
  logsCard.querySelector('.nym-card-header').click();
  await sleep(20);
  check(logsCard.classList.contains('expanded') && eq(callsTo(t, 'logs_get'), [{ lines: 200 }]), 'expanding fetches 200 lines');
  const viewer = logsCard.querySelector('.nym-log-viewer');
  check(viewer.querySelectorAll('.nym-log-error').length === 1 && viewer.querySelectorAll('.nym-log-info').length === 2 && !viewer.querySelector('b'), 'levels coloured, markup escaped');
  const filter = logsCard.querySelectorAll('select')[2];
  filter.value = 'err0';
  fire(t, filter, 'change');
  const filtered = viewer.textContent.split('\n');
  check(filtered.length === 2 && /⋯/.test(filtered[0]) && /bad/.test(filtered[1]) && !/fine/.test(viewer.textContent), 'Errors only filter: skipped run collapsed to ⋯, error line kept');
  check(logsCard.querySelector('.nym-log-status').textContent === 'live', 'live when expanded');
  logsCard.querySelector('.nym-card-header').click();
  check(logsCard.querySelector('.nym-log-status').textContent === 'paused', 'paused when collapsed');

  section('diagnostics');
  const report = { dns: { system: { ok: true, value: [{ hostname: 'nymvpn.com', resolution: { ok: true, value: ['1.2.3.4'] }, resolution_duration_ms: 12 }] } },
    http: { ok: true, value: { health_response: { ok: false, error: 'timeout' } } },
    gateway: { tcp: { ok: true } } };
  const t2 = setup({ rpc: { diagnostic_run: { success: true, report: JSON.stringify(report) } } });
  const diag = card(t2, 'Diagnostics');
  diag.querySelector('button').click();
  await sleep(20);
  check(eq(callsTo(t2, 'diagnostic_run'), [{ skip_dns: false, skip_http: false, gateway: '' }]), 'diagnostic_run(false, false, "")');
  const chips = Array.from(diag.querySelectorAll('.nym-diag-chip')).map((c) => c.textContent);
  check(eq(chips, ['PASS', 'FAIL', 'PASS']), 'PASS/FAIL rows: ' + JSON.stringify(chips));
  check(Array.from(diag.querySelectorAll('.nym-diag-group-title')).map((e) => e.textContent).join('|') === 'DNS Resolution|VPN API (HTTP)|Gateway', 'groups in order');
}

(async () => {
  const started = Date.now();
  await scenarioStructure();
  await scenarioTunnelToggles();
  await scenarioIndependenceToggles();
  await scenarioFallbackTunnelGet();
  await scenarioPickers();
  await scenarioConnectSelectionGuard();
  await scenarioConnectPlain();
  await scenarioNeedsRelaxed();
  await scenarioTentativeDegraded();
  await scenarioConnectFailures();
  await scenarioDisconnectAndCancel();
  await scenarioErrorState();
  await scenarioConnectedFamilies();
  await scenarioInbound();
  await scenarioSplit();
  await scenarioDns();
  await scenarioMixnetTuning();
  await scenarioAccount();
  await scenarioService();
  await scenarioAlwaysOn();
  await scenarioLogsAndDiagnostics();
  console.log('\n' + total + ' checks, ' + failures + ' failure(s), ' + (Date.now() - started) + ' ms');
  process.exit(failures ? 1 : 0);
})().catch((e) => {
  console.error('CRASH', e);
  process.exit(2);
});
