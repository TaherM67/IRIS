"use strict";
/* Unit tests, not a browser or visual-layout test.
 * Run: node demo_app/tests/test_ui_controller.js. No npm install is required.
 * Python renders the real role-filtered original template. DOM/API doubles
 * exercise the actual controller without accessing user keys or demo records.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const {execFileSync} = require("node:child_process");
const root = path.resolve(__dirname, "../static"), repository = path.resolve(__dirname, "../..");
const markupCache = new Map();

class Element {
  constructor(tag = "div", attrs = {}) {
    this.tag = tag; this.children = []; this.events = {}; this.content = "";
    this.attributes = {...attrs}; this.type = attrs.type || ""; this.dataset = {};
    this.value = attrs.value || ""; this.checked = "checked" in attrs;
    this.hidden = "hidden" in attrs; this.disabled = false; this.open = false;
    for (const [key, value] of Object.entries(attrs)) if (key.startsWith("data-")) this.dataset[key.slice(5)] = value;
    const flags = new Set();
    this.classList = {toggle(key, on) { on ? flags.add(key) : flags.delete(key); }, contains: key => flags.has(key)};
  }
  set textContent(value) { this.content = String(value); this.children = []; }
  get textContent() { return this.content + this.children.map(n => n.textContent).join(""); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.content = ""; this.children = nodes; }
  addEventListener(event, callback) { (this.events[event] ||= []).push(callback); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  emit(event, extra = {}) { for (const callback of this.events[event] || []) callback({preventDefault() {}, ...extra}); }
  reset() { this.value = ""; }
  click() {}
  remove() {}
  closest(selector) {
    for (let current = this; current; current = current.parentElement) {
      if (selector.startsWith('.') ? (current.attributes.class || '').split(' ').includes(selector.slice(1)) : current.tag === selector) return current;
    }
    return null;
  }
}

function documentFor(role, unfiltered = false) {
  assert.ok(["admin", "soc", "grc"].includes(role));
  if (!markupCache.has(role)) {
    // Use the real server renderer, not another copy of its filtering algorithm.
    const code = "import sys; from demo_app.server import dashboard_html; sys.stdout.buffer.write(dashboard_html('" + role + "'))";
    markupCache.set(role, execFileSync(process.env.IRIS_TEST_PYTHON || "python", ["-c", code],
      {cwd: repository, encoding: "utf8", maxBuffer: 2 * 1024 * 1024}));
  }
  const html = (unfiltered ? fs.readFileSync(path.join(root, 'index.html'), 'utf8') : markupCache.get(role)).replace(/<!--[\s\S]*?-->/g, "");
  const nodes = [], ids = new Map(), stack = [];
  for (const match of html.matchAll(/<(\/?)([a-z][a-z0-9-]*)\b([^>]*)>/gi)) {
    if (match[1]) { while (stack.length && stack.pop().tag !== match[2]) {} continue; }
    const attrs = {};
    for (const attr of match[3].matchAll(/([a-z][a-z0-9-]*)(?:="([^"]*)")?/gi)) attrs[attr[1]] = attr[2] || "";
    const element = new Element(match[2], attrs); nodes.push(element);
    element.parentElement = stack[stack.length - 1] || null;
    if (element.parentElement) element.parentElement.append(element);
    if (!['meta', 'link', 'input', 'br', 'hr', 'img'].includes(element.tag)) stack.push(element);
    if (attrs.id) { assert.ok(!ids.has(attrs.id), "Duplicate HTML ID: " + attrs.id); ids.set(attrs.id, element); }
  }
  return {hidden: false, body: Object.assign(new Element(), {dataset: {role}}),
    getElementById: id => ids.get(id) || null, createElement: tag => new Element(tag),
    querySelectorAll: selector => selector === "button" ? nodes.filter(n => n.tag === "button") :
      selector === '.workspace-nav a' ? nodes.filter(n => n.tag === 'a' && n.closest('nav')?.getAttribute('aria-label') === 'Sections') :
      selector === 'nav[aria-label="Dashboards"] a' ? nodes.filter(n => n.tag === 'a' && n.closest('nav')?.getAttribute('aria-label') === 'Dashboards') : nodes.filter(n => "count" in n.dataset)};
}

function fixture(role) {
  const shared = {hostname: "identity-server", asset_criticality: 5};
  const controls = [{name: "Example access control", control_id: "SC005", current_state: "implemented", action_type: "verify"}];
  // SOC intentionally has no policy/controls; GRC has no raw telemetry or shadow.
  // Old unconditional field accesses would therefore fail this regression.
  const technical = {...shared, primary_assessment: {scenario_class: "credential_access"},
    features: {event_count: 29, failed_count: 28, max_rule_level: 15}, warnings: [],
    ml_shadow: {scenario: "credential_access", confidence: .92}, priority_reason: "Strong technical evidence."};
  const full = {...technical, primary_controls: {recommendations: controls}, policy: {priority: "Critical"}};
  const business = {...shared, observed_activity: "credential_access", risk_category: "Unauthorized Access",
    risk_reason: "Matched registered risk and policy likelihood increase.", controls};
  const soc = {proposal_id: "PROP-" + "a".repeat(32), case_id: "CASE-SOC", kind: "soc", status: "pending",
    payload: {changed_alerts: 19, before_counts: {High: 19}, new_priority: "Critical", evidence: role === "admin" ? full : technical}};
  const grc = {proposal_id: "PROP-" + "b".repeat(32), case_id: "CASE-GRC", kind: "grc", status: "pending",
    payload: {risk_id: "DEMO-R001-1", before: {score: .6, likelihood: 3, impact: 5},
      after: {score: .8, likelihood: 4, impact: 5}, evidence: role === "admin" ? full : business}};
  const counts = role === "soc" ? {alerts: 2355, pending_soc: 1, reprioritized_alerts: 0} :
    role === "grc" ? {risks: 60, pending_grc: 1, changed_risks: 0} :
    {alerts: 2355, risks: 60, pending_soc: 1, pending_grc: 1, reprioritized_alerts: 0, changed_risks: 0};
  return {state: {role, exercise_id: "UI-TEST", label: "Synthetic UI fixture", analyzed: true, counts,
    ...(role === "admin" ? {analysis: {sessions: 132}, model: {loaded: true}, exercise_history: []} : {})},
    pending: role === "admin" ? [soc, grc] : role === "soc" ? [soc] : [grc], changed: false};
}

const TEST_PASSWORD = "SYNTHETIC-UI-TEST-PASSWORD";
const TEST_TOKEN = 'synthetic-session-token'.padEnd(43, '0');

function mockFetch(role, data, calls, behavior = {}) {
  return async (url, options = {}) => {
    const route = new URL(url, "http://local.test").pathname.replace("/api/demo", ""); calls.push(route);
    const response = (value, status = 200) => ({ok: status >= 200 && status < 300, status,
      json: async () => JSON.parse(JSON.stringify(value))});
    assert.equal(options.headers?.['X-IRIS-Key'], undefined);
    if (route === '/auth/login') {
      const body = JSON.parse(options.body);
      assert.deepEqual(Object.keys(body).sort(), ['password','username','workspace']);
      assert.equal(options.headers?.Authorization, undefined);
      if (body.workspace !== role || behavior.stateStatus === 401)
        return response({detail:'Invalid username, password or selected workspace'}, 401);
      return response({role:behavior.stateRole || role,username:'Test-' + role,access_token:TEST_TOKEN});
    }
    assert.equal(options.headers?.Authorization, 'Bearer ' + TEST_TOKEN);
    if (route === '/auth/logout') return response({signed_out:true});
    if (route === behavior.failRoute) return response({detail: "Synthetic initial loading failure"}, 500);
    let value;
    if (route === "/state") value = {...data.state, role: behavior.stateRole || data.state.role};
    else if (route === "/proposals") value = {exercise_id: "UI-TEST", items: data.pending, total: data.pending.length};
    else if (route === "/changes") value = {exercise_id: "UI-TEST", items: []};
    else if (route === '/chat/clear') {
      assert.deepEqual(JSON.parse(options.body), {});
      data.clearedThrough = Math.max(0,...(data.messages || []).map(item=>item.id));
      value = {cleared_through:data.clearedThrough,retention_months:3,logs_preserved:true};
    }
    else if (route === '/chat/logs') {
      assert.equal(role,'admin');
      value = {active_logs:data.messages || [],archived_logs:[],retention_months:3};
    }
    else if (route === "/chat") {
      data.messages ||= [];
      if (options.method === 'POST') {
        assert.notEqual(role, 'admin');
        const body = JSON.parse(options.body);
        assert.deepEqual(Object.keys(body), ['text']);
        value = {id: data.messages.length + 1, role, text: body.text, created_at: '2026-10-27T12:00:00Z'};
        data.messages.push(value);
      } else {
        const after = Number(new URL(url, 'http://local.test').searchParams.get('after') || 0);
        const floor = Math.max(after,data.clearedThrough || 0);
        value = {items: data.messages.filter(item => item.id > floor), cursor: Math.max(data.messages.length,floor),
          cleared_through:data.clearedThrough || 0,has_more:false};
      }
    }
    else if (route === "/audit") { assert.equal(role, "admin"); value = []; }
    else if (route === '/activity') {
      assert.equal(role, 'admin');
      value = {active_commands: 1, events: [{time: '2026-10-25T12:00:00+00:00', role: 'admin', action: 'analysis', state: 'running', message: 'Real test backend event'}]};
    }
    else if (route === "/risks") {
      if (role === 'soc') return response({detail: 'This action requires the ADMIN OR GRC role'}, 403);
      value = {exercise_id: "UI-TEST", items: [{risk_id: "DEMO-R001-1", hostname: "identity-server", category: "Unauthorized Access",
        baseline_likelihood: 3, current_likelihood: data.changed ? 4 : 3, impact: 5, baseline_score: .6, current_score: data.changed ? .8 : .6,
        version: data.changed ? 2 : 1, updated_by: data.changed ? "grc" : null}]};
    } else if (route === "/alerts") {
      if (role === 'grc') return response({detail: 'This action requires the ADMIN OR SOC role'}, 403);
      value = {exercise_id: "UI-TEST", total: data.changed ? 19 : 2355, items: [{event_id: "UI-EVENT", hostname: "identity-server",
        event_time: "2026-10-25T12:00:00Z", baseline_priority: "High", current_priority: data.changed ? "Critical" : "High",
        version: data.changed ? 2 : 1, updated_by: data.changed ? "soc" : null}]};
    } else if (route.endsWith("/review")) {
      assert.notEqual(role, "admin", "Admin must not submit a team's approval");
      const body = JSON.parse(options.body);
      assert.deepEqual(Object.keys(body).sort(), ["decision", "reason"]);
      assert.ok(body.reason.length >= 5); assert.equal(body.decision, "approve");
      data.changed = true; data.pending = [];
      if (role === "soc") Object.assign(data.state.counts, {pending_soc: 0, reprioritized_alerts: 19});
      else Object.assign(data.state.counts, {pending_grc: 0, changed_risks: 1});
      value = {demo_records_written: role === "soc" ? 19 : 1};
    } else throw new Error("Unexpected UI endpoint: " + route);
    return response(value);
  };
}

async function settle(context) {
  for (let attempt = 0; attempt < 100; attempt++) {
    await new Promise(resolve => setImmediate(resolve));
    if (!vm.runInContext("busy", context)) return;
  }
  throw new Error("Controller action did not settle");
}
function harness(role, behavior = {}) {
  const document = documentFor(role, behavior.unfiltered), data = fixture(role), calls = [], navigations = [];
  if (role === 'grc' && behavior.controlsShape) {
    const proposal = data.pending[0];
    if (behavior.controlsShape.startsWith('legacy')) {
      proposal.payload.evidence = fixture('admin').pending[1].payload.evidence;
      if (behavior.controlsShape === 'legacy-missing') proposal.payload.evidence.primary_controls = {};
    } else if (behavior.controlsShape === 'missing') delete proposal.payload.evidence.controls;
    else if (behavior.controlsShape === 'null') proposal.payload.evidence.controls = null;
    else if (behavior.controlsShape === 'object') proposal.payload.evidence.controls = {};
    else if (behavior.controlsShape === 'bad-entries') proposal.payload.evidence.controls = [null, 'invalid'];
  }
  const context = vm.createContext({document, location: {pathname: "/" + role, assign: url => navigations.push(url)}, fetch: mockFetch(role, data, calls, behavior), AbortController,
    Option: function(label, value) { const option = new Element("option"); option.textContent = label; option.value = value; return option; },
    setInterval() { return 1; }, setTimeout, URL, Blob, confirm: () => true, console});
  vm.runInContext(fs.readFileSync(path.join(root, "app.js"), "utf8"), context);
  assert.deepEqual(calls, [], "Original page waits for Connect, with no version/session prerequisites");
  return {document, data, calls, context, navigations};
}
async function login(test) {
  test.document.getElementById("username").value = 'Test-' + test.data.state.role;
  test.document.getElementById("password").value = TEST_PASSWORD;
  test.document.getElementById("login-form").emit("submit"); await settle(test.context);
}
function locked(test) {
  assert.equal(test.document.body.dataset.session, 'locked');
  assert.equal(test.document.getElementById("workspace").hidden, true);
  assert.equal(test.document.getElementById("login-panel").hidden, false);
  assert.equal(vm.runInContext("sessionToken", test.context), "");
  assert.equal(vm.runInContext("identity", test.context), null);
  assert.equal(test.document.getElementById("password").value, "");
}

async function check(role) {
  const test = harness(role), {document, data, calls, context} = test;
  await login(test);
  assert.equal(document.getElementById("login-panel").hidden, true, document.getElementById("message").textContent);
  assert.equal(document.getElementById("workspace").hidden, false);
  assert.equal(document.body.dataset.session, 'connected');
  assert.match(document.getElementById("proposal-summary").textContent, /identity-server/);
  assert.equal(calls[0], "/auth/login", "Sign-in exchanges credentials for a session before private reads");
  assert.ok(!calls.includes("/info") && !calls.includes("/session"));
  assert.equal(document.getElementById("pending-count").textContent, role === "admin" ? "2" : "1");
  if (role === "soc") {
    for (const id of ["risk-panel", "risk-count", "risk-changed", "model-status"]) assert.equal(document.getElementById(id), null);
    assert.ok(!calls.includes("/risks") && !calls.includes("/audit"));
    assert.ok(!calls.includes('/activity'));
    assert.equal(document.getElementById("alert-count").textContent, "2,355");
    assert.match(document.getElementById("proposal-summary").textContent, /19 alerts.*Critical/);
    assert.doesNotMatch(document.getElementById("proposal-evidence").textContent, /primary_controls|"controls"|"policy"/);
  } else if (role === "grc") {
    for (const id of ["alert-panel", "alert-count", "alert-changed", "model-status"]) assert.equal(document.getElementById(id), null);
    assert.ok(!calls.includes("/alerts") && !calls.includes("/audit"));
    assert.ok(!calls.includes('/activity'));
    assert.equal(document.getElementById("risk-count").textContent, "60");
    assert.match(document.getElementById("proposal-summary").textContent, /0\.60 → 0\.80/);
    assert.match(document.getElementById("proposal-evidence").textContent, /Example access control/);
    assert.doesNotMatch(document.getElementById("proposal-summary").textContent, /ML shadow|confidence/);
    assert.doesNotMatch(document.getElementById("proposal-evidence").textContent, /"features"|ml_shadow|confidence/);
  } else {
    assert.ok(calls.includes("/risks") && calls.includes("/alerts") && calls.includes("/audit"));
    assert.equal(document.getElementById("review-form").hidden, true);
    assert.match(document.getElementById("proposal-evidence").textContent, /"policy"/);
    assert.match(document.getElementById("model-status").textContent, /loaded/);
    await vm.runInContext('refreshActivity()', context);
    assert.match(document.getElementById('backend-events').textContent, /Real test backend event/);
  }
  if (role !== "admin") {
    document.getElementById("reason").value = "Reviewed synthetic evidence; approve this demo change.";
    document.getElementById("review-form").emit("submit", {submitter: {value: "approve"}}); await settle(context);
    assert.equal(data.changed, true, document.getElementById("message").textContent);
    assert.equal(document.getElementById("review-form").hidden, true);
    assert.match(document.getElementById(role === "soc" ? "alert-rows" : "risk-rows").textContent, role === "soc" ? /Critical/ : /0.60 → 0.80/);
    assert.equal(document.getElementById(role === "soc" ? "alert-changed" : "risk-changed").textContent, role === "soc" ? "19" : "1");
    assert.equal(document.getElementById("pending-count").textContent, "0");
  }
  document.getElementById("logout").emit("click"); locked(test);
  assert.equal(document.getElementById(role === "soc" ? "alert-rows" : "risk-rows").textContent, "");
  console.log(role.toUpperCase() + ": original login, own counters, role-only reads, approval/read-only and logout passed");
}

async function failureChecks() {
  for (const role of ["admin", "soc", "grc"]) {
    const test = harness(role, {stateRole: role === "admin" ? "soc" : "admin"}); await login(test); locked(test);
    assert.ok(test.calls.every(route => ['/auth/login','/auth/logout'].includes(route)), "Wrong-role account must not fetch private records");
    assert.match(test.document.getElementById("message").textContent, /account|workspace|role/i);
  }
  {
    const test = harness("soc", {stateStatus: 401}); await login(test); locked(test);
    assert.ok(test.calls.every(route => route === "/auth/login"));
    assert.match(test.document.getElementById("message").textContent, /password|valid|rejected/i);
  }
  for (const route of ["/proposals", "/alerts"]) {
    const test = harness("soc", {failRoute: route}); await login(test); locked(test);
    assert.equal(vm.runInContext("state", test.context), null);
    assert.equal(test.document.getElementById("alert-rows").textContent, "");
    assert.match(test.document.getElementById("message").textContent, /initial loading failure/);
  }
  console.log("FAILURES: 3 wrong-role keys, rejected key and 2 initial-load failures stay locked");
}

async function unfilteredChecks() {
  for (const role of ['soc', 'grc', 'admin']) {
    const test = harness(role, {unfiltered: true});
    await login(test);
    assert.equal(test.document.getElementById('login-panel').hidden, true,
      'Unfiltered original markup must not cause a cross-team request: ' + test.document.getElementById('message').textContent);
    if (role !== 'admin') {
      const otherPanel = test.document.getElementById(role === 'soc' ? 'risk-panel' : 'alert-panel');
      assert.equal(otherPanel.hidden, true);
      assert.ok(!test.calls.includes(role === 'soc' ? '/risks' : '/alerts'));
      assert.ok(!test.calls.includes('/audit'));
      for (const id of role === 'soc' ? ['risk-count', 'risk-changed'] : ['alert-count', 'alert-changed']) {
        assert.equal(test.document.getElementById(id).closest('.stat').hidden, true);
      }
      assert.equal(test.document.getElementById('model-status').closest('section').hidden, true);
      assert.equal(test.document.getElementById('pending-count').textContent, '1');
      await vm.runInContext('refresh()', test.context);
      assert.ok(!test.calls.includes(role === 'soc' ? '/risks' : '/alerts'), 'Polling must remain role-specific');
    } else assert.ok(test.calls.includes('/risks') && test.calls.includes('/alerts'));
  }
  console.log('UNFILTERED: SOC, GRC and Admin load correctly even with every panel present');
}

async function grcControlChecks() {
  for (const shape of ['legacy', 'missing', 'null', 'object', 'bad-entries', 'legacy-missing']) {
    const test = harness('grc', {unfiltered: true, controlsShape: shape});
    await login(test);
    assert.equal(test.document.getElementById('login-panel').hidden, true,
      shape + ': ' + test.document.getElementById('message').textContent);
    const summary = test.document.getElementById('proposal-summary').textContent;
    assert.match(summary, /0\.60 → 0\.80/);
    assert.doesNotMatch(summary, /undefined|ML shadow|confidence/);
    const evidence = test.document.getElementById('proposal-evidence').textContent;
    assert.doesNotMatch(evidence, /ml_shadow|"features"|"policy"|confidence/);
    if (shape === 'legacy') assert.match(summary, /Example access control/);
    else assert.match(summary, /No control recommendations are available/);
    await vm.runInContext('refresh()', test.context);
    test.document.getElementById('reason').value = 'Reviewed the saved risk proposal for this synthetic example.';
    test.document.getElementById('review-form').emit('submit', {submitter: {value: 'approve'}});
    await settle(test.context);
    assert.equal(test.data.changed, true);
    assert.match(test.document.getElementById('risk-rows').textContent, /0\.60 → 0\.80/);
  }
  console.log('GRC CONTROLS: legacy, absent, null and malformed lists load, poll and review without a crash');
}

async function activityChecks() {
  const test = harness('admin');
  await login(test);
  vm.runInContext('busy = true', test.context);
  const before = test.calls.filter(route => route === '/activity').length;
  await vm.runInContext('refreshActivity()', test.context);
  assert.ok(test.calls.filter(route => route === '/activity').length > before);
  assert.match(test.document.getElementById('backend-status').textContent, /running/);
  vm.runInContext('busy = false', test.context);
  test.document.getElementById('logout').emit('click');
  assert.doesNotMatch(test.document.getElementById('backend-events').textContent, /Real test backend event/);
  const failure = harness('admin', {failRoute: '/activity'});
  await login(failure);
  await vm.runInContext('refreshActivity()', failure.context);
  assert.equal(failure.document.getElementById('login-panel').hidden, true);
  assert.equal(failure.document.getElementById('backend-status').textContent, 'Monitor unavailable');
  console.log('MONITOR: polls during commands, clears on logout, and failure does not block login');
}

async function chatChecks() {
  for (const role of ['soc', 'grc', 'admin']) {
    const test = harness(role), {document, context, data} = test;
    data.messages = [{id: 1, role: 'soc', text: '<img src=x onerror=alert(1)>', created_at: '2026-10-27T12:00:00Z'}];
    await login(test);
    await vm.runInContext('refreshChat()', context);
    const log = document.getElementById('chat-messages');
    assert.match(log.textContent, /<img src=x onerror=alert\(1\)>/);
    assert.equal(log.children[0].children[1].tag, 'p', 'Message is a plain-text paragraph');
    const count = log.children.length;
    await vm.runInContext('refreshChat()', context);
    assert.equal(log.children.length, count, 'Polling must not duplicate messages');
    vm.runInContext('busy = true', context);
    if (role === 'admin') {
      assert.equal(document.getElementById('chat-form'), null);
      await vm.runInContext('sendChat()', context);
      assert.equal(data.messages.length, 1);
    } else {
      document.getElementById('chat-text').value = 'Please review this asset.';
      await vm.runInContext('sendChat()', context);
      assert.equal(data.messages[1].role, role);
      assert.equal(document.getElementById('chat-text').value, '');
      assert.match(log.textContent, /Please review this asset/);
      assert.equal(document.getElementById('chat-send').disabled, false);
    }
    vm.runInContext('busy = false', context);
    document.getElementById('logout').emit('click');
    assert.equal(log.textContent, '', 'Logout clears all chat text');
    assert.equal(vm.runInContext('chatCursor', context), null);
  }
  const failure = harness('soc', {failRoute: '/chat'});
  await login(failure);
  failure.document.getElementById('chat-text').value = 'Preserve this draft';
  await vm.runInContext('sendChat()', failure.context);
  assert.equal(failure.document.getElementById('login-panel').hidden, true, 'Chat failure must not prevent dashboard login');
  assert.equal(failure.document.getElementById('chat-text').value, 'Preserve this draft');
  assert.match(failure.document.getElementById('chat-feedback').textContent, /draft is preserved/);
  const unfiltered = harness('admin', {unfiltered: true});
  await login(unfiltered);
  assert.equal(unfiltered.document.getElementById('chat-form').hidden, true);
  console.log('CHAT: team sends during commands, admin read-only, plain text, polling, logout and failed-send draft preservation passed');
}

async function inboxChecks() {
  const test = harness('admin'), {document, context} = test;
  await login(test);
  const list = document.getElementById('proposal-list');
  assert.equal(list.children.length, 2);
  assert.equal(document.getElementById('proposal-select'), null);
  const second = test.data.pending[1].proposal_id;
  list.children[1].children[0].emit('click');
  assert.equal(vm.runInContext('selected', context), second);
  document.getElementById('reason').value = 'Keep my review draft';
  list.scrollTop = 75;
  const originalRow = list.children[1];
  await vm.runInContext('refresh()', context);
  assert.equal(document.getElementById('reason').value, 'Keep my review draft');
  assert.equal(list.children[1], originalRow, 'Polling must not rebuild unchanged inbox rows');
  assert.equal(list.scrollTop, 75);
  document.getElementById('proposal-search').value = 'no-such-asset';
  document.getElementById('proposal-search').emit('input');
  assert.equal(list.children.length, 0);
  assert.equal(document.getElementById('inbox-empty').hidden, false);
  assert.equal(vm.runInContext('selected', context), second, 'Search must not silently substitute the decision');
  document.getElementById('proposal-search').value = '';
  document.getElementById('proposal-search').emit('input');
  document.getElementById('proposal-filters').children[1].emit('click');
  assert.equal(list.children.length, 1);
  assert.match(list.textContent, /SOC/);
  test.data.pending = test.data.pending.filter(p => p.proposal_id !== second);
  await vm.runInContext('refresh()', context);
  assert.equal(vm.runInContext('selected', context), '');
  assert.equal(document.getElementById('reason').value, '');
  document.getElementById('logout').emit('click');
  assert.equal(document.getElementById('proposal-search').value, '');
  assert.equal(list.children.length, 0);
  console.log('INBOX: click selection, search, team filters, polling scroll/draft preservation and stale selection passed');
}

async function chatWindowChecks() {
  const test = harness('soc'), {document, context, data} = test;
  await login(test);
  await vm.runInContext('refreshChat()', context);
  document.getElementById('chat-toggle').emit('click');
  assert.equal(document.getElementById('chat-body').hidden, true);
  assert.equal(document.getElementById('chat-toggle').getAttribute('aria-expanded'), 'false');
  data.messages.push({id: 1, role: 'grc', text: 'A new message', created_at: '2026-10-28T12:00:00Z'});
  await vm.runInContext('refreshChat()', context);
  assert.equal(document.getElementById('chat-unread').textContent, '1');
  assert.equal(document.getElementById('chat-unread').hidden, false);
  await vm.runInContext('refreshChat()', context);
  assert.equal(document.getElementById('chat-unread').textContent, '1');
  document.getElementById('chat-toggle').emit('click');
  assert.equal(document.getElementById('chat-body').hidden, false);
  assert.equal(document.getElementById('chat-unread').hidden, true);
  console.log('CHAT WINDOW: collapse, background updates, unread counts and reopening passed');
}

async function chatClearChecks() {
  for (const role of ['admin','soc','grc']) {
    const test=harness(role), {document,context,data}=test;
    data.messages=[{id:1,role:'soc',text:'Saved message',created_at:'2026-10-28T12:00:00Z'}];
    await login(test); await vm.runInContext('refreshChat()',context);
    assert.ok(document.getElementById('chat-clear').events.click.length);
    if (role !== 'admin') document.getElementById('chat-text').value='Preserve my draft';
    await vm.runInContext('clearChat()',context);
    assert.equal(document.getElementById('chat-messages').textContent,'');
    assert.equal(data.messages.length,1,'Clear must preserve the saved log');
    assert.equal(vm.runInContext('chatCursor',context),1);
    await vm.runInContext('refreshChat()',context);
    assert.equal(document.getElementById('chat-messages').textContent,'','Polling must not restore cleared messages');
    if (role !== 'admin') assert.equal(document.getElementById('chat-text').value,'Preserve my draft');
    data.messages.push({id:2,role:'grc',text:'A new message after clearing',created_at:'2026-10-28T13:00:00Z'});
    await vm.runInContext('refreshChat()',context);
    assert.match(document.getElementById('chat-messages').textContent,/A new message after clearing/);
    assert.doesNotMatch(document.getElementById('chat-messages').textContent,/Saved message/);
    assert.equal(!!document.getElementById('chat-logs'),role === 'admin');
    if (role === 'admin') {
      await vm.runInContext('downloadChatLogs()',context);
      assert.ok(test.calls.includes('/chat/logs'));
      assert.match(document.getElementById('chat-feedback').textContent,/downloaded/);
    }
  }
  const failure=harness('soc',{failRoute:'/chat/clear'});
  failure.data.messages=[{id:1,role:'grc',text:'Keep visible on failure',created_at:'2026-10-28T12:00:00Z'}];
  await login(failure); await vm.runInContext('refreshChat()',failure.context);
  failure.document.getElementById('chat-text').value='My draft';
  await vm.runInContext('clearChat()',failure.context);
  assert.match(failure.document.getElementById('chat-messages').textContent,/Keep visible on failure/);
  assert.equal(failure.document.getElementById('chat-text').value,'My draft');
  assert.equal(failure.document.getElementById('chat-clear').disabled,false);

  const race=harness('soc');
  race.data.messages=[{id:1,role:'grc',text:'Old pending poll',created_at:'2026-10-28T12:00:00Z'}];
  await login(race); await vm.runInContext('refreshChat()',race.context);
  const originalFetch=race.context.fetch;
  let release,started;
  const ready=new Promise(resolve=>{started=resolve;});
  race.context.fetch=async (url,options)=>{
    const response=await originalFetch(url,options);
    if (url.split('?')[0] === '/api/demo/chat' && !release) {
      await new Promise(resolve=>{release=resolve;started();});
    }
    return response;
  };
  const pendingPoll=vm.runInContext('refreshChat()',race.context);
  await ready;
  await vm.runInContext('clearChat()',race.context);
  release(); await pendingPoll;
  assert.equal(race.document.getElementById('chat-messages').textContent,'','A response started before Clear must be ignored');
  race.data.messages.push({id:2,role:'grc',text:'Still live after a stale response',created_at:'2026-10-28T13:00:00Z'});
  await vm.runInContext('refreshChat()',race.context);
  assert.match(race.document.getElementById('chat-messages').textContent,/Still live/);
  race.data.clearedThrough=2;
  await vm.runInContext('refreshChat()',race.context);
  assert.equal(race.document.getElementById('chat-messages').textContent,'','A clear from another tab of the same account updates this view');
  console.log('CLEAR CHAT: retained logs, per-view polling, drafts, failure recovery, stale responses and Admin export passed');
}

async function roleCardChecks() {
  for (const role of ['admin', 'soc', 'grc']) {
    const test = harness(role), {document} = test;
    assert.equal(document.body.dataset.session, 'locked');
    for (const candidate of ['admin', 'soc', 'grc'])
      assert.equal(document.getElementById('workspace-role-' + candidate).checked, candidate === role);
    assert.match(document.getElementById('login-submit').textContent, /Sign in as/);
    const target = role === 'soc' ? 'grc' : 'soc';
    document.getElementById('password').value = 'DO-NOT-TRANSFER-THIS-TEST-PASSWORD';
    document.getElementById('workspace-role-' + target).checked = true;
    document.getElementById('workspace-role-' + target).emit('change');
    assert.deepEqual(test.navigations, [], 'Role cards must not navigate or reload the page');
    assert.equal(vm.runInContext('loginRole', test.context), target);
    assert.equal(vm.runInContext('pageRole', test.context), role, 'Workspace changes only after successful sign-in');
    assert.match(document.getElementById('login-submit').textContent, new RegExp(target === 'soc' ? 'SOC analyst' : 'GRC officer'));
    assert.equal(document.getElementById('password').value, '');
    assert.deepEqual(test.calls, [], 'Choosing a role never authenticates or fetches private records');
    await login(test);
    locked(test);
    assert.deepEqual(test.calls, ['/auth/login'], 'A different role account must be rejected before loading another workspace');
  }
  console.log('ROLE CARDS: in-place selection, no navigation/API reads, updated labels and wrong-role rejection passed');
}

async function modelReviewChecks() {
  const test = harness('grc');
  test.data.pending[0].payload.evidence.model2_review = {
    source: 'experimental_grounded_candidate_model', release_eligible: false, automatic_execution: false,
    recommendations: [{control_id:'CTL-IAM-002',name:'Enforce MFA for remote access',reason:'Observed technique matches a registered-risk link',
      source:'experimental_grounded_candidate_model',current_state:'unknown',implementation_state_known:false,model_score:.99}]
  };
  await login(test);
  const summary = test.document.getElementById('proposal-summary').textContent;
  assert.match(summary, /Enforce MFA for remote access.*CTL-IAM-002/);
  assert.match(summary, /State: unknown/);
  assert.match(summary, /Source: experimental_grounded_candidate_model/);
  assert.match(summary, /Observed technique matches/);
  assert.doesNotMatch(test.document.getElementById('proposal-evidence').textContent, /model_score|0\.99/);
  const missing = harness('grc');
  missing.data.pending[0].payload.evidence.model2_review = {
    source:'not_run',reason:'Required context is absent',missing_fields:['asset.control_groups','alerts.mitre_technique'],recommendations:[]
  };
  await login(missing);
  assert.match(missing.document.getElementById('proposal-summary').textContent, /Missing runtime fields: asset.control_groups, alerts.mitre_technique/);
  missing.document.getElementById('reason').value = 'Review the existing rules-based proposal';
  missing.document.getElementById('review-form').emit('submit', {submitter:{value:'approve'}});
  await settle(missing.context);
  assert.equal(missing.data.changed, true, 'Missing experimental context must not change the existing approval workflow');
  console.log('MODEL REVIEW: name, ID, reason, source, unknown state, score isolation and missing-context approval regression passed');
}

(async () => {
  for (const role of ["soc", "grc", "admin"]) await check(role);
  await failureChecks();
  await unfilteredChecks();
  await grcControlChecks();
  await activityChecks();
  await chatChecks();
  await inboxChecks();
  await chatWindowChecks();
  await chatClearChecks();
  await roleCardChecks();
  await modelReviewChecks();
})().catch(error => { console.error(error); process.exitCode = 1; });
