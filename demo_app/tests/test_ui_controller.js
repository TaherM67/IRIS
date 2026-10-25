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
    const code = "from demo_app.server import dashboard_html; print(dashboard_html('" + role + "').decode('utf-8'))";
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
    if (!['meta', 'link', 'input', 'br', 'hr', 'img'].includes(element.tag)) stack.push(element);
    if (attrs.id) { assert.ok(!ids.has(attrs.id), "Duplicate HTML ID: " + attrs.id); ids.set(attrs.id, element); }
  }
  return {hidden: false, body: Object.assign(new Element(), {dataset: {role}}),
    getElementById: id => ids.get(id) || null, createElement: tag => new Element(tag),
    querySelectorAll: selector => selector === "button" ? nodes.filter(n => n.tag === "button") :
      selector === 'nav[aria-label="Dashboards"] a' ? nodes.filter(n => n.tag === 'a' && n.closest('nav')) : nodes.filter(n => "count" in n.dataset)};
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

const TEST_KEY = "SYNTHETIC-UI-TEST-KEY-NOT-A-REAL-SECRET";

function mockFetch(role, data, calls, behavior = {}) {
  return async (url, options = {}) => {
    const route = new URL(url, "http://local.test").pathname.replace("/api/demo", ""); calls.push(route);
    assert.equal(typeof options.headers?.["X-IRIS-Key"], "string");
    const response = (value, status = 200) => ({ok: status >= 200 && status < 300, status,
      json: async () => JSON.parse(JSON.stringify(value))});
    if (behavior.stateStatus === 401 && route === "/state") return response({detail: "A valid local demo key is required"}, 401);
    if (route === behavior.failRoute) return response({detail: "Synthetic initial loading failure"}, 500);
    let value;
    if (route === "/state") value = {...data.state, role: behavior.stateRole || data.state.role};
    else if (route === "/proposals") value = {exercise_id: "UI-TEST", items: data.pending, total: data.pending.length};
    else if (route === "/changes") value = {exercise_id: "UI-TEST", items: []};
    else if (route === "/audit") { assert.equal(role, "admin"); value = []; }
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
  const document = documentFor(role, behavior.unfiltered), data = fixture(role), calls = [];
  const context = vm.createContext({document, location: {pathname: "/" + role}, fetch: mockFetch(role, data, calls, behavior), AbortController,
    Option: function(label, value) { const option = new Element("option"); option.textContent = label; option.value = value; return option; },
    setInterval() { return 1; }, setTimeout, URL, Blob, confirm: () => true, console});
  vm.runInContext(fs.readFileSync(path.join(root, "app.js"), "utf8"), context);
  assert.deepEqual(calls, [], "Original page waits for Connect, with no version/session prerequisites");
  return {document, data, calls, context};
}
async function login(test) {
  test.document.getElementById("key").value = TEST_KEY;
  test.document.getElementById("login-form").emit("submit"); await settle(test.context);
}
function locked(test) {
  assert.equal(test.document.getElementById("workspace").hidden, true);
  assert.equal(test.document.getElementById("login-panel").hidden, false);
  assert.equal(vm.runInContext("key", test.context), "");
  assert.equal(vm.runInContext("identity", test.context), null);
  assert.equal(test.document.getElementById("key").value, "");
}

async function check(role) {
  const test = harness(role), {document, data, calls, context} = test;
  await login(test);
  assert.equal(document.getElementById("login-panel").hidden, true, document.getElementById("message").textContent);
  assert.equal(document.getElementById("workspace").hidden, false);
  assert.match(document.getElementById("proposal-summary").textContent, /identity-server/);
  assert.equal(calls[0], "/state", "Original sign-in authenticates directly with /state");
  assert.ok(!calls.includes("/info") && !calls.includes("/session"));
  assert.equal(document.getElementById("pending-count").textContent, role === "admin" ? "2" : "1");
  if (role === "soc") {
    for (const id of ["risk-panel", "risk-count", "risk-changed", "model-status"]) assert.equal(document.getElementById(id), null);
    assert.ok(!calls.includes("/risks") && !calls.includes("/audit"));
    assert.equal(document.getElementById("alert-count").textContent, "2,355");
    assert.match(document.getElementById("proposal-summary").textContent, /19 alerts.*Critical/);
    assert.doesNotMatch(document.getElementById("proposal-evidence").textContent, /primary_controls|"controls"|"policy"/);
  } else if (role === "grc") {
    for (const id of ["alert-panel", "alert-count", "alert-changed", "model-status"]) assert.equal(document.getElementById(id), null);
    assert.ok(!calls.includes("/alerts") && !calls.includes("/audit"));
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
    assert.ok(test.calls.every(route => route === "/state"), "Wrong-role key must not fetch proposal/table records");
    assert.match(test.document.getElementById("message").textContent, /key|dashboard|role/i);
  }
  {
    const test = harness("soc", {stateStatus: 401}); await login(test); locked(test);
    assert.ok(test.calls.every(route => route === "/state"));
    assert.match(test.document.getElementById("message").textContent, /key|valid|rejected/i);
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

(async () => {
  for (const role of ["soc", "grc", "admin"]) await check(role);
  await failureChecks();
  await unfilteredChecks();
})().catch(error => { console.error(error); process.exitCode = 1; });
