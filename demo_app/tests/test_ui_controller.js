"use strict";
/* Unit checks for the actual controller, not a browser or visual-layout test.
 * Run: node demo_app/tests/test_ui_controller.js. No npm install is required.
 * Deliberate DOM/API doubles verify role-only reads and approval rendering.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const root = path.resolve(__dirname, "../static");

class Element {
  constructor(tag = "div", attrs = {}) {
    this.tag = tag; this.children = []; this.events = {}; this.content = "";
    this.attributes = {...attrs}; this.type = attrs.type || "";
    this.value = attrs.value || ""; this.checked = "checked" in attrs;
    this.hidden = "hidden" in attrs; this.disabled = false; this.open = false; this.dataset = {};
    for (const [key, value] of Object.entries(attrs)) if (key.startsWith("data-")) this.dataset[key.slice(5)] = value;
    const flags = new Set();
    this.classList = {toggle(key, on) { on ? flags.add(key) : flags.delete(key); }, contains: key => flags.has(key)};
  }
  set textContent(value) { this.content = String(value); this.children = []; }
  get textContent() { return this.content + this.children.map(n => n.textContent).join(""); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.content = ""; this.children = nodes; }
  addEventListener(event, callback) { (this.events[event] ||= []).push(callback); }
  setAttribute(name, value) { this.attributes[name] = String(value); if (name === "type") this.type = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  emit(event, extra = {}) { for (const callback of this.events[event] || []) callback({preventDefault() {}, ...extra}); }
  reset() { this.value = ""; }
  click() {}
  remove() {}
}

function documentFor(role) {
  const reviews = fs.readFileSync(path.join(root, "reviews.html"), "utf8");
  const partial = fs.readFileSync(path.join(root, role + ".html"), "utf8").replace("<!-- IRIS: reviews -->", reviews);
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8").replace("<!-- IRIS: workspace -->", partial).replace(/<!--[\s\S]*?-->/g, "");
  const nodes = [], ids = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/gi)) {
    const attrs = {};
    for (const attribute of match[2].matchAll(/([a-z][a-z0-9-]*)(?:="([^"]*)")?/gi)) attrs[attribute[1]] = attribute[2] || "";
    const element = new Element(match[1], attrs); nodes.push(element);
    if (attrs.id) ids.set(attrs.id, element);
  }
  if (ids.has("proposal-status")) ids.get("proposal-status").value = "pending";
  return {hidden: false, body: Object.assign(new Element(), {dataset: {role}}),
    getElementById: id => ids.get(id) || null, createElement: tag => new Element(tag),
    querySelectorAll: selector => selector === "button" ? nodes.filter(n => n.tag === "button") : nodes.filter(n => "count" in n.dataset)};
}

function fixture(role) {
  const shared = {hostname: "identity-server", asset_criticality: 5};
  const controls = [{name: "Example access control", control_id: "SC005", current_state: "implemented", action_type: "verify"}];
  const technical = {...shared, primary_assessment: {scenario_class: "credential_access"},
    features: {event_count: 29, failed_count: 28, max_rule_level: 15}, warnings: [],
    ml_shadow: {scenario: "credential_access", confidence: .92}, primary_controls: {recommendations: controls}, policy: {priority: "Critical"}};
  const business = {...shared, observed_activity: "credential_access", risk_category: "Unauthorized Access", controls};
  const soc = {proposal_id: "PROP-" + "a".repeat(32), kind: "soc", status: "pending",
    payload: {changed_alerts: 19, before_counts: {High: 19}, new_priority: "Critical", evidence: technical}};
  const grc = {proposal_id: "PROP-" + "b".repeat(32), kind: "grc", status: "pending",
    payload: {risk_id: "DEMO-R001-1", before: {score: .6, likelihood: 3, impact: 5}, after: {score: .8, likelihood: 4, impact: 5}, evidence: role === "admin" ? technical : business}};
  const counts = role === "soc" ? {alerts: 2355, pending_soc: 1, reprioritized_alerts: 0} :
    role === "grc" ? {risks: 60, pending_grc: 1, changed_risks: 0} :
    {alerts: 2355, risks: 60, pending_soc: 1, pending_grc: 1, reprioritized_alerts: 0, changed_risks: 0};
  return {state: {role, exercise_id: "UI-TEST", label: "Synthetic UI fixture", analyzed: true, counts,
    ...(role === "admin" ? {analysis: {sessions: 132}, model: {loaded: true}, exercise_history: []} : {})},
    pending: role === "admin" ? [soc, grc] : role === "soc" ? [soc] : [grc], changed: false};
}

const TEST_KEY = "SYNTHETIC-UI-TEST-KEY-NOT-A-REAL-SECRET";
const UI_VERSION = "2026.10.25.2";

// These responses deliberately model only the API contract. They do not bypass
// the real server's authorization checks or use any locally configured key.
function mockFetch(role, data, calls, requests, behavior = {}) {
  return async (url, options = {}) => {
    const route = new URL(url, "http://local.test").pathname.replace("/api/demo", ""); calls.push(route);
    requests.push({route, headers: {...options.headers}});
    const response = (value, status = 200) => ({ok: status >= 200 && status < 300, status,
      json: async () => JSON.parse(JSON.stringify(value))});
    if (route === "/info") {
      assert.equal(Object.keys(options.headers || {}).some(name => name.toLowerCase() === "x-iris-key"), false,
        "The public build/profile check must never send a role credential");
      return response({service: "iris-active-demo", ui_version: behavior.infoVersion || UI_VERSION, access_profile: "test-profile"});
    }
    assert.equal(typeof options.headers?.["X-IRIS-Key"], "string");
    if (route === "/session") return response(behavior.sessionStatus === 401 ? {detail: "Rejected synthetic test credential"} :
      {role: behavior.sessionRole || data.state.role, access_profile: "test-profile"}, behavior.sessionStatus || 200);
    if (route === behavior.failRoute) return response({detail: "Synthetic initial loading failure"}, 500);
    let value;
    if (route === "/state") value = data.state;
    else if (route === "/proposals") value = {exercise_id: "UI-TEST", items: data.pending, total: data.pending.length};
    else if (route === "/changes") value = {exercise_id: "UI-TEST", items: []};
    else if (route === "/audit") { assert.equal(role, "admin"); value = []; }
    else if (route === "/risks") {
      assert.notEqual(role, "soc");
      value = {exercise_id: "UI-TEST", items: [{risk_id: "DEMO-R001-1", hostname: "identity-server", category: "Unauthorized Access",
        baseline_likelihood: 3, current_likelihood: data.changed ? 4 : 3, impact: 5, baseline_score: .6, current_score: data.changed ? .8 : .6, version: data.changed ? 2 : 1}]};
    } else if (route === "/alerts") {
      assert.notEqual(role, "grc");
      value = {exercise_id: "UI-TEST", total: data.changed ? 19 : 2355, items: [{event_id: "UI-EVENT", hostname: "identity-server",
        baseline_priority: "High", current_priority: data.changed ? "Critical" : "High", version: data.changed ? 2 : 1}]};
    } else if (route.endsWith("/review")) {
      assert.notEqual(role, "admin");
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
  const document = documentFor(role), data = fixture(role), calls = [], requests = [];
  const context = vm.createContext({document, fetch: mockFetch(role, data, calls, requests, behavior), AbortController,
    Option: function(label, value) { const option = new Element("option"); option.textContent = label; option.value = value; return option; },
    setInterval() { return 1; }, setTimeout, URL, Blob, confirm: () => true, console});
  vm.runInContext(fs.readFileSync(path.join(root, "app.js"), "utf8"), context);
  return {document, data, calls, requests, context};
}

async function login(test, value = TEST_KEY) {
  test.document.getElementById("key").value = value;
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
  assert.equal(document.getElementById("login-panel").hidden, true);
  assert.equal(document.getElementById("message").classList.contains("error"), false);
  assert.equal(document.getElementById("proposal-asset").textContent, "identity-server");
  if (role === "soc") {
    assert.equal(document.getElementById("risk-panel"), null);
    assert.ok(!calls.includes("/risks") && !calls.includes("/audit"));
    assert.equal(document.getElementById("after-value").textContent, "Critical");
  } else if (role === "grc") {
    assert.equal(document.getElementById("alert-panel"), null);
    assert.ok(!calls.includes("/alerts") && !calls.includes("/audit"));
    assert.equal(document.getElementById("after-value").textContent, "0.80");
    assert.match(document.getElementById("decision-details").textContent, /Control recommendations/);
    assert.doesNotMatch(document.getElementById("decision-details").textContent, /confidence|Failed sign-ins/);
  } else {
    assert.ok(calls.includes("/risks") && calls.includes("/alerts") && calls.includes("/audit"));
    assert.equal(document.getElementById("review-form").hidden, true);
    assert.match(document.getElementById("admin-evidence").textContent, /policy/);
  }
  if (role !== "admin") {
    document.getElementById("reason").value = "Reviewed synthetic evidence; approve this demo change.";
    document.getElementById("review-form").emit("submit", {submitter: {value: "approve"}}); await settle(context);
    assert.equal(data.changed, true);
    assert.equal(document.getElementById("message").classList.contains("error"), false);
    assert.equal(document.getElementById("proposal-content").hidden, true);
    const rows = document.getElementById(role === "soc" ? "alert-rows" : "risk-rows").textContent;
    assert.match(rows, role === "soc" ? /Critical/ : /0.60 → 0.80/);
  }
  document.getElementById("logout").emit("click");
  assert.equal(document.getElementById("workspace").hidden, true);
  assert.equal(vm.runInContext("key", context), "");
  // A valid key for another role must not open this page or paint its records.
  data.state.role = role === "admin" ? "soc" : "admin";
  const stateReads = calls.filter(route => route === "/state").length;
  await login(test, "SYNTHETIC-WRONG-ROLE-UI-FIXTURE");
  assert.equal(document.getElementById("workspace").hidden, true);
  assert.equal(document.getElementById("message").classList.contains("error"), true);
  assert.equal(vm.runInContext("key", context), "");
  assert.equal(calls.filter(route => route === "/state").length, stateReads,
    "A mismatched authenticated role must not fetch dashboard records");
  console.log(role.toUpperCase() + ": role-only controller login, render, approval/read-only and logout passed");
}

async function accessChecks() {
  // Single labelled/quoted CLI lines and smart OUTER quotes are normalized only;
  // no internal characters are guessed, removed or replaced.
  for (const input of [`soc: "${TEST_KEY}"`, `'${TEST_KEY}'`, `“${TEST_KEY}”`]) {
    const test = harness("soc"); await login(test, input);
    assert.equal(test.document.getElementById("login-panel").hidden, true);
    const session = test.requests.find(request => request.route === "/session");
    assert.equal(session.headers["X-IRIS-Key"], TEST_KEY);
  }
  for (const [input, expected] of [
    [`grc: ${TEST_KEY}`, /labelled GRC/],
    [`${TEST_KEY}\n${TEST_KEY}`, /one complete role key on one line/],
    [`${TEST_KEY.slice(0, 12)}“${TEST_KEY.slice(12)}`, /one complete role key on one line/]
  ]) {
    const test = harness("soc"); await login(test, input); locked(test);
    assert.equal(test.calls.includes("/session"), false, "Malformed input must fail before authentication");
    assert.equal(test.calls.includes("/state"), false);
    assert.match(test.document.getElementById("login-error").textContent, expected);
    assert.equal(test.document.getElementById("login-error").hidden, false);
  }
  {
    const test = harness("soc", {sessionStatus: 401}); await login(test); locked(test);
    assert.match(test.document.getElementById("login-error").textContent, /Key not accepted.*SAME project folder/);
    assert.equal(test.calls.includes("/state"), false);
  }
  {
    const test = harness("soc", {sessionRole: "admin"}); await login(test); locked(test);
    assert.match(test.document.getElementById("login-error").textContent, /belongs to ADMIN/);
    assert.equal(test.calls.includes("/state"), false);
  }
  {
    const test = harness("soc", {failRoute: "/proposals"}); await login(test); locked(test);
    assert.equal(vm.runInContext("state", test.context), null);
    assert.match(test.document.getElementById("login-error").textContent, /initial loading failure/);
    assert.equal(test.document.getElementById("alert-rows").textContent, "");
  }
  {
    const test = harness("soc", {infoVersion: "outdated-fixture"}); await login(test); locked(test);
    assert.match(test.document.getElementById("login-error").textContent, /older or different app/);
    assert.ok(test.requests.length > 0);
    assert.ok(test.requests.every(request => request.route === "/info" && !("X-IRIS-Key" in request.headers)),
      "An unverified/stale server must not receive the supplied key");
  }
  {
    const test = harness("soc"), {document} = test;
    const toggle = document.getElementById("toggle-key"), input = document.getElementById("key");
    assert.ok(toggle, "The key visibility control must be present in the actual HTML");
    assert.equal(input.type, "password");
    toggle.emit("click"); assert.equal(input.type, "text"); assert.equal(toggle.getAttribute("aria-pressed"), "true");
    toggle.emit("click"); assert.equal(input.type, "password"); assert.equal(toggle.getAttribute("aria-pressed"), "false");
    toggle.emit("click"); await login(test);
    assert.equal(input.type, "password"); assert.equal(input.value, ""); assert.equal(toggle.getAttribute("aria-pressed"), "false");
    document.getElementById("logout").emit("click"); locked(test);
    assert.equal(input.type, "password"); assert.equal(toggle.getAttribute("aria-pressed"), "false");
    assert.equal(document.getElementById("alert-rows").textContent, "");
  }
  console.log("ACCESS: 11 normalization, locked-failure, server-version and visibility scenarios passed");
}

(async () => {
  for (const role of ["soc", "grc", "admin"]) await check(role);
  await accessChecks();
})().catch(error => { console.error(error); process.exitCode = 1; });
