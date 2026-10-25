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

function mockFetch(role, data, calls) {
  return async (url, options = {}) => {
    const route = new URL(url, "http://local.test").pathname.replace("/api/demo", ""); calls.push(route);
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
    return {ok: true, json: async () => JSON.parse(JSON.stringify(value))};
  };
}

async function settle(context) {
  for (let attempt = 0; attempt < 100; attempt++) {
    await new Promise(resolve => setImmediate(resolve));
    if (!vm.runInContext("busy", context)) return;
  }
  throw new Error("Controller action did not settle");
}

async function check(role) {
  const document = documentFor(role), data = fixture(role), calls = [];
  const context = vm.createContext({document, fetch: mockFetch(role, data, calls), AbortController,
    Option: function(label, value) { const option = new Element("option"); option.textContent = label; option.value = value; return option; },
    setInterval() { return 1; }, setTimeout, URL, Blob, confirm: () => true, console});
  vm.runInContext(fs.readFileSync(path.join(root, "app.js"), "utf8"), context);
  document.getElementById("key").value = "SYNTHETIC-UI-TEST-KEY-NOT-A-REAL-SECRET";
  document.getElementById("login-form").emit("submit"); await settle(context);
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
  document.getElementById("key").value = "SYNTHETIC-WRONG-ROLE-UI-FIXTURE";
  document.getElementById("login-form").emit("submit"); await settle(context);
  assert.equal(document.getElementById("workspace").hidden, true);
  assert.equal(document.getElementById("message").classList.contains("error"), true);
  assert.equal(vm.runInContext("key", context), "");
  console.log(role.toUpperCase() + ": role-only controller login, render, approval/read-only and logout passed");
}

(async () => { for (const role of ["soc", "grc", "admin"]) await check(role); })().catch(error => { console.error(error); process.exitCode = 1; });
