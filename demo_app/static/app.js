"use strict";

// The server selects the page template. The key, not this label, authorizes API data.
const el = id => document.getElementById(id);
const pageRole = document.body.dataset.role;
const uiVersion = "2026.10.25.2";
let key = "", identity = null, state = null, proposals = [], selected = "";
let offset = 0, totalAlerts = 0, busy = false, generation = 0, selectFirst = true;
let controller = new AbortController();

// Safe DOM helpers: evidence is text, never source HTML supplied by a dataset.
function node(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = text;
  if (className) result.className = className;
  return result;
}
function text(id, value) { if (el(id)) el(id).textContent = value; }
function pretty(id, value) { text(id, JSON.stringify(value, null, 2)); }
function message(value, error = false) {
  text("message", value); el("message").classList.toggle("error", error);
  // A login failure must remain next to the input, not below the locked page.
  if (el("login-error")) {
    el("login-error").hidden = !error || el("login-panel").hidden;
    text("login-error", error ? value : "");
  }
}
function cell(value, detail) {
  const result = node("td", value);
  if (detail) result.append(node("span", detail, "secondary-line"));
  return result;
}
function priority(value) { return node("span", value, "priority priority-" + value.toLowerCase()); }
function activity(value) {
  return {credential_access: "Suspicious sign-in activity", reconnaissance: "Network scanning", benign: "Routine activity"}[value] || "Insufficient evidence";
}
function score(value) { return Number(value).toFixed(2); }
function changedValue(before, after, format = String) { return before === after ? format(after) : `${format(before)} → ${format(after)}`; }

// Accept a clearly labelled, single-line CLI paste without guessing/truncating a
// secret. Wrong-role labels and malformed input fail before HTTP header creation.
function normalizeKey(value) {
  let token = value.trim();
  const label = token.match(/^(admin|soc|grc)\s*:\s*/i);
  if (label) {
    if (label[1].toLowerCase() !== pageRole) throw new Error(`This is labelled ${label[1].toUpperCase()}. Use python demo.py keys --role ${pageRole} for this workspace.`);
    token = token.slice(label[0].length).trim();
  }
  const pairs = {'"': '"', "'": "'", "“": "”", "‘": "’"};
  if (pairs[token[0]] && token.endsWith(pairs[token[0]])) token = token.slice(1, -1);
  if (!/^[\x21-\x7E]{32,256}$/.test(token)) throw new Error("Paste one complete role key on one line. Do not include terminal instructions, spaces or JSON fields.");
  return token;
}

// This public endpoint contains three safe labels only. Comparing the displayed
// profile to the private CLI helps spot a different folder or a stale process.
async function serverInfo() {
  let response;
  try { response = await fetch("/api/demo/info", {cache: "no-store", credentials: "omit", redirect: "error", signal: controller.signal}); }
  catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error("Cannot reach IRIS. Start python demo.py and open the local URL printed in that terminal.");
  }
  let info;
  try { info = await response.json(); } catch (_) { /* Report a safe error below, never echo a foreign page. */ }
  if (!response.ok || info?.service !== "iris-active-demo" || info.ui_version !== uiVersion) throw new Error("The running server is an older or different app. Stop it, run the updated demo.py, then press Ctrl+F5.");
  text("access-profile", `Key profile ${info.access_profile} · compare with demo.py keys`);
  return info;
}

// Authenticate every call with the tab's memory-only key; discard old-session replies.
async function api(path, options = {}) {
  const current = generation;
  let response;
  try {
    response = await fetch("/api/demo" + path, {
      ...options, headers: {"X-IRIS-Key": key, ...(options.headers || {})},
      signal: controller.signal, cache: "no-store", credentials: "omit", redirect: "error"
    });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error("Connection lost. Keep the demo terminal running, then reconnect or refresh.");
  }
  let result;
  try { result = await response.json(); }
  catch (_) { throw new Error("This server did not return the IRIS API. Restart the updated demo.py and reload this tab."); }
  if (generation !== current) throw new Error("The connection changed. Please reconnect.");
  if (response.status === 401) {
    disconnect();
    throw new Error(`Key not accepted by this server. Run python demo.py doctor in the SAME project folder, then use python demo.py keys --role ${pageRole}. Older backend keys will not work.`);
  }
  if (!response.ok) throw new Error(result.detail || "The backend could not complete this action.");
  return result;
}
function post(path, body) { return api(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}); }

// Serialise tab actions so polling cannot overwrite a review during submission.
async function action(callback) {
  if (busy) return;
  busy = true;
  const buttons = Array.from(document.querySelectorAll("button"));
  for (const button of buttons) button.disabled = true;
  try { await callback(); }
  catch (error) { if (error.name !== "AbortError") message(error.message, true); }
  finally { busy = false; for (const button of buttons) button.disabled = false; pager(); }
}
function pager() {
  if (!el("previous")) return;
  el("previous").disabled = busy || offset === 0;
  el("next").disabled = busy || offset + 50 >= totalAlerts;
}

// Render a short fact list rather than raw JSON on either team page.
function facts(items) {
  const list = node("dl", undefined, "fact-list");
  for (const [label, value] of items) list.append(node("dt", label), node("dd", String(value)));
  return list;
}
function socDetails(evidence) {
  const features = evidence.features;
  const panel = node("div");
  panel.append(node("p", evidence.priority_reason || "IRIS combines observed severity with asset criticality."));
  // Show the signal relevant to this activity instead of a meaningless login
  // failure count on a network-scan review.
  const signal = features.event_family === "network" ? ["Distinct triggered rules", features.distinct_rules] : ["Failed sign-ins", features.failed_count];
  panel.append(facts([
    ["Activity", activity(evidence.primary_assessment.scenario_class)],
    ["Events in this session", features.event_count], signal,
    ["Highest SIEM rule level", `${features.max_rule_level}/16`],
    ["Asset criticality", `${evidence.asset_criticality}/5`]
  ]));
  // SOC may inspect the scenario candidate; GRC never receives this confidence.
  const shadow = evidence.ml_shadow;
  if (shadow) {
    const scenario = shadow.scenario === undefined ? shadow.scenario_class : shadow.scenario;
    panel.append(node("p", `Experimental model comparison: ${activity(scenario)} · ${(shadow.confidence * 100).toFixed(1)}% confidence. This is not an approved decision.`, "technical-note"));
  }
  if (evidence.warnings.length) panel.append(node("p", evidence.warnings.join(" "), "small-help"));
  return panel;
}
function grcDetails(evidence, payload) {
  const panel = node("div");
  const scenario = evidence.observed_activity || evidence.primary_assessment?.scenario_class;
  panel.append(node("p", evidence.risk_reason || "The activity matches this registered risk. The explicit policy proposes a likelihood increase; impact stays unchanged."));
  panel.append(facts([
    ["Registered risk", payload.risk_id],
    ["Risk category", evidence.risk_category || (scenario === "credential_access" ? "Unauthorized Access" : "Reconnaissance")],
    ["Observed activity", activity(scenario)], ["Asset criticality", `${evidence.asset_criticality}/5`]
  ]));
  const controls = evidence.controls || evidence.primary_controls?.recommendations || [];
  if (controls.length) {
    panel.append(node("h3", "Control recommendations"));
    const table = node("table"), header = node("tr"), body = node("tbody");
    for (const label of ["Control", "Recorded state", "Suggested action"]) header.append(node("th", label));
    const head = node("thead"); head.append(header); table.append(head);
    for (const control of controls) {
      const row = node("tr");
      const actionName = {install: "Consider adding", extend: "Extend coverage", verify: "Verify existing control", review: "Human review needed"}[control.action_type];
      const stateName = {implemented: "In place", partial: "Partly in place", missing: "Not in place", exception: "Policy exception", not_assessed: "Not assessed", unknown: "Not recorded", compensating: "Compensating control"}[control.current_state];
      row.append(cell(control.name, control.control_id), cell(stateName || control.current_state), cell(actionName || control.action_type));
      body.append(row);
    }
    table.append(body); const wrap = node("div", undefined, "table-wrap"); wrap.append(table); panel.append(wrap);
    panel.append(node("p", "Control advice is not executed here. This approval changes the risk register only.", "small-help"));
  }
  return panel;
}

// Show one review with a clear before/after pair and a role-specific explanation.
function renderProposal() {
  const proposal = proposals.find(item => item.proposal_id === selected);
  el("proposal-content").hidden = !proposal;
  el("review-empty").hidden = !!proposal;
  el("review-form").hidden = !proposal || pageRole === "admin";
  el("decision-details").replaceChildren();
  if (!proposal) {
    text("review-empty", !state?.analyzed ? "Waiting for Admin to analyze the demo data." : proposals.length ? "Choose a proposal to review." : "No reviews are waiting. Saved changes remain visible below.");
    text("admin-evidence", "Select a review to inspect its full saved evidence.");
    return;
  }
  const payload = proposal.payload, evidence = payload.evidence;
  const isSoc = proposal.kind === "soc";
  text("proposal-asset", evidence.hostname);
  if (isSoc) {
    const before = Object.keys(payload.before_counts);
    text("proposal-description", `${payload.changed_alerts} alerts have a recommended priority change.`);
    text("before-value", before.length === 1 ? before[0] : "Mixed priorities");
    text("before-detail", Object.entries(payload.before_counts).map(([name, count]) => `${count} ${name.toLowerCase()}`).join(" · "));
    text("after-value", payload.new_priority); text("after-detail", `${payload.changed_alerts} alerts will be updated`);
    el("decision-details").append(socDetails(evidence));
  } else {
    text("proposal-description", `${payload.risk_id} · likelihood changes; impact stays the same.`);
    text("before-value", score(payload.before.score)); text("after-value", score(payload.after.score));
    text("before-detail", `Likelihood ${payload.before.likelihood} · impact ${payload.before.impact}`);
    text("after-detail", `Likelihood ${payload.after.likelihood} · impact ${payload.after.impact}`);
    el("decision-details").append(grcDetails(evidence, payload));
  }
  // Historical Admin reviews must not mislabel old values as current state.
  const pending = proposal.status === "pending";
  text("before-label", pending ? (isSoc ? "Current priority" : "Current risk score") : "Before review");
  text("after-label", pending ? (isSoc ? "Recommended priority" : "Recommended risk score") : proposal.status === "approved" ? "Approved result" : "Proposed result");
  text("approve", isSoc ? "Approve priority change" : "Approve risk update");
  pretty("admin-evidence", proposal);
}
function renderProposalList(result) {
  proposals = result.items;
  const previous = selected;
  if (selectFirst && proposals.length) { selected = proposals[0].proposal_id; selectFirst = false; }
  else if (!proposals.some(item => item.proposal_id === selected)) selected = "";
  // An invalidated review must not silently switch to a different approval target.
  if (previous !== selected) { el("reason").value = ""; el("review-details").open = false; }
  const options = [new Option("Choose a proposal", "")];
  for (const proposal of proposals) {
    const p = proposal.payload;
    const label = proposal.kind === "soc" ? `${p.changed_alerts} alerts → ${p.new_priority}` : `risk score ${score(p.before.score)} → ${score(p.after.score)}`;
    options.push(new Option(`${p.evidence.hostname} · ${label}${pageRole === "admin" ? " · " + proposal.status : ""}`, proposal.proposal_id));
  }
  el("proposal-select").replaceChildren(...options); el("proposal-select").value = selected;
  text("proposal-count", `${result.total} ${pageRole === "admin" ? "reviews" : "pending"}`);
  renderProposal();
}

// Tables always use current backend records; green rows are actual saved revisions.
function renderRisks(result) {
  el("risk-rows").replaceChildren(...result.items.map(item => {
    const row = node("tr", undefined, item.version > 1 ? "changed" : "");
    row.append(cell(item.risk_id, `${item.hostname} · ${item.category}`), cell(changedValue(item.baseline_likelihood, item.current_likelihood)), cell(String(item.impact)), cell(changedValue(item.baseline_score, item.current_score, score)), cell(item.version > 1 ? "Updated" : "Unchanged", item.version > 1 ? `Approved · revision ${item.version}` : "Original record"));
    return row;
  }));
}
function renderAlerts(result) {
  totalAlerts = result.total;
  text("alert-page", result.total ? `${offset + 1}–${Math.min(offset + result.items.length, result.total)} of ${result.total}` : "No changed alerts yet");
  el("alert-rows").replaceChildren(...result.items.map(item => {
    const row = node("tr", undefined, item.version > 1 ? "changed" : "");
    const before = node("td"), after = node("td"); before.append(priority(item.baseline_priority)); after.append(priority(item.current_priority));
    row.append(cell(item.event_id, item.hostname), before, after, cell(item.version > 1 ? "Reprioritized" : "Unchanged", item.version > 1 ? `Approved · revision ${item.version}` : "Original priority"));
    return row;
  }));
  pager();
}
function renderChanges(result) {
  el("changes-empty").hidden = result.items.length > 0; el("changes-table").hidden = result.items.length === 0;
  el("change-rows").replaceChildren(...result.items.map(item => {
    const row = node("tr");
    const format = value => item.target_kind === "risk" ? `Score ${score(value.score)} · likelihood ${value.likelihood}` : value.priority;
    row.append(cell(item.target_id, pageRole === "admin" ? `${item.actor.toUpperCase()} approval` : "Approved change"), cell(format(item.before)), cell(format(item.after)), cell(item.reason, item.changed_at));
    return row;
  }));
}

// Read only endpoints represented by this role's server-rendered panels.
// Stage results before painting so a concurrent new rehearsal cannot mix records.
async function refresh() {
  if (!identity) return;
  const next = await api("/state");
  if (next.role !== pageRole) { disconnect(); throw new Error("The server role changed. Reconnect with this workspace's own key."); }
  const query = el("proposal-status") ? `?status=${encodeURIComponent(el("proposal-status").value)}` : "";
  const requests = {proposals: api("/proposals" + query), changes: api("/changes")};
  if (el("risk-panel")) requests.risks = api("/risks");
  if (el("alert-panel")) requests.alerts = api(`/alerts?limit=50&offset=${offset}&changed_only=${el("changed-only").checked}`);
  if (el("admin-detail")) requests.audit = api("/audit");
  const entries = await Promise.all(Object.entries(requests).map(async ([name, pending]) => [name, await pending]));
  const results = Object.fromEntries(entries);
  if (entries.some(([, value]) => value.exercise_id && value.exercise_id !== next.exercise_id)) throw new Error("The rehearsal changed while loading. Please refresh.");
  if (state && state.exercise_id !== next.exercise_id) {
    selected = ""; selectFirst = true; offset = 0; el("reason").value = "";
    if (el("changed-only")) el("changed-only").checked = false;
    state = next;
    message("A new rehearsal is ready. Original working records have been loaded.");
    return refresh();
  }
  state = next;
  text("exercise", state.label);
  for (const counter of document.querySelectorAll("[data-count]")) counter.textContent = state.counts[counter.dataset.count].toLocaleString();
  renderProposalList(results.proposals); renderChanges(results.changes);
  if (results.risks) renderRisks(results.risks);
  if (results.alerts) renderAlerts(results.alerts);
  if (el("admin-detail")) {
    pretty("audit", results.audit); pretty("integration", state.analysis); pretty("history", state.exercise_history); pretty("model-status", state.model);
    text("analysis-status", state.analyzed ? `${state.analysis.sessions} cases analyzed. Teams can now review their proposals.` : "Ready to analyze the three bundled datasets. Current working records have not been changed.");
  }
}

// Connect only when this page and the server-authenticated role agree.
el("login-form").addEventListener("submit", event => {
  event.preventDefault();
  action(async () => {
    generation += 1;
    try {
      key = normalizeKey(el("key").value);
      const info = await serverInfo();
      const result = await api("/session");
      if (result.role !== pageRole) throw new Error(`That key belongs to ${String(result.role).toUpperCase()}. Use python demo.py keys --role ${pageRole} for this workspace.`);
      if (result.access_profile !== info.access_profile) throw new Error("The running server changed during sign-in. Please try again.");
      identity = result.role; state = null; selectFirst = true;
      text("identity", `${identity.toUpperCase()} connected`);
      text("review-title", {admin: "Team reviews", soc: "Priority reviews", grc: "Risk update reviews"}[pageRole]);
      if (pageRole === "admin") text("review-help", "Read-only overview. Each team approves changes in its own workspace.");
      // Show the dashboard only after all initial role-scoped reads succeeded.
      await refresh();
      el("key").value = ""; el("key").type = "password";
      if (el("toggle-key")) { text("toggle-key", "Show"); el("toggle-key").setAttribute("aria-pressed", "false"); }
      el("workspace").hidden = false; el("login-panel").hidden = true;
      message("Connected. You are viewing saved backend records.");
    } catch (error) { disconnect(); throw error; }
  });
});

// Disconnect cancels pending fetches and removes records/key from this tab.
function disconnect() {
  generation += 1; controller.abort(); controller = new AbortController();
  key = ""; identity = null; state = null; selected = ""; proposals = []; offset = 0; selectFirst = true;
  el("workspace").hidden = true; el("login-panel").hidden = false; el("review-form").reset();
  for (const id of ["risk-rows", "alert-rows", "change-rows", "audit", "integration", "history", "model-status", "admin-evidence", "decision-details"]) if (el(id)) el(id).replaceChildren();
  for (const id of ["identity", "exercise", "proposal-asset", "proposal-description", "before-value", "before-detail", "after-value", "after-detail", "analysis-status", "alert-page"]) text(id, "");
  el("proposal-content").hidden = true; el("review-form").hidden = true;
  el("review-empty").hidden = false; text("review-empty", "Connect to load your reviews.");
  text("proposal-count", "0 pending");
  el("proposal-select").replaceChildren(new Option("No pending proposals", ""));
  el("key").value = ""; el("key").type = "password";
  if (el("toggle-key")) { text("toggle-key", "Show"); el("toggle-key").setAttribute("aria-pressed", "false"); }
  for (const counter of document.querySelectorAll("[data-count]")) counter.textContent = "—";
}
el("logout").addEventListener("click", () => { disconnect(); message("Disconnected."); });
if (el("toggle-key")) el("toggle-key").addEventListener("click", () => {
  const show = el("key").type === "password";
  el("key").type = show ? "text" : "password";
  text("toggle-key", show ? "Hide" : "Show"); el("toggle-key").setAttribute("aria-pressed", String(show));
});
// Safe public build/profile check on first paint; never signs a role in itself.
serverInfo().catch(error => { if (error.name !== "AbortError" && !identity) message(error.message, true); });
el("refresh").addEventListener("click", () => action(refresh));
el("proposal-select").addEventListener("change", () => { selected = el("proposal-select").value; selectFirst = false; el("reason").value = ""; el("review-details").open = false; renderProposal(); });

// One shared approval form, but no Admin approval and no client-chosen update values.
el("review-form").addEventListener("submit", event => {
  event.preventDefault();
  const decision = event.submitter?.value || "approve";
  action(async () => {
    if (!selected || identity === "admin") throw new Error("Choose a pending review using its team's own key.");
    const result = await post(`/proposals/${encodeURIComponent(selected)}/review`, {decision, reason: el("reason").value});
    selected = ""; selectFirst = false; el("reason").value = "";
    if (pageRole === "soc" && decision === "approve") { el("changed-only").checked = true; offset = 0; }
    await refresh();
    message(decision === "reject" ? "Rejected. Current values were not changed." : pageRole === "soc" ? `${result.demo_records_written} alert priorities updated and saved.` : "Risk update approved and saved in the register.");
  });
});

// Only Admin's template contains these engine/rehearsal/proposal-history controls.
if (el("analyze")) el("analyze").addEventListener("click", () => action(async () => {
  message("Analyzing demo data. Please wait…"); const result = await post("/analyze", {});
  await refresh(); message(`${result.sessions} cases analyzed. Each team can review its own proposals.`);
}));
if (el("exercise-form")) el("exercise-form").addEventListener("submit", event => {
  event.preventDefault(); action(async () => {
    if (!confirm("Start a fresh rehearsal? Previous records and audit history will be kept.")) return;
    await post("/exercises", {label: el("exercise-label").value}); await refresh(); message("Fresh rehearsal created. Analyze data to prepare new reviews.");
  });
});
if (el("proposal-status")) el("proposal-status").addEventListener("change", () => action(async () => { selected = ""; selectFirst = true; await refresh(); }));
if (el("changed-only")) el("changed-only").addEventListener("change", () => action(async () => { offset = 0; await refresh(); }));
if (el("previous")) el("previous").addEventListener("click", () => action(async () => { offset = Math.max(0, offset - 50); await refresh(); }));
if (el("next")) el("next").addEventListener("click", () => action(async () => { offset += 50; await refresh(); }));

// Download current authorized records; keys never appear in the generated URL.
async function download(kind) {
  const data = await api("/export/" + kind);
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + "\n"], {type: "application/json"}));
  const link = node("a"); link.href = url;
  link.download = kind === "risks" ? "IRIS_current_demo_risk_register.json" : "IRIS_current_demo_alert_priorities.json";
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
if (el("export-risks")) el("export-risks").addEventListener("click", () => action(() => download("risks")));
if (el("export-alerts")) el("export-alerts").addEventListener("click", () => action(() => download("alerts")));

// Poll only a visible, connected, idle tab; the backend remains the source of truth.
setInterval(() => { if (identity && !busy && !document.hidden && el("auto-refresh").checked) action(refresh); }, 3000);
