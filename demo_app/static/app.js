// IRIS EXPLAIN: Active demo: real state comes from the isolated approval-gated backend.
// IRIS EXPLAIN: Use strict JavaScript semantics, including rejecting accidental undeclared assignments.
"use strict";
// IRIS EXPLAIN: Function el: Find a fixed dashboard element by its HTML id.
const el = id => document.getElementById(id);
// IRIS EXPLAIN: Declare pageRole for this tab's state/rendering; keys remain in memory, not browser storage.
const pageRole = ["admin", "soc", "grc"].includes(location.pathname.slice(1)) ? location.pathname.slice(1) : "admin";
// IRIS EXPLAIN: Declare key for this tab's state/rendering; keys remain in memory, not browser storage.
let key = "", identity = null, state = null, proposals = [], selected = "", offset = 0, totalAlerts = 0, busy = false, generation = 0, selectFirst = true;
// IRIS EXPLAIN: Declare controller for this tab's state/rendering; keys remain in memory, not browser storage.
let controller = new AbortController();
// IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
el("title").textContent = {admin:"Admin · engine control", soc:"SOC · live alert queue", grc:"GRC · live risk register"}[pageRole];
// IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
el("subtitle").textContent = {admin:"Analyze evidence. Follow approvals. Show the audit trail.", soc:"Inspect a proposal, approve it, and watch alert priorities actually change.", grc:"Review risk evidence, approve it, and watch the register actually change."}[pageRole];
// IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
el("login-hint").textContent = `Run python demo.py keys in a private terminal. Connect with the ${pageRole.toUpperCase()} demo key, not the older backend key.`;
// A stale server may return the original full HTML. DOM presence is not a role
// permission: hide unrelated blocks, and independently scope every API read.
function applyRoleView() {
  document.body.dataset.role = pageRole;
  for (const [id, roles] of Object.entries({"admin-actions":["admin"], "admin-detail":["admin"], "backend-monitor":["admin"],
    "risk-panel":["admin", "grc"], "alert-panel":["admin", "soc"], "review-panel":["admin", "soc", "grc"]})) {
    if (el(id)) el(id).hidden = !roles.includes(pageRole);
  }
  for (const [id, owner] of [["risk-count", "grc"], ["risk-changed", "grc"], ["alert-count", "soc"], ["alert-changed", "soc"]]) {
    const card = el(id)?.closest(".stat");
    if (card) card.hidden = pageRole !== "admin" && pageRole !== owner;
  }
  const modelPanel = el("model-status")?.closest("section");
  if (modelPanel) modelPanel.hidden = pageRole !== "admin";
  for (const link of document.querySelectorAll('nav[aria-label="Dashboards"] a')) {
    link.hidden = pageRole !== "admin" && link.getAttribute("href") !== "/" + pageRole;
  }
}
applyRoleView();
// IRIS EXPLAIN: Function message: Show safe plain-text progress/error feedback in the live status area. Write plain text, so
// IRIS EXPLAIN: evidence/labels are not interpreted as HTML or executable markup.
const message = text => { el("message").textContent = text; };
// IRIS EXPLAIN: Function pretty: Display structured backend evidence as formatted plain JSON, not executable HTML. Write plain
// IRIS EXPLAIN: text, so evidence/labels are not interpreted as HTML or executable markup.
const pretty = (id, value) => { if (el(id)) el(id).textContent = JSON.stringify(value, null, 2); };
// IRIS EXPLAIN: Function node: Create a DOM element, assign textContent safely, and optionally apply a server-independent CSS
// IRIS EXPLAIN: class. Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
function node(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
// IRIS EXPLAIN: Function priority: Build a styled priority label from the stored backend value.
function priority(value) { return node("span", value, "priority priority-" + value.toLowerCase()); }
// IRIS EXPLAIN: Function cell: Build one table cell with optional secondary plain-text detail.
function cell(text, secondary) { const n = node("td", text); if (secondary) n.append(node("span", secondary, "secondary-line")); return n; }
// IRIS EXPLAIN: Function api: Send an authenticated same-origin API request with the in-memory role key, reject stale-session
// IRIS EXPLAIN: responses, parse JSON and surface backend errors.
async function api(path, options = {}) {
  // IRIS EXPLAIN: Declare current for this tab's state/rendering; keys remain in memory, not browser storage.
  const current = generation;
  // IRIS EXPLAIN: Declare response for this tab's state/rendering; keys remain in memory, not browser storage. Call the local
  // IRIS EXPLAIN: backend rather than compute an ML decision in the browser; subsequent code checks the HTTP response. Send the
  // IRIS EXPLAIN: configured in-memory role key as a header, not in the URL or a client-supplied actor field.
  const response = await fetch("/api/demo" + path, {...options, headers:{"X-IRIS-Key":key,...(options.headers || {})}, signal:controller.signal, cache:"no-store", credentials:"omit"});
  // IRIS EXPLAIN: Declare result for this tab's state/rendering; keys remain in memory, not browser storage. Decode the backend
  // IRIS EXPLAIN: JSON response; these values originate from the API, not hard-coded table mutations.
  const result = await response.json();
  // IRIS EXPLAIN: Invalidate/ignore responses from an earlier dashboard connection so stale requests cannot repaint another
  // IRIS EXPLAIN: session.
  if (generation !== current) throw new Error("Dashboard connection changed. Reconnect if needed.");
  // IRIS EXPLAIN: Reject non-success HTTP statuses and surface the backend's safe diagnostic.
  if (response.status === 401) disconnect();
  if (!response.ok) throw new Error(result.detail || "The backend rejected this request.");
  // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
  return result;
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function post: Send a JSON POST command through the same authenticated request boundary.
function post(path, body) { return api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}); }
// IRIS EXPLAIN: Function action: Prevent overlapping UI actions, disable buttons while awaiting work, catch errors and restore
// IRIS EXPLAIN: controls afterward.
async function action(callback, silent = false) {
  // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks intact.
  if (busy) return;
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: busy = true;
  busy = true;
  // IRIS EXPLAIN: Declare buttons for this tab's state/rendering; keys remain in memory, not browser storage.
  const buttons = Array.from(document.querySelectorAll("button"));
  // IRIS EXPLAIN: Iterate the existing buttons/records/options to update this view from its current state.
  for (const button of buttons) button.disabled = true;
  // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
  try { await callback(); } catch (error) { if (error.name !== "AbortError") message(error.message); }
  // IRIS EXPLAIN: Update button availability to prevent overlapping commands or out-of-range paging.
  finally { busy = false; for (const button of buttons) button.disabled = false; pager(); }
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function pager: Enable alert pagination only within the backend-reported bounds and outside an active action.
function pager() { if (el("previous")) el("previous").disabled = busy || offset === 0; if (el("next")) el("next").disabled = busy || offset + 50 >= totalAlerts; }
// Display adapter for both saved-response shapes: new GRC responses have
// controls[], older ones have primary_controls.recommendations[]. Optional
// advice can be absent; it must not prevent reviewing a valid risk proposal.
// This copies only GRC fields and never edits saved evidence or approval values.
function grcEvidence(source) {
  const pick = (record, names) => Object.fromEntries(names.filter(name => record[name] !== undefined).map(name => [name, record[name]]));
  const raw = Array.isArray(source.controls) ? source.controls :
    Array.isArray(source.primary_controls?.recommendations) ? source.primary_controls.recommendations : [];
  const controls = raw.filter(item => item && typeof item === "object" &&
    (typeof item.name === "string" || typeof item.control_id === "string"))
    .map(item => pick(item, ["control_id", "name", "current_state", "action_type", "catalogue_action", "warnings"]));
  const scenario = source.observed_activity || source.primary_assessment?.scenario_class;
  return {...pick(source, ["hostname", "asset_id", "asset_criticality", "session_id", "session_time", "decision_basis"]),
    observed_activity: scenario || "Not recorded",
    risk_category: source.risk_category || {credential_access: "Unauthorized Access", reconnaissance: "Reconnaissance"}[scenario] || "Not recorded",
    risk_reason: source.risk_reason || "Review the registered risk and saved before/after values. Control advice does not execute a security control.",
    controls};
}
// IRIS EXPLAIN: Function renderProposal: Keep the original saved-proposal layout,
// but describe only evidence returned for this team's authenticated role.
function renderProposal() {
  const p = proposals.find(item => item.proposal_id === selected);
  el("proposal-summary").replaceChildren();
  el("evidence-panel").hidden = !p;
  el("review-form").hidden = !p || pageRole === "admin";
  if (!p) {
    el("proposal-summary").textContent = state && state.analyzed ? "No pending proposal selected. Approved changes remain visible in the live records and change history." : "Run analysis from Admin to prepare proposals.";
    pretty("proposal-evidence", null);
    return;
  }
  const data = p.payload, evidence = pageRole === "grc" ? grcEvidence(data.evidence) : data.evidence;
  const summary = el("proposal-summary");
  summary.append(node("h3", evidence.hostname + " · " + (p.kind === "soc" ? "SOC reprioritization" : "GRC risk update")));
  // SOC has technical activity and the proposed priority, not GRC policy fields.
  if (pageRole === "soc") {
    summary.append(node("p", "Primary: " + evidence.primary_assessment.scenario_class + " · proposed priority: " + data.new_priority + " · criticality: " + evidence.asset_criticality + "/5"));
    summary.append(node("p", evidence.priority_reason));
  } else if (pageRole === "grc") {
    // GRC receives business/control context, not raw telemetry or ML confidence.
    summary.append(node("p", "Registered risk: " + evidence.risk_category + " · observed activity: " + evidence.observed_activity + " · criticality: " + evidence.asset_criticality + "/5"));
    summary.append(node("p", evidence.risk_reason));
  } else {
    // Admin retains the original complete primary-policy and model comparison.
    summary.append(node("p", "Primary: " + evidence.primary_assessment.scenario_class + " · engine priority: " + evidence.policy.priority + " · criticality: " + evidence.asset_criticality + "/5"));
  }
  if (p.kind === "soc") {
    summary.append(node("p", data.changed_alerts + " alerts → " + data.new_priority, "big-change"));
    summary.append(node("p", "Current priorities among the alerts to change: " + Object.entries(data.before_counts).map(([label, count]) => label + ": " + count).join(" · ")));
  } else {
    summary.append(node("p", "Risk score " + data.before.score.toFixed(2) + " → " + data.after.score.toFixed(2), "big-change"));
    summary.append(node("p", data.risk_id + " · likelihood " + data.before.likelihood + " → " + data.after.likelihood + " · impact stays " + data.after.impact));
    if (pageRole === "grc") {
      summary.append(node("p", evidence.controls.length ? "Control recommendations: " + evidence.controls.map(control =>
        (control.name || control.control_id) + " (" + (control.current_state || "not recorded") + "; " + (control.action_type || "review required") + ")").join(" · ") :
        "No control recommendations are available for this proposal.", "muted"));
    }
  }
  if (pageRole !== "grc") {
    const shadow = evidence.ml_shadow;
    summary.append(node("p", shadow ? "ML shadow: " + (shadow.scenario || "ABSTAINED") + " · confidence " + (shadow.confidence*100).toFixed(1) + "% (not an approved decision)" : "ML shadow: unavailable for this evidence; no prediction is invented.", "muted"));
  }
  summary.append(node("p", "Human approval changes synthetic system records only. It does not execute any suggested security control.", "muted"));
  // The current backend projects roles; the GRC adapter also filters old full
  // responses so raw telemetry/model confidence never appear in this view.
  pretty("proposal-evidence", {proposal_id:p.proposal_id,case_id:p.case_id,...evidence});
}

// IRIS EXPLAIN: Function renderProposalList: Preserve the selected saved proposal
// and review note during polling. Never silently substitute another decision.
function renderProposalList(result) {
  proposals = result.items;
  const previous = selected;
  if (selected && !proposals.some(p => p.proposal_id === selected)) {
    selected = ""; selectFirst = false;
  } else if (!selected && selectFirst && proposals.length) {
    selected = proposals[0].proposal_id; selectFirst = false;
  }
  const choices = proposals.map(p => new Option(p.payload.evidence.hostname + " · " + p.kind.toUpperCase() + " · " + (p.kind === "soc" ? p.payload.changed_alerts + " alerts → " + p.payload.new_priority : p.payload.before.score.toFixed(2) + " → " + p.payload.after.score.toFixed(2)), p.proposal_id));
  if (!selected || !proposals.length) choices.unshift(new Option(proposals.length ? "Choose a pending proposal" : "No pending proposals", ""));
  el("proposal-select").replaceChildren(...choices);
  el("proposal-select").value = selected;
  el("proposal-count").textContent = result.total + " PENDING";
  if (previous !== selected) el("reason").value = "";
  renderProposal();
}

// IRIS EXPLAIN: Function renderRisks: Render original/current risk values returned by the database and highlight actual approved
// IRIS EXPLAIN: revisions.
function renderRisks(result) {
  // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
  el("risk-rows").replaceChildren(...result.items.map(item => {
    // IRIS EXPLAIN: Declare tr for this tab's state/rendering; keys remain in memory, not browser storage.
    const tr = node("tr",undefined,item.version > 1 ? "changed" : "");
    // IRIS EXPLAIN: Append the prepared safe DOM elements to their current table/proposal container.
    tr.append(cell(item.risk_id,item.hostname), cell(item.category), cell(`${item.baseline_likelihood} → ${item.current_likelihood}`), cell(String(item.impact)), cell(`${item.baseline_score.toFixed(2)} → ${item.current_score.toFixed(2)}`), cell(`v${item.version}`,item.updated_by ? `${item.updated_by.toUpperCase()} · ${item.updated_at}` : "Original imported record"));
    // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
    return tr;
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  }));
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function renderAlerts: Render the backend-sorted current-priority queue, original priority, revision evidence
// IRIS EXPLAIN: and page counts.
function renderAlerts(result) {
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: totalAlerts =
  // IRIS EXPLAIN: result.total;
  totalAlerts = result.total;
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  el("alert-page").textContent = result.total ? `${offset+1}–${Math.min(offset+result.items.length,result.total)} of ${result.total} alerts` : "No matching alerts. Approve an SOC proposal to create reprioritized records.";
  // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
  el("alert-rows").replaceChildren(...result.items.map(item => {
    // IRIS EXPLAIN: Declare tr for this tab's state/rendering; keys remain in memory, not browser storage.
    const tr = node("tr",undefined,item.version > 1 ? "changed" : "");
    // IRIS EXPLAIN: Declare before for this tab's state/rendering; keys remain in memory, not browser storage.
    const before = node("td"), after = node("td"); before.append(priority(item.baseline_priority)); after.append(priority(item.current_priority));
    // IRIS EXPLAIN: Append the prepared safe DOM elements to their current table/proposal container.
    tr.append(cell(item.event_id,item.hostname),cell(item.event_time),before,after,cell(`v${item.version}`,item.updated_by ? `Approved by ${item.updated_by.toUpperCase()}` : "Original technical priority"));
    // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
    return tr;
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  }));
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: pager();
  pager();
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function renderChanges: Render persisted before/after change evidence with the approver role, reason and
// IRIS EXPLAIN: timestamp.
function renderChanges(result) {
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  el("changes-empty").hidden = result.items.length > 0;
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  el("changes-table").hidden = result.items.length === 0;
  // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
  el("change-rows").replaceChildren(...result.items.map(item => {
    // IRIS EXPLAIN: Declare tr for this tab's state/rendering; keys remain in memory, not browser storage.
    const tr = node("tr",undefined,"changed");
    // IRIS EXPLAIN: Declare format for this tab's state/rendering; keys remain in memory, not browser storage.
    const format = value => item.target_kind === "risk" ? `L=${value.likelihood}, I=${value.impact}, score=${value.score.toFixed(2)}, v${value.version}` : `${value.priority}, v${value.version}`;
    // IRIS EXPLAIN: Append the prepared safe DOM elements to their current table/proposal container.
    tr.append(cell(item.target_id,item.target_kind.toUpperCase()),cell(format(item.before)),cell(format(item.after)),cell(`${item.actor.toUpperCase()} · ${item.reason}`,item.changed_at));
    // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
    return tr;
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  }));
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function refresh: Read only this role's current backend records.
// Stage replies before rendering so concurrent rehearsal changes cannot mix data.
async function refresh() {
  if (!identity) return;
  const current = await api("/state");
  if (current.role !== pageRole) throw new Error("Reconnect using this dashboard's own role key.");
  if (state && state.exercise_id !== current.exercise_id) {
    selected = ""; selectFirst = true; offset = 0; el("reason").value = "";
    if (el("changed-only")) el("changed-only").checked = false;
    message("Admin selected a new rehearsal. This tab now shows its original demo records.");
  }
  const requests = {proposals:api("/proposals"), changes:api("/changes")};
  // Authorize by the server-confirmed identity, NEVER by a panel's existence.
  if (identity === "admin" || identity === "grc") requests.risks = api("/risks");
  if (identity === "admin" || identity === "soc") requests.alerts = api("/alerts?limit=50&offset=" + offset + "&changed_only=" + el("changed-only").checked);
  if (identity === "admin") requests.audit = api("/audit");
  const entries = await Promise.all(Object.entries(requests).map(async ([name, pending]) => [name, await pending]));
  const results = Object.fromEntries(entries);
  if (entries.some(([, value]) => value.exercise_id && value.exercise_id !== current.exercise_id)) throw new Error("The rehearsal changed while loading. Please refresh.");
  state = current;
  el("exercise").textContent = state.label + " · " + state.exercise_id.slice(0,13);
  const c = state.counts;
  const counters = {"risk-count":c.risks,"alert-count":c.alerts,"risk-changed":c.changed_risks,"alert-changed":c.reprioritized_alerts,"pending-count":pageRole === "admin" ? c.pending_soc+c.pending_grc : pageRole === "soc" ? c.pending_soc : c.pending_grc};
  // Other-team counters are absent from both served markup and the API response.
  for (const [id,value] of Object.entries(counters)) if (el(id) && Number.isFinite(value)) el(id).textContent = value.toLocaleString();
  renderProposalList(results.proposals);
  renderChanges(results.changes);
  if (results.risks) renderRisks(results.risks);
  if (results.alerts) renderAlerts(results.alerts);
  if (pageRole === "admin") {
    pretty("model-status",state.model);
    el("analysis-status").textContent = state.analyzed ? state.analysis.sessions + " model sessions analyzed. Proposals wait for separate SOC/GRC approvals. Re-analysis reuses identical evidence and does not reset reviews." : "Ready: 30 assets, 60 current risks and 2,355 matched unique alerts. Nothing has been changed.";
    pretty("audit",results.audit); pretty("integration",state.analysis); pretty("history",state.exercise_history);
  }
}

// IRIS EXPLAIN: The original sign-in flow checks /state with the supplied key.
// No build-info, version check, second session endpoint or extra key gate is used.
el("login-form").addEventListener("submit",event => {
  event.preventDefault();
  action(async () => {
    generation += 1; key = el("key").value.trim();
    try {
      const result = await api("/state");
      if (result.role !== pageRole) throw new Error("This is the " + pageRole.toUpperCase() + " dashboard. Use its own demo key.");
      identity = result.role; state = null; selectFirst = true;
      el("identity").textContent = identity.toUpperCase() + " connected";
      applyRoleView();
      el("proposal-title").textContent = pageRole === "admin" ? "Team proposals · read-only for Admin" : pageRole.toUpperCase() + " approval inbox";
      el("approval-note").textContent = pageRole === "admin" ? "Open the SOC and GRC links in separate tabs and use their own keys to approve. Admin cannot impersonate either team." : "Inspect the saved evidence and before/after values. Approve to write the demo database, or reject to preserve the current values.";
      await refresh();
      // Initial data must load successfully before the existing workspace opens.
      el("key").value = ""; el("workspace").hidden = false; el("login-panel").hidden = true;
      message("Connected. These tables read live backend records, not a static mockup.");
      refreshActivity();
    } catch (error) { disconnect(); throw error; }
  });
});
// IRIS EXPLAIN: Clear the original workspace and memory-only credentials on logout
// or a failed connection. Role-filtered controls can be absent from the document.
function disconnect() {
  generation += 1; controller.abort(); controller = new AbortController();
  key = ""; identity = null; state = null; proposals = []; selected = ""; offset = 0; selectFirst = true;
  el("workspace").hidden = true; el("login-panel").hidden = false; el("key").value = "";
  for (const id of ["risk-rows","alert-rows","change-rows","audit","integration","history","model-status","proposal-evidence","proposal-summary"]) if (el(id)) el(id).replaceChildren();
  for (const id of ["identity","exercise","analysis-status","alert-page","proposal-count"]) if (el(id)) el(id).textContent = "";
  for (const id of ["risk-count","alert-count","risk-changed","alert-changed","pending-count"]) if (el(id)) el(id).textContent = "—";
  if (el("backend-status")) el("backend-status").textContent = "Disconnected";
  if (el("backend-events")) el("backend-events").textContent = "Connect as Admin to see real backend activity.";
  el("proposal-select").replaceChildren(new Option("No pending proposals",""));
  el("review-form").reset(); el("review-form").hidden = true; el("evidence-panel").hidden = true;
}
el("logout").addEventListener("click",() => { disconnect(); message("Disconnected. The key has been removed from this tab's memory."); });

// IRIS EXPLAIN: Register the click event handler for refresh; the callback below performs only the explicit user action.
el("refresh").addEventListener("click",() => action(refresh));
// IRIS EXPLAIN: Register the click event handler for analyze; the callback below performs only the explicit user action.
if (el("analyze")) el("analyze").addEventListener("click",() => action(async () => { message("Running the actual saved models and explicit engine policy. Please wait…"); const result = await post("/analyze",{}); await refresh(); message(`${result.sessions} cases analyzed. No working risk/alert records changed yet. Open SOC and GRC to review and apply proposals.`); }));
// IRIS EXPLAIN: Register the submit event handler for exercise-form; the callback below performs only the explicit user action.
// IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
if (el("exercise-form")) el("exercise-form").addEventListener("submit",event => { event.preventDefault(); action(async () => { if (!confirm("Create a fresh synthetic rehearsal? Earlier exercises and audit history will be preserved.")) return; await post("/exercises",{label:el("exercise-label").value}); await refresh(); message("New rehearsal created. Analyze again. Earlier exercises remain saved, not deleted."); }); });
// IRIS EXPLAIN: Register the change event handler for proposal-select; the callback below performs only the explicit user
// IRIS EXPLAIN: action.
el("proposal-select").addEventListener("change",() => { selected = el("proposal-select").value; selectFirst = false; el("reason").value = ""; renderProposal(); });
// IRIS EXPLAIN: Register the submit event handler for review-form; the callback below performs only the explicit user action.
el("review-form").addEventListener("submit",event => {
  // IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
  event.preventDefault();
  // IRIS EXPLAIN: Declare decision for this tab's state/rendering; keys remain in memory, not browser storage.
  const decision = event.submitter ? event.submitter.value : "approve";
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: action(async () => {
  action(async () => {
    // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks
    // IRIS EXPLAIN: intact.
    if (!selected || identity === "admin") throw new Error("Choose a pending proposal using its owning team key.");
    // IRIS EXPLAIN: Declare chosen for this tab's state/rendering; keys remain in memory, not browser storage.
    const chosen = selected;
    // IRIS EXPLAIN: Declare result for this tab's state/rendering; keys remain in memory, not browser storage.
    const result = await post(`/proposals/${encodeURIComponent(chosen)}/review`,{decision,reason:el("reason").value});
    // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks
    // IRIS EXPLAIN: intact.
    selected = ""; selectFirst = false; el("reason").value = "";
    if (pageRole === "soc" && decision === "approve") { el("changed-only").checked = true; offset = 0; }
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    await refresh();
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message(decision ===
    // IRIS EXPLAIN: "approve" ? `Applied: ${result.demo_records_written} demo record(s) changed and saved. The other dashboards
    // IRIS EXPLAIN: see the new counts on refresh. No exte...
    message(decision === "approve" ? `Applied: ${result.demo_records_written} demo record(s) changed and saved. The other dashboards see the new counts on refresh. No external system was changed.` : "Rejected. The working records did not change; the decision was audited.");
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
});
// IRIS EXPLAIN: Register the change event handler for changed-only; the callback below performs only the explicit user action.
if (el("changed-only")) el("changed-only").addEventListener("change",() => action(async () => { offset = 0; await refresh(); }));
// IRIS EXPLAIN: Register the click event handler for previous; the callback below performs only the explicit user action.
if (el("previous")) el("previous").addEventListener("click",() => action(async () => { offset = Math.max(0,offset-50); await refresh(); }));
// IRIS EXPLAIN: Register the click event handler for next; the callback below performs only the explicit user action.
if (el("next")) el("next").addEventListener("click",() => action(async () => { offset += 50; await refresh(); }));
// IRIS EXPLAIN: Function download: Fetch current authorized backend records, create a temporary JSON download URL and revoke it
// IRIS EXPLAIN: afterward; original static source files are not substituted. Create a temporary local download from fetched
// IRIS EXPLAIN: current records, then revoke the URL; do not put role keys in it.
async function download(kind) { const data = await api("/export/"+kind); const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"})); const a = node("a"); a.href = url; a.download = kind === "risks" ? "IRIS_current_demo_risk_register.json" : "IRIS_current_demo_alert_priorities.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); }
// IRIS EXPLAIN: Register the click event handler for export-risks; the callback below performs only the explicit user action.
if (el("export-risks")) el("export-risks").addEventListener("click",() => action(() => download("risks")));
// IRIS EXPLAIN: Register the click event handler for export-alerts; the callback below performs only the explicit user action.
if (el("export-alerts")) el("export-alerts").addEventListener("click",() => action(() => download("alerts")));
// IRIS EXPLAIN: Poll the backend every three seconds only while connected, idle, visible and opted into auto-refresh; this is
// IRIS EXPLAIN: GET polling, not WebSockets.
setInterval(() => { if (identity && !busy && !document.hidden && el("auto-refresh").checked) action(refresh,true); },3000);

// Read-only polling is independent of command-busy, so Admin can see an analysis
// request running while its POST is pending. Monitor failure never blocks login.
let activityLoading = false;
async function refreshActivity() {
  if (identity !== "admin" || !el("backend-monitor") || activityLoading) return;
  const current = generation;
  activityLoading = true;
  try {
    const result = await api("/activity");
    if (current !== generation || identity !== "admin") return;
    el("backend-status").textContent = result.active_commands ? `${result.active_commands} command(s) running` : "Backend idle";
    el("backend-events").textContent = result.events.slice().reverse().map(event =>
      `${event.time} | ${event.role.toUpperCase()} | ${event.action} | ${event.state.toUpperCase()}${event.elapsed_seconds === undefined ? "" : ` | ${event.elapsed_seconds}s`}\n${event.message}`
    ).join("\n\n") || "No backend command events yet.";
  } catch (error) {
    if (error.name !== "AbortError" && current === generation && identity === "admin") {
      el("backend-status").textContent = "Monitor unavailable";
      el("backend-events").textContent = "Restart the updated Python server to enable this read-only monitor. Other dashboard actions are unchanged.";
    }
  } finally { activityLoading = false; }
}
setInterval(() => { if (identity === "admin" && !document.hidden && el("auto-refresh").checked) refreshActivity(); },1000);
