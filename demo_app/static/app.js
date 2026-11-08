// IRIS EXPLAIN: Active demo: real state comes from the isolated approval-gated backend.
// IRIS EXPLAIN: Use strict JavaScript semantics, including rejecting accidental undeclared assignments.
"use strict";
// IRIS EXPLAIN: Function el: Find a fixed dashboard element by its HTML id.
const el = id => document.getElementById(id);
// IRIS EXPLAIN: Declare pageRole for this tab's state/rendering; keys remain in memory, not browser storage.
let pageRole = ["admin", "soc", "grc"].includes(location.pathname.slice(1)) ? location.pathname.slice(1) : "admin";
let loginRole = pageRole;
// IRIS EXPLAIN: Declare key for this tab's state/rendering; keys remain in memory, not browser storage.
let sessionToken = "", currentUsername = "", identity = null, state = null, proposals = [], selected = "", offset = 0, totalAlerts = 0, busy = false, generation = 0, selectFirst = true;
// IRIS EXPLAIN: Declare controller for this tab's state/rendering; keys remain in memory, not browser storage.
let controller = new AbortController();
let proposalTeam = "all", inboxSignature = "";
document.body.dataset.session = "locked";
const roleNames = {admin:"Administrator", soc:"SOC analyst", grc:"GRC officer"};
function renderRoleSelection() {
  for (const role of Object.keys(roleNames)) el("workspace-role-" + role).checked = role === loginRole;
  el("login-submit").textContent = "Sign in as " + roleNames[loginRole];
  el("login-hint").textContent = `Use your ${roleNames[loginRole]} username and password.`;
}
for (const role of Object.keys(roleNames)) {
  const radio = el("workspace-role-" + role);
  radio.addEventListener("change", () => {
    if (!radio.checked || role === loginRole) return;
    if (busy || identity) { renderRoleSelection(); return; }
    loginRole = role;
    el("password").value = "";
    renderRoleSelection();
  });
}
renderRoleSelection();
function renderWorkspaceHeading() {
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  el("title").textContent = {admin:"Operations overview", soc:"Security operations", grc:"Risk & compliance"}[pageRole];
  el("role-label").textContent = pageRole === "admin" ? "Admin" : pageRole.toUpperCase();
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  el("subtitle").textContent = {admin:"A clear view of evidence, decisions and team activity.", soc:"Your alerts, the context behind them, and the decisions that matter.", grc:"Connect business risk with evidence. Review each change with confidence."}[pageRole];
  document.title = "IRIS · " + el("title").textContent;
}
renderWorkspaceHeading();
// A stale server may return the original full HTML. DOM presence is not a role
// permission: hide unrelated blocks, and independently scope every API read.
function applyRoleView() {
  document.body.dataset.role = pageRole;
  for (const [id, roles] of Object.entries({"admin-actions":["admin"], "admin-detail":["admin"], "backend-monitor":["admin"],
    "risk-panel":["admin", "grc"], "alert-panel":["admin", "soc"], "review-panel":["admin", "soc", "grc"], "chat-form":["soc", "grc"], "chat-logs":["admin"], "dashboard-switcher":["admin"]})) {
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
function bindNavigation() {
  for (const link of document.querySelectorAll('.workspace-nav a')) link.addEventListener("click", () => {
    for (const item of document.querySelectorAll('.workspace-nav a')) {
      item.classList.toggle("active", item === link);
      item.setAttribute("aria-current", item === link ? "location" : "false");
    }
  });
}

async function mountWorkspace(role) {
  if (role === pageRole) return;
  const current = generation;
  // Fetch only server-owned, role-filtered markup. The role key stays in memory
  // and is never included in this public page request, a URL or browser storage.
  const response = await fetch("/" + role, {signal:controller.signal, cache:"no-store", credentials:"omit"});
  if (!response.ok) throw new Error("Could not open the selected workspace. Please try signing in again.");
  const markup = await response.text();
  if (current !== generation) throw new Error("Dashboard connection changed. Please sign in again.");
  const incoming = new DOMParser().parseFromString(markup, "text/html");
  if (incoming.body.dataset.role !== role || !incoming.getElementById("workspace") || !incoming.querySelector(".sidebar"))
    throw new Error("The selected workspace could not be loaded. Please refresh and try again.");
  el("workspace").replaceWith(document.importNode(incoming.getElementById("workspace"), true));
  document.querySelector(".sidebar").replaceWith(document.importNode(incoming.querySelector(".sidebar"), true));
  pageRole = role; proposalTeam = "all"; inboxSignature = "";
  renderWorkspaceHeading();
  bindWorkspaceEvents();
  resetChat();
}
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
  const response = await fetch("/api/demo" + path, {...options, headers:{...(sessionToken ? {Authorization:"Bearer " + sessionToken} : {}),...(options.headers || {})}, signal:controller.signal, cache:"no-store", credentials:"omit"});
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
  const buttons = Array.from(document.querySelectorAll("button")).filter(button => !["chat-send", "chat-toggle"].includes(button.getAttribute("id")));
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
  const review = source.model2_review;
  const model2_review = review && typeof review === "object" ? {
    ...pick(review, ["source", "reason", "missing_fields", "validation_scope", "release_eligible", "automatic_execution"]),
    recommendations: (Array.isArray(review.recommendations) ? review.recommendations : [])
      .filter(item => item && typeof item === "object")
      .map(item => pick(item, ["control_id", "name", "reason", "source", "current_state", "implementation_state_known", "action_type"]))
  } : undefined;
  return {...pick(source, ["hostname", "asset_id", "asset_criticality", "session_id", "session_time", "decision_basis"]),
    observed_activity: scenario || "Not recorded",
    risk_category: source.risk_category || {credential_access: "Unauthorized Access", reconnaissance: "Reconnaissance"}[scenario] || "Not recorded",
    risk_reason: source.risk_reason || "Review the registered risk and saved before/after values. Control advice does not execute a security control.",
    controls, ...(model2_review ? {model2_review} : {})};
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
  summary.append(node("p", p.case_id + " / " + p.proposal_id.slice(0, 13), "case-reference"));
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
  if (pageRole !== "soc" && evidence.model2_review) {
    const review = evidence.model2_review;
    summary.append(node("h4", "Experimental control review"));
    summary.append(node("p", "Synthetic association matching only. Recommendations require human review; scores do not measure effectiveness.", "muted"));
    if (!review.recommendations?.length) summary.append(node("p", review.reason || "No control candidates exceeded the review threshold.", "muted"));
    if (review.missing_fields?.length) summary.append(node("p", "Missing runtime fields: " + review.missing_fields.join(", "), "muted"));
    for (const item of review.recommendations || []) summary.append(node("p",
      `${item.name} (${item.control_id}) · State: ${item.current_state || "unknown"}${item.implementation_state_known ? " (known)" : ""} · Source: ${item.source || review.source}. ${item.reason || "Analyst review required."}`));
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
  el("proposal-count").textContent = result.total + " PENDING";
  el("nav-pending").textContent = result.total;
  if (previous !== selected) el("reason").value = "";
  renderApprovalInbox();
  renderProposal();
}

function renderApprovalInbox() {
  const query = el("proposal-search").value.trim().toLowerCase();
  const filtered = proposals.filter(p => (proposalTeam === "all" || p.kind === proposalTeam) &&
    [p.payload.evidence.hostname, p.payload.risk_id, p.case_id, p.proposal_id, p.kind, p.payload.new_priority]
      .filter(Boolean).join(" ").toLowerCase().includes(query));
  el("inbox-result").textContent = `${filtered.length} of ${proposals.length} pending`;
  el("inbox-empty").hidden = filtered.length > 0;
  el("inbox-empty").textContent = proposals.length ? "No approvals match your search." : "You're all caught up. New proposals appear after analysis.";
  const signature = JSON.stringify([selected, filtered.map(p => [p.proposal_id, p.payload])]);
  if (signature === inboxSignature) return;
  inboxSignature = signature;
  const list = el("proposal-list"), scrollTop = list.scrollTop;
  const focused = document.activeElement?.getAttribute("data-proposal-id");
  let restoreFocus;
  list.replaceChildren(...filtered.map(p => {
    const row = node("li"), button = node("button", undefined, "proposal-item" + (p.proposal_id === selected ? " selected" : ""));
    button.type = "button"; button.setAttribute("data-proposal-id", p.proposal_id);
    button.setAttribute("aria-pressed", String(p.proposal_id === selected));
    const title = node("span", undefined, "inbox-item-top");
    title.append(node("strong", p.payload.evidence.hostname), node("span", p.kind.toUpperCase(), "inbox-team"));
    const summary = p.kind === "soc" ? `${p.payload.changed_alerts} alerts → ${p.payload.new_priority}` :
      `Risk ${p.payload.before.score.toFixed(2)} → ${p.payload.after.score.toFixed(2)}`;
    button.append(title, node("span", summary, "inbox-summary"));
    button.addEventListener("click", () => {
      if (busy) return;
      if (selected !== p.proposal_id) el("reason").value = "";
      selected = p.proposal_id; selectFirst = false;
      renderApprovalInbox(); renderProposal();
    });
    if (focused === p.proposal_id) restoreFocus = button;
    row.append(button); return row;
  }));
  if (restoreFocus?.focus) restoreFocus.focus({preventScroll:true});
  list.scrollTop = scrollTop;
}

function bindApprovalInbox() {
  el("proposal-search").addEventListener("input", renderApprovalInbox);
  for (const button of el("proposal-filters")?.children || []) button.addEventListener("click", () => {
    proposalTeam = button.getAttribute("data-team");
    for (const tab of el("proposal-filters").children) {
      const active = tab === button; tab.classList.toggle("active", active); tab.setAttribute("aria-pressed", String(active));
    }
    renderApprovalInbox();
  });
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
  if (current.role !== pageRole) throw new Error("Sign in with an account for this workspace.");
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

// Passwords are submitted once over HTTPS. Each tab keeps its own session in memory.
el("login-form").addEventListener("submit",event => {
  event.preventDefault();
  action(async () => {
    generation += 1;
    try {
      const result = await post("/auth/login", {username:el("username").value.trim(), password:el("password").value, workspace:loginRole});
      el("password").value = "";
      sessionToken = result.access_token;
      if (result.role !== loginRole || typeof sessionToken !== "string" || !sessionToken)
        throw new Error("This account cannot open the selected workspace.");
      currentUsername = result.username;
      await mountWorkspace(result.role);
      identity = result.role; state = null; selectFirst = true;
      el("identity").textContent = currentUsername + " · " + identity.toUpperCase();
      applyRoleView();
      el("proposal-title").textContent = pageRole === "admin" ? "Team approvals" : "Pending approvals";
      el("approval-note").textContent = pageRole === "admin" ? "Monitor both teams here. Each team reviews and approves with its own account." : "Select an item to review its evidence and proposed changes.";
      await refresh();
      if (location.pathname !== "/" + pageRole) history.replaceState(null, "", "/" + pageRole);
      // Initial data must load successfully before the existing workspace opens.
      el("workspace").hidden = false; el("login-panel").hidden = true;
      document.body.dataset.session = "connected";
      message("Connected. Your workspace is up to date.");
      refreshActivity();
      refreshChat();
    } catch (error) { disconnect(); throw error; }
  });
});
// IRIS EXPLAIN: Clear the original workspace and memory-only credentials on logout
// or a failed connection. Role-filtered controls can be absent from the document.
function disconnect() {
  const departingToken = sessionToken;
  if (departingToken) fetch("/api/demo/auth/logout", {method:"POST", headers:{Authorization:"Bearer " + departingToken,"Content-Type":"application/json"},body:"{}",cache:"no-store",credentials:"omit"}).catch(() => {});
  document.body.dataset.session = "locked";
  resetChat();
  generation += 1; controller.abort(); controller = new AbortController();
  sessionToken = ""; currentUsername = ""; identity = null; state = null; proposals = []; selected = ""; offset = 0; selectFirst = true;
  el("workspace").hidden = true; el("login-panel").hidden = false; el("password").value = "";
  for (const id of ["risk-rows","alert-rows","change-rows","audit","integration","history","model-status","proposal-evidence","proposal-summary"]) if (el(id)) el(id).replaceChildren();
  for (const id of ["identity","exercise","analysis-status","alert-page","proposal-count"]) if (el(id)) el(id).textContent = "";
  for (const id of ["risk-count","alert-count","risk-changed","alert-changed","pending-count"]) if (el(id)) el(id).textContent = "—";
  if (el("backend-status")) el("backend-status").textContent = "Disconnected";
  if (el("backend-events")) el("backend-events").textContent = "Connect as Admin to see real backend activity.";
  proposalTeam = "all"; inboxSignature = ""; el("proposal-search").value = "";
  el("proposal-list").replaceChildren(); el("nav-pending").textContent = "0";
  for (const tab of el("proposal-filters")?.children || []) {
    const active = tab.getAttribute("data-team") === "all";
    tab.classList.toggle("active", active); tab.setAttribute("aria-pressed", String(active));
  }
  el("review-form").reset(); el("review-form").hidden = true; el("evidence-panel").hidden = true;
}
function bindDashboardControls() {
  el("logout").addEventListener("click",() => { disconnect(); message("Signed out. Your session has ended."); });

  // IRIS EXPLAIN: Register the click event handler for refresh; the callback below performs only the explicit user action.
  el("refresh").addEventListener("click",() => action(refresh));
  // IRIS EXPLAIN: Register the click event handler for analyze; the callback below performs only the explicit user action.
  if (el("analyze")) el("analyze").addEventListener("click",() => action(async () => { message("Running the actual saved models and explicit engine policy. Please wait…"); const result = await post("/analyze",{}); await refresh(); message(`${result.sessions} cases analyzed. No working risk/alert records changed yet. Open SOC and GRC to review and apply proposals.`); }));
  // IRIS EXPLAIN: Register the submit event handler for exercise-form; the callback below performs only the explicit user action.
  // IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
  if (el("exercise-form")) el("exercise-form").addEventListener("submit",event => { event.preventDefault(); action(async () => { if (!confirm("Create a fresh synthetic rehearsal? Earlier exercises and audit history will be preserved.")) return; await post("/exercises",{label:el("exercise-label").value}); await refresh(); message("New rehearsal created. Analyze again. Earlier exercises remain saved, not deleted."); }); });
  // IRIS EXPLAIN: Register the change event handler for proposal-select; the callback below performs only the explicit user
  // IRIS EXPLAIN: action.
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
      if (!selected || identity === "admin") throw new Error("Choose a pending proposal using its owning team account.");
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
}
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

// Independent from dashboard commands: chat stays live during analysis/reviews.
let chatCursor = null, chatLoading = false, chatSending = false;
let chatCollapsed = false, chatUnread = 0;
let chatViewVersion = 0, chatClearedThrough = 0, chatClearing = false;
const chatSeen = new Set();
function updateChatWindow() {
  el("chat-body").hidden = chatCollapsed;
  el("chat-toggle").setAttribute("aria-expanded", String(!chatCollapsed));
  el("chat-toggle").setAttribute("aria-label", chatCollapsed ? "Open team chat" : "Collapse team chat");
  el("chat-toggle").textContent = chatCollapsed ? "+" : "−";
  el("chat-unread").hidden = chatUnread === 0;
  el("chat-unread").textContent = chatUnread > 99 ? "99+" : String(chatUnread);
}
function toggleChatWindow() {
  chatCollapsed = !chatCollapsed;
  if (!chatCollapsed) {
    chatUnread = 0;
    const log = el("chat-messages"); log.scrollTop = log.scrollHeight;
  }
  updateChatWindow();
}
function resetChat() {
  chatViewVersion += 1; chatClearedThrough = 0; chatClearing = false;
  chatCollapsed = false; chatUnread = 0; updateChatWindow();
  chatCursor = null; chatLoading = false; chatSending = false; chatSeen.clear();
  if (el("chat-messages")) el("chat-messages").replaceChildren();
  if (el("chat-empty")) el("chat-empty").hidden = false;
  if (el("chat-text")) el("chat-text").value = "";
  if (el("chat-send")) el("chat-send").disabled = false;
  if (el("chat-clear")) el("chat-clear").disabled = false;
  if (el("chat-feedback")) el("chat-feedback").textContent = "";
  if (el("chat-status")) el("chat-status").textContent = "Disconnected";
}
function renderChat(items) {
  const log = el("chat-messages");
  const atBottom = !log.children.length || log.scrollHeight - log.scrollTop - log.clientHeight < 60;
  for (const item of items) {
    if (chatSeen.has(item.id)) continue;
    chatSeen.add(item.id);
    const ownMessage = item.username ? item.username === currentUsername : item.role === identity;
    if (chatCollapsed && chatCursor !== null && !ownMessage) chatUnread += 1;
    const article = node("article", undefined, "chat-message chat-" + item.role + (ownMessage ? " chat-own" : ""));
    const date = new Date(item.created_at);
    const meta = node("div", undefined, "chat-meta"), time = node("time", date.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}));
    time.setAttribute("datetime", item.created_at);
    time.setAttribute("title", date.toLocaleString());
    meta.append(node("strong", (item.username ? item.username + " · " : "") + item.role.toUpperCase()), time);
    // User messages are plain text, never HTML or executable markup.
    article.append(meta, node("p", item.text));
    log.append(article);
  }
  el("chat-empty").hidden = chatSeen.size > 0;
  if (atBottom) log.scrollTop = log.scrollHeight;
  updateChatWindow();
}
async function refreshChat() {
  if (!identity || !el("team-chat") || chatLoading || chatClearing) return;
  const current = generation, viewVersion = chatViewVersion;
  chatLoading = true;
  if (el("chat-form")) el("chat-form").hidden = identity === "admin";
  try {
    const result = await api("/chat" + (chatCursor === null ? "" : "?after=" + chatCursor));
    if (current !== generation || viewVersion !== chatViewVersion || !identity) return;
    if ((result.cleared_through || 0) > chatClearedThrough) {
      chatClearedThrough = result.cleared_through;
      el("chat-messages").replaceChildren(); chatSeen.clear(); chatUnread = 0;
    }
    renderChat(result.items.filter(item => item.id > chatClearedThrough));
    chatCursor = Math.max(result.cursor,chatClearedThrough);
    el("chat-history-note").textContent = result.archive_warning || "Clear chat hides messages only for you. Logs are kept for 3 months, then archived.";
    if (el("chat-status").textContent === "Reconnecting...") el("chat-feedback").textContent = "Chat reconnected.";
    el("chat-status").textContent = result.has_more ? "Loading messages..." : "Live / 1 s";
  } catch (error) {
    if (error.name !== "AbortError" && current === generation && viewVersion === chatViewVersion && identity) {
      el("chat-status").textContent = "Reconnecting...";
      el("chat-feedback").textContent = "Chat is unavailable. Retrying automatically; your draft is preserved.";
    }
  } finally { if (current === generation && viewVersion === chatViewVersion) chatLoading = false; }
}
async function clearChat() {
  if (!identity || chatClearing) return;
  const current = generation;
  chatClearing = true; el("chat-clear").disabled = true;
  try {
    const result = await post("/chat/clear", {});
    if (current !== generation || !identity) return;
    chatViewVersion += 1; chatLoading = false;
    chatClearedThrough = result.cleared_through; chatCursor = chatClearedThrough;
    chatSeen.clear(); chatUnread = 0; el("chat-messages").replaceChildren();
    el("chat-empty").hidden = false; updateChatWindow();
    el("chat-feedback").textContent = "Your chat view is clear. Message logs are preserved.";
  } catch (error) {
    if (current === generation && identity && error.name !== "AbortError")
      el("chat-feedback").textContent = "Could not clear your view. Your conversation and draft are unchanged.";
  } finally {
    if (current === generation) { chatClearing = false; el("chat-clear").disabled = false; }
  }
}
async function downloadChatLogs() {
  if (identity !== "admin") return;
  const current = generation;
  try {
    const logs = await api("/chat/logs");
    const url = URL.createObjectURL(new Blob([JSON.stringify(logs,null,2) + "\n"],{type:"application/json"}));
    const link = node("a"); link.href = url; link.download = "IRIS_chat_logs.json"; link.click();
    setTimeout(() => URL.revokeObjectURL(url),1000);
    el("chat-feedback").textContent = "Chat logs downloaded, including cleared views and archived messages.";
  } catch (error) {
    if (current === generation && identity === "admin" && error.name !== "AbortError")
      el("chat-feedback").textContent = "Could not download chat logs. Please try again.";
  }
}
async function sendChat() {
  if (!identity || identity === "admin" || chatSending) return;
  const input = el("chat-text"), text = input.value.trim(), current = generation;
  if (!text || text.length > 2000) {
    el("chat-feedback").textContent = "Write a message of 1 to 2,000 characters."; return;
  }
  chatSending = true; el("chat-send").disabled = true;
  try {
    await post("/chat", {text});
    if (current !== generation || !identity) return;
    if (input.value.trim() === text) input.value = "";
    el("chat-feedback").textContent = "Message sent.";
    await refreshChat();
  } catch (error) {
    if (error.name !== "AbortError" && current === generation && identity)
      el("chat-feedback").textContent = "Could not confirm sending. Check the conversation before retrying. Your draft is preserved.";
  } finally {
    if (current === generation) { chatSending = false; el("chat-send").disabled = false; }
  }
}
function bindChatControls() {
  el("chat-toggle").addEventListener("click", toggleChatWindow);
  el("chat-clear").addEventListener("click", clearChat);
  if (el("chat-logs")) el("chat-logs").addEventListener("click", downloadChatLogs);
  if (el("chat-form")) el("chat-form").addEventListener("submit", event => { event.preventDefault(); sendChat(); });
  if (el("chat-text")) el("chat-text").addEventListener("keydown", event => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) { event.preventDefault(); sendChat(); }
  });
}
function bindWorkspaceEvents() {
  bindNavigation(); bindApprovalInbox(); bindDashboardControls(); bindChatControls();
}
bindWorkspaceEvents();
setInterval(() => { if (identity && !document.hidden) refreshChat(); }, 1000);
