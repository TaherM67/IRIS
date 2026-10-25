// IRIS EXPLAIN: Earlier passive interface: local follow-up reviews do not apply working-system changes.
// IRIS EXPLAIN: Use strict JavaScript semantics, including rejecting accidental undeclared assignments.
"use strict";
// IRIS EXPLAIN: Function element: Find a fixed dashboard element by its HTML id.
const element = id => document.getElementById(id);
// IRIS EXPLAIN: Declare key for this tab's state/rendering; keys remain in memory, not browser storage.
let key = "", identity = null, offset = 0, total = 0, selected = null, busy = false, generation = 0;
// IRIS EXPLAIN: Declare requests for this tab's state/rendering; keys remain in memory, not browser storage.
let requests = new AbortController();
// IRIS EXPLAIN: Function message: Show safe plain-text progress/error feedback in the live status area. Write plain text, so
// IRIS EXPLAIN: evidence/labels are not interpreted as HTML or executable markup.
function message(text) { element("message").textContent = text; }
// IRIS EXPLAIN: Function pretty: Display structured backend evidence as formatted plain JSON, not executable HTML. Write plain
// IRIS EXPLAIN: text, so evidence/labels are not interpreted as HTML or executable markup.
function pretty(id, value) { element(id).textContent = JSON.stringify(value, null, 2); }
// IRIS EXPLAIN: Function api: Send an authenticated same-origin API request with the in-memory role key, reject stale-session
// IRIS EXPLAIN: responses, parse JSON and surface backend errors.
async function api(path, options = {}) {
  // IRIS EXPLAIN: Declare currentGeneration for this tab's state/rendering; keys remain in memory, not browser storage.
  const currentGeneration = generation;
  // IRIS EXPLAIN: Declare response for this tab's state/rendering; keys remain in memory, not browser storage. Call the local
  // IRIS EXPLAIN: backend rather than compute an ML decision in the browser; subsequent code checks the HTTP response.
  const response = await fetch("/api" + path, {
    // IRIS EXPLAIN: Send the configured in-memory role key as a header, not in the URL or a client-supplied actor field.
    ...options, headers: {"X-IRIS-Key": key, ...(options.headers || {})},
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: signal:
    // IRIS EXPLAIN: requests.signal, cache: "no-store", credentials: "omit"
    signal: requests.signal, cache: "no-store", credentials: "omit"
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
  // IRIS EXPLAIN: Declare data for this tab's state/rendering; keys remain in memory, not browser storage. Decode the backend
  // IRIS EXPLAIN: JSON response; these values originate from the API, not hard-coded table mutations.
  const data = await response.json();
  // IRIS EXPLAIN: Invalidate/ignore responses from an earlier dashboard connection so stale requests cannot repaint another
  // IRIS EXPLAIN: session.
  if (currentGeneration !== generation) throw new Error("Session changed; reconnect if needed.");
  // IRIS EXPLAIN: Reject non-success HTTP statuses and surface the backend's safe diagnostic.
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
  // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
  return data;
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function action: Prevent overlapping UI actions, disable buttons while awaiting work, catch errors and restore
// IRIS EXPLAIN: controls afterward.
async function action(callback) {
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
  finally { busy = false; for (const button of buttons) button.disabled = false; updatePager(); }
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function updatePager: Enable previous/next only when another case page exists and no action is in progress.
function updatePager() {
  // IRIS EXPLAIN: Update button availability to prevent overlapping commands or out-of-range paging.
  element("previous").disabled = busy || offset === 0;
  // IRIS EXPLAIN: Update button availability to prevent overlapping commands or out-of-range paging.
  element("next").disabled = busy || offset + 25 >= total;
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function refreshRuns: Read completed runs from the backend and preserve the current run filter when it is still
// IRIS EXPLAIN: available.
async function refreshRuns() {
  // IRIS EXPLAIN: Declare runs for this tab's state/rendering; keys remain in memory, not browser storage.
  const runs = await api("/runs");
  // IRIS EXPLAIN: Declare current for this tab's state/rendering; keys remain in memory, not browser storage.
  const current = element("run").value;
  // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
  element("run").replaceChildren(new Option("All completed runs", ""));
  // IRIS EXPLAIN: Iterate the existing buttons/records/options to update this view from its current state.
  for (const run of runs.filter(item => item.status === "completed")) {
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement:
    // IRIS EXPLAIN: element("run").add(new Option(run.run_id + " · " + run.summary.sessions + " sessions", run.run_id));
    element("run").add(new Option(run.run_id + " · " + run.summary.sessions + " sessions", run.run_id));
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  }
  // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks intact.
  if (Array.from(element("run").options).some(option => option.value === current)) element("run").value = current;
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function selectCase: Fetch one authorized SOC/GRC case, render its evidence and show the earlier local-review
// IRIS EXPLAIN: form only for an unreviewed GRC-key session.
async function selectCase(caseId) {
  // IRIS EXPLAIN: Declare audience for this tab's state/rendering; keys remain in memory, not browser storage.
  const audience = element("view").value;
  // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
  selected = await api("/" + audience + "/cases/" + encodeURIComponent(caseId));
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: pretty("case-detail",
  // IRIS EXPLAIN: selected);
  pretty("case-detail", selected);
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("review-form").hidden = !(identity.role === "grc" && audience === "grc" && !selected.review);
  // IRIS EXPLAIN: Iterate the existing buttons/records/options to update this view from its current state.
  for (const button of element("case-list").querySelectorAll("button")) button.setAttribute("aria-pressed", String(button.dataset.caseId === caseId));
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function refreshCases: Fetch a bounded page of backend cases, build safe text-only selection buttons and update
// IRIS EXPLAIN: pagination.
async function refreshCases() {
  // IRIS EXPLAIN: Declare audience for this tab's state/rendering; keys remain in memory, not browser storage.
  const audience = element("view").value;
  // IRIS EXPLAIN: Declare query for this tab's state/rendering; keys remain in memory, not browser storage.
  const query = new URLSearchParams({limit: "25", offset: String(offset)});
  // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks intact.
  if (element("run").value) query.set("run_id", element("run").value);
  // IRIS EXPLAIN: Declare page for this tab's state/rendering; keys remain in memory, not browser storage.
  const page = await api("/" + audience + "/cases?" + query);
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: total = page.total;
  total = page.total;
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  element("case-count").textContent = total ? `${offset + 1}–${Math.min(offset + page.items.length, total)} of ${total} cases` : "No cases yet. Admin or SOC can analyze a batch.";
  // IRIS EXPLAIN: Declare nodes for this tab's state/rendering; keys remain in memory, not browser storage.
  const nodes = page.items.map(item => {
    // IRIS EXPLAIN: Declare button for this tab's state/rendering; keys remain in memory, not browser storage.
    const button = document.createElement("button");
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: button.type =
    // IRIS EXPLAIN: "button";
    button.type = "button";
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: button.className =
    // IRIS EXPLAIN: "case-button";
    button.className = "case-button";
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement:
    // IRIS EXPLAIN: button.dataset.caseId = item.case_id;
    button.dataset.caseId = item.case_id;
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement:
    // IRIS EXPLAIN: button.setAttribute("aria-pressed", String(selected && selected.case_id === item.case_id));
    button.setAttribute("aria-pressed", String(selected && selected.case_id === item.case_id));
    // IRIS EXPLAIN: Declare shadow for this tab's state/rendering; keys remain in memory, not browser storage.
    const shadow = item.shadow_candidate;
    // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
    button.textContent = `${item.asset.hostname} · ${item.priority}\nPrimary: ${item.primary_assessment.scenario_class || "Needs Review"} · ML shadow: ${shadow ? shadow.scenario_class || "Abstained" : "Unavailable"}`;
    // IRIS EXPLAIN: Register the click event handler; the callback below performs only the explicit user action.
    button.addEventListener("click", () => action(() => selectCase(item.case_id)));
    // IRIS EXPLAIN: Return the existing rendered node/result to the caller, ending this function path.
    return button;
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
  // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
  element("case-list").replaceChildren(...nodes);
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: updatePager();
  updatePager();
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Function refresh: Pull current backend state and rebuild the authorized dashboard tables/counters; the browser
// IRIS EXPLAIN: does not run ML or fabricate record changes.
async function refresh() {
  // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks intact.
  if (!identity) return;
  // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
  await refreshRuns();
  // IRIS EXPLAIN: Declare audience for this tab's state/rendering; keys remain in memory, not browser storage.
  const audience = element("view").value;
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("admin-panel").hidden = audience !== "admin";
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("cases-panel").hidden = audience === "admin";
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("processing").hidden = !["admin", "soc"].includes(identity.role);
  // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks intact.
  if (audience === "admin") {
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    pretty("admin-status", await api("/admin/status"));
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    pretty("audit", await api("/admin/audit"));
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  } else {
    // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
    element("cases-title").textContent = audience.toUpperCase() + " cases";
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    await refreshCases();
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  }
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Register the submit event handler for login-form; the callback below performs only the explicit user action.
element("login-form").addEventListener("submit", event => {
  // IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
  event.preventDefault();
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: action(async () => {
  action(async () => {
    // IRIS EXPLAIN: Invalidate/ignore responses from an earlier dashboard connection so stale requests cannot repaint another
    // IRIS EXPLAIN: session.
    generation += 1;
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: key =
    // IRIS EXPLAIN: element("key").value.trim();
    key = element("key").value.trim();
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    identity = await api("/me");
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: element("key").value
    // IRIS EXPLAIN: = "";
    element("key").value = "";
    // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
    element("identity").textContent = "Connected as " + identity.role.toUpperCase();
    // IRIS EXPLAIN: Replace the rendered DOM children with nodes derived from the current authorized backend state.
    element("view").replaceChildren(...identity.views.map(view => new Option(view.toUpperCase(), view)));
    // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
    // IRIS EXPLAIN: enforces access.
    element("workspace").hidden = false;
    // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
    // IRIS EXPLAIN: enforces access.
    element("login-panel").hidden = true;
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    pretty("model-status", await api("/model"));
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    await refresh();
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message("Connected.
    // IRIS EXPLAIN: All ML results are shadow-only; there is no live external delivery.");
    message("Connected. All ML results are shadow-only; there is no live external delivery.");
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
});
// IRIS EXPLAIN: Register the click event handler for logout; the callback below performs only the explicit user action.
element("logout").addEventListener("click", () => {
  // IRIS EXPLAIN: Invalidate/ignore responses from an earlier dashboard connection so stale requests cannot repaint another
  // IRIS EXPLAIN: session. Abort outstanding requests and clear the disconnected tab's key/selection state.
  generation += 1; requests.abort(); requests = new AbortController();
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: key = ""; identity =
  // IRIS EXPLAIN: null; selected = null; offset = 0; total = 0;
  key = ""; identity = null; selected = null; offset = 0; total = 0;
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("workspace").hidden = true; element("login-panel").hidden = false;
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup. Replace the rendered
  // IRIS EXPLAIN: DOM children with nodes derived from the current authorized backend state.
  element("case-list").replaceChildren(); element("case-detail").textContent = "Select a case.";
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("review-form").reset(); element("review-form").hidden = true;
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  for (const id of ["admin-status", "audit", "model-status"]) element(id).textContent = "";
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message("Disconnected.
  // IRIS EXPLAIN: The role key was removed from this page's memory.");
  message("Disconnected. The role key was removed from this page's memory.");
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
});
// IRIS EXPLAIN: Register the click event handler for refresh; the callback below performs only the explicit user action.
element("refresh").addEventListener("click", () => action(refresh));
// IRIS EXPLAIN: Register the change event handler for view; the callback below performs only the explicit user action.
element("view").addEventListener("change", () => action(async () => {
  // IRIS EXPLAIN: Write plain text, so evidence/labels are not interpreted as HTML or executable markup.
  offset = 0; selected = null; element("case-detail").textContent = "Select a case.";
  // IRIS EXPLAIN: Show/hide only the UI controls appropriate to the authenticated view/state; server authorization still
  // IRIS EXPLAIN: enforces access.
  element("review-form").hidden = true; await refresh();
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}));
// IRIS EXPLAIN: Register the change event handler for run; the callback below performs only the explicit user action. Write
// IRIS EXPLAIN: plain text, so evidence/labels are not interpreted as HTML or executable markup. Show/hide only the UI controls
// IRIS EXPLAIN: appropriate to the authenticated view/state; server authorization still enforces access.
element("run").addEventListener("change", () => action(async () => { offset = 0; selected = null; element("case-detail").textContent = "Select a case."; element("review-form").hidden = true; await refreshCases(); }));
// IRIS EXPLAIN: Register the click event handler for previous; the callback below performs only the explicit user action.
element("previous").addEventListener("click", () => action(async () => { offset = Math.max(0, offset - 25); await refreshCases(); }));
// IRIS EXPLAIN: Register the click event handler for next; the callback below performs only the explicit user action.
element("next").addEventListener("click", () => action(async () => { offset += 25; await refreshCases(); }));
// IRIS EXPLAIN: Function afterBatch: Refresh saved run/case state and report whether the server reused identical evidence.
async function afterBatch(summary) {
  // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
  await refresh();
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement:
  // IRIS EXPLAIN: message(`${summary.sessions} sessions processed. ${summary.reused_existing_run ? "Reused the identical saved
  // IRIS EXPLAIN: run." : "Saved a new run."} Open SOC or GRC to inspect cas...
  message(`${summary.sessions} sessions processed. ${summary.reused_existing_run ? "Reused the identical saved run." : "Saved a new run."} Open SOC or GRC to inspect cases. No external updates were sent.`);
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}
// IRIS EXPLAIN: Register the click event handler for sample; the callback below performs only the explicit user action.
element("sample").addEventListener("click", () => action(async () => {
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message("Processing
  // IRIS EXPLAIN: the bundled sample. Please wait; 900 sessions may take a minute or more.");
  message("Processing the bundled sample. Please wait; 900 sessions may take a minute or more.");
  // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
  await afterBatch(await api("/runs/sample", {method: "POST"}));
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
}));
// IRIS EXPLAIN: Register the submit event handler for upload-form; the callback below performs only the explicit user action.
element("upload-form").addEventListener("submit", event => {
  // IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
  event.preventDefault();
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: action(async () => {
  action(async () => {
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message("Processing
    // IRIS EXPLAIN: your three files. Please wait; do not close the backend terminal.");
    message("Processing your three files. Please wait; do not close the backend terminal.");
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    await afterBatch(await api("/runs", {method: "POST", body: new FormData(event.target)}));
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
});
// IRIS EXPLAIN: Register the submit event handler for review-form; the callback below performs only the explicit user action.
element("review-form").addEventListener("submit", event => {
  // IRIS EXPLAIN: Handle the form through the explicit API callback instead of a default browser navigation.
  event.preventDefault();
  // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: action(async () => {
  action(async () => {
    // IRIS EXPLAIN: Apply the condition shown here before the existing branch; keep role, busy-state and page-bound checks
    // IRIS EXPLAIN: intact.
    if (!selected || identity.role !== "grc") throw new Error("Select a case using the GRC key first.");
    // IRIS EXPLAIN: Declare fields for this tab's state/rendering; keys remain in memory, not browser storage.
    const fields = new FormData(event.target);
    // IRIS EXPLAIN: Submit only the saved proposal/case review decision and reason; the server decides whether any authorized
    // IRIS EXPLAIN: write may apply.
    await api("/grc/cases/" + encodeURIComponent(selected.case_id) + "/review", {
      // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: method: "POST",
      // IRIS EXPLAIN: headers: {"Content-Type": "application/json"},
      method: "POST", headers: {"Content-Type": "application/json"},
      // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: body:
      // IRIS EXPLAIN: JSON.stringify({disposition: fields.get("disposition"), comment: fields.get("comment")})
      body: JSON.stringify({disposition: fields.get("disposition"), comment: fields.get("comment")})
    // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
    });
    // IRIS EXPLAIN: Wait for the stated backend/refresh step before continuing so later UI actions use the completed result.
    await selectCase(selected.case_id); await refreshCases();
    // IRIS EXPLAIN: Update the existing tab-local presentation/request state using the unchanged statement: message("Local
    // IRIS EXPLAIN: review recorded. No risk register was changed and no control was executed.");
    message("Local review recorded. No risk register was changed and no control was executed.");
  // IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
  });
// IRIS EXPLAIN: Close/continue this existing callback, conditional or collection without changing its execution order.
});
// IRIS EXPLAIN: Poll the backend every ten seconds only while connected, idle, visible and opted into auto-refresh; this is GET
// IRIS EXPLAIN: polling, not WebSockets.
setInterval(() => { if (identity && !busy && !document.hidden && element("auto-refresh").checked) action(refresh); }, 10000);
