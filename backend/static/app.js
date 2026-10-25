"use strict";
const element = id => document.getElementById(id);
let key = "", identity = null, offset = 0, total = 0, selected = null, busy = false, generation = 0;
let requests = new AbortController();
function message(text) { element("message").textContent = text; }
function pretty(id, value) { element(id).textContent = JSON.stringify(value, null, 2); }
async function api(path, options = {}) {
  const currentGeneration = generation;
  const response = await fetch("/api" + path, {
    ...options, headers: {"X-IRIS-Key": key, ...(options.headers || {})},
    signal: requests.signal, cache: "no-store", credentials: "omit"
  });
  const data = await response.json();
  if (currentGeneration !== generation) throw new Error("Session changed; reconnect if needed.");
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
  return data;
}
async function action(callback) {
  if (busy) return;
  busy = true;
  const buttons = Array.from(document.querySelectorAll("button"));
  for (const button of buttons) button.disabled = true;
  try { await callback(); } catch (error) { if (error.name !== "AbortError") message(error.message); }
  finally { busy = false; for (const button of buttons) button.disabled = false; updatePager(); }
}
function updatePager() {
  element("previous").disabled = busy || offset === 0;
  element("next").disabled = busy || offset + 25 >= total;
}
async function refreshRuns() {
  const runs = await api("/runs");
  const current = element("run").value;
  element("run").replaceChildren(new Option("All completed runs", ""));
  for (const run of runs.filter(item => item.status === "completed")) {
    element("run").add(new Option(run.run_id + " · " + run.summary.sessions + " sessions", run.run_id));
  }
  if (Array.from(element("run").options).some(option => option.value === current)) element("run").value = current;
}
async function selectCase(caseId) {
  const audience = element("view").value;
  selected = await api("/" + audience + "/cases/" + encodeURIComponent(caseId));
  pretty("case-detail", selected);
  element("review-form").hidden = !(identity.role === "grc" && audience === "grc" && !selected.review);
  for (const button of element("case-list").querySelectorAll("button")) button.setAttribute("aria-pressed", String(button.dataset.caseId === caseId));
}
async function refreshCases() {
  const audience = element("view").value;
  const query = new URLSearchParams({limit: "25", offset: String(offset)});
  if (element("run").value) query.set("run_id", element("run").value);
  const page = await api("/" + audience + "/cases?" + query);
  total = page.total;
  element("case-count").textContent = total ? `${offset + 1}–${Math.min(offset + page.items.length, total)} of ${total} cases` : "No cases yet. Admin or SOC can analyze a batch.";
  const nodes = page.items.map(item => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "case-button";
    button.dataset.caseId = item.case_id;
    button.setAttribute("aria-pressed", String(selected && selected.case_id === item.case_id));
    const shadow = item.shadow_candidate;
    button.textContent = `${item.asset.hostname} · ${item.priority}\nPrimary: ${item.primary_assessment.scenario_class || "Needs Review"} · ML shadow: ${shadow ? shadow.scenario_class || "Abstained" : "Unavailable"}`;
    button.addEventListener("click", () => action(() => selectCase(item.case_id)));
    return button;
  });
  element("case-list").replaceChildren(...nodes);
  updatePager();
}
async function refresh() {
  if (!identity) return;
  await refreshRuns();
  const audience = element("view").value;
  element("admin-panel").hidden = audience !== "admin";
  element("cases-panel").hidden = audience === "admin";
  element("processing").hidden = !["admin", "soc"].includes(identity.role);
  if (audience === "admin") {
    pretty("admin-status", await api("/admin/status"));
    pretty("audit", await api("/admin/audit"));
  } else {
    element("cases-title").textContent = audience.toUpperCase() + " cases";
    await refreshCases();
  }
}
element("login-form").addEventListener("submit", event => {
  event.preventDefault();
  action(async () => {
    generation += 1;
    key = element("key").value.trim();
    identity = await api("/me");
    element("key").value = "";
    element("identity").textContent = "Connected as " + identity.role.toUpperCase();
    element("view").replaceChildren(...identity.views.map(view => new Option(view.toUpperCase(), view)));
    element("workspace").hidden = false;
    element("login-panel").hidden = true;
    pretty("model-status", await api("/model"));
    await refresh();
    message("Connected. All ML results are shadow-only; there is no live external delivery.");
  });
});
element("logout").addEventListener("click", () => {
  generation += 1; requests.abort(); requests = new AbortController();
  key = ""; identity = null; selected = null; offset = 0; total = 0;
  element("workspace").hidden = true; element("login-panel").hidden = false;
  element("case-list").replaceChildren(); element("case-detail").textContent = "Select a case.";
  element("review-form").reset(); element("review-form").hidden = true;
  for (const id of ["admin-status", "audit", "model-status"]) element(id).textContent = "";
  message("Disconnected. The role key was removed from this page's memory.");
});
element("refresh").addEventListener("click", () => action(refresh));
element("view").addEventListener("change", () => action(async () => {
  offset = 0; selected = null; element("case-detail").textContent = "Select a case.";
  element("review-form").hidden = true; await refresh();
}));
element("run").addEventListener("change", () => action(async () => { offset = 0; selected = null; element("case-detail").textContent = "Select a case."; element("review-form").hidden = true; await refreshCases(); }));
element("previous").addEventListener("click", () => action(async () => { offset = Math.max(0, offset - 25); await refreshCases(); }));
element("next").addEventListener("click", () => action(async () => { offset += 25; await refreshCases(); }));
async function afterBatch(summary) {
  await refresh();
  message(`${summary.sessions} sessions processed. ${summary.reused_existing_run ? "Reused the identical saved run." : "Saved a new run."} Open SOC or GRC to inspect cases. No external updates were sent.`);
}
element("sample").addEventListener("click", () => action(async () => {
  message("Processing the bundled sample. Please wait; 900 sessions may take a minute or more.");
  await afterBatch(await api("/runs/sample", {method: "POST"}));
}));
element("upload-form").addEventListener("submit", event => {
  event.preventDefault();
  action(async () => {
    message("Processing your three files. Please wait; do not close the backend terminal.");
    await afterBatch(await api("/runs", {method: "POST", body: new FormData(event.target)}));
  });
});
element("review-form").addEventListener("submit", event => {
  event.preventDefault();
  action(async () => {
    if (!selected || identity.role !== "grc") throw new Error("Select a case using the GRC key first.");
    const fields = new FormData(event.target);
    await api("/grc/cases/" + encodeURIComponent(selected.case_id) + "/review", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({disposition: fields.get("disposition"), comment: fields.get("comment")})
    });
    await selectCase(selected.case_id); await refreshCases();
    message("Local review recorded. No risk register was changed and no control was executed.");
  });
});
setInterval(() => { if (identity && !busy && !document.hidden && element("auto-refresh").checked) action(refresh); }, 10000);
