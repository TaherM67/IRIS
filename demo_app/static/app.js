"use strict";
const el = id => document.getElementById(id);
const pageRole = ["admin", "soc", "grc"].includes(location.pathname.slice(1)) ? location.pathname.slice(1) : "admin";
let key = "", identity = null, state = null, proposals = [], selected = "", offset = 0, totalAlerts = 0, busy = false, generation = 0;
let controller = new AbortController();
el("title").textContent = {admin:"Admin · engine control", soc:"SOC · live alert queue", grc:"GRC · live risk register"}[pageRole];
el("subtitle").textContent = {admin:"Analyze evidence. Follow approvals. Show the audit trail.", soc:"Inspect a proposal, approve it, and watch alert priorities actually change.", grc:"Review risk evidence, approve it, and watch the register actually change."}[pageRole];
el("login-hint").textContent = `Run python demo.py keys in a private terminal. Connect with the ${pageRole.toUpperCase()} demo key, not the older backend key.`;
const message = text => { el("message").textContent = text; };
const pretty = (id, value) => { el(id).textContent = JSON.stringify(value, null, 2); };
function node(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
function priority(value) { return node("span", value, "priority priority-" + value.toLowerCase()); }
function cell(text, secondary) { const n = node("td", text); if (secondary) n.append(node("span", secondary, "secondary-line")); return n; }
async function api(path, options = {}) {
  const current = generation;
  const response = await fetch("/api/demo" + path, {...options, headers:{"X-IRIS-Key":key,...(options.headers || {})}, signal:controller.signal, cache:"no-store", credentials:"omit"});
  const result = await response.json();
  if (generation !== current) throw new Error("Dashboard connection changed. Reconnect if needed.");
  if (!response.ok) throw new Error(result.detail || "The backend rejected this request.");
  return result;
}
function post(path, body) { return api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}); }
async function action(callback, silent = false) {
  if (busy) return;
  busy = true;
  const buttons = Array.from(document.querySelectorAll("button"));
  for (const button of buttons) button.disabled = true;
  try { await callback(); } catch (error) { if (error.name !== "AbortError") message(error.message); }
  finally { busy = false; for (const button of buttons) button.disabled = false; pager(); }
}
function pager() { el("previous").disabled = busy || offset === 0; el("next").disabled = busy || offset + 50 >= totalAlerts; }
function renderProposal() {
  const p = proposals.find(item => item.proposal_id === selected);
  el("proposal-summary").replaceChildren();
  el("evidence-panel").hidden = !p;
  el("review-form").hidden = !p || pageRole === "admin";
  if (!p) { el("proposal-summary").textContent = state && state.analyzed ? "No pending proposal selected. Approved changes remain visible in the live records and change history." : "Run analysis from Admin to prepare proposals."; return; }
  const data = p.payload, evidence = data.evidence;
  const summary = el("proposal-summary");
  summary.append(node("h3", evidence.hostname + " · " + (p.kind === "soc" ? "SOC reprioritization" : "GRC risk update")));
  summary.append(node("p", `Primary: ${evidence.primary_assessment.scenario_class} · engine priority: ${evidence.policy.priority} · criticality: ${evidence.asset_criticality}/5`));
  if (p.kind === "soc") {
    summary.append(node("p", `${data.changed_alerts} alerts → ${data.new_priority}`, "big-change"));
    summary.append(node("p", "Current priorities among the alerts to change: " + Object.entries(data.before_counts).map(([label, count]) => `${label}: ${count}`).join(" · ")));
  } else {
    summary.append(node("p", `Risk score ${data.before.score.toFixed(2)} → ${data.after.score.toFixed(2)}`, "big-change"));
    summary.append(node("p", `${data.risk_id} · likelihood ${data.before.likelihood} → ${data.after.likelihood} · impact stays ${data.after.impact}`));
  }
  const shadow = evidence.ml_shadow;
  summary.append(node("p", shadow ? `ML shadow: ${shadow.scenario || "ABSTAINED"} · confidence ${(shadow.confidence*100).toFixed(1)}% (not an approved decision)` : "ML shadow: unavailable for this evidence; no prediction is invented.", "muted"));
  summary.append(node("p", "Human approval changes synthetic system records only. It does not execute any suggested security control.", "muted"));
  pretty("proposal-evidence", {proposal_id:p.proposal_id,case_id:p.case_id,...evidence});
}
function renderProposalList(result) {
  proposals = result.items;
  const previous = selected;
  if (!proposals.some(p => p.proposal_id === selected)) selected = proposals.length ? proposals[0].proposal_id : "";
  el("proposal-select").replaceChildren(...(proposals.length ? proposals.map(p => new Option(`${p.payload.evidence.hostname} · ${p.kind.toUpperCase()} · ${p.kind === "soc" ? p.payload.changed_alerts + " alerts → " + p.payload.new_priority : p.payload.before.score.toFixed(2) + " → " + p.payload.after.score.toFixed(2)}`,p.proposal_id)) : [new Option("No pending proposals","")]));
  el("proposal-select").value = selected;
  el("proposal-count").textContent = `${result.total} PENDING`;
  if (previous !== selected) el("reason").value = "";
  renderProposal();
}
function renderRisks(result) {
  el("risk-rows").replaceChildren(...result.items.map(item => {
    const tr = node("tr",undefined,item.version > 1 ? "changed" : "");
    tr.append(cell(item.risk_id,item.hostname), cell(item.category), cell(`${item.baseline_likelihood} → ${item.current_likelihood}`), cell(String(item.impact)), cell(`${item.baseline_score.toFixed(2)} → ${item.current_score.toFixed(2)}`), cell(`v${item.version}`,item.updated_by ? `${item.updated_by.toUpperCase()} · ${item.updated_at}` : "Original imported record"));
    return tr;
  }));
}
function renderAlerts(result) {
  totalAlerts = result.total;
  el("alert-page").textContent = result.total ? `${offset+1}–${Math.min(offset+result.items.length,result.total)} of ${result.total} alerts` : "No matching alerts. Approve an SOC proposal to create reprioritized records.";
  el("alert-rows").replaceChildren(...result.items.map(item => {
    const tr = node("tr",undefined,item.version > 1 ? "changed" : "");
    const before = node("td"), after = node("td"); before.append(priority(item.baseline_priority)); after.append(priority(item.current_priority));
    tr.append(cell(item.event_id,item.hostname),cell(item.event_time),before,after,cell(`v${item.version}`,item.updated_by ? `Approved by ${item.updated_by.toUpperCase()}` : "Original technical priority"));
    return tr;
  }));
  pager();
}
function renderChanges(result) {
  el("changes-empty").hidden = result.items.length > 0;
  el("changes-table").hidden = result.items.length === 0;
  el("change-rows").replaceChildren(...result.items.map(item => {
    const tr = node("tr",undefined,"changed");
    const format = value => item.target_kind === "risk" ? `L=${value.likelihood}, I=${value.impact}, score=${value.score.toFixed(2)}, v${value.version}` : `${value.priority}, v${value.version}`;
    tr.append(cell(item.target_id,item.target_kind.toUpperCase()),cell(format(item.before)),cell(format(item.after)),cell(`${item.actor.toUpperCase()} · ${item.reason}`,item.changed_at));
    return tr;
  }));
}
async function refresh() {
  if (!identity) return;
  const current = await api("/state");
  if (state && state.exercise_id !== current.exercise_id) { selected = ""; offset = 0; el("reason").value = ""; el("changed-only").checked = false; message("Admin selected a new rehearsal. This tab now shows its original demo records."); }
  state = current;
  el("exercise").textContent = `${state.label} · ${state.exercise_id.slice(0,13)}`;
  const c = state.counts;
  for (const [id,value] of Object.entries({"risk-count":c.risks,"alert-count":c.alerts,"risk-changed":c.changed_risks,"alert-changed":c.reprioritized_alerts,"pending-count":c.pending_soc+c.pending_grc})) el(id).textContent = value.toLocaleString();
  pretty("model-status",state.model);
  const proposalResult = await api("/proposals");
  renderProposalList(proposalResult);
  renderChanges(await api("/changes"));
  if (pageRole === "grc") renderRisks(await api("/risks"));
  if (pageRole === "soc") renderAlerts(await api(`/alerts?limit=50&offset=${offset}&changed_only=${el("changed-only").checked}`));
  if (pageRole === "admin") {
    el("analysis-status").textContent = state.analyzed ? `${state.analysis.sessions} model sessions analyzed. Proposals wait for separate SOC/GRC approvals. Re-analysis reuses identical evidence and does not reset reviews.` : "Ready: 30 assets, 60 current risks and 2,355 matched unique alerts. Nothing has been changed.";
    pretty("audit",await api("/audit")); pretty("integration",state.analysis); pretty("history",state.exercise_history);
  }
}
el("login-form").addEventListener("submit",event => {
  event.preventDefault();
  action(async () => {
    generation += 1; key = el("key").value.trim();
    const result = await api("/state");
    if (result.role !== pageRole) { key = ""; throw new Error(`This is the ${pageRole.toUpperCase()} dashboard. Use its own demo key, or open the matching dashboard link above.`); }
    identity = result.role; state = null;
    el("key").value = ""; el("identity").textContent = identity.toUpperCase() + " connected";
    el("workspace").hidden = false; el("login-panel").hidden = true;
    el("admin-actions").hidden = pageRole !== "admin"; el("admin-detail").hidden = pageRole !== "admin";
    el("risk-panel").hidden = pageRole !== "grc"; el("alert-panel").hidden = pageRole !== "soc";
    el("review-panel").hidden = false;
    el("proposal-title").textContent = pageRole === "admin" ? "Team proposals · read-only for Admin" : `${pageRole.toUpperCase()} approval inbox`;
    el("approval-note").textContent = pageRole === "admin" ? "Open the SOC and GRC links in separate tabs and use their own keys to approve. Admin cannot impersonate either team." : "Inspect the saved evidence and before/after values. Approve to write the demo database, or reject to preserve the current values.";
    await refresh(); message("Connected. These tables read live backend records, not a static mockup.");
  });
});
el("logout").addEventListener("click",() => {
  generation += 1; controller.abort(); controller = new AbortController(); key = ""; identity = null; state = null; proposals = []; selected = ""; offset = 0;
  el("workspace").hidden = true; el("login-panel").hidden = false;
  for (const id of ["risk-rows","alert-rows","change-rows","audit","integration","history","model-status","proposal-evidence","proposal-summary"]) el(id).replaceChildren();
  el("review-form").reset(); message("Disconnected. The key has been removed from this tab's memory.");
});
el("refresh").addEventListener("click",() => action(refresh));
el("analyze").addEventListener("click",() => action(async () => { message("Running the actual saved models and explicit engine policy. Please wait…"); const result = await post("/analyze",{}); await refresh(); message(`${result.sessions} cases analyzed. No working risk/alert records changed yet. Open SOC and GRC to review and apply proposals.`); }));
el("exercise-form").addEventListener("submit",event => { event.preventDefault(); action(async () => { if (!confirm("Create a fresh synthetic rehearsal? Earlier exercises and audit history will be preserved.")) return; await post("/exercises",{label:el("exercise-label").value}); await refresh(); message("New rehearsal created. Analyze again. Earlier exercises remain saved, not deleted."); }); });
el("proposal-select").addEventListener("change",() => { selected = el("proposal-select").value; el("reason").value = ""; renderProposal(); });
el("review-form").addEventListener("submit",event => {
  event.preventDefault();
  const decision = event.submitter ? event.submitter.value : "approve";
  action(async () => {
    if (!selected) throw new Error("Choose a pending proposal first.");
    const chosen = selected;
    const result = await post(`/proposals/${encodeURIComponent(chosen)}/review`,{decision,reason:el("reason").value});
    if (pageRole === "soc" && decision === "approve") { el("changed-only").checked = true; offset = 0; }
    await refresh();
    message(decision === "approve" ? `Applied: ${result.demo_records_written} demo record(s) changed and saved. The other dashboards see the new counts on refresh. No external system was changed.` : "Rejected. The working records did not change; the decision was audited.");
  });
});
el("changed-only").addEventListener("change",() => action(async () => { offset = 0; await refresh(); }));
el("previous").addEventListener("click",() => action(async () => { offset = Math.max(0,offset-50); await refresh(); }));
el("next").addEventListener("click",() => action(async () => { offset += 50; await refresh(); }));
async function download(kind) { const data = await api("/export/"+kind); const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"})); const a = node("a"); a.href = url; a.download = kind === "risks" ? "IRIS_current_demo_risk_register.json" : "IRIS_current_demo_alert_priorities.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); }
el("export-risks").addEventListener("click",() => action(() => download("risks")));
el("export-alerts").addEventListener("click",() => action(() => download("alerts")));
setInterval(() => { if (identity && !busy && !document.hidden && el("auto-refresh").checked) action(refresh,true); },3000);
