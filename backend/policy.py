# IRIS EXPLAIN: File purpose: Deterministic prototype risk/priority rules and matched-risk control advice; ML does not invent
# IRIS EXPLAIN: official likelihood or impact.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Small, versioned prototype policy, adapted from the v0.3 risk logic.

Only the primary rule assessment drives this policy. ML shadows never change
registered risks. This is not a validated organizational risk methodology.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Store 'iris-shadow-policy-v1' in VERSION; later lines use this named result.
VERSION = "iris-shadow-policy-v1"
# IRIS EXPLAIN: Store a mapping containing credential_access, reconnaissance in CATEGORIES; later lines use this named result.
CATEGORIES = {"credential_access": {"Unauthorized Access"}, "reconnaissance": {"Reconnaissance"}}
# IRIS EXPLAIN: Store a mapping containing Low, Medium, High, Critical in MATRIX; later lines use this named result.
MATRIX = {
    # IRIS EXPLAIN: Continue the current record with Low, Low, Medium, High, Critical; each value comes from the expression
    # IRIS EXPLAIN: shown on this unchanged line.
    "Low": {"Low": "Low", "Medium": "Low", "High": "Medium", "Critical": "Medium"},
    # IRIS EXPLAIN: Continue the current record with Medium, Low, Medium, High, Critical; each value comes from the expression
    # IRIS EXPLAIN: shown on this unchanged line.
    "Medium": {"Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"},
    # IRIS EXPLAIN: Continue the current record with High, Low, Medium, High, Critical; each value comes from the expression
    # IRIS EXPLAIN: shown on this unchanged line.
    "High": {"Low": "Medium", "Medium": "High", "High": "High", "Critical": "Critical"},
    # IRIS EXPLAIN: Continue the current record with Critical, Low, Medium, High, Critical; each value comes from the expression
    # IRIS EXPLAIN: shown on this unchanged line.
    "Critical": {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"},
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
}


# IRIS EXPLAIN: Function evaluate: Require a usable primary rule assessment and unique registered-risk mapping, then derive a
# IRIS EXPLAIN: review-only priority/likelihood proposal from the explicit prototype matrix.
# IRIS EXPLAIN: Inputs: session: observed session features plus time-valid asset/risk context; prediction: saved primary
# IRIS EXPLAIN: assessment and separate experimental ML candidate.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def evaluate(session: dict, prediction: dict) -> dict:
    # IRIS EXPLAIN: Store prediction['soc_assessment'] in primary; later lines use this named result.
    primary = prediction["soc_assessment"]
    # IRIS EXPLAIN: Store the result of primary.get('scenario_class') (read an optional mapping field using its stated fallback)
    # IRIS EXPLAIN: in scenario; later lines use this named result.
    scenario = primary.get("scenario_class")
    # IRIS EXPLAIN: Store a mapping containing policy_version, assessment_basis, mapping_status, priority, matched_risk_id,
    # IRIS EXPLAIN: candidate_risk_ids, baseline_risk_0_1 and additional fields in result; later lines use this named result.
    result = {
        # IRIS EXPLAIN: Set/describe these existing record fields: policy_version: identity of the exact explicit risk-policy
        # IRIS EXPLAIN: rules used for this proposal; assessment_basis: which primary rule/model method supplied the usable
        # IRIS EXPLAIN: scenario evidence.
        "policy_version": VERSION, "assessment_basis": primary["method"],
        # IRIS EXPLAIN: Set/describe these existing record fields: mapping_status: whether risk matching is unique, absent,
        # IRIS EXPLAIN: ambiguous or not applicable; uncertainty is not guessed away; priority: explicit policy priority; in the
        # IRIS EXPLAIN: active demo it is written only after SOC approval.
        "mapping_status": "UNMAPPED", "priority": "Needs Review",
        # IRIS EXPLAIN: Set/describe these existing record fields: matched_risk_id: the uniquely matched registered-risk
        # IRIS EXPLAIN: identity, or None when no safe match exists; candidate_risk_ids: all scenario-compatible registered
        # IRIS EXPLAIN: risks retained to expose ambiguous mappings.
        "matched_risk_id": None, "candidate_risk_ids": [],
        # IRIS EXPLAIN: Set/describe these existing record fields: baseline_risk_0_1: pre-existing likelihood times impact
        # IRIS EXPLAIN: divided by 25, not an ML probability; proposed_likelihood: review-only explicit-policy likelihood
        # IRIS EXPLAIN: proposal capped at 5; proposed_risk_0_1: proposed likelihood times registered impact divided by 25; not
        # IRIS EXPLAIN: predicted control effectiveness.
        "baseline_risk_0_1": None, "proposed_likelihood": None, "proposed_risk_0_1": None,
        # IRIS EXPLAIN: Set/describe these existing record fields: risk_appetite_threshold: the prototype comparison threshold,
        # IRIS EXPLAIN: not an organization-validated standard; requires_human_review: explicit requirement for a human to
        # IRIS EXPLAIN: review advisory evidence.
        "risk_appetite_threshold": 0.5, "requires_human_review": True,
        # IRIS EXPLAIN: Set/describe these existing record fields: official_risk_register_write: safety flag: model inference
        # IRIS EXPLAIN: does not change an official company register; rationale: plain-text evidence and limits explaining the
        # IRIS EXPLAIN: policy decision.
        "official_risk_register_write": False, "rationale": [],
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Enter this branch only when primary.get('status') != 'ASSESSED' or primary['method'] != 'rule_baseline'.
    if primary.get("status") != "ASSESSED" or primary["method"] != "rule_baseline":
        # IRIS EXPLAIN: Store ['No usable primary rule assessment; ML remains shadow-only.'] in result['rationale']; later lines
        # IRIS EXPLAIN: use this named result.
        result["rationale"] = ["No usable primary rule assessment; ML remains shadow-only."]
        # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
        return result
    # IRIS EXPLAIN: Enter this branch only when scenario == 'benign'.
    if scenario == "benign":
        # IRIS EXPLAIN: Call result.update(mapping_status='NOT_APPLICABLE', priority='Low', requires_human_review=False): merge
        # IRIS EXPLAIN: the supplied fields into this existing mapping.
        result.update(mapping_status="NOT_APPLICABLE", priority="Low", requires_human_review=False)
        # IRIS EXPLAIN: Store ['Business criticality alone does not turn benign evidence into an incident.'] in
        # IRIS EXPLAIN: result['rationale']; later lines use this named result.
        result["rationale"] = ["Business criticality alone does not turn benign evidence into an incident."]
        # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
        return result
    # IRIS EXPLAIN: Store the comprehension [r for r in session.get('risk_snapshots', []) if r['risk_category'] in
    # IRIS EXPLAIN: CATEGORIES.get(scenario, set())] in candidates; later lines use this named result.
    candidates = [r for r in session.get("risk_snapshots", []) if r["risk_category"] in CATEGORIES.get(scenario, set())]
    # IRIS EXPLAIN: Store sorted((r['risk_id'] for r in candidates)) in result['candidate_risk_ids']; later lines use this named
    # IRIS EXPLAIN: result.
    result["candidate_risk_ids"] = sorted(r["risk_id"] for r in candidates)
    # IRIS EXPLAIN: Enter this branch only when len(candidates) != 1.
    if len(candidates) != 1:
        # IRIS EXPLAIN: Store 'AMBIGUOUS' when candidates; otherwise 'UNMAPPED' in result['mapping_status']; later lines use
        # IRIS EXPLAIN: this named result.
        result["mapping_status"] = "AMBIGUOUS" if candidates else "UNMAPPED"
        # IRIS EXPLAIN: Store ['A unique scenario-to-registered-risk match is required; no first-match or highest-risk guess is
        # IRIS EXPLAIN: used.'] in result['rationale']; later lines use this named result.
        result["rationale"] = ["A unique scenario-to-registered-risk match is required; no first-match or highest-risk guess is used."]
        # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
        return result
    # IRIS EXPLAIN: Store candidates[0] in risk; later lines use this named result.
    risk = candidates[0]
    # IRIS EXPLAIN: Store the result of session.get('asset_snapshot', {}).get('criticality') (read an optional mapping field
    # IRIS EXPLAIN: using its stated fallback) in criticality; later lines use this named result.
    criticality = session.get("asset_snapshot", {}).get("criticality")
    # IRIS EXPLAIN: Enter this branch only when type(criticality) is not int or not 1 <= criticality <= 5.
    if type(criticality) is not int or not 1 <= criticality <= 5:
        # IRIS EXPLAIN: Store ['Business criticality is unavailable; no value is invented.'] in result['rationale']; later lines
        # IRIS EXPLAIN: use this named result.
        result["rationale"] = ["Business criticality is unavailable; no value is invented."]
        # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
        return result
    # IRIS EXPLAIN: Store session['features'] in features; later lines use this named result.
    features = session["features"]
    # IRIS EXPLAIN: Store the computed value features['max_rule_level'] * 10 / 16 in severity; later lines use this named
    # IRIS EXPLAIN: result.
    severity = features["max_rule_level"] * 10 / 16
    # IRIS EXPLAIN: Store 'Low' when severity < 3; otherwise 'Medium' when severity < 6; otherwise 'High' when severity < 8;
    # IRIS EXPLAIN: otherwise 'Critical' in technical; later lines use this named result.
    technical = "Low" if severity < 3 else "Medium" if severity < 6 else "High" if severity < 8 else "Critical"
    # IRIS EXPLAIN: Store 'Low' when criticality <= 2; otherwise 'Medium' when criticality == 3; otherwise 'High' when
    # IRIS EXPLAIN: criticality == 4; otherwise 'Critical' in business; later lines use this named result.
    business = "Low" if criticality <= 2 else "Medium" if criticality == 3 else "High" if criticality == 4 else "Critical"
    # IRIS EXPLAIN: Store risk['likelihood'] in likelihood; later lines use this named result.
    likelihood = risk["likelihood"]
    # IRIS EXPLAIN: Enter this branch only when scenario == 'credential_access' and (features['failed_count'] >= 20 or
    # IRIS EXPLAIN: features['success_after_failures']) or (scenario == 'reconnaissance' and (features['distinct_rules'] >= 4 or
    # IRIS EXPLAIN: features['event_count'] >= 30)).
    if (scenario == "credential_access" and (features["failed_count"] >= 20 or features["success_after_failures"])) or (
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: scenario == "reconnaissance" and (features["distinct_rules"] >= 4 or features["event_count"] >= 30).
        scenario == "reconnaissance" and (features["distinct_rules"] >= 4 or features["event_count"] >= 30)
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    ):
        # IRIS EXPLAIN: Store min(5, likelihood + 1) in likelihood; later lines use this named result.
        likelihood = min(5, likelihood + 1)
    # IRIS EXPLAIN: Store the computed value risk['likelihood'] * risk['impact'] / 25 in baseline; later lines use this named
    # IRIS EXPLAIN: result.
    baseline = risk["likelihood"] * risk["impact"] / 25
    # IRIS EXPLAIN: Store the computed value likelihood * risk['impact'] / 25 in proposed; later lines use this named result.
    proposed = likelihood * risk["impact"] / 25
    # IRIS EXPLAIN: Call result.update(mapping_status='MATCHED', matched_risk_id=risk['risk_id'],
    # IRIS EXPLAIN: matched_risk_version_id=risk['risk_version_id'], priority=MATRIX[technical][business...: merge the supplied
    # IRIS EXPLAIN: fields into this existing mapping.
    result.update(mapping_status="MATCHED", matched_risk_id=risk["risk_id"],
                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                  # IRIS EXPLAIN: arguments/items: matched_risk_version_id=risk["risk_version_id"],
                  # IRIS EXPLAIN: priority=MATRIX[technical][business],.
                  matched_risk_version_id=risk["risk_version_id"], priority=MATRIX[technical][business],
                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                  # IRIS EXPLAIN: arguments/items: baseline_risk_0_1=round(baseline, 4), proposed_likelihood=likelihood,.
                  baseline_risk_0_1=round(baseline, 4), proposed_likelihood=likelihood,
                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                  # IRIS EXPLAIN: arguments/items: proposed_risk_0_1=round(proposed, 4), requires_human_review=True).
                  proposed_risk_0_1=round(proposed, 4), requires_human_review=True)
    # IRIS EXPLAIN: Store [f'Prototype matrix combines technical severity {technical} with business criticality {business}.',
    # IRIS EXPLAIN: 'Baseline is pre-existing likelihood times impa... in result['rationale']; later lines use this named
    # IRIS EXPLAIN: result.
    result["rationale"] = [
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: f"Prototype matrix combines technical severity {technical} with business criticality {business}.",.
        f"Prototype matrix combines technical severity {technical} with business criticality {business}.",
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: "Baseline is pre-existing likelihood times impact divided by 25; any proposed likelihood is for human
        # IRIS EXPLAIN: review only.",.
        "Baseline is pre-existing likelihood times impact divided by 25; any proposed likelihood is for human review only.",
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: "Neither an ML prediction nor a local review writes an official risk-register value.",.
        "Neither an ML prediction nor a local review writes an official risk-register value.",
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    ]
    # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
    return result


# IRIS EXPLAIN: Function primary_controls: Re-evaluate catalogue advice against the uniquely matched risk's own control states
# IRIS EXPLAIN: and exceptions, not an unrelated representative ML-context risk.
# IRIS EXPLAIN: Inputs: session: observed session features plus time-valid asset/risk context; prediction: saved primary
# IRIS EXPLAIN: assessment and separate experimental ML candidate; risk_review: the explicit risk review input used by the
# IRIS EXPLAIN: unchanged statements below.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def primary_controls(session: dict, prediction: dict, risk_review: dict) -> dict:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Use a uniquely matched risk's control state for primary catalogue advice.

    Keep ML Model 2's representative training context untouched in the separate
    shadow result. Never use an unrelated high-prior risk as an official match.
    """
    # IRIS EXPLAIN: Store the result of next((r for r in session.get('risk_snapshots', []) if r['risk_id'] ==
    # IRIS EXPLAIN: risk_review['matched_risk_id']), None) in risk; later lines use this named result.
    risk = next((r for r in session.get("risk_snapshots", []) if r["risk_id"] == risk_review["matched_risk_id"]), None)
    # IRIS EXPLAIN: Store the result of risk.get('control_states', {}) (read an optional mapping field using its stated
    # IRIS EXPLAIN: fallback) when risk; otherwise a mapping containing  in states; later lines use this named result.
    states = risk.get("control_states", {}) if risk else {}
    # IRIS EXPLAIN: Store set(risk.get('active_exception_control_ids', [])) when risk; otherwise set() in exceptions; later
    # IRIS EXPLAIN: lines use this named result.
    exceptions = set(risk.get("active_exception_control_ids", [])) if risk else set()
    # IRIS EXPLAIN: Store [] in rows; later lines use this named result.
    rows = []
    # IRIS EXPLAIN: Iterate prediction['grc_control_review'].get('recommendations', []), binding each item to original; process
    # IRIS EXPLAIN: only the existing observed/fixture collection.
    for original in prediction["grc_control_review"].get("recommendations", []):
        # IRIS EXPLAIN: Store the comprehension {k: original[k] for k in ('control_id', 'name', 'catalogue_action')} in row;
        # IRIS EXPLAIN: later lines use this named result.
        row = {k: original[k] for k in ("control_id", "name", "catalogue_action")}
        # IRIS EXPLAIN: Store the result of states.get(row['control_id'], 'unknown') (read an optional mapping field using its
        # IRIS EXPLAIN: stated fallback) in state; later lines use this named result.
        state = states.get(row["control_id"], "unknown")
        # IRIS EXPLAIN: Store the result of {'missing': 'install', 'partial': 'extend', 'implemented': 'verify'}.get(state,
        # IRIS EXPLAIN: 'review') (read an optional mapping field using its stated fallback) in action; later lines use this
        # IRIS EXPLAIN: named result.
        action = {"missing": "install", "partial": "extend", "implemented": "verify"}.get(state, "review")
        # IRIS EXPLAIN: Store [] in warnings; later lines use this named result.
        warnings = []
        # IRIS EXPLAIN: Enter this branch only when state == 'unknown'.
        if state == "unknown":
            # IRIS EXPLAIN: Call warnings.append('No uniquely matched risk control-state evidence; human review is required.'):
            # IRIS EXPLAIN: append one item to the working list.
            warnings.append("No uniquely matched risk control-state evidence; human review is required.")
        # IRIS EXPLAIN: Enter this branch only when state == 'implemented'.
        if state == "implemented":
            # IRIS EXPLAIN: Call warnings.append('Verify existing coverage and effectiveness; do not reinstall blindly.'):
            # IRIS EXPLAIN: append one item to the working list.
            warnings.append("Verify existing coverage and effectiveness; do not reinstall blindly.")
        # IRIS EXPLAIN: Enter this branch only when row['control_id'] in exceptions.
        if row["control_id"] in exceptions:
            # IRIS EXPLAIN: Store 'review' in action; later lines use this named result.
            action = "review"
            # IRIS EXPLAIN: Call warnings.append('An active exception requires review before any response.'): append one item to
            # IRIS EXPLAIN: the working list.
            warnings.append("An active exception requires review before any response.")
        # IRIS EXPLAIN: Call row.update(current_state=state, action_type=action, model_score=None, requires_human_approval=True,
        # IRIS EXPLAIN: warnings=warnings): merge the supplied fields into this existing mapping.
        row.update(current_state=state, action_type=action, model_score=None,
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: requires_human_approval=True, warnings=warnings).
                   requires_human_approval=True, warnings=warnings)
        # IRIS EXPLAIN: Call rows.append(row): append one item to the working list.
        rows.append(row)
    # IRIS EXPLAIN: Return a mapping containing source, control_state_risk_id, recommendations to the caller; this ends the
    # IRIS EXPLAIN: current function path.
    return {"source": "catalogue_fallback", "control_state_risk_id": risk["risk_id"] if risk else None, "recommendations": rows}
