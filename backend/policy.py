"""Small, versioned prototype policy, adapted from the v0.3 risk logic.

Only the primary rule assessment drives this policy. ML shadows never change
registered risks. This is not a validated organizational risk methodology.
"""
from __future__ import annotations

VERSION = "iris-shadow-policy-v1"
CATEGORIES = {"credential_access": {"Unauthorized Access"}, "reconnaissance": {"Reconnaissance"}}
MATRIX = {
    "Low": {"Low": "Low", "Medium": "Low", "High": "Medium", "Critical": "Medium"},
    "Medium": {"Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"},
    "High": {"Low": "Medium", "Medium": "High", "High": "High", "Critical": "Critical"},
    "Critical": {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"},
}


def evaluate(session: dict, prediction: dict) -> dict:
    primary = prediction["soc_assessment"]
    scenario = primary.get("scenario_class")
    result = {
        "policy_version": VERSION, "assessment_basis": primary["method"],
        "mapping_status": "UNMAPPED", "priority": "Needs Review",
        "matched_risk_id": None, "candidate_risk_ids": [],
        "baseline_risk_0_1": None, "proposed_likelihood": None, "proposed_risk_0_1": None,
        "risk_appetite_threshold": 0.5, "requires_human_review": True,
        "official_risk_register_write": False, "rationale": [],
    }
    if primary.get("status") != "ASSESSED" or primary["method"] != "rule_baseline":
        result["rationale"] = ["No usable primary rule assessment; ML remains shadow-only."]
        return result
    if scenario == "benign":
        result.update(mapping_status="NOT_APPLICABLE", priority="Low", requires_human_review=False)
        result["rationale"] = ["Business criticality alone does not turn benign evidence into an incident."]
        return result
    candidates = [r for r in session.get("risk_snapshots", []) if r["risk_category"] in CATEGORIES.get(scenario, set())]
    result["candidate_risk_ids"] = sorted(r["risk_id"] for r in candidates)
    if len(candidates) != 1:
        result["mapping_status"] = "AMBIGUOUS" if candidates else "UNMAPPED"
        result["rationale"] = ["A unique scenario-to-registered-risk match is required; no first-match or highest-risk guess is used."]
        return result
    risk = candidates[0]
    criticality = session.get("asset_snapshot", {}).get("criticality")
    if type(criticality) is not int or not 1 <= criticality <= 5:
        result["rationale"] = ["Business criticality is unavailable; no value is invented."]
        return result
    features = session["features"]
    severity = features["max_rule_level"] * 10 / 16
    technical = "Low" if severity < 3 else "Medium" if severity < 6 else "High" if severity < 8 else "Critical"
    business = "Low" if criticality <= 2 else "Medium" if criticality == 3 else "High" if criticality == 4 else "Critical"
    likelihood = risk["likelihood"]
    if (scenario == "credential_access" and (features["failed_count"] >= 20 or features["success_after_failures"])) or (
        scenario == "reconnaissance" and (features["distinct_rules"] >= 4 or features["event_count"] >= 30)
    ):
        likelihood = min(5, likelihood + 1)
    baseline = risk["likelihood"] * risk["impact"] / 25
    proposed = likelihood * risk["impact"] / 25
    result.update(mapping_status="MATCHED", matched_risk_id=risk["risk_id"],
                  matched_risk_version_id=risk["risk_version_id"], priority=MATRIX[technical][business],
                  baseline_risk_0_1=round(baseline, 4), proposed_likelihood=likelihood,
                  proposed_risk_0_1=round(proposed, 4), requires_human_review=True)
    result["rationale"] = [
        f"Prototype matrix combines technical severity {technical} with business criticality {business}.",
        "Baseline is pre-existing likelihood times impact divided by 25; any proposed likelihood is for human review only.",
        "Neither an ML prediction nor a local review writes an official risk-register value.",
    ]
    return result


def primary_controls(session: dict, prediction: dict, risk_review: dict) -> dict:
    """Use a uniquely matched risk's control state for primary catalogue advice.

    Keep ML Model 2's representative training context untouched in the separate
    shadow result. Never use an unrelated high-prior risk as an official match.
    """
    risk = next((r for r in session.get("risk_snapshots", []) if r["risk_id"] == risk_review["matched_risk_id"]), None)
    states = risk.get("control_states", {}) if risk else {}
    exceptions = set(risk.get("active_exception_control_ids", [])) if risk else set()
    rows = []
    for original in prediction["grc_control_review"].get("recommendations", []):
        row = {k: original[k] for k in ("control_id", "name", "catalogue_action")}
        state = states.get(row["control_id"], "unknown")
        action = {"missing": "install", "partial": "extend", "implemented": "verify"}.get(state, "review")
        warnings = []
        if state == "unknown":
            warnings.append("No uniquely matched risk control-state evidence; human review is required.")
        if state == "implemented":
            warnings.append("Verify existing coverage and effectiveness; do not reinstall blindly.")
        if row["control_id"] in exceptions:
            action = "review"
            warnings.append("An active exception requires review before any response.")
        row.update(current_state=state, action_type=action, model_score=None,
                   requires_human_approval=True, warnings=warnings)
        rows.append(row)
    return {"source": "catalogue_fallback", "control_state_risk_id": risk["risk_id"] if risk else None, "recommendations": rows}
