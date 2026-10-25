"""Advisory inference with independent integrity, release and policy checks."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from .contracts import (
    CATEGORICAL, CONTROL_FEATURES, FEATURES, FEATURE_SCHEMA, NUMERIC, digest,
    frame, rule_label, utc_now, validate_context, validate_features, write_json,
)
from .training import load_catalog

FALLBACK_CONTROLS = {
    "benign": [],
    "credential_access": ["SC005", "SC006", "SC007", "SC013", "SC026"],
    "reconnaissance": ["SC011", "SC012", "SC029"],
}


def promote(model_dir: Path, component: str, reviewer: str) -> dict:
    if component not in {"model1", "model2"} or not reviewer.strip():
        raise ValueError("Choose model1/model2 and an identified reviewer")
    metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    if digest(model_dir / "models.joblib") != metadata["model_sha256"]:
        raise ValueError("Model checksum mismatch")
    if not metadata[component].get("eligible_for_reviewed_advisory_release", False):
        raise ValueError(f"{component} release blocked: validation/evidence gate failed; remain in shadow mode")
    release_path = model_dir / "release.json"
    release = json.loads(release_path.read_text(encoding="utf-8")) if release_path.exists() else {}
    if component == "model2" and "model1" not in release:
        raise ValueError("Release Model 1 first; Model 2 depends on its predictions")
    release[component] = {"reviewer": reviewer.strip(), "reviewed_at_utc": utc_now(),
                          "scope": "human-reviewed advisory only", "model_sha256": metadata["model_sha256"],
                          "metadata_sha256": digest(model_dir / "metadata.json")}
    write_json(release_path, release)
    return release[component]


def linear_explanation(pipeline, X: pd.DataFrame, label: str) -> dict:
    estimator = pipeline.named_steps["classifier"]
    if not hasattr(estimator, "coef_"):
        return {"kind": "observed_evidence_only", "note": "Nonlinear model; observed inputs are evidence, not a per-case attribution."}
    labels = list(estimator.classes_)
    if label not in labels:
        return {"kind": "not_available"}
    coefficients = estimator.coef_[labels.index(label)]
    transformer = pipeline.named_steps["features"]
    transformed = np.asarray(transformer.transform(X))[0]
    terms = transformed * coefficients
    names = transformer.get_feature_names_out()
    top = np.argsort(np.abs(terms))[::-1][:6]
    return {"kind": "base_classifier_logit_contributions", "class": label,
            "top_terms": [{"feature": str(names[i]), "signed_contribution": float(terms[i])} for i in top],
            "note": "Explains the uncalibrated base classifier score, not causation, the final calibrated probability, or control effectiveness."}


class ModelService:
    def __init__(self, model_dir: Path | None, catalog_path: Path):
        self.catalog = load_catalog(catalog_path)
        self.model_dir = model_dir
        self.bundle, self.metadata, self.load_error = None, None, None
        self.release = {}
        if model_dir is None:
            self.load_error = "No trained artifact configured"
            return
        try:
            metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
            if metadata["feature_schema"] != FEATURE_SCHEMA or metadata["features"] != FEATURES:
                raise ValueError("Model feature schema mismatch")
            if metadata["scikit_learn_version"] != sklearn.__version__:
                raise ValueError("scikit-learn version mismatch; use pinned dependencies or retrain")
            if digest(model_dir / "models.joblib") != metadata["model_sha256"]:
                raise ValueError("Model checksum mismatch")
            if digest(catalog_path) != metadata["catalog_sha256"]:
                raise ValueError("Catalogue changed since training")
            # joblib can execute Python. Integrity checks do NOT establish authenticity.
            # Only use a locally trained artifact or a separately trusted distribution.
            bundle = joblib.load(model_dir / "models.joblib")
            self.bundle, self.metadata = bundle, metadata
            release_path = model_dir / "release.json"
            if release_path.exists():
                self.release = json.loads(release_path.read_text(encoding="utf-8"))
        except Exception as exc:  # Boundary: report load failures and retain safe fallback.
            self.bundle, self.metadata = None, None
            self.load_error = f"{type(exc).__name__}: {exc}"

    def released(self, component: str) -> bool:
        if self.bundle is None or self.metadata is None or self.model_dir is None:
            return False
        approval = self.release.get(component, {})
        return bool(
            self.metadata[component].get("eligible_for_reviewed_advisory_release", False)
            and approval.get("reviewer")
            and approval.get("model_sha256") == self.metadata["model_sha256"]
            and approval.get("metadata_sha256") == digest(self.model_dir / "metadata.json")
            and (component == "model1" or self.released("model1"))
        )

    def _controls(self, label: str | None, features: dict, context: dict | None, *, learned=False) -> dict:
        if label is None:
            return {"source": "not_run", "recommendations": [], "reason": "Scenario abstained"}
        if context is not None and not isinstance(context, dict):
            return {"source": "not_run", "recommendations": [], "reason": "Invalid GRC context object"}
        policy_context = context or {}
        if not isinstance(policy_context.get("controls", {}), dict) or not isinstance(policy_context.get("active_exception_control_ids", []), list):
            return {"source": "not_run", "recommendations": [], "reason": "Invalid control-state/exception schema"}
        if any(not isinstance(value, str) for value in policy_context.get("controls", {}).values()):
            return {"source": "not_run", "recommendations": [], "reason": "Control states must be strings"}
        if any(not isinstance(value, str) for value in policy_context.get("active_exception_control_ids", [])):
            return {"source": "not_run", "recommendations": [], "reason": "Exception control IDs must be strings"}
        source, ranked = "catalogue_fallback", []
        warnings = []
        if learned and self.bundle and self.bundle["control_model"]:
            try:
                ctx = validate_context(context)
                row = {**features, **ctx, "predicted_scenario": label}
                X = pd.DataFrame([row], columns=CONTROL_FEATURES)
                control_model = self.bundle["control_model"]
                Z = control_model["transformer"].transform(X)
                for cid, clf in control_model["classifiers"].items():
                    score = float(clf.predict_proba(Z)[0, list(clf.classes_).index(1)])
                    if score >= control_model["thresholds"][cid]:
                        terms = np.asarray(Z)[0] * clf.coef_[0]
                        names = control_model["transformer"].get_feature_names_out()
                        top = np.argsort(np.abs(terms))[::-1][:5]
                        ranked.append({"control_id": cid, "model_score": score,
                                       "explanation_terms": [{"feature": str(names[i]), "signed_logit_contribution": float(terms[i])} for i in top]})
                source = "learned_control_model"
                warnings.append("Membership scores are not calibrated efficacy probabilities or predicted risk reduction")
            except Exception as exc:  # Boundary: failed model is never an approval.
                warnings.append(f"Model 2 not usable: {exc}; catalogue fallback used")
        if not ranked:
            if source == "learned_control_model":
                warnings.append("No learned label exceeded its threshold; conservative catalogue fallback used")
            source = "catalogue_fallback"
            ranked = [{"control_id": c, "model_score": None} for c in FALLBACK_CONTROLS.get(label, [])]
        context = context or {}
        states = context.get("controls", {})
        exceptions = set(context.get("active_exception_control_ids", []))
        recommendations = []
        for item in sorted(ranked, key=lambda c: (-(c["model_score"] or 0), c["control_id"])):
            cid = item["control_id"]
            if cid not in self.catalog:
                continue
            current = states.get(cid, "unknown")
            action = {"missing": "install", "partial": "extend", "implemented": "verify"}.get(current, "review")
            warning = []
            if cid in exceptions:
                action = "review"
                warning.append("Active policy exception; review authorization/compensating controls first")
            if current == "implemented":
                warning.append("Verify effectiveness and coverage; do not reinstall blindly")
            if current == "unknown":
                warning.append("No asset-specific control-state record; analyst review required")
            recommendations.append({**item, "name": self.catalog[cid]["Control_Name"],
                                    "catalogue_action": self.catalog[cid]["Recommended_Action"],
                                    "current_state": current, "action_type": action,
                                    "requires_human_approval": True, "warnings": warning})
        return {"source": source, "recommendations": recommendations, "warnings": warnings}

    def predict(self, session: dict, *, mode="shadow") -> dict:
        if mode not in {"shadow", "advisory", "rules"}:
            raise ValueError("mode must be shadow, advisory or rules")
        features = validate_features(session["features"])
        healthy = session.get("sensor_healthy") is True
        warnings = []
        primary = {"scenario_class": None, "confidence": None, "status": "ABSTAINED", "method": "no_usable_evidence"}
        shadow = None
        if not healthy:
            warnings.append("Explicit healthy-sensor evidence missing; no attack/benign assessment is issued")
        else:
            baseline = rule_label(features)
            primary = {"scenario_class": baseline, "confidence": None,
                       "status": "ASSESSED" if baseline else "ABSTAINED", "method": "rule_baseline"}
            if mode != "rules" and self.bundle:
                vocab = self.metadata["model1"]["categorical_vocab"]
                unfamiliar = [key for key in CATEGORICAL if features[key] not in vocab[key]]
                if session.get("aggregation_schema") != self.metadata.get("aggregation_schema"):
                    warnings.append("Normalization/sessionization contract differs from training; ML disabled. Export training rows through the same runtime adapter.")
                elif unfamiliar:
                    warnings.append(f"Unseen categories {unfamiliar}; ML abstains. This is not a complete unknown-attack detector.")
                else:
                    X = frame([features])
                    try:
                        model = self.bundle["scenario_model"]
                        probs = model.predict_proba(X)[0]
                        i = int(probs.argmax())
                        label, score = str(model.classes_[i]), float(probs[i])
                        threshold = self.metadata["model1"]["threshold"]
                        label_or_none = label if score >= threshold else None
                        shadow = {"scenario_class": label_or_none, "top_candidate": label, "confidence": score,
                                  "status": "ASSESSED" if label_or_none else "ABSTAINED",
                                  "method": "calibrated_model1", "threshold": threshold,
                                  "class_probabilities": {str(c): float(p) for c, p in zip(model.classes_, probs)},
                                  "explanation": linear_explanation(self.bundle["scenario_base_pipeline"], X, label),
                                  "controls": self._controls(label_or_none, features, session.get("context"), learned=True)}
                        if mode == "advisory" and self.released("model1"):
                            primary = {k: v for k, v in shadow.items() if k != "controls"}
                        for key in NUMERIC:
                            low, high = self.metadata["model1"]["numeric_train_ranges"][key]
                            if not low <= features[key] <= high:
                                warnings.append(f"{key} outside fitted range [{low}, {high}]; review extrapolation")
                    except Exception as exc:  # Boundary: retain rules/abstention and expose warning.
                        warnings.append(f"Model inference failed; rule baseline retained: {exc}")
            if mode == "advisory" and not self.released("model1"):
                warnings.append("Model 1 not released: primary output remains rules/abstention; candidate is shadow-only")
        if self.load_error:
            warnings.append(f"ML unavailable: {self.load_error}")
        learned_controls = mode == "advisory" and primary["method"] == "calibrated_model1" and self.released("model2")
        controls = self._controls(primary["scenario_class"], features, session.get("context"), learned=learned_controls)
        return {
            "session_id": session.get("session_id"), "generated_at_utc": utc_now(), "mode": mode,
            "soc_assessment": primary, "grc_control_review": controls, "shadow_candidate": shadow,
            "evidence_features": features, "evidence_refs": session.get("evidence_refs", []),
            "warnings": warnings, "requires_human_review": True,
            "automatic_execution": False, "official_risk_register_write": False,
            "risk_scoring": "Delegate to the explicit versioned IRIS risk policy; ML does not set official likelihood/impact",
            "model1_released": self.released("model1"), "model2_released": self.released("model2"),
            "model_sha256": self.metadata["model_sha256"] if self.metadata else None,
        }
