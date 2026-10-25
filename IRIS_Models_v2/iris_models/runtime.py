# IRIS EXPLAIN: File purpose: Loads trusted model artifacts, checks integrity/release gates, and keeps experimental candidates
# IRIS EXPLAIN: separate from rules and human-approved actions.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Advisory inference with independent integrity, release and policy checks."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import joblib to serialize/load trusted learned estimators; loading untrusted pickle content is unsafe.
import joblib
# IRIS EXPLAIN: Import numpy as np to perform reproducible numeric sampling, vectorized predictions and array calculations.
import numpy as np
# IRIS EXPLAIN: Import pandas as pd to assemble allowlisted feature tables and catalogue records.
import pandas as pd
# IRIS EXPLAIN: Import sklearn to construct, fit, freeze, calibrate and evaluate the tabular ML estimators.
import sklearn

# IRIS EXPLAIN: Import CATEGORICAL, CONTROL_FEATURES, FEATURES, FEATURE_SCHEMA, NUMERIC, digest, frame, rule_label, utc_now,
# IRIS EXPLAIN: validate_context, validate_features, write_json from .contracts to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .contracts import (
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: CATEGORICAL, CONTROL_FEATURES, FEATURES, FEATURE_SCHEMA, NUMERIC, digest,.
    CATEGORICAL, CONTROL_FEATURES, FEATURES, FEATURE_SCHEMA, NUMERIC, digest,
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items: frame,
    # IRIS EXPLAIN: rule_label, utc_now, validate_context, validate_features, write_json,.
    frame, rule_label, utc_now, validate_context, validate_features, write_json,
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
)
# IRIS EXPLAIN: Import load_catalog from .training to reuse the shared project contract/implementation rather than duplicate it.
from .training import load_catalog

# IRIS EXPLAIN: Store a mapping containing benign, credential_access, reconnaissance in FALLBACK_CONTROLS; later lines use this
# IRIS EXPLAIN: named result.
FALLBACK_CONTROLS = {
    # IRIS EXPLAIN: Continue the current record with benign; each value comes from the expression shown on this unchanged line.
    "benign": [],
    # IRIS EXPLAIN: Continue the current record with credential_access; each value comes from the expression shown on this
    # IRIS EXPLAIN: unchanged line.
    "credential_access": ["SC005", "SC006", "SC007", "SC013", "SC026"],
    # IRIS EXPLAIN: Continue the current record with reconnaissance; each value comes from the expression shown on this
    # IRIS EXPLAIN: unchanged line.
    "reconnaissance": ["SC011", "SC012", "SC029"],
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
}


# IRIS EXPLAIN: Function promote: Write a named advisory approval only after existing artifact and evidence gates pass;
# IRIS EXPLAIN: synthetic or failing models must remain unreleased.
# IRIS EXPLAIN: Inputs: model_dir: operator-trusted model bundle directory; component: model1 or model2, with the existing
# IRIS EXPLAIN: dependent release gates; reviewer: the explicitly named offline/advisory reviewer.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def promote(model_dir: Path, component: str, reviewer: str) -> dict:
    # IRIS EXPLAIN: Enter this branch only when component not in {'model1', 'model2'} or not reviewer.strip().
    if component not in {"model1", "model2"} or not reviewer.strip():
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Choose model1/model2 and an identified
        # IRIS EXPLAIN: reviewer'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Choose model1/model2 and an identified reviewer")
    # IRIS EXPLAIN: Store the result of json.loads((model_dir / 'metadata.json').read_text(encoding='utf-8')) (decode the
    # IRIS EXPLAIN: existing JSON text) in metadata; later lines use this named result.
    metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    # IRIS EXPLAIN: Enter this branch only when digest(model_dir / 'models.joblib') != metadata['model_sha256'].
    if digest(model_dir / "models.joblib") != metadata["model_sha256"]:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Model checksum mismatch'); the caller's
        # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Model checksum mismatch")
    # IRIS EXPLAIN: Enter this branch only when not metadata[component].get('eligible_for_reviewed_advisory_release', False).
    if not metadata[component].get("eligible_for_reviewed_advisory_release", False):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{component} release blocked:
        # IRIS EXPLAIN: validation/evidence gate failed; remain in shadow mode'); the caller's existing boundary determines
        # IRIS EXPLAIN: rollback or the HTTP diagnostic.
        raise ValueError(f"{component} release blocked: validation/evidence gate failed; remain in shadow mode")
    # IRIS EXPLAIN: Store the computed value model_dir / 'release.json' in release_path; later lines use this named result.
    release_path = model_dir / "release.json"
    # IRIS EXPLAIN: Store the result of json.loads(release_path.read_text(encoding='utf-8')) (decode the existing JSON text)
    # IRIS EXPLAIN: when release_path.exists(); otherwise a mapping containing  in release; later lines use this named result.
    release = json.loads(release_path.read_text(encoding="utf-8")) if release_path.exists() else {}
    # IRIS EXPLAIN: Enter this branch only when component == 'model2' and 'model1' not in release.
    if component == "model2" and "model1" not in release:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Release Model 1 first; Model 2 depends
        # IRIS EXPLAIN: on its predictions'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Release Model 1 first; Model 2 depends on its predictions")
    # IRIS EXPLAIN: Store a mapping containing reviewer, reviewed_at_utc, scope, model_sha256, metadata_sha256 in
    # IRIS EXPLAIN: release[component]; later lines use this named result.
    release[component] = {"reviewer": reviewer.strip(), "reviewed_at_utc": utc_now(),
                          # IRIS EXPLAIN: Set/describe these existing record fields: model_sha256: content identity of the saved
                          # IRIS EXPLAIN: trusted model bundle.
                          "scope": "human-reviewed advisory only", "model_sha256": metadata["model_sha256"],
                          # IRIS EXPLAIN: Continue the current record with metadata_sha256; each value comes from the expression
                          # IRIS EXPLAIN: shown on this unchanged line.
                          "metadata_sha256": digest(model_dir / "metadata.json")}
    # IRIS EXPLAIN: Call write_json(release_path, release) using the existing explicit arguments.
    write_json(release_path, release)
    # IRIS EXPLAIN: Return release[component] to the caller; this ends the current function path.
    return release[component]


# IRIS EXPLAIN: Function linear_explanation: For linear classifiers, report signed base-logit feature contributions; for
# IRIS EXPLAIN: nonlinear models, explicitly avoid pretending observed inputs are causal attributions.
# IRIS EXPLAIN: Inputs: pipeline: the existing fitted preprocessing/classifier pipeline; X: the allowlisted predictor table;
# IRIS EXPLAIN: label: the existing scenario/control label or human-readable rehearsal name in this context.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def linear_explanation(pipeline, X: pd.DataFrame, label: str) -> dict:
    # IRIS EXPLAIN: Store pipeline.named_steps['classifier'] in estimator; later lines use this named result.
    estimator = pipeline.named_steps["classifier"]
    # IRIS EXPLAIN: Enter this branch only when not hasattr(estimator, 'coef_').
    if not hasattr(estimator, "coef_"):
        # IRIS EXPLAIN: Return a mapping containing kind, note to the caller; this ends the current function path.
        return {"kind": "observed_evidence_only", "note": "Nonlinear model; observed inputs are evidence, not a per-case attribution."}
    # IRIS EXPLAIN: Store list(estimator.classes_) in labels; later lines use this named result.
    labels = list(estimator.classes_)
    # IRIS EXPLAIN: Enter this branch only when label not in labels.
    if label not in labels:
        # IRIS EXPLAIN: Return a mapping containing kind to the caller; this ends the current function path.
        return {"kind": "not_available"}
    # IRIS EXPLAIN: Store estimator.coef_[labels.index(label)] in coefficients; later lines use this named result.
    coefficients = estimator.coef_[labels.index(label)]
    # IRIS EXPLAIN: Store pipeline.named_steps['features'] in transformer; later lines use this named result.
    transformer = pipeline.named_steps["features"]
    # IRIS EXPLAIN: Store np.asarray(transformer.transform(X))[0] in transformed; later lines use this named result.
    transformed = np.asarray(transformer.transform(X))[0]
    # IRIS EXPLAIN: Store the computed value transformed * coefficients in terms; later lines use this named result.
    terms = transformed * coefficients
    # IRIS EXPLAIN: Store the result of transformer.get_feature_names_out() (read fitted predictor names for traceable model
    # IRIS EXPLAIN: explanations) in names; later lines use this named result.
    names = transformer.get_feature_names_out()
    # IRIS EXPLAIN: Store np.argsort(np.abs(terms))[::-1][:6] in top; later lines use this named result.
    top = np.argsort(np.abs(terms))[::-1][:6]
    # IRIS EXPLAIN: Return a mapping containing kind, class, top_terms, note to the caller; this ends the current function path.
    return {"kind": "base_classifier_logit_contributions", "class": label,
            # IRIS EXPLAIN: Continue the current record with top_terms, feature, signed_contribution; each value comes from the
            # IRIS EXPLAIN: expression shown on this unchanged line.
            "top_terms": [{"feature": str(names[i]), "signed_contribution": float(terms[i])} for i in top],
            # IRIS EXPLAIN: Continue the current record with note; each value comes from the expression shown on this unchanged
            # IRIS EXPLAIN: line.
            "note": "Explains the uncalibrated base classifier score, not causation, the final calibrated probability, or control effectiveness."}


# IRIS EXPLAIN: Class ModelService: Shared trusted-artifact inference service with explicit schema/integrity/release gates and
# IRIS EXPLAIN: conservative fallback.
class ModelService:
    # IRIS EXPLAIN: Function ModelService.__init__: Load the catalogue and, only after version/schema/hash checks, the
    # IRIS EXPLAIN: operator-trusted joblib artifact; preserve safe fallback state when loading fails.
    # IRIS EXPLAIN: Inputs: model_dir: operator-trusted model bundle directory; catalog_path: the control catalogue CSV path.
    def __init__(self, model_dir: Path | None, catalog_path: Path):
        # IRIS EXPLAIN: Store the result of load_catalog(catalog_path) in self.catalog; later lines use this named result.
        self.catalog = load_catalog(catalog_path)
        # IRIS EXPLAIN: Store model_dir in self.model_dir; later lines use this named result.
        self.model_dir = model_dir
        # IRIS EXPLAIN: Store (None, None, None) in (self.bundle, self.metadata, self.load_error); later lines use this named
        # IRIS EXPLAIN: result.
        self.bundle, self.metadata, self.load_error = None, None, None
        # IRIS EXPLAIN: Store a mapping containing  in self.release; later lines use this named result.
        self.release = {}
        # IRIS EXPLAIN: Enter this branch only when model_dir is None.
        if model_dir is None:
            # IRIS EXPLAIN: Store 'No trained artifact configured' in self.load_error; later lines use this named result.
            self.load_error = "No trained artifact configured"
            # IRIS EXPLAIN: Exit this function now without an additional result; do not continue into the remaining branch.
            return
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of json.loads((model_dir / 'metadata.json').read_text(encoding='utf-8')) (decode
            # IRIS EXPLAIN: the existing JSON text) in metadata; later lines use this named result.
            metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
            # IRIS EXPLAIN: Enter this branch only when metadata['feature_schema'] != FEATURE_SCHEMA or metadata['features'] !=
            # IRIS EXPLAIN: FEATURES.
            if metadata["feature_schema"] != FEATURE_SCHEMA or metadata["features"] != FEATURES:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Model feature schema
                # IRIS EXPLAIN: mismatch'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Model feature schema mismatch")
            # IRIS EXPLAIN: Enter this branch only when metadata['scikit_learn_version'] != sklearn.__version__.
            if metadata["scikit_learn_version"] != sklearn.__version__:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('scikit-learn version mismatch;
                # IRIS EXPLAIN: use pinned dependencies or retrain'); the caller's existing boundary determines rollback or the
                # IRIS EXPLAIN: HTTP diagnostic.
                raise ValueError("scikit-learn version mismatch; use pinned dependencies or retrain")
            # IRIS EXPLAIN: Enter this branch only when digest(model_dir / 'models.joblib') != metadata['model_sha256'].
            if digest(model_dir / "models.joblib") != metadata["model_sha256"]:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Model checksum mismatch'); the
                # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Model checksum mismatch")
            # IRIS EXPLAIN: Enter this branch only when digest(catalog_path) != metadata['catalog_sha256'].
            if digest(catalog_path) != metadata["catalog_sha256"]:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Catalogue changed since
                # IRIS EXPLAIN: training'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Catalogue changed since training")
            # joblib can execute Python. Integrity checks do NOT establish authenticity.
            # Only use a locally trained artifact or a separately trusted distribution.
            # IRIS EXPLAIN: Store the result of joblib.load(model_dir / 'models.joblib') in bundle; later lines use this named
            # IRIS EXPLAIN: result.
            bundle = joblib.load(model_dir / "models.joblib")
            # IRIS EXPLAIN: Store (bundle, metadata) in (self.bundle, self.metadata); later lines use this named result.
            self.bundle, self.metadata = bundle, metadata
            # IRIS EXPLAIN: Store the computed value model_dir / 'release.json' in release_path; later lines use this named
            # IRIS EXPLAIN: result.
            release_path = model_dir / "release.json"
            # IRIS EXPLAIN: Enter this branch only when release_path.exists().
            if release_path.exists():
                # IRIS EXPLAIN: Store the result of json.loads(release_path.read_text(encoding='utf-8')) (decode the existing
                # IRIS EXPLAIN: JSON text) in self.release; later lines use this named result.
                self.release = json.loads(release_path.read_text(encoding="utf-8"))
        # IRIS EXPLAIN: Catch Exception as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except Exception as exc:  # Boundary: report load failures and retain safe fallback.
            # IRIS EXPLAIN: Store (None, None) in (self.bundle, self.metadata); later lines use this named result.
            self.bundle, self.metadata = None, None
            # IRIS EXPLAIN: Store the formatted text f'{type(exc).__name__}: {exc}' in self.load_error; later lines use this
            # IRIS EXPLAIN: named result.
            self.load_error = f"{type(exc).__name__}: {exc}"

    # IRIS EXPLAIN: Function ModelService.released: Verify that a component has matching, current, named approval and eligible
    # IRIS EXPLAIN: metadata; Model 2 additionally depends on Model 1 release.
    # IRIS EXPLAIN: Inputs: component: model1 or model2, with the existing dependent release gates.
    # IRIS EXPLAIN: Declared return type: bool; the return statements below show each actual result/fallback.
    def released(self, component: str) -> bool:
        # IRIS EXPLAIN: Enter this branch only when self.bundle is None or self.metadata is None or self.model_dir is None.
        if self.bundle is None or self.metadata is None or self.model_dir is None:
            # IRIS EXPLAIN: Return False to the caller; this ends the current function path.
            return False
        # IRIS EXPLAIN: Store the result of self.release.get(component, {}) (read an optional mapping field using its stated
        # IRIS EXPLAIN: fallback) in approval; later lines use this named result.
        approval = self.release.get(component, {})
        # IRIS EXPLAIN: Return bool(self.metadata[component].get('eligible_for_reviewed_advisory_release', False) and
        # IRIS EXPLAIN: approval.get('review... to the caller; this ends the current function path.
        return bool(
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: self.metadata[component].get("eligible_for_reviewed_advisory_release", False).
            self.metadata[component].get("eligible_for_reviewed_advisory_release", False)
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: and approval.get("reviewer").
            and approval.get("reviewer")
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: and approval.get("model_sha256") == self.metadata["model_sha256"].
            and approval.get("model_sha256") == self.metadata["model_sha256"]
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: and approval.get("metadata_sha256") == digest(self.model_dir / "metadata.json").
            and approval.get("metadata_sha256") == digest(self.model_dir / "metadata.json")
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: and (component == "model1" or self.released("model1")).
            and (component == "model1" or self.released("model1"))
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        )

    # IRIS EXPLAIN: Function ModelService._controls: Produce learned or catalogue-fallback control candidates, then apply
    # IRIS EXPLAIN: current-state and exception policy; membership scores are not efficacy or risk-reduction probabilities.
    # IRIS EXPLAIN: Inputs: label: the existing scenario/control label or human-readable rehearsal name in this context;
    # IRIS EXPLAIN: features: the strict allowlisted telemetry predictor mapping; context: existing pre-decision
    # IRIS EXPLAIN: business/control context; learned: the explicit learned input used by the unchanged statements below.
    # IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
    def _controls(self, label: str | None, features: dict, context: dict | None, *, learned=False) -> dict:
        # IRIS EXPLAIN: Enter this branch only when label is None.
        if label is None:
            # IRIS EXPLAIN: Return a mapping containing source, recommendations, reason to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return {"source": "not_run", "recommendations": [], "reason": "Scenario abstained"}
        # IRIS EXPLAIN: Enter this branch only when context is not None and (not isinstance(context, dict)).
        if context is not None and not isinstance(context, dict):
            # IRIS EXPLAIN: Return a mapping containing source, recommendations, reason to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return {"source": "not_run", "recommendations": [], "reason": "Invalid GRC context object"}
        # IRIS EXPLAIN: Store context or {} in policy_context; later lines use this named result.
        policy_context = context or {}
        # IRIS EXPLAIN: Enter this branch only when not isinstance(policy_context.get('controls', {}), dict) or not
        # IRIS EXPLAIN: isinstance(policy_context.get('active_exception_control_ids', []), list).
        if not isinstance(policy_context.get("controls", {}), dict) or not isinstance(policy_context.get("active_exception_control_ids", []), list):
            # IRIS EXPLAIN: Return a mapping containing source, recommendations, reason to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return {"source": "not_run", "recommendations": [], "reason": "Invalid control-state/exception schema"}
        # IRIS EXPLAIN: Enter this branch only when any((not isinstance(value, str) for value in policy_context.get('controls',
        # IRIS EXPLAIN: {}).values())).
        if any(not isinstance(value, str) for value in policy_context.get("controls", {}).values()):
            # IRIS EXPLAIN: Return a mapping containing source, recommendations, reason to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return {"source": "not_run", "recommendations": [], "reason": "Control states must be strings"}
        # IRIS EXPLAIN: Enter this branch only when any((not isinstance(value, str) for value in
        # IRIS EXPLAIN: policy_context.get('active_exception_control_ids', []))).
        if any(not isinstance(value, str) for value in policy_context.get("active_exception_control_ids", [])):
            # IRIS EXPLAIN: Return a mapping containing source, recommendations, reason to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return {"source": "not_run", "recommendations": [], "reason": "Exception control IDs must be strings"}
        # IRIS EXPLAIN: Store ('catalogue_fallback', []) in (source, ranked); later lines use this named result.
        source, ranked = "catalogue_fallback", []
        # IRIS EXPLAIN: Store [] in warnings; later lines use this named result.
        warnings = []
        # IRIS EXPLAIN: Enter this branch only when learned and self.bundle and self.bundle['control_model'].
        if learned and self.bundle and self.bundle["control_model"]:
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store the result of validate_context(context) in ctx; later lines use this named result.
                ctx = validate_context(context)
                # IRIS EXPLAIN: Store a mapping containing predicted_scenario in row; later lines use this named result.
                row = {**features, **ctx, "predicted_scenario": label}
                # IRIS EXPLAIN: Store the result of pd.DataFrame([row], columns=CONTROL_FEATURES) in X; later lines use this
                # IRIS EXPLAIN: named result.
                X = pd.DataFrame([row], columns=CONTROL_FEATURES)
                # IRIS EXPLAIN: Store self.bundle['control_model'] in control_model; later lines use this named result.
                control_model = self.bundle["control_model"]
                # IRIS EXPLAIN: Store the result of control_model['transformer'].transform(X) (apply already fitted
                # IRIS EXPLAIN: preprocessing without fitting on the new data) in Z; later lines use this named result.
                Z = control_model["transformer"].transform(X)
                # IRIS EXPLAIN: Iterate control_model['classifiers'].items(), binding each item to (cid, clf); process only the
                # IRIS EXPLAIN: existing observed/fixture collection.
                for cid, clf in control_model["classifiers"].items():
                    # IRIS EXPLAIN: Store float(clf.predict_proba(Z)[0, list(clf.classes_).index(1)]) in score; later lines use
                    # IRIS EXPLAIN: this named result.
                    score = float(clf.predict_proba(Z)[0, list(clf.classes_).index(1)])
                    # IRIS EXPLAIN: Enter this branch only when score >= control_model['thresholds'][cid].
                    if score >= control_model["thresholds"][cid]:
                        # IRIS EXPLAIN: Store the computed value np.asarray(Z)[0] * clf.coef_[0] in terms; later lines use this
                        # IRIS EXPLAIN: named result.
                        terms = np.asarray(Z)[0] * clf.coef_[0]
                        # IRIS EXPLAIN: Store the result of control_model['transformer'].get_feature_names_out() (read fitted
                        # IRIS EXPLAIN: predictor names for traceable model explanations) in names; later lines use this named
                        # IRIS EXPLAIN: result.
                        names = control_model["transformer"].get_feature_names_out()
                        # IRIS EXPLAIN: Store np.argsort(np.abs(terms))[::-1][:5] in top; later lines use this named result.
                        top = np.argsort(np.abs(terms))[::-1][:5]
                        # IRIS EXPLAIN: Call ranked.append({'control_id': cid, 'model_score': score, 'explanation_terms':
                        # IRIS EXPLAIN: [{'feature': str(names[i]), 'signed_logit_contribution': float(terms[i])} for i ...:
                        # IRIS EXPLAIN: append one item to the working list.
                        ranked.append({"control_id": cid, "model_score": score,
                                       # IRIS EXPLAIN: Continue the current record with explanation_terms, feature,
                                       # IRIS EXPLAIN: signed_logit_contribution; each value comes from the expression shown on
                                       # IRIS EXPLAIN: this unchanged line.
                                       "explanation_terms": [{"feature": str(names[i]), "signed_logit_contribution": float(terms[i])} for i in top]})
                # IRIS EXPLAIN: Store 'learned_control_model' in source; later lines use this named result.
                source = "learned_control_model"
                # IRIS EXPLAIN: Call warnings.append('Membership scores are not calibrated efficacy probabilities or predicted
                # IRIS EXPLAIN: risk reduction'): append one item to the working list.
                warnings.append("Membership scores are not calibrated efficacy probabilities or predicted risk reduction")
            # IRIS EXPLAIN: Catch Exception as exc; execute the existing error/fallback path rather than silently treating it as
            # IRIS EXPLAIN: success.
            except Exception as exc:  # Boundary: failed model is never an approval.
                # IRIS EXPLAIN: Call warnings.append(f'Model 2 not usable: {exc}; catalogue fallback used'): append one item to
                # IRIS EXPLAIN: the working list.
                warnings.append(f"Model 2 not usable: {exc}; catalogue fallback used")
        # IRIS EXPLAIN: Enter this branch only when not ranked.
        if not ranked:
            # IRIS EXPLAIN: Enter this branch only when source == 'learned_control_model'.
            if source == "learned_control_model":
                # IRIS EXPLAIN: Call warnings.append('No learned label exceeded its threshold; conservative catalogue fallback
                # IRIS EXPLAIN: used'): append one item to the working list.
                warnings.append("No learned label exceeded its threshold; conservative catalogue fallback used")
            # IRIS EXPLAIN: Store 'catalogue_fallback' in source; later lines use this named result.
            source = "catalogue_fallback"
            # IRIS EXPLAIN: Store the comprehension [{'control_id': c, 'model_score': None} for c in
            # IRIS EXPLAIN: FALLBACK_CONTROLS.get(label, [])] in ranked; later lines use this named result.
            ranked = [{"control_id": c, "model_score": None} for c in FALLBACK_CONTROLS.get(label, [])]
        # IRIS EXPLAIN: Store context or {} in context; later lines use this named result.
        context = context or {}
        # IRIS EXPLAIN: Store the result of context.get('controls', {}) (read an optional mapping field using its stated
        # IRIS EXPLAIN: fallback) in states; later lines use this named result.
        states = context.get("controls", {})
        # IRIS EXPLAIN: Store set(context.get('active_exception_control_ids', [])) in exceptions; later lines use this named
        # IRIS EXPLAIN: result.
        exceptions = set(context.get("active_exception_control_ids", []))
        # IRIS EXPLAIN: Store [] in recommendations; later lines use this named result.
        recommendations = []
        # IRIS EXPLAIN: Iterate sorted(ranked, key=lambda c: (-(c['model_score'] or 0), c['control_id'])), binding each item to
        # IRIS EXPLAIN: item; process only the existing observed/fixture collection.
        for item in sorted(ranked, key=lambda c: (-(c["model_score"] or 0), c["control_id"])):
            # IRIS EXPLAIN: Store item['control_id'] in cid; later lines use this named result.
            cid = item["control_id"]
            # IRIS EXPLAIN: Enter this branch only when cid not in self.catalog.
            if cid not in self.catalog:
                # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted
                # IRIS EXPLAIN: result for this skipped input.
                continue
            # IRIS EXPLAIN: Store the result of states.get(cid, 'unknown') (read an optional mapping field using its stated
            # IRIS EXPLAIN: fallback) in current; later lines use this named result.
            current = states.get(cid, "unknown")
            # IRIS EXPLAIN: Store the result of {'missing': 'install', 'partial': 'extend', 'implemented':
            # IRIS EXPLAIN: 'verify'}.get(current, 'review') (read an optional mapping field using its stated fallback) in
            # IRIS EXPLAIN: action; later lines use this named result.
            action = {"missing": "install", "partial": "extend", "implemented": "verify"}.get(current, "review")
            # IRIS EXPLAIN: Store [] in warning; later lines use this named result.
            warning = []
            # IRIS EXPLAIN: Enter this branch only when cid in exceptions.
            if cid in exceptions:
                # IRIS EXPLAIN: Store 'review' in action; later lines use this named result.
                action = "review"
                # IRIS EXPLAIN: Call warning.append('Active policy exception; review authorization/compensating controls
                # IRIS EXPLAIN: first'): append one item to the working list.
                warning.append("Active policy exception; review authorization/compensating controls first")
            # IRIS EXPLAIN: Enter this branch only when current == 'implemented'.
            if current == "implemented":
                # IRIS EXPLAIN: Call warning.append('Verify effectiveness and coverage; do not reinstall blindly'): append one
                # IRIS EXPLAIN: item to the working list.
                warning.append("Verify effectiveness and coverage; do not reinstall blindly")
            # IRIS EXPLAIN: Enter this branch only when current == 'unknown'.
            if current == "unknown":
                # IRIS EXPLAIN: Call warning.append('No asset-specific control-state record; analyst review required'): append
                # IRIS EXPLAIN: one item to the working list.
                warning.append("No asset-specific control-state record; analyst review required")
            # IRIS EXPLAIN: Call recommendations.append({**item, 'name': self.catalog[cid]['Control_Name'], 'catalogue_action':
            # IRIS EXPLAIN: self.catalog[cid]['Recommended_Action'], 'current_state': curr...: append one item to the working
            # IRIS EXPLAIN: list.
            recommendations.append({**item, "name": self.catalog[cid]["Control_Name"],
                                    # IRIS EXPLAIN: Continue the current record with catalogue_action; each value comes from the
                                    # IRIS EXPLAIN: expression shown on this unchanged line.
                                    "catalogue_action": self.catalog[cid]["Recommended_Action"],
                                    # IRIS EXPLAIN: Continue the current record with current_state, action_type; each value
                                    # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                    "current_state": current, "action_type": action,
                                    # IRIS EXPLAIN: Set/describe these existing record fields: requires_human_approval: control
                                    # IRIS EXPLAIN: advice cannot authorize its own execution.
                                    "requires_human_approval": True, "warnings": warning})
        # IRIS EXPLAIN: Return a mapping containing source, recommendations, warnings to the caller; this ends the current
        # IRIS EXPLAIN: function path.
        return {"source": source, "recommendations": recommendations, "warnings": warnings}

    # IRIS EXPLAIN: Function ModelService.predict: Validate a session, fail closed on unhealthy sensors, compute primary rules
    # IRIS EXPLAIN: and separate ML candidates, and use advisory outputs only when explicit release gates permit.
    # IRIS EXPLAIN: Inputs: session: observed session features plus time-valid asset/risk context; mode: the existing
    # IRIS EXPLAIN: rules/shadow/advisory choice, still governed by release checks.
    # IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
    def predict(self, session: dict, *, mode="shadow") -> dict:
        # IRIS EXPLAIN: Enter this branch only when mode not in {'shadow', 'advisory', 'rules'}.
        if mode not in {"shadow", "advisory", "rules"}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('mode must be shadow, advisory or
            # IRIS EXPLAIN: rules'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("mode must be shadow, advisory or rules")
        # IRIS EXPLAIN: Store the result of validate_features(session['features']) in features; later lines use this named
        # IRIS EXPLAIN: result.
        features = validate_features(session["features"])
        # IRIS EXPLAIN: Store the comparison session.get('sensor_healthy') is True in healthy; later lines use this named
        # IRIS EXPLAIN: result.
        healthy = session.get("sensor_healthy") is True
        # IRIS EXPLAIN: Store [] in warnings; later lines use this named result.
        warnings = []
        # IRIS EXPLAIN: Store a mapping containing scenario_class, confidence, status, method in primary; later lines use this
        # IRIS EXPLAIN: named result.
        primary = {"scenario_class": None, "confidence": None, "status": "ABSTAINED", "method": "no_usable_evidence"}
        # IRIS EXPLAIN: Store None (no result/value) in shadow; later lines use this named result.
        shadow = None
        # IRIS EXPLAIN: Enter this branch only when not healthy.
        if not healthy:
            # IRIS EXPLAIN: Call warnings.append('Explicit healthy-sensor evidence missing; no attack/benign assessment is
            # IRIS EXPLAIN: issued'): append one item to the working list.
            warnings.append("Explicit healthy-sensor evidence missing; no attack/benign assessment is issued")
        # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
        else:
            # IRIS EXPLAIN: Store the result of rule_label(features) in baseline; later lines use this named result.
            baseline = rule_label(features)
            # IRIS EXPLAIN: Store a mapping containing scenario_class, confidence, status, method in primary; later lines use
            # IRIS EXPLAIN: this named result.
            primary = {"scenario_class": baseline, "confidence": None,
                       # IRIS EXPLAIN: Set/describe these existing record fields: status: the stated assessment/proposal/run
                       # IRIS EXPLAIN: state; an abstention must not be relabeled benign.
                       "status": "ASSESSED" if baseline else "ABSTAINED", "method": "rule_baseline"}
            # IRIS EXPLAIN: Enter this branch only when mode != 'rules' and self.bundle.
            if mode != "rules" and self.bundle:
                # IRIS EXPLAIN: Store self.metadata['model1']['categorical_vocab'] in vocab; later lines use this named result.
                vocab = self.metadata["model1"]["categorical_vocab"]
                # IRIS EXPLAIN: Store the comprehension [key for key in CATEGORICAL if features[key] not in vocab[key]] in
                # IRIS EXPLAIN: unfamiliar; later lines use this named result.
                unfamiliar = [key for key in CATEGORICAL if features[key] not in vocab[key]]
                # IRIS EXPLAIN: Enter this branch only when session.get('aggregation_schema') !=
                # IRIS EXPLAIN: self.metadata.get('aggregation_schema').
                if session.get("aggregation_schema") != self.metadata.get("aggregation_schema"):
                    # IRIS EXPLAIN: Call warnings.append('Normalization/sessionization contract differs from training; ML
                    # IRIS EXPLAIN: disabled. Export training rows through the same runtime adapter.'): append one item to the
                    # IRIS EXPLAIN: working list.
                    warnings.append("Normalization/sessionization contract differs from training; ML disabled. Export training rows through the same runtime adapter.")
                # IRIS EXPLAIN: Check this alternative branch when unfamiliar.
                elif unfamiliar:
                    # IRIS EXPLAIN: Call warnings.append(f'Unseen categories {unfamiliar}; ML abstains. This is not a complete
                    # IRIS EXPLAIN: unknown-attack detector.'): append one item to the working list.
                    warnings.append(f"Unseen categories {unfamiliar}; ML abstains. This is not a complete unknown-attack detector.")
                # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
                else:
                    # IRIS EXPLAIN: Store the result of frame([features]) in X; later lines use this named result.
                    X = frame([features])
                    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing
                    # IRIS EXPLAIN: except/finally blocks decide fallback and cleanup.
                    try:
                        # IRIS EXPLAIN: Store self.bundle['scenario_model'] in model; later lines use this named result.
                        model = self.bundle["scenario_model"]
                        # IRIS EXPLAIN: Store model.predict_proba(X)[0] in probs; later lines use this named result.
                        probs = model.predict_proba(X)[0]
                        # IRIS EXPLAIN: Store int(probs.argmax()) in i; later lines use this named result.
                        i = int(probs.argmax())
                        # IRIS EXPLAIN: Store (str(model.classes_[i]), float(probs[i])) in (label, score); later lines use this
                        # IRIS EXPLAIN: named result.
                        label, score = str(model.classes_[i]), float(probs[i])
                        # IRIS EXPLAIN: Store self.metadata['model1']['threshold'] in threshold; later lines use this named
                        # IRIS EXPLAIN: result.
                        threshold = self.metadata["model1"]["threshold"]
                        # IRIS EXPLAIN: Store label when score >= threshold; otherwise None (no result/value) in label_or_none;
                        # IRIS EXPLAIN: later lines use this named result.
                        label_or_none = label if score >= threshold else None
                        # IRIS EXPLAIN: Store a mapping containing scenario_class, top_candidate, confidence, status, method,
                        # IRIS EXPLAIN: threshold, class_probabilities and additional fields in shadow; later lines use this
                        # IRIS EXPLAIN: named result.
                        shadow = {"scenario_class": label_or_none, "top_candidate": label, "confidence": score,
                                  # IRIS EXPLAIN: Set/describe these existing record fields: status: the stated
                                  # IRIS EXPLAIN: assessment/proposal/run state; an abstention must not be relabeled benign.
                                  "status": "ASSESSED" if label_or_none else "ABSTAINED",
                                  # IRIS EXPLAIN: Continue the current record with method, threshold; each value comes from the
                                  # IRIS EXPLAIN: expression shown on this unchanged line.
                                  "method": "calibrated_model1", "threshold": threshold,
                                  # IRIS EXPLAIN: Continue the current record with class_probabilities; each value comes from
                                  # IRIS EXPLAIN: the expression shown on this unchanged line.
                                  "class_probabilities": {str(c): float(p) for c, p in zip(model.classes_, probs)},
                                  # IRIS EXPLAIN: Continue the current record with explanation; each value comes from the
                                  # IRIS EXPLAIN: expression shown on this unchanged line.
                                  "explanation": linear_explanation(self.bundle["scenario_base_pipeline"], X, label),
                                  # IRIS EXPLAIN: Set/describe these existing record fields: controls: control implementation
                                  # IRIS EXPLAIN: context or separately identified recommendations; labels remain offline-only
                                  # IRIS EXPLAIN: targets.
                                  "controls": self._controls(label_or_none, features, session.get("context"), learned=True)}
                        # IRIS EXPLAIN: Enter this branch only when mode == 'advisory' and self.released('model1').
                        if mode == "advisory" and self.released("model1"):
                            # IRIS EXPLAIN: Store the comprehension {k: v for k, v in shadow.items() if k != 'controls'} in
                            # IRIS EXPLAIN: primary; later lines use this named result.
                            primary = {k: v for k, v in shadow.items() if k != "controls"}
                        # IRIS EXPLAIN: Iterate NUMERIC, binding each item to key; process only the existing observed/fixture
                        # IRIS EXPLAIN: collection.
                        for key in NUMERIC:
                            # IRIS EXPLAIN: Store self.metadata['model1']['numeric_train_ranges'][key] in (low, high); later
                            # IRIS EXPLAIN: lines use this named result.
                            low, high = self.metadata["model1"]["numeric_train_ranges"][key]
                            # IRIS EXPLAIN: Enter this branch only when not low <= features[key] <= high.
                            if not low <= features[key] <= high:
                                # IRIS EXPLAIN: Call warnings.append(f'{key} outside fitted range [{low}, {high}]; review
                                # IRIS EXPLAIN: extrapolation'): append one item to the working list.
                                warnings.append(f"{key} outside fitted range [{low}, {high}]; review extrapolation")
                    # IRIS EXPLAIN: Catch Exception as exc; execute the existing error/fallback path rather than silently
                    # IRIS EXPLAIN: treating it as success.
                    except Exception as exc:  # Boundary: retain rules/abstention and expose warning.
                        # IRIS EXPLAIN: Call warnings.append(f'Model inference failed; rule baseline retained: {exc}'): append
                        # IRIS EXPLAIN: one item to the working list.
                        warnings.append(f"Model inference failed; rule baseline retained: {exc}")
            # IRIS EXPLAIN: Enter this branch only when mode == 'advisory' and (not self.released('model1')).
            if mode == "advisory" and not self.released("model1"):
                # IRIS EXPLAIN: Call warnings.append('Model 1 not released: primary output remains rules/abstention; candidate
                # IRIS EXPLAIN: is shadow-only'): append one item to the working list.
                warnings.append("Model 1 not released: primary output remains rules/abstention; candidate is shadow-only")
        # IRIS EXPLAIN: Enter this branch only when self.load_error.
        if self.load_error:
            # IRIS EXPLAIN: Call warnings.append(f'ML unavailable: {self.load_error}'): append one item to the working list.
            warnings.append(f"ML unavailable: {self.load_error}")
        # IRIS EXPLAIN: Store mode == 'advisory' and primary['method'] == 'calibrated_model1' and self.released('model2') in
        # IRIS EXPLAIN: learned_controls; later lines use this named result.
        learned_controls = mode == "advisory" and primary["method"] == "calibrated_model1" and self.released("model2")
        # IRIS EXPLAIN: Store the result of self._controls(primary['scenario_class'], features, session.get('context'),
        # IRIS EXPLAIN: learned=learned_controls) in controls; later lines use this named result.
        controls = self._controls(primary["scenario_class"], features, session.get("context"), learned=learned_controls)
        # IRIS EXPLAIN: Return a mapping containing session_id, generated_at_utc, mode, soc_assessment, grc_control_review,
        # IRIS EXPLAIN: shadow_candidate, evidence_features and additional fields to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return {
            # IRIS EXPLAIN: Set/describe these existing record fields: session_id: deterministic observed session identity
            # IRIS EXPLAIN: linking evidence to separate reviews/cases.
            "session_id": session.get("session_id"), "generated_at_utc": utc_now(), "mode": mode,
            # IRIS EXPLAIN: Set/describe these existing record fields: soc_assessment: primary assessment selected by the
            # IRIS EXPLAIN: existing rule/release policy; grc_control_review: advisory control candidates and
            # IRIS EXPLAIN: current-state/exception policy result; shadow_candidate: separate experimental ML result; it is not
            # IRIS EXPLAIN: automatically the primary policy assessment.
            "soc_assessment": primary, "grc_control_review": controls, "shadow_candidate": shadow,
            # IRIS EXPLAIN: Set/describe these existing record fields: evidence_refs: source-file/line references retained for
            # IRIS EXPLAIN: traceability.
            "evidence_features": features, "evidence_refs": session.get("evidence_refs", []),
            # IRIS EXPLAIN: Set/describe these existing record fields: requires_human_review: explicit requirement for a human
            # IRIS EXPLAIN: to review advisory evidence.
            "warnings": warnings, "requires_human_review": True,
            # IRIS EXPLAIN: Set/describe these existing record fields: automatic_execution: safety flag separating
            # IRIS EXPLAIN: recommendations from automatic control execution; official_risk_register_write: safety flag: model
            # IRIS EXPLAIN: inference does not change an official company register.
            "automatic_execution": False, "official_risk_register_write": False,
            # IRIS EXPLAIN: Continue the current record with risk_scoring; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "risk_scoring": "Delegate to the explicit versioned IRIS risk policy; ML does not set official likelihood/impact",
            # IRIS EXPLAIN: Continue the current record with model1_released, model2_released; each value comes from the
            # IRIS EXPLAIN: expression shown on this unchanged line.
            "model1_released": self.released("model1"), "model2_released": self.released("model2"),
            # IRIS EXPLAIN: Set/describe these existing record fields: model_sha256: content identity of the saved trusted model
            # IRIS EXPLAIN: bundle.
            "model_sha256": self.metadata["model_sha256"] if self.metadata else None,
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }
