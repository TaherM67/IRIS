"""Reproducible two-model training, honest holdout metrics and release gates."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, hamming_loss,
    precision_recall_fscore_support, precision_score, recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

from . import __version__
from .contracts import (
    CATEGORICAL, CLASSES, CONTEXT_CATEGORICAL, CONTEXT_NUMERIC, CONTROL_FEATURES,
    FEATURES, FEATURE_SCHEMA, NUMERIC, digest, rule_label, utc_now, write_json,
)
from .dataset import load_dataset, split_groups


def preprocessing(categorical=CATEGORICAL, numeric=NUMERIC) -> ColumnTransformer:
    return ColumnTransformer([
        ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(categorical)),
        ("numeric", StandardScaler(), list(numeric)),
    ], remainder="drop", verbose_feature_names_out=True)


def candidates(seed: int) -> dict[str, Pipeline]:
    estimators = {
        "logistic_regression": LogisticRegression(C=1, max_iter=2500, class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(n_estimators=160, max_depth=12, min_samples_leaf=3,
                                                class_weight="balanced_subsample", n_jobs=2, random_state=seed),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15,
                                                               l2_regularization=1, random_state=seed),
    }
    return {name: Pipeline([("features", preprocessing()), ("classifier", estimator)])
            for name, estimator in estimators.items()}


def wilson_interval(successes: int, trials: int) -> list[float] | None:
    if not trials:
        return None
    z = 1.96
    p = successes / trials
    denominator = 1 + z*z/trials
    center = (p + z*z/(2*trials)) / denominator
    radius = z * np.sqrt(p*(1-p)/trials + z*z/(4*trials*trials)) / denominator
    return [max(0.0, float(center-radius)), min(1.0, float(center+radius))]


def scenario_metrics(y, predictions) -> dict:
    y, predictions = np.asarray(y, dtype=str), np.asarray(predictions, dtype=str)
    accepted = predictions != "ABSTAINED"
    precision, recall, f1, support = precision_recall_fscore_support(y, predictions, labels=list(CLASSES), zero_division=0)
    benign = y == "benign"
    false_alarms = int(((predictions != "benign") & accepted & benign).sum())
    benign_n = int(benign.sum())
    return {
        "n": len(y), "coverage": float(accepted.mean()),
        "macro_f1": float(f1_score(y, predictions, labels=list(CLASSES), average="macro", zero_division=0)),
        "accuracy_all_sessions": float(accuracy_score(y, predictions)),
        "accepted_accuracy": float(accuracy_score(y[accepted], predictions[accepted])) if accepted.any() else None,
        "benign_false_positive_rate": false_alarms / benign_n if benign_n else None,
        "benign_false_alarms": false_alarms, "benign_support": benign_n,
        "benign_fpr_wilson_95_percent": wilson_interval(false_alarms, benign_n),
        "per_class": {label: {"precision": float(precision[i]), "recall": float(recall[i]),
                              "f1": float(f1[i]), "support": int(support[i])}
                      for i, label in enumerate(CLASSES)},
        "confusion_labels": [*CLASSES, "ABSTAINED"],
        "confusion_matrix": confusion_matrix(y, predictions, labels=[*CLASSES, "ABSTAINED"]).tolist(),
        "metric_semantics": "Abstentions count as missed true classes (false negatives), never dropped from recall/F1. FPR excludes abstentions and must be read together with coverage.",
    }


def scenario_predictions(model, X, threshold: float) -> np.ndarray:
    probabilities = model.predict_proba(X)
    return np.where(probabilities.max(axis=1) >= threshold,
                    np.asarray(model.classes_)[probabilities.argmax(axis=1)], "ABSTAINED")


def operational_checks(metrics: dict) -> dict:
    return {
        "macro_f1_at_least_0_80": metrics["macro_f1"] >= .80,
        "attack_recall_at_least_0_75": all(metrics["per_class"][c]["recall"] >= .75 for c in CLASSES if c != "benign"),
        "benign_fpr_at_most_0_05": metrics["benign_false_positive_rate"] is not None and metrics["benign_false_positive_rate"] <= .05,
        "coverage_at_least_0_80": metrics["coverage"] >= .80,
    }


def choose_threshold(model, X, y) -> tuple[float, list[dict]]:
    grid = []
    for value in np.arange(.40, .951, .025):
        metrics = scenario_metrics(y, scenario_predictions(model, X, float(value)))
        grid.append({"threshold": round(float(value), 3), "metrics": metrics,
                     "meets_operational_checks": all(operational_checks(metrics).values())})
    best = max(grid, key=lambda r: (r["meets_operational_checks"], r["metrics"]["macro_f1"], r["metrics"]["coverage"], r["threshold"]))
    return best["threshold"], grid


def load_catalog(path: Path) -> dict:
    rows = pd.read_csv(path, keep_default_na=False)
    required = {"Control_ID", "Control_Name", "Recommended_Action"}
    if not required.issubset(rows.columns) or rows.empty or rows.Control_ID.duplicated().any():
        raise ValueError("Control catalogue requires unique Control_ID, Control_Name, Recommended_Action")
    if any(not str(value).strip() for value in rows.Control_ID):
        raise ValueError("Empty catalogue control ID")
    return rows.set_index("Control_ID").to_dict("index")


def control_frame(data: pd.DataFrame, scenario_values) -> pd.DataFrame:
    result = data[FEATURES + ["asset_type"] + CONTEXT_NUMERIC].copy()
    result["predicted_scenario"] = np.asarray(scenario_values, dtype=str)
    return result[CONTROL_FEATURES]


def control_metrics(y: np.ndarray, predicted: np.ndarray, labels: list[str]) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(y, predicted, average=None, zero_division=0)
    return {
        "n": len(y), "micro_precision": float(precision_score(y, predicted, average="micro", zero_division=0)),
        "micro_recall": float(recall_score(y, predicted, average="micro", zero_division=0)),
        "micro_f1": float(f1_score(y, predicted, average="micro", zero_division=0)),
        "macro_f1_all_catalogue_controls": float(f1_score(y, predicted, average="macro", zero_division=0)),
        "hamming_loss": float(hamming_loss(y, predicted)),
        "exact_set_accuracy": float(np.mean(np.all(y == predicted, axis=1))),
        "per_control": {cid: {"precision": float(precision[i]), "recall": float(recall[i]),
                              "f1": float(f1[i]), "test_positive_support": int(support[i])}
                        for i, cid in enumerate(labels)},
    }


def fit_controls(data, split, selected_pipeline, calibrated, scenario_threshold, catalog, seed) -> tuple[dict | None, dict]:
    """Train on cross-fitted scenario inputs; no oracle scenario labels to Model 2."""
    fit_ix = np.concatenate([split["train"], split["selection"]])
    pool = data.iloc[fit_ix].reset_index(drop=True)
    groups = pool.campaign_id + "/" + pool.run_id
    oof = np.full(len(pool), "ABSTAINED", dtype=object)
    # Match the experiment's outer independence unit, not random rows.
    group_key = data.attrs.get("group_by", "campaign_id")
    if group_key != "run_id":
        groups = pool[group_key].astype(str)
    n_splits = min(3, groups.nunique())
    if n_splits < 2:
        return None, {"status": "not_trained", "reason": "Insufficient independent groups for Model 2 scenario cross-fitting"}
    for tr, va in StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed).split(pool, pool.scenario_class, groups):
        if set(pool.iloc[tr].scenario_class) != set(CLASSES):
            return None, {"status": "not_trained", "reason": "Cross-fit fold lacks a supported scenario class"}
        candidate = clone(selected_pipeline).fit(pool.iloc[tr][FEATURES], pool.iloc[tr].scenario_class)
        probs = candidate.predict_proba(pool.iloc[va][FEATURES])
        oof[va] = np.where(probs.max(axis=1) >= scenario_threshold,
                           np.asarray(candidate.classes_)[probs.argmax(axis=1)], "ABSTAINED")
    Xfit = control_frame(pool, oof)
    reviewed_fit = pool.controls_reviewed.to_numpy(dtype=bool)
    validation = data.iloc[split["threshold"]]
    test = data.iloc[split["test"]]
    if not reviewed_fit.any() or not validation.controls_reviewed.any() or not test.controls_reviewed.any():
        return None, {"status": "not_trained", "reason": "Need separately reviewed control targets in fit, threshold and test splits. Attack labels do not create control labels."}
    labels = sorted(catalog)
    def targets(part):
        unknown = set(c for values in part.controls for c in values) - set(labels)
        if unknown:
            raise ValueError(f"Reviewed controls are absent from catalogue: {sorted(unknown)}")
        return np.asarray([[int(cid in controls) for cid in labels] for controls in part.controls], dtype=np.int8)
    yfit, yval, ytest = targets(pool), targets(validation), targets(test)
    Xval = control_frame(validation, scenario_predictions(calibrated, validation[FEATURES], scenario_threshold))
    Xtest = control_frame(test, scenario_predictions(calibrated, test[FEATURES], scenario_threshold))
    keep_val = validation.controls_reviewed.to_numpy(dtype=bool)
    keep_test = test.controls_reviewed.to_numpy(dtype=bool)
    transformer = preprocessing(CATEGORICAL + CONTEXT_CATEGORICAL, NUMERIC + CONTEXT_NUMERIC)
    Zfit = transformer.fit_transform(Xfit[reviewed_fit])
    Zval, Ztest = transformer.transform(Xval[keep_val]), transformer.transform(Xtest[keep_test])
    bank, thresholds, support, unsupported = {}, {}, {}, []
    scores_test = np.zeros((int(keep_test.sum()), len(labels)))
    learned = np.zeros_like(scores_test, dtype=np.int8)
    for j, cid in enumerate(labels):
        target = yfit[reviewed_fit, j]
        positive, negative = int(target.sum()), int((1-target).sum())
        support[cid] = {"train_positive": positive, "train_negative": negative,
                        "threshold_positive": int(yval[keep_val, j].sum()),
                        "test_positive": int(ytest[keep_test, j].sum())}
        if min(positive, negative) < 5:
            unsupported.append(cid)
            continue
        clf = LogisticRegression(C=1, max_iter=2500, random_state=seed).fit(Zfit, target)
        val_score = clf.predict_proba(Zval)[:, list(clf.classes_).index(1)]
        options = []
        for t in np.arange(.20, .951, .05):
            p = val_score >= t
            if p.any() and precision_score(yval[keep_val, j], p, zero_division=0) >= .8:
                options.append((f1_score(yval[keep_val, j], p, zero_division=0), float(t)))
        # If validation cannot support useful precision, suppress the learned label.
        threshold = max(options)[1] if options else 1.000001
        bank[cid], thresholds[cid] = clf, threshold
        scores_test[:, j] = clf.predict_proba(Ztest)[:, list(clf.classes_).index(1)]
        learned[:, j] = scores_test[:, j] >= threshold
    if not bank:
        return None, {"status": "not_trained", "reason": "No control has at least 5 reviewed positive and 5 negative fit examples", "support": support}
    metrics = control_metrics(ytest[keep_test], learned, labels)
    # Training-only scenario-frequency baseline: does context add predictive value?
    fit_scenarios = np.asarray(oof)[reviewed_fit]
    lookup = {scenario: yfit[reviewed_fit][fit_scenarios == scenario].mean(axis=0)
              for scenario in sorted(set(fit_scenarios))}
    baseline_scores = np.asarray([lookup.get(scenario, np.zeros(len(labels)))
                                  for scenario in Xtest.loc[keep_test, "predicted_scenario"]])
    baseline_metrics = control_metrics(ytest[keep_test], (baseline_scores >= .5).astype(np.int8), labels)
    active = [cid for cid in bank if thresholds[cid] <= 1]
    checks = {
        "at_least_one_supported_control": bool(active),
        "micro_precision_at_least_0_80": metrics["micro_precision"] >= .8,
        "micro_f1_at_least_0_80": metrics["micro_f1"] >= .8,
        "not_worse_than_scenario_frequency_baseline": metrics["micro_f1"] >= baseline_metrics["micro_f1"],
        "reviewed_training_support": bool(active) and all(support[c]["train_positive"] >= 20 and support[c]["train_negative"] >= 20 for c in active),
        "heldout_positive_support": bool(active) and all(support[c]["test_positive"] >= 5 for c in active),
    }
    model = {"transformer": transformer, "classifiers": bank, "thresholds": thresholds, "labels": labels}
    report = {"status": "trained_shadow", "algorithm": "binary_relevance_logistic_regression",
              "scenario_inputs": "grouped out-of-fold predictions for fitting; frozen Model 1 predictions for threshold/test, never oracle classes",
              "score_meaning": "Uncalibrated membership score, not probability of efficacy or causal risk reduction",
              "support": support, "unsupported_controls": unsupported,
              "validation_suppressed_controls": [cid for cid, t in thresholds.items() if t > 1],
              "metrics": metrics, "checks": checks,
              "scenario_frequency_baseline": baseline_metrics,
              "proposed_control_gate_passed": all(checks.values()),
              "note": "Control gate is a proposed engineering minimum requiring project-owner agreement, not an established compliance standard."}
    return model, report


def train(sessions: Path, reviews: Path, catalog_path: Path, out: Path, *, synthetic=False, group_by="campaign_id", seed=42) -> dict:
    if (out / "metadata.json").exists() or (out / "models.joblib").exists():
        raise ValueError("Output already contains an experiment. Choose a new directory; do not overwrite a held-out experiment.")
    data, quality = load_dataset(sessions, reviews, synthetic=synthetic)
    split, split_manifest = split_groups(data, group_by, seed)
    data.attrs["group_by"] = group_by
    catalog = load_catalog(catalog_path)
    tr, selection = data.iloc[split["train"]], data.iloc[split["selection"]]
    pipelines, scores = candidates(seed), {}
    with threadpool_limits(limits=2):
        for name, pipeline in pipelines.items():
            pipeline.fit(tr[FEATURES], tr.scenario_class)
            scores[name] = scenario_metrics(selection.scenario_class, pipeline.predict(selection[FEATURES]))["macro_f1"]
        best = max(scores.values())
        chosen = next(name for name in pipelines if scores[name] >= best-.01)
        pool = data.iloc[np.concatenate([split["train"], split["selection"]])]
        selected = clone(pipelines[chosen]).fit(pool[FEATURES], pool.scenario_class)
        cal = data.iloc[split["calibration"]]
        # The base pipeline is already fitted ONLY on fit+selection data.
        # FrozenEstimator.fit is a no-op. Score every separate calibration row
        # once, without imposing the library's default five-fold minimum.
        # These nominal overlapping CV indices do not refit the frozen base;
        # only the sigmoid calibrator learns from calibration labels.
        calibration_ix = np.arange(len(cal))
        calibrated = CalibratedClassifierCV(
            FrozenEstimator(selected), method="sigmoid", ensemble=False,
            cv=[(calibration_ix, calibration_ix)],
        ).fit(cal[FEATURES], cal.scenario_class)
        val = data.iloc[split["threshold"]]
        threshold, grid = choose_threshold(calibrated, val[FEATURES], val.scenario_class)
        test = data.iloc[split["test"]]
        metrics = scenario_metrics(test.scenario_class, scenario_predictions(calibrated, test[FEATURES], threshold))
        baseline = scenario_metrics(test.scenario_class, [rule_label(row) or "ABSTAINED" for row in test[FEATURES].to_dict("records")])
        checks = {
            **operational_checks(metrics),
            "improvement_over_frozen_rules_at_least_0_05": metrics["macro_f1"] - baseline["macro_f1"] >= .05 - 1e-12,
            "minimum_10_test_sessions_per_class": all(metrics["per_class"][c]["support"] >= 10 for c in CLASSES),
            "real_reviewed_cyber_range_data": not synthetic,
            "campaign_or_template_holdout": group_by in {"campaign_id", "template_group"},
        }
        model2, report2 = fit_controls(data, split, selected, calibrated, threshold, catalog, seed)
    metadata = {
        "package_version": __version__, "trained_at_utc": utc_now(), "feature_schema": FEATURE_SCHEMA,
        "aggregation_schema": quality["aggregation_schema"],
        "scikit_learn_version": sklearn.__version__, "features": FEATURES,
        "data_quality": quality, "split": split_manifest, "catalog_sha256": digest(catalog_path),
        "model1": {"algorithm": chosen, "selection_scores": scores, "threshold": threshold,
                   "calibration_strategy": "Frozen base; every disjoint calibration row scored once; no base refit",
                   "classes": list(CLASSES), "metrics": metrics, "rule_baseline": baseline,
                   "checks": checks, "eligible_for_reviewed_advisory_release": all(checks.values()),
                   "categorical_vocab": {c: sorted(pool[c].unique().tolist()) for c in CATEGORICAL},
                   "numeric_train_ranges": {c: [float(pool[c].min()), float(pool[c].max())] for c in NUMERIC}},
        "model2": report2,
        "safety": {"requires_human_review": True, "automatic_execution": False,
                   "official_risk_register_write": False, "default_mode": "shadow",
                   "no_claim": "No production validation, unknown-attack guarantee, control effectiveness estimate, or autonomous response"},
    }
    metadata["model2"]["eligible_for_reviewed_advisory_release"] = (
        model2 is not None and report2.get("proposed_control_gate_passed", False)
        and not synthetic and group_by != "run_id" and all(checks.values()))
    out.mkdir(parents=True, exist_ok=True)
    model_path = out / "models.joblib"
    joblib.dump({"scenario_model": calibrated, "scenario_base_pipeline": selected,
                 "control_model": model2, "catalog": catalog}, model_path, compress=3)
    metadata["model_sha256"] = digest(model_path)
    write_json(out / "metadata.json", metadata)
    write_json(out / "threshold_search.json", grid)
    write_json(out / "split_manifest.json", split_manifest)
    return metadata
