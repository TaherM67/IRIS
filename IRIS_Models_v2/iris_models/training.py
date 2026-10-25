# IRIS EXPLAIN: File purpose: Compares tabular scenario classifiers, calibrates a frozen model, trains multi-label controls with
# IRIS EXPLAIN: cross-fitted scenario inputs, and records honest holdout metrics and release gates.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Reproducible two-model training, honest holdout metrics and release gates."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import copy to create independent fixtures or estimators without mutating the original.
import copy
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
# IRIS EXPLAIN: Import clone from sklearn.base to construct, fit, freeze, calibrate and evaluate the tabular ML estimators.
from sklearn.base import clone
# IRIS EXPLAIN: Import CalibratedClassifierCV from sklearn.calibration to construct, fit, freeze, calibrate and evaluate the
# IRIS EXPLAIN: tabular ML estimators.
from sklearn.calibration import CalibratedClassifierCV
# IRIS EXPLAIN: Import ColumnTransformer from sklearn.compose to construct, fit, freeze, calibrate and evaluate the tabular ML
# IRIS EXPLAIN: estimators.
from sklearn.compose import ColumnTransformer
# IRIS EXPLAIN: Import HistGradientBoostingClassifier, RandomForestClassifier from sklearn.ensemble to construct, fit, freeze,
# IRIS EXPLAIN: calibrate and evaluate the tabular ML estimators.
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
# IRIS EXPLAIN: Import FrozenEstimator from sklearn.frozen to construct, fit, freeze, calibrate and evaluate the tabular ML
# IRIS EXPLAIN: estimators.
from sklearn.frozen import FrozenEstimator
# IRIS EXPLAIN: Import LogisticRegression from sklearn.linear_model to construct, fit, freeze, calibrate and evaluate the
# IRIS EXPLAIN: tabular ML estimators.
from sklearn.linear_model import LogisticRegression
# IRIS EXPLAIN: Import accuracy_score, confusion_matrix, f1_score, hamming_loss, precision_recall_fscore_support,
# IRIS EXPLAIN: precision_score, recall_score from sklearn.metrics to construct, fit, freeze, calibrate and evaluate the tabular
# IRIS EXPLAIN: ML estimators.
from sklearn.metrics import (
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: accuracy_score, confusion_matrix, f1_score, hamming_loss,.
    accuracy_score, confusion_matrix, f1_score, hamming_loss,
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: precision_recall_fscore_support, precision_score, recall_score,.
    precision_recall_fscore_support, precision_score, recall_score,
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
)
# IRIS EXPLAIN: Import StratifiedGroupKFold from sklearn.model_selection to construct, fit, freeze, calibrate and evaluate the
# IRIS EXPLAIN: tabular ML estimators.
from sklearn.model_selection import StratifiedGroupKFold
# IRIS EXPLAIN: Import Pipeline from sklearn.pipeline to construct, fit, freeze, calibrate and evaluate the tabular ML
# IRIS EXPLAIN: estimators.
from sklearn.pipeline import Pipeline
# IRIS EXPLAIN: Import OneHotEncoder, StandardScaler from sklearn.preprocessing to construct, fit, freeze, calibrate and
# IRIS EXPLAIN: evaluate the tabular ML estimators.
from sklearn.preprocessing import OneHotEncoder, StandardScaler
# IRIS EXPLAIN: Import threadpool_limits from threadpoolctl to bound native ML thread usage during the experiment.
from threadpoolctl import threadpool_limits

# IRIS EXPLAIN: Import __version__ from . to reuse the shared project contract/implementation rather than duplicate it.
from . import __version__
# IRIS EXPLAIN: Import CATEGORICAL, CLASSES, CONTEXT_CATEGORICAL, CONTEXT_NUMERIC, CONTROL_FEATURES, FEATURES, FEATURE_SCHEMA,
# IRIS EXPLAIN: NUMERIC, digest, rule_label, utc_now, write_json from .contracts to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .contracts import (
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
    # IRIS EXPLAIN: CATEGORICAL, CLASSES, CONTEXT_CATEGORICAL, CONTEXT_NUMERIC, CONTROL_FEATURES,.
    CATEGORICAL, CLASSES, CONTEXT_CATEGORICAL, CONTEXT_NUMERIC, CONTROL_FEATURES,
    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items: FEATURES,
    # IRIS EXPLAIN: FEATURE_SCHEMA, NUMERIC, digest, rule_label, utc_now, write_json,.
    FEATURES, FEATURE_SCHEMA, NUMERIC, digest, rule_label, utc_now, write_json,
# IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
)
# IRIS EXPLAIN: Import load_dataset, split_groups from .dataset to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from .dataset import load_dataset, split_groups


# IRIS EXPLAIN: Function preprocessing: One-hot encode categorical columns, standardize numeric columns, and drop every column
# IRIS EXPLAIN: outside the declared predictors.
# IRIS EXPLAIN: Inputs: categorical: the explicit categorical input used by the unchanged statements below; numeric: the
# IRIS EXPLAIN: explicit numeric input used by the unchanged statements below.
# IRIS EXPLAIN: Declared return type: ColumnTransformer; the return statements below show each actual result/fallback.
def preprocessing(categorical=CATEGORICAL, numeric=NUMERIC) -> ColumnTransformer:
    # IRIS EXPLAIN: Return the result of ColumnTransformer([('categorical', OneHotEncoder(handle_unknown='ignore',
    # IRIS EXPLAIN: sparse_output=False), list(catego... to the caller; this ends the current function path.
    return ColumnTransformer([
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(categorical)),.
        ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(categorical)),
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
        # IRIS EXPLAIN: ("numeric", StandardScaler(), list(numeric)),.
        ("numeric", StandardScaler(), list(numeric)),
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    ], remainder="drop", verbose_feature_names_out=True)


# IRIS EXPLAIN: Function candidates: Build separate preprocessing/classifier pipelines for logistic regression, random forest
# IRIS EXPLAIN: and histogram gradient boosting with reproducible seeds.
# IRIS EXPLAIN: Inputs: seed: the reproducible random seed.
# IRIS EXPLAIN: Declared return type: dict[str, Pipeline]; the return statements below show each actual result/fallback.
def candidates(seed: int) -> dict[str, Pipeline]:
    # IRIS EXPLAIN: Store a mapping containing logistic_regression, random_forest, hist_gradient_boosting in estimators; later
    # IRIS EXPLAIN: lines use this named result.
    estimators = {
        # IRIS EXPLAIN: Continue the current record with logistic_regression; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "logistic_regression": LogisticRegression(C=1, max_iter=2500, class_weight="balanced", random_state=seed),
        # IRIS EXPLAIN: Continue the current record with random_forest; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "random_forest": RandomForestClassifier(n_estimators=160, max_depth=12, min_samples_leaf=3,
                                                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                                # IRIS EXPLAIN: these existing arguments/items:
                                                # IRIS EXPLAIN: class_weight="balanced_subsample", n_jobs=2, random_state=seed),.
                                                class_weight="balanced_subsample", n_jobs=2, random_state=seed),
        # IRIS EXPLAIN: Continue the current record with hist_gradient_boosting; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15,
                                                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                                               # IRIS EXPLAIN: these existing arguments/items: l2_regularization=1,
                                                               # IRIS EXPLAIN: random_state=seed),.
                                                               l2_regularization=1, random_state=seed),
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Return the comprehension {name: Pipeline([('features', preprocessing()), ('classifier', estimator)]) for
    # IRIS EXPLAIN: name, estimator in estimators.items()} to the caller; this ends the current function path.
    return {name: Pipeline([("features", preprocessing()), ("classifier", estimator)])
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: for name, estimator in estimators.items()}.
            for name, estimator in estimators.items()}


# IRIS EXPLAIN: Function wilson_interval: Compute a bounded 95% Wilson binomial interval, returning None when there are no
# IRIS EXPLAIN: trials.
# IRIS EXPLAIN: Inputs: successes: the observed positive count for the binomial interval; trials: the available observation
# IRIS EXPLAIN: count; zero means no interval can be inferred.
# IRIS EXPLAIN: Declared return type: list[float] | None; the return statements below show each actual result/fallback.
def wilson_interval(successes: int, trials: int) -> list[float] | None:
    # IRIS EXPLAIN: Enter this branch only when not trials.
    if not trials:
        # IRIS EXPLAIN: Return None (no result/value) to the caller; this ends the current function path.
        return None
    # IRIS EXPLAIN: Store 1.96 in z; later lines use this named result.
    z = 1.96
    # IRIS EXPLAIN: Store the computed value successes / trials in p; later lines use this named result.
    p = successes / trials
    # IRIS EXPLAIN: Store the computed value 1 + z * z / trials in denominator; later lines use this named result.
    denominator = 1 + z*z/trials
    # IRIS EXPLAIN: Store the computed value (p + z * z / (2 * trials)) / denominator in center; later lines use this named
    # IRIS EXPLAIN: result.
    center = (p + z*z/(2*trials)) / denominator
    # IRIS EXPLAIN: Store the computed value z * np.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator in
    # IRIS EXPLAIN: radius; later lines use this named result.
    radius = z * np.sqrt(p*(1-p)/trials + z*z/(4*trials*trials)) / denominator
    # IRIS EXPLAIN: Return [max(0.0, float(center - radius)), min(1.0, float(center + radius))] to the caller; this ends the
    # IRIS EXPLAIN: current function path.
    return [max(0.0, float(center-radius)), min(1.0, float(center+radius))]


# IRIS EXPLAIN: Function scenario_metrics: Measure three-class accuracy, F1, coverage, false alarms and uncertainty; abstentions
# IRIS EXPLAIN: remain missed true classes rather than disappearing from recall.
# IRIS EXPLAIN: Inputs: y: the separately reviewed target labels; predictions: the evaluated predicted labels, including
# IRIS EXPLAIN: abstentions.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def scenario_metrics(y, predictions) -> dict:
    # IRIS EXPLAIN: Store (np.asarray(y, dtype=str), np.asarray(predictions, dtype=str)) in (y, predictions); later lines use
    # IRIS EXPLAIN: this named result.
    y, predictions = np.asarray(y, dtype=str), np.asarray(predictions, dtype=str)
    # IRIS EXPLAIN: Store the comparison predictions != 'ABSTAINED' in accepted; later lines use this named result.
    accepted = predictions != "ABSTAINED"
    # IRIS EXPLAIN: Store the result of precision_recall_fscore_support(y, predictions, labels=list(CLASSES), zero_division=0)
    # IRIS EXPLAIN: in (precision, recall, f1, support); later lines use this named result.
    precision, recall, f1, support = precision_recall_fscore_support(y, predictions, labels=list(CLASSES), zero_division=0)
    # IRIS EXPLAIN: Store the comparison y == 'benign' in benign; later lines use this named result.
    benign = y == "benign"
    # IRIS EXPLAIN: Store int(((predictions != 'benign') & accepted & benign).sum()) in false_alarms; later lines use this named
    # IRIS EXPLAIN: result.
    false_alarms = int(((predictions != "benign") & accepted & benign).sum())
    # IRIS EXPLAIN: Store int(benign.sum()) in benign_n; later lines use this named result.
    benign_n = int(benign.sum())
    # IRIS EXPLAIN: Return a mapping containing n, coverage, macro_f1, accuracy_all_sessions, accepted_accuracy,
    # IRIS EXPLAIN: benign_false_positive_rate, benign_false_alarms and additional fields to the caller; this ends the current
    # IRIS EXPLAIN: function path.
    return {
        # IRIS EXPLAIN: Set/describe these existing record fields: coverage: fraction of sessions whose scenario output was not
        # IRIS EXPLAIN: abstained.
        "n": len(y), "coverage": float(accepted.mean()),
        # IRIS EXPLAIN: Set/describe these existing record fields: macro_f1: unweighted mean class F1 across the supported
        # IRIS EXPLAIN: three-class scenario set.
        "macro_f1": float(f1_score(y, predictions, labels=list(CLASSES), average="macro", zero_division=0)),
        # IRIS EXPLAIN: Continue the current record with accuracy_all_sessions; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "accuracy_all_sessions": float(accuracy_score(y, predictions)),
        # IRIS EXPLAIN: Continue the current record with accepted_accuracy; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "accepted_accuracy": float(accuracy_score(y[accepted], predictions[accepted])) if accepted.any() else None,
        # IRIS EXPLAIN: Set/describe these existing record fields: benign_false_positive_rate: false attack alarms divided by
        # IRIS EXPLAIN: reviewed benign support; read together with coverage.
        "benign_false_positive_rate": false_alarms / benign_n if benign_n else None,
        # IRIS EXPLAIN: Continue the current record with benign_false_alarms, benign_support; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "benign_false_alarms": false_alarms, "benign_support": benign_n,
        # IRIS EXPLAIN: Continue the current record with benign_fpr_wilson_95_percent; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "benign_fpr_wilson_95_percent": wilson_interval(false_alarms, benign_n),
        # IRIS EXPLAIN: Set/describe these existing record fields: precision: positive-prediction precision for the explicitly
        # IRIS EXPLAIN: selected scenario/control target; recall: coverage of true reviewed positives, including
        # IRIS EXPLAIN: missed/abstained classes in the configured metric.
        "per_class": {label: {"precision": float(precision[i]), "recall": float(recall[i]),
                              # IRIS EXPLAIN: Continue the current record with f1, support; each value comes from the expression
                              # IRIS EXPLAIN: shown on this unchanged line.
                              "f1": float(f1[i]), "support": int(support[i])}
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: for i, label in enumerate(CLASSES)},.
                      for i, label in enumerate(CLASSES)},
        # IRIS EXPLAIN: Continue the current record with confusion_labels; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "confusion_labels": [*CLASSES, "ABSTAINED"],
        # IRIS EXPLAIN: Continue the current record with confusion_matrix; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "confusion_matrix": confusion_matrix(y, predictions, labels=[*CLASSES, "ABSTAINED"]).tolist(),
        # IRIS EXPLAIN: Continue the current record with metric_semantics; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "metric_semantics": "Abstentions count as missed true classes (false negatives), never dropped from recall/F1. FPR excludes abstentions and must be read together with coverage.",
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }


# IRIS EXPLAIN: Function scenario_predictions: Select each row's highest-probability class only when its confidence reaches the
# IRIS EXPLAIN: fixed threshold; otherwise return ABSTAINED.
# IRIS EXPLAIN: Inputs: model: the explicit model input used by the unchanged statements below; X: the allowlisted predictor
# IRIS EXPLAIN: table; threshold: the existing confidence cutoff; not a production approval.
# IRIS EXPLAIN: Declared return type: np.ndarray; the return statements below show each actual result/fallback.
def scenario_predictions(model, X, threshold: float) -> np.ndarray:
    # IRIS EXPLAIN: Store the result of model.predict_proba(X) (compute classifier membership/confidence scores for the supplied
    # IRIS EXPLAIN: rows) in probabilities; later lines use this named result.
    probabilities = model.predict_proba(X)
    # IRIS EXPLAIN: Return the result of np.where(probabilities.max(axis=1) >= threshold,
    # IRIS EXPLAIN: np.asarray(model.classes_)[probabilities.argmax(axis=1)], ... to the caller; this ends the current function
    # IRIS EXPLAIN: path.
    return np.where(probabilities.max(axis=1) >= threshold,
                    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                    # IRIS EXPLAIN: arguments/items: np.asarray(model.classes_)[probabilities.argmax(axis=1)], "ABSTAINED").
                    np.asarray(model.classes_)[probabilities.argmax(axis=1)], "ABSTAINED")


# IRIS EXPLAIN: Function operational_checks: Evaluate the configured F1, attack-recall, benign false-positive-rate and coverage
# IRIS EXPLAIN: gates; these engineering checks do not establish production validation.
# IRIS EXPLAIN: Inputs: metrics: the already computed evaluation metrics.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def operational_checks(metrics: dict) -> dict:
    # IRIS EXPLAIN: Return a mapping containing macro_f1_at_least_0_80, attack_recall_at_least_0_75, benign_fpr_at_most_0_05,
    # IRIS EXPLAIN: coverage_at_least_0_80 to the caller; this ends the current function path.
    return {
        # IRIS EXPLAIN: Continue the current record with macro_f1_at_least_0_80; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "macro_f1_at_least_0_80": metrics["macro_f1"] >= .80,
        # IRIS EXPLAIN: Continue the current record with attack_recall_at_least_0_75; each value comes from the expression shown
        # IRIS EXPLAIN: on this unchanged line.
        "attack_recall_at_least_0_75": all(metrics["per_class"][c]["recall"] >= .75 for c in CLASSES if c != "benign"),
        # IRIS EXPLAIN: Continue the current record with benign_fpr_at_most_0_05; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "benign_fpr_at_most_0_05": metrics["benign_false_positive_rate"] is not None and metrics["benign_false_positive_rate"] <= .05,
        # IRIS EXPLAIN: Continue the current record with coverage_at_least_0_80; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "coverage_at_least_0_80": metrics["coverage"] >= .80,
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }


# IRIS EXPLAIN: Function choose_threshold: Search confidence thresholds only on the threshold partition, preferring passed
# IRIS EXPLAIN: operational checks and then F1/coverage; do not tune against test data.
# IRIS EXPLAIN: Inputs: model: the explicit model input used by the unchanged statements below; X: the allowlisted predictor
# IRIS EXPLAIN: table; y: the separately reviewed target labels.
# IRIS EXPLAIN: Declared return type: tuple[float, list[dict]]; the return statements below show each actual result/fallback.
def choose_threshold(model, X, y) -> tuple[float, list[dict]]:
    # IRIS EXPLAIN: Store [] in grid; later lines use this named result.
    grid = []
    # IRIS EXPLAIN: Iterate np.arange(0.4, 0.951, 0.025), binding each item to value; process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for value in np.arange(.40, .951, .025):
        # IRIS EXPLAIN: Store the result of scenario_metrics(y, scenario_predictions(model, X, float(value))) in metrics; later
        # IRIS EXPLAIN: lines use this named result.
        metrics = scenario_metrics(y, scenario_predictions(model, X, float(value)))
        # IRIS EXPLAIN: Call grid.append({'threshold': round(float(value), 3), 'metrics': metrics, 'meets_operational_checks':
        # IRIS EXPLAIN: all(operational_checks(metrics).values())}): append one item to the working list.
        grid.append({"threshold": round(float(value), 3), "metrics": metrics,
                     # IRIS EXPLAIN: Continue the current record with meets_operational_checks; each value comes from the
                     # IRIS EXPLAIN: expression shown on this unchanged line.
                     "meets_operational_checks": all(operational_checks(metrics).values())})
    # IRIS EXPLAIN: Store max(grid, key=lambda r: (r['meets_operational_checks'], r['metrics']['macro_f1'],
    # IRIS EXPLAIN: r['metrics']['coverage'],... in best; later lines use this named result.
    best = max(grid, key=lambda r: (r["meets_operational_checks"], r["metrics"]["macro_f1"], r["metrics"]["coverage"], r["threshold"]))
    # IRIS EXPLAIN: Return (best['threshold'], grid) to the caller; this ends the current function path.
    return best["threshold"], grid


# IRIS EXPLAIN: Function load_catalog: Load the control catalogue CSV and reject missing columns, empty identifiers or duplicate
# IRIS EXPLAIN: control IDs.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def load_catalog(path: Path) -> dict:
    # IRIS EXPLAIN: Store the result of pd.read_csv(path, keep_default_na=False) in rows; later lines use this named result.
    rows = pd.read_csv(path, keep_default_na=False)
    # IRIS EXPLAIN: Store {'Control_ID', 'Control_Name', 'Recommended_Action'} in required; later lines use this named result.
    required = {"Control_ID", "Control_Name", "Recommended_Action"}
    # IRIS EXPLAIN: Enter this branch only when not required.issubset(rows.columns) or rows.empty or
    # IRIS EXPLAIN: rows.Control_ID.duplicated().any().
    if not required.issubset(rows.columns) or rows.empty or rows.Control_ID.duplicated().any():
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Control catalogue requires unique
        # IRIS EXPLAIN: Control_ID, Control_Name, Recommended_Action'); the caller's existing boundary determines rollback or
        # IRIS EXPLAIN: the HTTP diagnostic.
        raise ValueError("Control catalogue requires unique Control_ID, Control_Name, Recommended_Action")
    # IRIS EXPLAIN: Enter this branch only when any((not str(value).strip() for value in rows.Control_ID)).
    if any(not str(value).strip() for value in rows.Control_ID):
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Empty catalogue control ID'); the
        # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Empty catalogue control ID")
    # IRIS EXPLAIN: Return the result of rows.set_index('Control_ID').to_dict('index') (convert existing tabular records into
    # IRIS EXPLAIN: dictionaries) to the caller; this ends the current function path.
    return rows.set_index("Control_ID").to_dict("index")


# IRIS EXPLAIN: Function control_frame: Assemble Model 2 predictors from telemetry, validated business context and predicted
# IRIS EXPLAIN: scenarios, not oracle scenario labels.
# IRIS EXPLAIN: Inputs: data: validated tabular observations; scenario_values: Model 1 predictions supplied as Model 2 inputs.
# IRIS EXPLAIN: Declared return type: pd.DataFrame; the return statements below show each actual result/fallback.
def control_frame(data: pd.DataFrame, scenario_values) -> pd.DataFrame:
    # IRIS EXPLAIN: Store the result of data[FEATURES + ['asset_type'] + CONTEXT_NUMERIC].copy() (make an independent shallow
    # IRIS EXPLAIN: copy) in result; later lines use this named result.
    result = data[FEATURES + ["asset_type"] + CONTEXT_NUMERIC].copy()
    # IRIS EXPLAIN: Store the result of np.asarray(scenario_values, dtype=str) in result['predicted_scenario']; later lines use
    # IRIS EXPLAIN: this named result.
    result["predicted_scenario"] = np.asarray(scenario_values, dtype=str)
    # IRIS EXPLAIN: Return result[CONTROL_FEATURES] to the caller; this ends the current function path.
    return result[CONTROL_FEATURES]


# IRIS EXPLAIN: Function control_metrics: Measure multi-label control prediction quality, including per-control positive support
# IRIS EXPLAIN: and whole-catalogue macro scores.
# IRIS EXPLAIN: Inputs: y: the separately reviewed target labels; predicted: the explicit predicted input used by the unchanged
# IRIS EXPLAIN: statements below; labels: the supported catalogue/control or scenario identities for this calculation.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def control_metrics(y: np.ndarray, predicted: np.ndarray, labels: list[str]) -> dict:
    # IRIS EXPLAIN: Store the result of precision_recall_fscore_support(y, predicted, average=None, zero_division=0) in
    # IRIS EXPLAIN: (precision, recall, f1, support); later lines use this named result.
    precision, recall, f1, support = precision_recall_fscore_support(y, predicted, average=None, zero_division=0)
    # IRIS EXPLAIN: Return a mapping containing n, micro_precision, micro_recall, micro_f1, macro_f1_all_catalogue_controls,
    # IRIS EXPLAIN: hamming_loss, exact_set_accuracy and additional fields to the caller; this ends the current function path.
    return {
        # IRIS EXPLAIN: Continue the current record with n, micro_precision; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "n": len(y), "micro_precision": float(precision_score(y, predicted, average="micro", zero_division=0)),
        # IRIS EXPLAIN: Continue the current record with micro_recall; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "micro_recall": float(recall_score(y, predicted, average="micro", zero_division=0)),
        # IRIS EXPLAIN: Set/describe these existing record fields: micro_f1: global multi-label precision/recall balance; not
        # IRIS EXPLAIN: full catalogue coverage or control efficacy.
        "micro_f1": float(f1_score(y, predicted, average="micro", zero_division=0)),
        # IRIS EXPLAIN: Continue the current record with macro_f1_all_catalogue_controls; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "macro_f1_all_catalogue_controls": float(f1_score(y, predicted, average="macro", zero_division=0)),
        # IRIS EXPLAIN: Continue the current record with hamming_loss; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "hamming_loss": float(hamming_loss(y, predicted)),
        # IRIS EXPLAIN: Continue the current record with exact_set_accuracy; each value comes from the expression shown on this
        # IRIS EXPLAIN: unchanged line.
        "exact_set_accuracy": float(np.mean(np.all(y == predicted, axis=1))),
        # IRIS EXPLAIN: Set/describe these existing record fields: precision: positive-prediction precision for the explicitly
        # IRIS EXPLAIN: selected scenario/control target; recall: coverage of true reviewed positives, including
        # IRIS EXPLAIN: missed/abstained classes in the configured metric.
        "per_control": {cid: {"precision": float(precision[i]), "recall": float(recall[i]),
                              # IRIS EXPLAIN: Set/describe these existing record fields: test_positive_support: number of
                              # IRIS EXPLAIN: held-out reviewed positives supporting this particular control.
                              "f1": float(f1[i]), "test_positive_support": int(support[i])}
                        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                        # IRIS EXPLAIN: arguments/items: for i, cid in enumerate(labels)},.
                        for i, cid in enumerate(labels)},
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }


# IRIS EXPLAIN: Function fit_controls: Cross-fit scenario predictions for the control-training pool, fit one logistic classifier
# IRIS EXPLAIN: per supported control, select thresholds separately, and evaluate held-out reviewed targets.
# IRIS EXPLAIN: Inputs: data: validated tabular observations; split: separate grouped fitting/evaluation partitions;
# IRIS EXPLAIN: selected_pipeline: the chosen base scenario estimator before calibration; calibrated: the frozen-base calibrated
# IRIS EXPLAIN: scenario model; scenario_threshold: the separately selected Model 1 acceptance cutoff; catalog: the validated
# IRIS EXPLAIN: control catalogue; seed: the reproducible random seed.
# IRIS EXPLAIN: Declared return type: tuple[dict | None, dict]; the return statements below show each actual result/fallback.
def fit_controls(data, split, selected_pipeline, calibrated, scenario_threshold, catalog, seed) -> tuple[dict | None, dict]:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Train on cross-fitted scenario inputs; no oracle scenario labels to Model 2."""
    # IRIS EXPLAIN: Store the result of np.concatenate([split['train'], split['selection']]) in fit_ix; later lines use this
    # IRIS EXPLAIN: named result.
    fit_ix = np.concatenate([split["train"], split["selection"]])
    # IRIS EXPLAIN: Store the result of data.iloc[fit_ix].reset_index(drop=True) in pool; later lines use this named result.
    pool = data.iloc[fit_ix].reset_index(drop=True)
    # IRIS EXPLAIN: Store the computed value pool.campaign_id + '/' + pool.run_id in groups; later lines use this named result.
    groups = pool.campaign_id + "/" + pool.run_id
    # IRIS EXPLAIN: Store the result of np.full(len(pool), 'ABSTAINED', dtype=object) in oof; later lines use this named result.
    oof = np.full(len(pool), "ABSTAINED", dtype=object)
    # Match the experiment's outer independence unit, not random rows.
    # IRIS EXPLAIN: Store the result of data.attrs.get('group_by', 'campaign_id') (read an optional mapping field using its
    # IRIS EXPLAIN: stated fallback) in group_key; later lines use this named result.
    group_key = data.attrs.get("group_by", "campaign_id")
    # IRIS EXPLAIN: Enter this branch only when group_key != 'run_id'.
    if group_key != "run_id":
        # IRIS EXPLAIN: Store the result of pool[group_key].astype(str) in groups; later lines use this named result.
        groups = pool[group_key].astype(str)
    # IRIS EXPLAIN: Store min(3, groups.nunique()) in n_splits; later lines use this named result.
    n_splits = min(3, groups.nunique())
    # IRIS EXPLAIN: Enter this branch only when n_splits < 2.
    if n_splits < 2:
        # IRIS EXPLAIN: Return (None, {'status': 'not_trained', 'reason': 'Insufficient independent groups for Model 2 scenario
        # IRIS EXPLAIN: cross-fitting'}) to the caller; this ends the current function path.
        return None, {"status": "not_trained", "reason": "Insufficient independent groups for Model 2 scenario cross-fitting"}
    # IRIS EXPLAIN: Iterate StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed).split(pool,
    # IRIS EXPLAIN: pool.scenario_class, groups), binding each item to (tr, va); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for tr, va in StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed).split(pool, pool.scenario_class, groups):
        # IRIS EXPLAIN: Enter this branch only when set(pool.iloc[tr].scenario_class) != set(CLASSES).
        if set(pool.iloc[tr].scenario_class) != set(CLASSES):
            # IRIS EXPLAIN: Return (None, {'status': 'not_trained', 'reason': 'Cross-fit fold lacks a supported scenario
            # IRIS EXPLAIN: class'}) to the caller; this ends the current function path.
            return None, {"status": "not_trained", "reason": "Cross-fit fold lacks a supported scenario class"}
        # IRIS EXPLAIN: Store the result of clone(selected_pipeline).fit(pool.iloc[tr][FEATURES], pool.iloc[tr].scenario_class)
        # IRIS EXPLAIN: (fit the estimator/transformer using the supplied partition only) in candidate; later lines use this
        # IRIS EXPLAIN: named result.
        candidate = clone(selected_pipeline).fit(pool.iloc[tr][FEATURES], pool.iloc[tr].scenario_class)
        # IRIS EXPLAIN: Store the result of candidate.predict_proba(pool.iloc[va][FEATURES]) (compute classifier
        # IRIS EXPLAIN: membership/confidence scores for the supplied rows) in probs; later lines use this named result.
        probs = candidate.predict_proba(pool.iloc[va][FEATURES])
        # IRIS EXPLAIN: Store the result of np.where(probs.max(axis=1) >= scenario_threshold,
        # IRIS EXPLAIN: np.asarray(candidate.classes_)[probs.argmax(axis=1)], 'AB... in oof[va]; later lines use this named
        # IRIS EXPLAIN: result.
        oof[va] = np.where(probs.max(axis=1) >= scenario_threshold,
                           # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                           # IRIS EXPLAIN: arguments/items: np.asarray(candidate.classes_)[probs.argmax(axis=1)], "ABSTAINED").
                           np.asarray(candidate.classes_)[probs.argmax(axis=1)], "ABSTAINED")
    # IRIS EXPLAIN: Store the result of control_frame(pool, oof) in Xfit; later lines use this named result.
    Xfit = control_frame(pool, oof)
    # IRIS EXPLAIN: Store the result of pool.controls_reviewed.to_numpy(dtype=bool) (convert this existing table/series to a
    # IRIS EXPLAIN: numeric array) in reviewed_fit; later lines use this named result.
    reviewed_fit = pool.controls_reviewed.to_numpy(dtype=bool)
    # IRIS EXPLAIN: Store data.iloc[split['threshold']] in validation; later lines use this named result.
    validation = data.iloc[split["threshold"]]
    # IRIS EXPLAIN: Store data.iloc[split['test']] in test; later lines use this named result.
    test = data.iloc[split["test"]]
    # IRIS EXPLAIN: Enter this branch only when not reviewed_fit.any() or not validation.controls_reviewed.any() or (not
    # IRIS EXPLAIN: test.controls_reviewed.any()).
    if not reviewed_fit.any() or not validation.controls_reviewed.any() or not test.controls_reviewed.any():
        # IRIS EXPLAIN: Return (None, {'status': 'not_trained', 'reason': 'Need separately reviewed control targets in fit,
        # IRIS EXPLAIN: threshold and test splits. Attack labels do not create... to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return None, {"status": "not_trained", "reason": "Need separately reviewed control targets in fit, threshold and test splits. Attack labels do not create control labels."}
    # IRIS EXPLAIN: Store sorted(catalog) in labels; later lines use this named result.
    labels = sorted(catalog)
    # IRIS EXPLAIN: Function targets: Convert reviewed control-ID sets into binary catalogue-membership vectors and reject
    # IRIS EXPLAIN: unknown control IDs.
    # IRIS EXPLAIN: Inputs: part: the existing partition being converted to control targets.
    def targets(part):
        # IRIS EXPLAIN: Store the computed value set((c for values in part.controls for c in values)) - set(labels) in unknown;
        # IRIS EXPLAIN: later lines use this named result.
        unknown = set(c for values in part.controls for c in values) - set(labels)
        # IRIS EXPLAIN: Enter this branch only when unknown.
        if unknown:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Reviewed controls are absent from
            # IRIS EXPLAIN: catalogue: {sorted(unknown)}'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError(f"Reviewed controls are absent from catalogue: {sorted(unknown)}")
        # IRIS EXPLAIN: Return the result of np.asarray([[int(cid in controls) for cid in labels] for controls in
        # IRIS EXPLAIN: part.controls], dtype=np.int8) to the caller; this ends the current function path.
        return np.asarray([[int(cid in controls) for cid in labels] for controls in part.controls], dtype=np.int8)
    # IRIS EXPLAIN: Store (targets(pool), targets(validation), targets(test)) in (yfit, yval, ytest); later lines use this named
    # IRIS EXPLAIN: result.
    yfit, yval, ytest = targets(pool), targets(validation), targets(test)
    # IRIS EXPLAIN: Store the result of control_frame(validation, scenario_predictions(calibrated, validation[FEATURES],
    # IRIS EXPLAIN: scenario_threshold)) in Xval; later lines use this named result.
    Xval = control_frame(validation, scenario_predictions(calibrated, validation[FEATURES], scenario_threshold))
    # IRIS EXPLAIN: Store the result of control_frame(test, scenario_predictions(calibrated, test[FEATURES],
    # IRIS EXPLAIN: scenario_threshold)) in Xtest; later lines use this named result.
    Xtest = control_frame(test, scenario_predictions(calibrated, test[FEATURES], scenario_threshold))
    # IRIS EXPLAIN: Store the result of validation.controls_reviewed.to_numpy(dtype=bool) (convert this existing table/series to
    # IRIS EXPLAIN: a numeric array) in keep_val; later lines use this named result.
    keep_val = validation.controls_reviewed.to_numpy(dtype=bool)
    # IRIS EXPLAIN: Store the result of test.controls_reviewed.to_numpy(dtype=bool) (convert this existing table/series to a
    # IRIS EXPLAIN: numeric array) in keep_test; later lines use this named result.
    keep_test = test.controls_reviewed.to_numpy(dtype=bool)
    # IRIS EXPLAIN: Store the result of preprocessing(CATEGORICAL + CONTEXT_CATEGORICAL, NUMERIC + CONTEXT_NUMERIC) in
    # IRIS EXPLAIN: transformer; later lines use this named result.
    transformer = preprocessing(CATEGORICAL + CONTEXT_CATEGORICAL, NUMERIC + CONTEXT_NUMERIC)
    # IRIS EXPLAIN: Store the result of transformer.fit_transform(Xfit[reviewed_fit]) (fit preprocessing on the supplied fitting
    # IRIS EXPLAIN: data and return transformed predictors) in Zfit; later lines use this named result.
    Zfit = transformer.fit_transform(Xfit[reviewed_fit])
    # IRIS EXPLAIN: Store (transformer.transform(Xval[keep_val]), transformer.transform(Xtest[keep_test])) in (Zval, Ztest);
    # IRIS EXPLAIN: later lines use this named result.
    Zval, Ztest = transformer.transform(Xval[keep_val]), transformer.transform(Xtest[keep_test])
    # IRIS EXPLAIN: Store ({}, {}, {}, []) in (bank, thresholds, support, unsupported); later lines use this named result.
    bank, thresholds, support, unsupported = {}, {}, {}, []
    # IRIS EXPLAIN: Store the result of np.zeros((int(keep_test.sum()), len(labels))) in scores_test; later lines use this named
    # IRIS EXPLAIN: result.
    scores_test = np.zeros((int(keep_test.sum()), len(labels)))
    # IRIS EXPLAIN: Store the result of np.zeros_like(scores_test, dtype=np.int8) in learned; later lines use this named result.
    learned = np.zeros_like(scores_test, dtype=np.int8)
    # IRIS EXPLAIN: Iterate enumerate(labels), binding each item to (j, cid); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for j, cid in enumerate(labels):
        # IRIS EXPLAIN: Store yfit[reviewed_fit, j] in target; later lines use this named result.
        target = yfit[reviewed_fit, j]
        # IRIS EXPLAIN: Store (int(target.sum()), int((1 - target).sum())) in (positive, negative); later lines use this named
        # IRIS EXPLAIN: result.
        positive, negative = int(target.sum()), int((1-target).sum())
        # IRIS EXPLAIN: Store a mapping containing train_positive, train_negative, threshold_positive, test_positive in
        # IRIS EXPLAIN: support[cid]; later lines use this named result.
        support[cid] = {"train_positive": positive, "train_negative": negative,
                        # IRIS EXPLAIN: Continue the current record with threshold_positive; each value comes from the
                        # IRIS EXPLAIN: expression shown on this unchanged line.
                        "threshold_positive": int(yval[keep_val, j].sum()),
                        # IRIS EXPLAIN: Continue the current record with test_positive; each value comes from the expression
                        # IRIS EXPLAIN: shown on this unchanged line.
                        "test_positive": int(ytest[keep_test, j].sum())}
        # IRIS EXPLAIN: Enter this branch only when min(positive, negative) < 5.
        if min(positive, negative) < 5:
            # IRIS EXPLAIN: Call unsupported.append(cid): append one item to the working list.
            unsupported.append(cid)
            # IRIS EXPLAIN: Skip the remainder of this iteration and move to the next item; do not fabricate an accepted result
            # IRIS EXPLAIN: for this skipped input.
            continue
        # IRIS EXPLAIN: Store the result of LogisticRegression(C=1, max_iter=2500, random_state=seed).fit(Zfit, target) (fit the
        # IRIS EXPLAIN: estimator/transformer using the supplied partition only) in clf; later lines use this named result.
        clf = LogisticRegression(C=1, max_iter=2500, random_state=seed).fit(Zfit, target)
        # IRIS EXPLAIN: Store clf.predict_proba(Zval)[:, list(clf.classes_).index(1)] in val_score; later lines use this named
        # IRIS EXPLAIN: result.
        val_score = clf.predict_proba(Zval)[:, list(clf.classes_).index(1)]
        # IRIS EXPLAIN: Store [] in options; later lines use this named result.
        options = []
        # IRIS EXPLAIN: Iterate np.arange(0.2, 0.951, 0.05), binding each item to t; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for t in np.arange(.20, .951, .05):
            # IRIS EXPLAIN: Store the comparison val_score >= t in p; later lines use this named result.
            p = val_score >= t
            # IRIS EXPLAIN: Enter this branch only when p.any() and precision_score(yval[keep_val, j], p, zero_division=0) >=
            # IRIS EXPLAIN: 0.8.
            if p.any() and precision_score(yval[keep_val, j], p, zero_division=0) >= .8:
                # IRIS EXPLAIN: Call options.append((f1_score(yval[keep_val, j], p, zero_division=0), float(t))): append one
                # IRIS EXPLAIN: item to the working list.
                options.append((f1_score(yval[keep_val, j], p, zero_division=0), float(t)))
        # If validation cannot support useful precision, suppress the learned label.
        # IRIS EXPLAIN: Store max(options)[1] when options; otherwise 1.000001 in threshold; later lines use this named result.
        threshold = max(options)[1] if options else 1.000001
        # IRIS EXPLAIN: Store (clf, threshold) in (bank[cid], thresholds[cid]); later lines use this named result.
        bank[cid], thresholds[cid] = clf, threshold
        # IRIS EXPLAIN: Store clf.predict_proba(Ztest)[:, list(clf.classes_).index(1)] in scores_test[:, j]; later lines use
        # IRIS EXPLAIN: this named result.
        scores_test[:, j] = clf.predict_proba(Ztest)[:, list(clf.classes_).index(1)]
        # IRIS EXPLAIN: Store the comparison scores_test[:, j] >= threshold in learned[:, j]; later lines use this named result.
        learned[:, j] = scores_test[:, j] >= threshold
    # IRIS EXPLAIN: Enter this branch only when not bank.
    if not bank:
        # IRIS EXPLAIN: Return (None, {'status': 'not_trained', 'reason': 'No control has at least 5 reviewed positive and 5
        # IRIS EXPLAIN: negative fit examples', 'support': support}) to the caller; this ends the current function path.
        return None, {"status": "not_trained", "reason": "No control has at least 5 reviewed positive and 5 negative fit examples", "support": support}
    # IRIS EXPLAIN: Store the result of control_metrics(ytest[keep_test], learned, labels) in metrics; later lines use this
    # IRIS EXPLAIN: named result.
    metrics = control_metrics(ytest[keep_test], learned, labels)
    # Training-only scenario-frequency baseline: does context add predictive value?
    # IRIS EXPLAIN: Store np.asarray(oof)[reviewed_fit] in fit_scenarios; later lines use this named result.
    fit_scenarios = np.asarray(oof)[reviewed_fit]
    # IRIS EXPLAIN: Store the comprehension {scenario: yfit[reviewed_fit][fit_scenarios == scenario].mean(axis=0) for scenario
    # IRIS EXPLAIN: in sorted(set(fit_scenarios))} in lookup; later lines use this named result.
    lookup = {scenario: yfit[reviewed_fit][fit_scenarios == scenario].mean(axis=0)
              # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
              # IRIS EXPLAIN: for scenario in sorted(set(fit_scenarios))}.
              for scenario in sorted(set(fit_scenarios))}
    # IRIS EXPLAIN: Store the result of np.asarray([lookup.get(scenario, np.zeros(len(labels))) for scenario in
    # IRIS EXPLAIN: Xtest.loc[keep_test, 'predicted_sce... in baseline_scores; later lines use this named result.
    baseline_scores = np.asarray([lookup.get(scenario, np.zeros(len(labels)))
                                  # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                  # IRIS EXPLAIN: existing arguments/items: for scenario in Xtest.loc[keep_test,
                                  # IRIS EXPLAIN: "predicted_scenario"]]).
                                  for scenario in Xtest.loc[keep_test, "predicted_scenario"]])
    # IRIS EXPLAIN: Store the result of control_metrics(ytest[keep_test], (baseline_scores >= 0.5).astype(np.int8), labels) in
    # IRIS EXPLAIN: baseline_metrics; later lines use this named result.
    baseline_metrics = control_metrics(ytest[keep_test], (baseline_scores >= .5).astype(np.int8), labels)
    # IRIS EXPLAIN: Store the comprehension [cid for cid in bank if thresholds[cid] <= 1] in active; later lines use this named
    # IRIS EXPLAIN: result.
    active = [cid for cid in bank if thresholds[cid] <= 1]
    # IRIS EXPLAIN: Store a mapping containing at_least_one_supported_control, micro_precision_at_least_0_80,
    # IRIS EXPLAIN: micro_f1_at_least_0_80, not_worse_than_scenario_frequency_baseline, reviewed_training_support,
    # IRIS EXPLAIN: heldout_positive_support in checks; later lines use this named result.
    checks = {
        # IRIS EXPLAIN: Continue the current record with at_least_one_supported_control; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "at_least_one_supported_control": bool(active),
        # IRIS EXPLAIN: Continue the current record with micro_precision_at_least_0_80; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "micro_precision_at_least_0_80": metrics["micro_precision"] >= .8,
        # IRIS EXPLAIN: Continue the current record with micro_f1_at_least_0_80; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "micro_f1_at_least_0_80": metrics["micro_f1"] >= .8,
        # IRIS EXPLAIN: Continue the current record with not_worse_than_scenario_frequency_baseline; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "not_worse_than_scenario_frequency_baseline": metrics["micro_f1"] >= baseline_metrics["micro_f1"],
        # IRIS EXPLAIN: Continue the current record with reviewed_training_support; each value comes from the expression shown
        # IRIS EXPLAIN: on this unchanged line.
        "reviewed_training_support": bool(active) and all(support[c]["train_positive"] >= 20 and support[c]["train_negative"] >= 20 for c in active),
        # IRIS EXPLAIN: Continue the current record with heldout_positive_support; each value comes from the expression shown on
        # IRIS EXPLAIN: this unchanged line.
        "heldout_positive_support": bool(active) and all(support[c]["test_positive"] >= 5 for c in active),
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Store a mapping containing transformer, classifiers, thresholds, labels in model; later lines use this named
    # IRIS EXPLAIN: result.
    model = {"transformer": transformer, "classifiers": bank, "thresholds": thresholds, "labels": labels}
    # IRIS EXPLAIN: Store a mapping containing status, algorithm, scenario_inputs, score_meaning, support, unsupported_controls,
    # IRIS EXPLAIN: validation_suppressed_controls and additional fields in report; later lines use this named result.
    report = {"status": "trained_shadow", "algorithm": "binary_relevance_logistic_regression",
              # IRIS EXPLAIN: Continue the current record with scenario_inputs; each value comes from the expression shown on
              # IRIS EXPLAIN: this unchanged line.
              "scenario_inputs": "grouped out-of-fold predictions for fitting; frozen Model 1 predictions for threshold/test, never oracle classes",
              # IRIS EXPLAIN: Continue the current record with score_meaning; each value comes from the expression shown on this
              # IRIS EXPLAIN: unchanged line.
              "score_meaning": "Uncalibrated membership score, not probability of efficacy or causal risk reduction",
              # IRIS EXPLAIN: Continue the current record with support, unsupported_controls; each value comes from the
              # IRIS EXPLAIN: expression shown on this unchanged line.
              "support": support, "unsupported_controls": unsupported,
              # IRIS EXPLAIN: Continue the current record with validation_suppressed_controls; each value comes from the
              # IRIS EXPLAIN: expression shown on this unchanged line.
              "validation_suppressed_controls": [cid for cid, t in thresholds.items() if t > 1],
              # IRIS EXPLAIN: Continue the current record with metrics, checks; each value comes from the expression shown on
              # IRIS EXPLAIN: this unchanged line.
              "metrics": metrics, "checks": checks,
              # IRIS EXPLAIN: Continue the current record with scenario_frequency_baseline; each value comes from the expression
              # IRIS EXPLAIN: shown on this unchanged line.
              "scenario_frequency_baseline": baseline_metrics,
              # IRIS EXPLAIN: Continue the current record with proposed_control_gate_passed; each value comes from the
              # IRIS EXPLAIN: expression shown on this unchanged line.
              "proposed_control_gate_passed": all(checks.values()),
              # IRIS EXPLAIN: Continue the current record with note; each value comes from the expression shown on this
              # IRIS EXPLAIN: unchanged line.
              "note": "Control gate is a proposed engineering minimum requiring project-owner agreement, not an established compliance standard."}
    # IRIS EXPLAIN: Return (model, report) to the caller; this ends the current function path.
    return model, report


# IRIS EXPLAIN: Function train: Run the reproducible grouped experiment, freeze base preprocessing before calibration, evaluate
# IRIS EXPLAIN: held-out models, and save trusted artifacts/metadata to a fresh output directory.
# IRIS EXPLAIN: Inputs: sessions: observed prepared sessions, not automatically reviewed labels; reviews: the separate
# IRIS EXPLAIN: offline/session review file or saved local opinions; catalog_path: the control catalogue CSV path; out: the
# IRIS EXPLAIN: destination path; existing safety checks govern overwrite behavior; synthetic: whether this offline experiment
# IRIS EXPLAIN: explicitly uses artificial data; group_by: the experiment independence unit: campaign, template family or run;
# IRIS EXPLAIN: seed: the reproducible random seed.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def train(sessions: Path, reviews: Path, catalog_path: Path, out: Path, *, synthetic=False, group_by="campaign_id", seed=42) -> dict:
    # IRIS EXPLAIN: Enter this branch only when (out / 'metadata.json').exists() or (out / 'models.joblib').exists().
    if (out / "metadata.json").exists() or (out / "models.joblib").exists():
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Output already contains an experiment.
        # IRIS EXPLAIN: Choose a new directory; do not overwrite a held-out experiment.'); the caller's existing boundary
        # IRIS EXPLAIN: determines rollback or the HTTP diagnostic.
        raise ValueError("Output already contains an experiment. Choose a new directory; do not overwrite a held-out experiment.")
    # IRIS EXPLAIN: Store the result of load_dataset(sessions, reviews, synthetic=synthetic) in (data, quality); later lines use
    # IRIS EXPLAIN: this named result.
    data, quality = load_dataset(sessions, reviews, synthetic=synthetic)
    # IRIS EXPLAIN: Store the result of split_groups(data, group_by, seed) in (split, split_manifest); later lines use this
    # IRIS EXPLAIN: named result.
    split, split_manifest = split_groups(data, group_by, seed)
    # IRIS EXPLAIN: Store group_by in data.attrs['group_by']; later lines use this named result.
    data.attrs["group_by"] = group_by
    # IRIS EXPLAIN: Store the result of load_catalog(catalog_path) in catalog; later lines use this named result.
    catalog = load_catalog(catalog_path)
    # IRIS EXPLAIN: Store (data.iloc[split['train']], data.iloc[split['selection']]) in (tr, selection); later lines use this
    # IRIS EXPLAIN: named result.
    tr, selection = data.iloc[split["train"]], data.iloc[split["selection"]]
    # IRIS EXPLAIN: Store (candidates(seed), {}) in (pipelines, scores); later lines use this named result.
    pipelines, scores = candidates(seed), {}
    # IRIS EXPLAIN: Enter threadpool_limits(limits=2); its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with threadpool_limits(limits=2):
        # IRIS EXPLAIN: Iterate pipelines.items(), binding each item to (name, pipeline); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for name, pipeline in pipelines.items():
            # IRIS EXPLAIN: Call pipeline.fit(tr[FEATURES], tr.scenario_class): fit the estimator/transformer using the supplied
            # IRIS EXPLAIN: partition only.
            pipeline.fit(tr[FEATURES], tr.scenario_class)
            # IRIS EXPLAIN: Store scenario_metrics(selection.scenario_class, pipeline.predict(selection[FEATURES]))['macro_f1']
            # IRIS EXPLAIN: in scores[name]; later lines use this named result.
            scores[name] = scenario_metrics(selection.scenario_class, pipeline.predict(selection[FEATURES]))["macro_f1"]
        # IRIS EXPLAIN: Store max(scores.values()) in best; later lines use this named result.
        best = max(scores.values())
        # IRIS EXPLAIN: Store the result of next((name for name in pipelines if scores[name] >= best - 0.01)) in chosen; later
        # IRIS EXPLAIN: lines use this named result.
        chosen = next(name for name in pipelines if scores[name] >= best-.01)
        # IRIS EXPLAIN: Store data.iloc[np.concatenate([split['train'], split['selection']])] in pool; later lines use this
        # IRIS EXPLAIN: named result.
        pool = data.iloc[np.concatenate([split["train"], split["selection"]])]
        # IRIS EXPLAIN: Store the result of clone(pipelines[chosen]).fit(pool[FEATURES], pool.scenario_class) (fit the
        # IRIS EXPLAIN: estimator/transformer using the supplied partition only) in selected; later lines use this named result.
        selected = clone(pipelines[chosen]).fit(pool[FEATURES], pool.scenario_class)
        # IRIS EXPLAIN: Store data.iloc[split['calibration']] in cal; later lines use this named result.
        cal = data.iloc[split["calibration"]]
        # The base pipeline is already fitted ONLY on fit+selection data.
        # FrozenEstimator.fit is a no-op. Score every separate calibration row
        # once, without imposing the library's default five-fold minimum.
        # These nominal overlapping CV indices do not refit the frozen base;
        # only the sigmoid calibrator learns from calibration labels.
        # IRIS EXPLAIN: Store the result of np.arange(len(cal)) in calibration_ix; later lines use this named result.
        calibration_ix = np.arange(len(cal))
        # IRIS EXPLAIN: Store the result of CalibratedClassifierCV(FrozenEstimator(selected), method='sigmoid', ensemble=False,
        # IRIS EXPLAIN: cv=[(calibration_ix, calibration_ix)]).fit(cal[F... (fit the estimator/transformer using the supplied
        # IRIS EXPLAIN: partition only) in calibrated; later lines use this named result.
        calibrated = CalibratedClassifierCV(
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: FrozenEstimator(selected), method="sigmoid", ensemble=False,.
            FrozenEstimator(selected), method="sigmoid", ensemble=False,
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: cv=[(calibration_ix, calibration_ix)],.
            cv=[(calibration_ix, calibration_ix)],
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        ).fit(cal[FEATURES], cal.scenario_class)
        # IRIS EXPLAIN: Store data.iloc[split['threshold']] in val; later lines use this named result.
        val = data.iloc[split["threshold"]]
        # IRIS EXPLAIN: Store the result of choose_threshold(calibrated, val[FEATURES], val.scenario_class) in (threshold,
        # IRIS EXPLAIN: grid); later lines use this named result.
        threshold, grid = choose_threshold(calibrated, val[FEATURES], val.scenario_class)
        # IRIS EXPLAIN: Store data.iloc[split['test']] in test; later lines use this named result.
        test = data.iloc[split["test"]]
        # IRIS EXPLAIN: Store the result of scenario_metrics(test.scenario_class, scenario_predictions(calibrated,
        # IRIS EXPLAIN: test[FEATURES], threshold)) in metrics; later lines use this named result.
        metrics = scenario_metrics(test.scenario_class, scenario_predictions(calibrated, test[FEATURES], threshold))
        # IRIS EXPLAIN: Store the result of scenario_metrics(test.scenario_class, [rule_label(row) or 'ABSTAINED' for row in
        # IRIS EXPLAIN: test[FEATURES].to_dict('re... in baseline; later lines use this named result.
        baseline = scenario_metrics(test.scenario_class, [rule_label(row) or "ABSTAINED" for row in test[FEATURES].to_dict("records")])
        # IRIS EXPLAIN: Store a mapping containing improvement_over_frozen_rules_at_least_0_05,
        # IRIS EXPLAIN: minimum_10_test_sessions_per_class, real_reviewed_cyber_range_data, campaign_or_template_holdout in
        # IRIS EXPLAIN: checks; later lines use this named result.
        checks = {
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: **operational_checks(metrics),.
            **operational_checks(metrics),
            # IRIS EXPLAIN: Continue the current record with improvement_over_frozen_rules_at_least_0_05; each value comes from
            # IRIS EXPLAIN: the expression shown on this unchanged line.
            "improvement_over_frozen_rules_at_least_0_05": metrics["macro_f1"] - baseline["macro_f1"] >= .05 - 1e-12,
            # IRIS EXPLAIN: Continue the current record with minimum_10_test_sessions_per_class; each value comes from the
            # IRIS EXPLAIN: expression shown on this unchanged line.
            "minimum_10_test_sessions_per_class": all(metrics["per_class"][c]["support"] >= 10 for c in CLASSES),
            # IRIS EXPLAIN: Continue the current record with real_reviewed_cyber_range_data; each value comes from the
            # IRIS EXPLAIN: expression shown on this unchanged line.
            "real_reviewed_cyber_range_data": not synthetic,
            # IRIS EXPLAIN: Continue the current record with campaign_or_template_holdout; each value comes from the expression
            # IRIS EXPLAIN: shown on this unchanged line.
            "campaign_or_template_holdout": group_by in {"campaign_id", "template_group"},
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }
        # IRIS EXPLAIN: Store the result of fit_controls(data, split, selected, calibrated, threshold, catalog, seed) in
        # IRIS EXPLAIN: (model2, report2); later lines use this named result.
        model2, report2 = fit_controls(data, split, selected, calibrated, threshold, catalog, seed)
    # IRIS EXPLAIN: Store a mapping containing package_version, trained_at_utc, feature_schema, aggregation_schema,
    # IRIS EXPLAIN: scikit_learn_version, features, data_quality and additional fields in metadata; later lines use this named
    # IRIS EXPLAIN: result.
    metadata = {
        # IRIS EXPLAIN: Continue the current record with package_version, trained_at_utc, feature_schema; each value comes from
        # IRIS EXPLAIN: the expression shown on this unchanged line.
        "package_version": __version__, "trained_at_utc": utc_now(), "feature_schema": FEATURE_SCHEMA,
        # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact normalization/session-window
        # IRIS EXPLAIN: contract used for training and inference.
        "aggregation_schema": quality["aggregation_schema"],
        # IRIS EXPLAIN: Continue the current record with scikit_learn_version, features; each value comes from the expression
        # IRIS EXPLAIN: shown on this unchanged line.
        "scikit_learn_version": sklearn.__version__, "features": FEATURES,
        # IRIS EXPLAIN: Set/describe these existing record fields: catalog_sha256: catalogue bytes used for the recorded
        # IRIS EXPLAIN: training experiment.
        "data_quality": quality, "split": split_manifest, "catalog_sha256": digest(catalog_path),
        # IRIS EXPLAIN: Set/describe these existing record fields: model1: scenario-classifier metadata and its independent
        # IRIS EXPLAIN: release checks.
        "model1": {"algorithm": chosen, "selection_scores": scores, "threshold": threshold,
                   # IRIS EXPLAIN: Set/describe these existing record fields: calibration_strategy: which disjoint calibration
                   # IRIS EXPLAIN: procedure was used without refitting the frozen base.
                   "calibration_strategy": "Frozen base; every disjoint calibration row scored once; no base refit",
                   # IRIS EXPLAIN: Continue the current record with classes, metrics, rule_baseline; each value comes from the
                   # IRIS EXPLAIN: expression shown on this unchanged line.
                   "classes": list(CLASSES), "metrics": metrics, "rule_baseline": baseline,
                   # IRIS EXPLAIN: Set/describe these existing record fields: eligible_for_reviewed_advisory_release: whether
                   # IRIS EXPLAIN: all configured evidence gates permit a separate named human approval.
                   "checks": checks, "eligible_for_reviewed_advisory_release": all(checks.values()),
                   # IRIS EXPLAIN: Set/describe these existing record fields: categorical_vocab: categories actually seen in the
                   # IRIS EXPLAIN: fitted scenario pool; unknown categories trigger ML abstention.
                   "categorical_vocab": {c: sorted(pool[c].unique().tolist()) for c in CATEGORICAL},
                   # IRIS EXPLAIN: Set/describe these existing record fields: numeric_train_ranges: observed fitted numeric
                   # IRIS EXPLAIN: ranges used to flag extrapolation, not to prove universal coverage.
                   "numeric_train_ranges": {c: [float(pool[c].min()), float(pool[c].max())] for c in NUMERIC}},
        # IRIS EXPLAIN: Set/describe these existing record fields: model2: multi-label control model metadata and
        # IRIS EXPLAIN: support/threshold checks.
        "model2": report2,
        # IRIS EXPLAIN: Set/describe these existing record fields: requires_human_review: explicit requirement for a human to
        # IRIS EXPLAIN: review advisory evidence; automatic_execution: safety flag separating recommendations from automatic
        # IRIS EXPLAIN: control execution.
        "safety": {"requires_human_review": True, "automatic_execution": False,
                   # IRIS EXPLAIN: Set/describe these existing record fields: official_risk_register_write: safety flag: model
                   # IRIS EXPLAIN: inference does not change an official company register.
                   "official_risk_register_write": False, "default_mode": "shadow",
                   # IRIS EXPLAIN: Continue the current record with no_claim; each value comes from the expression shown on this
                   # IRIS EXPLAIN: unchanged line.
                   "no_claim": "No production validation, unknown-attack guarantee, control effectiveness estimate, or autonomous response"},
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Store model2 is not None and report2.get('proposed_control_gate_passed', False) and (not synthetic) and
    # IRIS EXPLAIN: (group_by != 'run_id') and all(checks.values()) in
    # IRIS EXPLAIN: metadata['model2']['eligible_for_reviewed_advisory_release']; later lines use this named result.
    metadata["model2"]["eligible_for_reviewed_advisory_release"] = (
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items: model2
        # IRIS EXPLAIN: is not None and report2.get("proposed_control_gate_passed", False).
        model2 is not None and report2.get("proposed_control_gate_passed", False)
        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items: and
        # IRIS EXPLAIN: not synthetic and group_by != "run_id" and all(checks.values())).
        and not synthetic and group_by != "run_id" and all(checks.values()))
    # IRIS EXPLAIN: Call out.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the existing
    # IRIS EXPLAIN: flags.
    out.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Store the computed value out / 'models.joblib' in model_path; later lines use this named result.
    model_path = out / "models.joblib"
    # IRIS EXPLAIN: Call joblib.dump({'scenario_model': calibrated, 'scenario_base_pipeline': selected, 'control_model': model2,
    # IRIS EXPLAIN: 'catalog': catalog}, model_path, compress=3) using the existing explicit arguments.
    joblib.dump({"scenario_model": calibrated, "scenario_base_pipeline": selected,
                 # IRIS EXPLAIN: Continue the current record with control_model, catalog; each value comes from the expression
                 # IRIS EXPLAIN: shown on this unchanged line.
                 "control_model": model2, "catalog": catalog}, model_path, compress=3)
    # IRIS EXPLAIN: Store the result of digest(model_path) (compute the selected file content hash) in metadata['model_sha256'];
    # IRIS EXPLAIN: later lines use this named result.
    metadata["model_sha256"] = digest(model_path)
    # IRIS EXPLAIN: Call write_json(out / 'metadata.json', metadata) using the existing explicit arguments.
    write_json(out / "metadata.json", metadata)
    # IRIS EXPLAIN: Call write_json(out / 'threshold_search.json', grid) using the existing explicit arguments.
    write_json(out / "threshold_search.json", grid)
    # IRIS EXPLAIN: Call write_json(out / 'split_manifest.json', split_manifest) using the existing explicit arguments.
    write_json(out / "split_manifest.json", split_manifest)
    # IRIS EXPLAIN: Return metadata to the caller; this ends the current function path.
    return metadata
