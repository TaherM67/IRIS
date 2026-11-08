"""Run the frozen Model 2 repair protocol without changing the live demo."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'IRIS_Models_v2'))
import joblib
import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from threadpoolctl import threadpool_limits

from iris_models.contracts import FEATURES, read_jsonl, write_json, write_jsonl
from iris_models.dataset import load_dataset, split_groups
from iris_models.grounded_controls import (
    PAIR_FEATURES, SCHEMA, GroundedControlRecommender, candidate_features, catalogue_digest,
)
from iris_models.training import control_frame, control_metrics, scenario_predictions


def select_threshold(truth, scores):
    options = []
    for threshold in np.arange(.05, .951, .025):
        prediction = scores >= threshold
        tp = int((prediction & truth).sum())
        fp = int((prediction & ~truth).sum())
        fn = int((~prediction & truth).sum())
        precision = tp / (tp+fp) if tp+fp else 0.
        f1 = 2*tp / (2*tp+fp+fn) if 2*tp+fp+fn else 0.
        options.append((precision >= .8, f1, precision, float(threshold)))
    best = max(options)
    return best[-1], {'precision_gate_passed': bool(best[0]), 'micro_f1': best[1], 'micro_precision': best[2]}


def fit_candidate_bank(xfit, yfit, xval, yval):
    """All candidate and threshold choices use the development subset only."""
    candidates = {
        'balanced_logistic': make_pipeline(StandardScaler(), LogisticRegression(
            C=1, class_weight='balanced', max_iter=1000, random_state=42)),
        'bounded_tree': DecisionTreeClassifier(max_depth=4, min_samples_leaf=20,
                                              class_weight='balanced', random_state=42),
    }
    reports, fitted = {}, {}
    for name, classifier in candidates.items():
        classifier.fit(xfit, yfit.ravel())
        scores = classifier.predict_proba(xval)[:, 1].reshape(yval.shape)
        threshold, report = select_threshold(yval, scores)
        reports[name] = {**report, 'threshold': threshold}
        fitted[name] = classifier
    name = max(candidates, key=lambda k: (reports[k]['precision_gate_passed'], reports[k]['micro_f1'],
                                         reports[k]['micro_precision']))
    return fitted[name], reports[name]['threshold'], name, reports


def run(args):
    if args.out.exists():
        raise ValueError('Choose a fresh output directory; prior experiments are immutable')
    baseline_meta = json.loads((args.source / 'models/metadata.json').read_text())
    data, _ = load_dataset(args.source / 'model_sessions.jsonl', args.source / 'synthetic_targets.jsonl', synthetic=True)
    split, _ = split_groups(data, 'campaign_id', 42)
    observed = {s['session_id']: s for s in read_jsonl(args.source / 'model_sessions.jsonl')}
    with zipfile.ZipFile(args.source / 'source_dataset.zip') as archive:
        load = lambda name: json.loads(archive.read('iris_dataset/' + name + '.json'))
        catalogue = load('security_controls')['controls']
        assets = {a['asset_id']: a for a in load('asset_inventory')['assets']}
        risks = {r['risk_id']: r for r in load('risk_register')['risks']}
        # Offline association IDs exist in the uploaded source but are removed
        # before ANY predictor receives a telemetry record.
        alert_allowlist = ['alert_id', 'timestamp', 'mitre_technique']
        events = {a['alert_id']: {k: a.get(k) for k in alert_allowlist} for a in load('siem_alerts')['alerts']}
    labels = sorted(c['control_id'] for c in catalogue)
    args.out.mkdir(parents=True)
    write_json(args.out / 'protocol.json', {
        'fit': ['original_train', 'original_selection'], 'selection': 'original_threshold',
        'final_control_target_audit': 'original_calibration', 'old_test': 'diagnostics only, excluded',
        'audit_control_targets_previously_used_in_control_training': False,
        'upstream_model1_predictions_used_by_repair': False,
        'static_control_membership_assumed_for_synthetic_replay': True,
        'protocol_sha256': hashlib.sha256((ROOT / 'docs/MODEL2_FIX_PROTOCOL.md').read_bytes()).hexdigest(),
        'source_model_sha256': baseline_meta['model_sha256'], 'synthetic': True})
    matrices, policy_predictions = [], []
    runtime_inputs = []
    for row in data.itertuples():
        session = observed[row.session_id]
        alerts = [events[eid] for eid in session['source_event_ids']]
        asset = assets[session['asset_id']]
        registered = [risks[r['risk_id']] for r in session['risk_snapshots']]
        ordered, matrix, policy = candidate_features(session, alerts, asset, registered, catalogue)
        assert ordered == labels
        matrices.append(matrix)
        policy_predictions.append([cid in policy for cid in labels])
        runtime_inputs.append((session, alerts, asset, registered))
    matrix = np.stack(matrices)
    targets = np.asarray([[cid in controls for cid in labels] for controls in data.controls], dtype=bool)
    fit = np.concatenate([split['train'], split['selection']])
    val, audit = split['threshold'], split['calibration']
    # Cohort membership is fixed before fitting. Never consult audit scores here.
    assert not set(data.iloc[fit].campaign_id) & set(data.iloc[audit].campaign_id)
    assert not set(data.iloc[val].campaign_id) & set(data.iloc[audit].campaign_id)
    keep = [i for i, f in enumerate(PAIR_FEATURES) if f not in {
        'candidate_registered_risk_count', 'candidate_matched_risk_count', 'candidate_matched_event_fraction'}]
    with threadpool_limits(limits=2):
        classifier, threshold, name, selection = fit_candidate_bank(
            matrix[fit].reshape(-1, len(PAIR_FEATURES)), targets[fit],
            matrix[val].reshape(-1, len(PAIR_FEATURES)), targets[val])
        ablated, ablated_threshold, ablated_name, ablated_selection = fit_candidate_bank(
            matrix[fit][:, :, keep].reshape(-1, len(keep)), targets[fit],
            matrix[val][:, :, keep].reshape(-1, len(keep)), targets[val])
    artifact = {'schema': SCHEMA, 'features': PAIR_FEATURES, 'classifier': classifier,
                'sklearn_version': sklearn.__version__, 'threshold': threshold,
                'catalogue_sha256': catalogue_digest(catalogue),
                'positive_fit_support': {cid: int(targets[fit, j].sum()) for j, cid in enumerate(labels)},
                'release_eligible': False, 'synthetic': True}
    model_path = args.out / 'grounded_model2.joblib'
    joblib.dump(artifact, model_path, compress=3)
    write_json(model_path.with_suffix('.json'), {'model_sha256': hashlib.sha256(model_path.read_bytes()).hexdigest(),
                'schema': SCHEMA, 'features': PAIR_FEATURES, 'release_eligible': False})
    write_json(args.out / 'selection.json', {'selected': name, 'candidates': selection,
                'without_grc_context_selected': ablated_name, 'without_grc_context_candidates': ablated_selection,
                'selection_rows': len(val), 'audit_used_for_selection': False})

    # Evaluate the new control-target audit once, after both choices are frozen.
    scores = classifier.predict_proba(matrix[audit].reshape(-1, len(PAIR_FEATURES)))[:, 1].reshape(targets[audit].shape)
    predicted = scores >= threshold
    ablated_scores = ablated.predict_proba(matrix[audit][:, :, keep].reshape(-1, len(keep)))[:, 1].reshape(targets[audit].shape)
    policy = np.asarray(policy_predictions, dtype=bool)[audit]
    truth = targets[audit]
    revised = control_metrics(truth, predicted, labels)
    without_grc = control_metrics(truth, ablated_scores >= ablated_threshold, labels)
    policy_metrics = control_metrics(truth, policy, labels)

    # Original Model 2 never fitted these control targets. Its upstream scenario
    # calibrator DID see these scenario labels previously, so rebuild calibration
    # on development rows before the like-for-like control comparison.
    baseline_bundle = joblib.load(args.source / 'models/models.joblib')
    ix = np.arange(len(val))
    with threadpool_limits(limits=2):
        scenario = CalibratedClassifierCV(FrozenEstimator(baseline_bundle['scenario_base_pipeline']),
            method='sigmoid', ensemble=False, cv=[(ix, ix)]).fit(data.iloc[val][FEATURES], data.iloc[val].scenario_class)
    scenario_labels = scenario_predictions(scenario, data.iloc[audit][FEATURES], baseline_meta['model1']['threshold'])
    old_controls = baseline_bundle['control_model']
    z = old_controls['transformer'].transform(control_frame(data.iloc[audit], scenario_labels))
    old = np.zeros_like(truth)
    for j, cid in enumerate(labels):
        if cid in old_controls['classifiers']:
            clf = old_controls['classifiers'][cid]
            old[:, j] = clf.predict_proba(z)[:, list(clf.classes_).index(1)] >= old_controls['thresholds'][cid]
    original_metrics = control_metrics(truth, old, labels)
    results = {'synthetic': True, 'control_targets': 'supplied synthetic associations, not expert recommendations',
               'fit_fragments': len(fit), 'selection_fragments': len(val), 'audit_fragments': len(audit),
               'audit_origin': 'previously unused Model 2 calibration control targets',
               'selected_algorithm': name, 'threshold': threshold,
               'original_model2_same_audit': original_metrics,
               'revised_grounded_model2': revised, 'without_grc_membership_ablation': without_grc,
               'deterministic_catalogue_matching_baseline': policy_metrics,
               'catalogue_size': len(labels),
               'controls_with_positive_audit_support': int((truth.sum(axis=0) > 0).sum()),
               'model2_exceeds_catalogue_baseline_f1': revised['micro_f1'] > policy_metrics['micro_f1'],
               'release_eligible': False, 'automatic_execution': False,
               'limitations': ['Data reused from an earlier study; this is internal validation, not a new external dataset.',
                   'Matched-risk membership is closely related to the deterministic synthetic label generator.',
                   'Improved synthetic association agreement is not independent AI efficacy validation.',
                   'Control membership history is absent: static membership is an explicit synthetic assumption.',
                   'Original Model 1 is not changed or deployed.']}
    write_json(args.out / 'results.json', results)
    write_jsonl(args.out / 'audit_predictions.jsonl', [
        {'session_id': str(data.iloc[ix].session_id), 'campaign_id': str(data.iloc[ix].campaign_id),
         'actual_synthetic_controls': [cid for j, cid in enumerate(labels) if truth[i, j]],
         'learned_controls': [cid for j, cid in enumerate(labels) if predicted[i, j]],
         'catalogue_policy_controls': [cid for j, cid in enumerate(labels) if policy[i, j]]}
        for i, ix in enumerate(audit)])
    service = GroundedControlRecommender.load(model_path)
    sample_ix = next(int(i) for i in audit if predicted[list(audit).index(i)].any())
    example = service.recommend(*runtime_inputs[sample_ix], catalogue)
    write_json(args.out / 'example_recommendations.json', example)
    write_json(args.out / 'example_request.json', {'session': runtime_inputs[sample_ix][0],
        'alerts': runtime_inputs[sample_ix][1], 'asset': runtime_inputs[sample_ix][2],
        'registered_risks': runtime_inputs[sample_ix][3], 'catalogue': catalogue})
    print(json.dumps({k: {m: v[m] for m in ('micro_precision', 'micro_recall', 'micro_f1', 'exact_set_accuracy')}
                    for k, v in results.items() if isinstance(v, dict)}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'artifacts/dataset_v2_run_20261029')
    parser.add_argument('--out', type=Path, required=True)
    run(parser.parse_args())
