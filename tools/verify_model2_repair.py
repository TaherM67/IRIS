"""Verify the complete repaired inference API against its frozen audit records."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'IRIS_Models_v2'))
import numpy as np
from iris_models.contracts import CONTEXT_NUMERIC, FEATURES, read_jsonl, write_json
from iris_models.dataset import load_dataset, split_groups
from iris_models.grounded_controls import GroundedControlRecommender
from iris_models.training import control_metrics


def run(source, repair):
    data, _ = load_dataset(source / 'model_sessions.jsonl', source / 'synthetic_targets.jsonl', synthetic=True)
    split, _ = split_groups(data, 'campaign_id', 42)
    fit = data.iloc[list(split['train']) + list(split['selection'])]
    buckets = defaultdict(list)
    feature_cols = FEATURES + ['asset_type'] + CONTEXT_NUMERIC
    for _, row in fit.iterrows():
        buckets[tuple(row[k] for k in feature_cols)].append(tuple(row.controls))
    ambiguous = [values for values in buckets.values() if len(set(values)) > 1]
    original = json.loads((source / 'models/metadata.json').read_text())
    diagnosis = {'fit_fragments': len(fit), 'ambiguous_identical_input_groups': len(ambiguous),
                 'fit_fragments_in_ambiguous_groups': sum(map(len, ambiguous)),
                 'original_unsupported_controls': len(original['model2']['unsupported_controls']),
                 'original_validation_suppressed_controls': len(original['model2']['validation_suppressed_controls']),
                 'original_control_micro_recall': original['model2']['metrics']['micro_recall'],
                 'note': 'Only fitting data used for the collision diagnostic. Predicted scenario cannot recover missing asset-specific control links.'}
    write_json(repair / 'diagnosis.json', diagnosis)
    with zipfile.ZipFile(source / 'source_dataset.zip') as archive:
        load = lambda name: json.loads(archive.read('iris_dataset/' + name + '.json'))
        assets = {a['asset_id']: a for a in load('asset_inventory')['assets']}
        risks = {r['risk_id']: r for r in load('risk_register')['risks']}
        catalogue = load('security_controls')['controls']
        events = {a['alert_id']: {key: a.get(key) for key in ('alert_id', 'timestamp', 'mitre_technique')}
                  for a in load('siem_alerts')['alerts']}
    sessions = {s['session_id']: s for s in read_jsonl(source / 'model_sessions.jsonl')}
    frozen = read_jsonl(repair / 'audit_predictions.jsonl')
    service = GroundedControlRecommender.load(repair / 'grounded_model2.joblib')
    predictions, targets = [], []
    labels = sorted(c['control_id'] for c in catalogue)
    for record in frozen:
        session = sessions[record['session_id']]
        response = service.recommend(session, [events[eid] for eid in session['source_event_ids']],
            assets[session['asset_id']], [risks[r['risk_id']] for r in session['risk_snapshots']], catalogue)
        ids = {r['control_id'] for r in response['recommendations']}
        if ids != set(record['learned_controls']):
            raise AssertionError('Runtime differs from frozen audit: ' + record['session_id'])
        assert response['automatic_execution'] is False and response['release_eligible'] is False
        predictions.append([cid in ids for cid in labels])
        targets.append([cid in record['actual_synthetic_controls'] for cid in labels])
    metrics = control_metrics(np.asarray(targets), np.asarray(predictions), labels)
    results = json.loads((repair / 'results.json').read_text())
    assert metrics == results['revised_grounded_model2']
    example = json.loads((repair / 'example_request.json').read_text())
    write_json(repair / 'example_recommendations_verified.json', service.recommend(**example))
    write_json(repair / 'runtime_verification.json', {
        'all_audit_requests_replayed': len(frozen), 'runtime_equals_frozen_audit_predictions': True,
        'metrics_reproduced': True, 'thresholds_retuned': False,
        'demo_or_original_weights_modified': False,
        'inference_module_sha256': hashlib.sha256((ROOT / 'IRIS_Models_v2/iris_models/grounded_controls.py').read_bytes()).hexdigest(),
        'independent_expert_control_validation': False})
    print(json.dumps({'audit_requests_verified': len(frozen), 'diagnosis': diagnosis}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'artifacts/dataset_v2_run_20261029')
    parser.add_argument('--repair', type=Path, default=ROOT / 'artifacts/model2_fix_20261029')
    args = parser.parse_args()
    run(args.source, args.repair)
