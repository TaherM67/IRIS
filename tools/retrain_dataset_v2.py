"""Offline synthetic-v2 adapter and isolated two-model training.

Never installs a model into the demo. Association IDs are weak targets only.
The uploaded ZIP is read as data; its Python scripts are never executed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile
import joblib
from importlib.metadata import version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'IRIS_Models_v2'))
from iris_models.contracts import CLASSES, digest, read_jsonl, write_json, write_jsonl
from iris_models.three_sources import integrate
from iris_models.training import train


def write_evaluation_files(out):
    """Replay the frozen test predictions and package an auditable experiment."""
    import numpy as np
    from iris_models.dataset import load_dataset, split_groups
    from iris_models.training import scenario_metrics, scenario_predictions, control_frame, control_metrics
    metadata = json.loads((out / 'models/metadata.json').read_text())
    split_manifest = json.loads((out / 'models/split_manifest.json').read_text())
    split_manifest['claim'] = metadata['split']['claim']
    write_json(out / 'models/split_manifest.json', split_manifest)
    data, _ = load_dataset(out / 'model_sessions.jsonl', out / 'synthetic_targets.jsonl', synthetic=True)
    split, _ = split_groups(data, 'campaign_id', 42)
    test = data.iloc[split['test']]
    bundle = joblib.load(out / 'models/models.joblib')
    predicted = scenario_predictions(bundle['scenario_model'], test[metadata['features']], metadata['model1']['threshold'])
    if scenario_metrics(test.scenario_class, predicted) != metadata['model1']['metrics']:
        raise ValueError('Frozen classifier results failed reproducibility check')
    model = bundle['control_model']
    if model is None:
        raise ValueError('Requested Model 2 did not train')
    labels = model['labels']
    z = model['transformer'].transform(control_frame(test, predicted))
    predicted_controls = np.zeros((len(test), len(labels)), dtype=np.int8)
    for j, cid in enumerate(labels):
        if cid in model['classifiers']:
            classifier = model['classifiers'][cid]
            scores = classifier.predict_proba(z)[:, list(classifier.classes_).index(1)]
            predicted_controls[:, j] = scores >= model['thresholds'][cid]
    truth = np.asarray([[int(cid in controls) for cid in labels] for controls in test.controls], dtype=np.int8)
    if control_metrics(truth, predicted_controls, labels) != metadata['model2']['metrics']:
        raise ValueError('Frozen control results failed reproducibility check')
    records = []
    for i, row in enumerate(test.itertuples()):
        records.append({'session_id': row.session_id, 'campaign_id': row.campaign_id,
                        'run_id': row.run_id, 'actual_scenario': row.scenario_class,
                        'predicted_scenario': str(predicted[i]),
                        'synthetic_control_targets': list(row.controls),
                        'predicted_controls': [cid for j, cid in enumerate(labels) if predicted_controls[i, j]]})
    write_jsonl(out / 'test_predictions.jsonl', records)
    write_json(out / 'replay_verification.json', {'model1_metrics_reproduced': True,
               'model2_metrics_reproduced': True, 'test_rows': len(test),
               'test_thresholds_retuned': False, 'deployment_changed': False})
    (out / 'requirements.txt').write_text('\n'.join(f'{name}=={version(name)}' for name in
        ['numpy', 'pandas', 'scikit-learn', 'joblib', 'threadpoolctl']) + '\n')
    m1, m2 = metadata['model1'], metadata['model2']
    report = f'''# IRIS dataset v2 retraining results

Both models were retrained using the supplied synthetic dataset. No demo model,
backend manifest, dashboard or runtime state was replaced. Results are not directly
comparable to the older 135-session experiment because dataset, catalogue and test
composition differ. No test-set tuning was performed.

## Recorded results

| Measure | Result |
| --- | ---: |
| Selected Model 1 | {m1['algorithm']} |
| Model 1 test sessions | {m1['metrics']['n']} |
| Model 1 accuracy | {m1['metrics']['accuracy_all_sessions']:.4%} |
| Model 1 macro F1 | {m1['metrics']['macro_f1']:.6f} |
| Model 1 coverage | {m1['metrics']['coverage']:.2%} |
| Benign false alarms | {m1['metrics']['benign_false_alarms']} / {m1['metrics']['benign_support']} |
| Model 2 micro precision | {m2['metrics']['micro_precision']:.6f} |
| Model 2 micro recall | {m2['metrics']['micro_recall']:.6f} |
| Model 2 micro F1 | {m2['metrics']['micro_f1']:.6f} |
| Model 2 exact set accuracy | {m2['metrics']['exact_set_accuracy']:.4%} |
| Model 2 Hamming loss | {m2['metrics']['hamming_loss']:.6f} |
| Model 2 macro F1 over 120 controls | {m2['metrics']['macro_f1_all_catalogue_controls']:.6f} |
| Controls with positive test support | {sum(v['test_positive'] > 0 for v in m2['support'].values())} / 120 |

Model 1 selection scores are in metadata. The fixed selection order prefers the
simpler candidate within 0.01 of the best score; Logistic Regression and Random
Forest tied in this run. The selected classifier is NOT Random Forest.

Confusion matrix rows are actual benign, credential access and reconnaissance;
columns are predicted benign, credential access, reconnaissance and abstention:

{json.dumps(m1['metrics']['confusion_matrix'][:3])}

The ten errors are credential-access fragments labeled benign. Zero benign false
alarms in 119 test fragments does not establish a zero real-world false-positive
rate. The saved Wilson interval quantifies binomial, not campaign-adjusted,
uncertainty. Both release eligibility flags are false. Model 2 fails its precision,
F1 and support checks and must not be deployed as trusted control advice.

## Data preparation and limits

535 assets, 2,372 risks and 120 controls enter the adapter. There are 6,764 raw
alerts; 99 fully identical redeliveries with different delivery IDs are removed.
The remaining 6,665 events include 131 unresolved-asset events, which are not
trained. There are 4,911 risk-history snapshots. The source has 1,340 labeled
sessions: 520 benign, 380 credential access, 380 reconnaissance, 60 unknown asset.
The existing account, asset, family and 60-second inactivity sessionizer produces
2,985 matched fragments. All fragments of each source session stay in one split.
Report the fragment denominator, not 2,985 independent campaigns.

Split row counts: {json.dumps(metadata['split']['rows'])}.
Group separation retains the 70 supplied attack campaigns and uses recurring
observed source-set proxies for benign activity, whose campaign IDs were null.
Category combinations serve only as legacy template-group metadata, not a
template-family holdout or a predictor. Multi-target reconnaissance is explicitly
present in the supplied generator; its fragments retain their source annotation.
The saved data-quality report records repeated feature vectors; these are common
across short/single-event fragments and limit the strength of generalization
claims even with group separation. Authorized-scan metadata may distinguish easy
synthetic cases. There is no organization, time or template-family external test.

Model 2 targets are unions of the supplied event association control IDs. They
are weak synthetic relevance targets, not independent expert recommendations or
proof of control effectiveness. Legacy `reviewed` flags identify the named
synthetic adapter, NOT a human reviewer. No ATT&CK IDs, control IDs, risk IDs,
held-out support flags or labels enter model features. The global catalogue
effectiveness and implementation fields are not asset-specific and are excluded.
They must not be used to claim measured risk reduction.

Historical likelihood/impact use supplied risk history, not current residual
values. Synthetic knowledge timestamps are assumed equal to validity starts;
sensor health is assumed for generated data. These assumptions cannot be copied
into a real-data connector. Criticality maps Low=1, Medium=3, High=4, Critical=5.

## Reproduce without replacing the demo

From the IRIS repository root, with the pinned environment installed:

```bash
python tools/retrain_dataset_v2.py --dataset artifacts/dataset_v2_run_20261028/source_dataset.zip --out artifacts/my_new_v2_run
python -m unittest tools.test_retrain_dataset_v2 -v
```

Use a NEW output directory. The script refuses to overwrite an experiment.
The bundle ZIP contains the source archive, adapted three-source inputs, prepared
sessions, weak targets, catalogue, weights, metrics, split manifest and replayed
test predictions. The source archive scripts are never executed by this adapter.
Joblib files are executable serialization: load only this locally trained trusted
artifact. The 120-control catalogue differs from the existing demo catalogue;
deploying it requires a separate reviewed integration, not just copying weights.
'''
    (out / 'README.md').write_text(report, encoding='utf-8')
    paths = sorted(x for x in out.rglob('*') if x.is_file() and x.name != 'retraining_bundle.zip')
    with zipfile.ZipFile(out / 'retraining_bundle.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, path.relative_to(out))


def load_upload(path):
    """Read only the declared JSON members and verify their supplied hashes."""
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read('iris_dataset/dataset_manifest.json'))
        if manifest.get('synthetic') is not True:
            raise ValueError('This adapter is synthetic-only')
        for row in manifest['files']:
            payload = archive.read('iris_dataset/' + row['file'])
            if hashlib.sha256(payload).hexdigest() != row['sha256']:
                raise ValueError('Source checksum mismatch: ' + row['file'])
        return {name: json.loads(archive.read('iris_dataset/' + name + '.json'))
                for name in ['asset_inventory', 'risk_register', 'security_controls', 'siem_alerts', 'training_labels']}


def normalize_alert(row):
    """Explicit telemetry mapping; no scenario, risk IDs or control targets."""
    category = row['category']
    family = ('authentication' if category in {'authentication_failed', 'authentication_success', 'brute_force', 'kerberos'}
              else 'network' if category in {'network_scan', 'web_scan', 'network_anomaly', 'enumeration'}
              else 'system')
    level = ({1: 10, 2: 7, 3: 4}[row['source_severity']]
             if row['source'] == 'suricata' else row['source_severity'])
    return {'event_id': row['alert_id'], 'timestamp': row['timestamp'],
            'asset_id': row['associations'].get('asset_id'), 'destination_ip': row['dst_ip'],
            'source_ip': row['src_ip'], 'agent_name': row['hostname'],
            'account': row.get('user'), 'event_family': family,
            'protocol': row['protocol'], 'rule_id': row['rule_id'], 'rule_level': level,
            'outcome': ('success' if category == 'authentication_success' else 'failed'
                        if category in {'authentication_failed', 'brute_force'} else 'unknown'),
            'run_id': row['session_id'], 'campaign_id': 'unassigned-runtime-group',
            'sensor_healthy': True, 'data_provenance': 'synthetic'}


def adapt(data, out):
    """Integrate historical context before the unchanged session feature builder."""
    converted = out / 'adapted'
    converted.mkdir(parents=True)
    criticality = {'Low': 1, 'Medium': 3, 'High': 4, 'Critical': 5}
    assets = []
    for asset in data['asset_inventory']['assets']:
        assets.append({'asset_id': asset['asset_id'], 'asset_version_id': asset['asset_id'] + '-V1',
                       'hostname': asset['hostname'], 'ip_addresses': [asset['ip_address']],
                       'asset_type': asset['asset_type'], 'criticality': criticality[asset['criticality']],
                       'zone': asset['network_zone'], 'owner': asset['owner'],
                       'valid_from': asset['valid_from'], 'valid_to': asset['valid_to'],
                       'recorded_at': asset['valid_from']})
    risks = []
    for risk in data['risk_register']['risks']:
        history = sorted(risk['history'], key=lambda x: x['valid_from'])
        if len({x['valid_from'] for x in history}) != len(history):
            raise ValueError('Ambiguous risk history: ' + risk['risk_id'])
        for i, version in enumerate(history):
            risks.append({'risk_id': risk['risk_id'], 'risk_version_id': risk['risk_id'] + '-V' + str(i+1),
                          'asset_id': risk['asset_id'], 'risk_category': risk['category'],
                          'likelihood': version['likelihood'], 'impact': version['impact'],
                          'valid_from': version['valid_from'],
                          'valid_to': history[i+1]['valid_from'] if i+1 < len(history) else None,
                          'recorded_at': version['valid_from'], 'control_states': {},
                          'active_exception_control_ids': []})
    write_json(converted / 'asset_inventory.json', {'schema_version': 'iris-asset-inventory-v1', 'data_provenance': 'synthetic', 'records': assets})
    write_json(converted / 'risk_register.json', {'schema_version': 'iris-risk-register-v1', 'data_provenance': 'synthetic', 'records': risks})
    # The generator explicitly describes redeliveries with NEW alert IDs.
    # Collapse only full-content equality excluding that delivery ID.
    seen, alerts, retained, duplicates = {}, [], {}, []
    for row in data['siem_alerts']['alerts']:
        key = json.dumps({k: v for k, v in row.items() if k != 'alert_id'}, sort_keys=True)
        if key in seen:
            duplicates.append({'removed': row['alert_id'], 'retained': seen[key]})
            continue
        seen[key] = row['alert_id']
        retained[row['alert_id']] = row
        alerts.append(normalize_alert(row))
    write_jsonl(converted / 'siem_alerts.jsonl', alerts)
    unified, sessions, integration = integrate(converted / 'asset_inventory.json', converted / 'risk_register.json', converted / 'siem_alerts.jsonl')
    write_json(out / 'integration_report.json', integration)
    write_json(out / 'duplicate_deliveries.json', duplicates)
    return sessions, retained


def attach_synthetic_targets(sessions, retained, labels, controls):
    """Label prepared sub-sessions by their explicit source-event membership.

    Original campaign IDs are retained for attack sessions. Benign groups use
    recurring observed source IPs, not independently invented campaign IDs.
    All sub-sessions of an original session must share a partition group.
    """
    annotations = {x['session_id']: x for x in labels}
    if len(annotations) != len(labels):
        raise ValueError('Duplicate annotation session IDs')
    originals = defaultdict(list)
    for row in retained.values():
        originals[row['session_id']].append(row)
    groups = {}
    for sid, rows in originals.items():
        label = annotations[sid]
        if label['campaign_id']:
            groups[sid] = label['campaign_id']
        else:
            sources = sorted({x['src_ip'] for x in rows})
            groups[sid] = 'BENIGN-SOURCE-' + hashlib.sha256('|'.join(sources).encode()).hexdigest()[:16]
    observations, reviews, excluded = [], [], []
    for session in sessions:
        rows = [retained[eid] for eid in session['source_event_ids']]
        ids = {x['session_id'] for x in rows}
        if len(ids) != 1:
            raise ValueError('Prepared session mixes source sessions')
        sid = ids.pop()
        label = annotations[sid]
        if label['scenario'] not in CLASSES:
            excluded.append({'session_id': session['session_id'], 'reason': 'Unsupported or unresolved source label'})
            continue
        # Do not accept an unknown-asset match against the annotation plane.
        if session['asset_id'] != label['primary_asset_id']:
            # The supplied generator explicitly creates multi-target internal
            # reconnaissance sweeps. Other classes must match the primary asset.
            if label['scenario'] != 'reconnaissance' or any(
                    row['associations']['asset_id'] != session['asset_id'] for row in rows):
                raise ValueError('Prepared asset disagrees with annotation')
        targets = sorted({c for row in rows for c in row['associations']['control_ids']})
        if set(targets) - controls:
            raise ValueError('Control target absent from supplied catalogue')
        session = {**session, 'campaign_id': groups[sid], 'source_session_id': sid,
                   'annotation_primary_asset_id': label['primary_asset_id']}
        observations.append(session)
        # Legacy trainer calls these flags reviewed/verified. Here the named
        # reviewer is explicitly an automatic synthetic annotation adapter,
        # never an assertion of human/expert review; release is blocked.
        reviews.append({'session_id': session['session_id'], 'run_id': session['run_id'],
                        'campaign_id': groups[sid], 'scenario_class': label['scenario'],
                        'template_group': 'synthetic-v2-category-proxy-' + '-'.join(sorted({r['category'] for r in originals[sid]})),
                        'label_verified': True, 'reviewer': 'synthetic-v2-supplied-scenario-adapter',
                        'controls_reviewed': True, 'control_reviewer': 'synthetic-association-adapter-not-human-reviewed',
                        'recommended_control_ids': targets, 'target_provenance': 'supplied_synthetic_associations'})
    return observations, reviews, excluded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('Choose a new run directory; existing runs are never overwritten')
    data = load_upload(args.dataset)
    args.out.mkdir(parents=True)
    shutil.copyfile(args.dataset, args.out / 'source_dataset.zip')
    catalog = args.out / 'control_catalog.csv'
    with catalog.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=['Control_ID', 'Control_Name', 'Recommended_Action'])
        writer.writeheader()
        for row in data['security_controls']['controls']:
            writer.writerow({'Control_ID': row['control_id'], 'Control_Name': row['name'],
                             'Recommended_Action': 'Review applicability and implementation of ' + row['name']})
    sessions, retained = adapt(data, args.out)
    observed, reviews, exclusions = attach_synthetic_targets(sessions, retained, data['training_labels']['labels'],
                                                           {x['control_id'] for x in data['security_controls']['controls']})
    write_jsonl(args.out / 'model_sessions.jsonl', observed)
    write_jsonl(args.out / 'synthetic_targets.jsonl', reviews)
    provenance = {'source_sha256': digest(args.dataset), 'synthetic': True,
                  'model2_targets': 'union of supplied association control IDs over each prepared session',
                  'human_reviewed': False, 'original_session_count': len(data['training_labels']['labels']),
                  'prepared_sessions': len(observed), 'source_scenario_counts': dict(Counter(x['scenario'] for x in data['training_labels']['labels'])),
                  'assumptions': ['Synthetic recorded_at equals valid_from because knowledge timestamps are absent.',
                                  'History likelihood and impact are used as supplied, not current residual values.',
                                  'Synthetic sensor health assumed true; this is not measured collector health.',
                                  'Criticality Low=1 Medium=3 High=4 Critical=5.',
                                  'Global control implementation state/effectiveness is not asset-specific and is excluded.',
                                  'Control IDs, risk IDs, ATT&CK IDs, held-out flags and labels are not predictor fields.',
                                  'Campaign holdout for supplied attack campaigns; benign groups are recurring-source-set proxies.',
                                  'Template groups are category-combination proxies; this is not a template-family holdout.',
                                  'Multi-target reconnaissance is labeled by source-event membership as defined in the supplied generator.',
                                  'Source sessions may split by account, event family, temporal gap or context; all fragments share a group.'],
                  'excluded_prepared_sessions': exclusions,
                  'not_deployed': True}
    write_json(args.out / 'adaptation_report.json', provenance)
    result = train(args.out / 'model_sessions.jsonl', args.out / 'synthetic_targets.jsonl', catalog,
                   args.out / 'models', synthetic=True, group_by='campaign_id', seed=42)
    result['evaluation_scope'] = provenance
    for key in ('model1', 'model2'):
        result[key]['eligible_for_reviewed_advisory_release'] = False
    result['model2']['target_provenance'] = 'synthetic associations, not independent expert recommendations'
    result['model2']['checks_are_synthetic_proxy_checks'] = True
    result['split']['claim'] = 'Synthetic attack-campaign and benign-source-proxy holdout; not real-world validation'
    write_json(args.out / 'models/metadata.json', result)
    write_json(args.out / 'evaluation_summary.json', {
        'synthetic': True, 'deployed': False, 'model1': result['model1'], 'model2': result['model2'],
        'split': result['split'], 'data_quality': result['data_quality'],
        'source_sha256': provenance['source_sha256']})
    write_evaluation_files(args.out)
    print(json.dumps({'model1_accuracy': result['model1']['metrics']['accuracy_all_sessions'],
                      'model2_micro_f1': result['model2'].get('metrics', {}).get('micro_f1'),
                      'splits': result['split']['rows']}, indent=2))


if __name__ == '__main__':
    main()
