"""Fit an explicitly experimental hospital classifier without splitting copied evidence.

The supplied annotations are unreviewed. A two-way, group-disjoint synthetic
experiment is possible; the reviewed five-role release protocol is not. Model
and confidence threshold are fixed before the holdout is evaluated. No expert
review, calibration, production release, or Model 2 refitting is claimed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'IRIS_Models_v2')]

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

from backend.input_contract import FILES, validate_inputs
from backend.scenarios import CLASSES, EXTRA_FEATURES, VERSION, rule_scenario
from backend.training_handoff import prepare_training
from iris_models.contracts import CATEGORICAL, FEATURES, NUMERIC, digest, write_json, write_jsonl

SEED = 20261114
PROFILE = 'iris_hospital_20261114'
THRESHOLD = 0.5


def grouped_holdout(rows):
    """Stratify whole connected groups using label counts, never fitted outcomes.

    Exhaustive enumeration is practical for the supplied 14 connected groups.
    Both roles need >=10 rows of every class. The policy targets 25% of rows,
    equally weights class fractions, and uses a seeded hash only to break ties.
    """
    grouped = defaultdict(Counter)
    for row in rows:
        grouped[row['experimental_group']][row['scenario_class']] += 1
    groups = sorted(grouped)
    if not 2 <= len(groups) <= 20:
        raise ValueError('This exhaustive protocol requires 2..20 independent groups')
    totals = Counter(row['scenario_class'] for row in rows)
    best = None
    for size in range(1, len(groups)):
        for selected in itertools.combinations(groups, size):
            counts = sum((grouped[g] for g in selected), Counter())
            if any(counts[c] < 10 or totals[c] - counts[c] < 10 for c in CLASSES):
                continue
            cost = (sum(abs(counts[c] / totals[c] - .25) for c in CLASSES)
                    + 4 * abs(sum(counts.values()) / len(rows) - .25))
            tie = hashlib.sha256((str(SEED) + '|'.join(selected)).encode()).hexdigest()
            candidate = (cost, tie, selected)
            if best is None or candidate < best:
                best = candidate
    if best is None:
        raise ValueError('No group-disjoint fit/test split supports every class')
    held = set(best[2])
    assignments = {g: 'test' if g in held else 'fit' for g in groups}
    for key in ('campaign_id', 'template_group'):
        roles = defaultdict(set)
        for row in rows:
            roles[row[key]].add(assignments[row['experimental_group']])
        if any(len(value) != 1 for value in roles.values()):
            raise ValueError(key + ' crosses the holdout boundary')
    features = defaultdict(set)
    for row in rows:
        features[json.dumps(row['features'], sort_keys=True)].add(assignments[row['experimental_group']])
    if any(len(value) != 1 for value in features.values()):
        raise ValueError('Identical observed features cross the holdout boundary')
    return assignments, dict(grouped)


def metrics(truth, labels, accepted):
    predicted = np.where(accepted, labels, 'ABSTAINED')
    benign = truth == 'benign'
    false_alarms = int(np.sum(benign & accepted & (labels != 'benign')))
    return dict(n=len(truth), coverage=float(accepted.mean()),
                accuracy_all_sessions=float(np.mean(predicted == truth)),
                accepted_accuracy=float(np.mean(labels[accepted] == truth[accepted])) if accepted.any() else None,
                macro_f1=float(f1_score(truth, predicted, labels=list(CLASSES), average='macro', zero_division=0)),
                benign_false_positive_rate=false_alarms / max(1, int(benign.sum())),
                benign_false_alarms=false_alarms, benign_support=int(benign.sum()),
                per_class=classification_report(truth, predicted, labels=list(CLASSES), output_dict=True, zero_division=0),
                confusion_labels=[*CLASSES, 'ABSTAINED'],
                confusion_matrix=confusion_matrix(truth, predicted, labels=[*CLASSES, 'ABSTAINED']).tolist(),
                validation_scope='Group-disjoint synthetic holdout with unreviewed generator annotations; not real-world accuracy',
                metric_semantics='Abstentions remain false negatives in class recall/F1 and count as incorrect in all-session accuracy.')


def train(dataset, out, *, experimental_synthetic=False):
    if not experimental_synthetic:
        raise ValueError('Unreviewed annotations require explicit --experimental-synthetic; reviewed release stays blocked')
    if out.exists():
        raise ValueError('Use a fresh output directory; fitted versions are immutable')
    paths = {key: dataset / 'data' / name for key, name in FILES.items()}
    qualification = validate_inputs(paths)
    if not qualification['valid'] or not qualification['readiness']['all_events_accounted_for']:
        raise ValueError('Hospital runtime qualification failed')
    labels_path = dataset / 'offline/training_labels.jsonl'
    for key in ('asset_inventory', 'risk_register'):
        if json.loads(paths[key].read_text())['data_provenance'] != 'synthetic':
            raise ValueError('Only declared synthetic data is allowed by this experiment')
    if any(json.loads(line).get('data_provenance') != 'synthetic'
           for line in paths['siem_alerts'].read_text().splitlines()):
        raise ValueError('Every observation must declare synthetic provenance')
    out.mkdir(parents=True)
    write_json(out / 'qualification.json', qualification)
    prepared = out / 'prepared'
    preparation = prepare_training(paths, labels_path, prepared)
    rows = sorted((json.loads(line) for line in (prepared / 'supervised_records.jsonl').read_text().splitlines()),
                  key=lambda row: row['session_id'])
    columns = FEATURES + EXTRA_FEATURES
    if any(set(row['features']) != set(columns) for row in rows):
        raise ValueError('Only the 23 observed features are allowed')
    assignments, group_support = grouped_holdout(rows)
    indexes = {role: np.array([i for i, row in enumerate(rows)
                              if assignments[row['experimental_group']] == role]) for role in ('fit', 'test')}
    manifest = dict(seed=SEED, protocol='fixed-logistic-regression-two-role-experimental-v1',
                    holdout_selection='Whole connected campaign/template/identical-feature groups; pre-fit class-count stratification, no model outcomes',
                    assignments=assignments, group_class_support=group_support,
                    session_ids={role: [rows[i]['session_id'] for i in ix] for role, ix in indexes.items()},
                    rows={role: len(ix) for role, ix in indexes.items()},
                    class_support={role: dict(Counter(rows[i]['scenario_class'] for i in ix)) for role, ix in indexes.items()},
                    features=columns, source_sha256=qualification['source_sha256'], labels_sha256=digest(labels_path),
                    hyperparameters=dict(algorithm='logistic_regression', C=1.0, class_weight='balanced', max_iter=1500),
                    threshold=THRESHOLD, calibration='Not fitted: insufficient independent template support for five roles',
                    annotation_review='Unreviewed synthetic references retained unchanged',
                    reviewed_five_role_fitting_ready=False, production_release_eligible=False)
    write_json(out / 'split_manifest.json', manifest)
    X = pd.DataFrame([row['features'] for row in rows], columns=columns)
    y = np.array([row['scenario_class'] for row in rows])
    model = Pipeline([
        ('features', ColumnTransformer([
            ('categorical', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL),
            ('numeric', StandardScaler(), NUMERIC + EXTRA_FEATURES)])),
        ('classifier', LogisticRegression(C=1.0, class_weight='balanced', max_iter=1500, random_state=SEED))])
    with threadpool_limits(limits=2):
        model.fit(X.iloc[indexes['fit']], y[indexes['fit']])
        probabilities = model.predict_proba(X.iloc[indexes['test']])
    labels = model.classes_[probabilities.argmax(axis=1)]
    accepted = probabilities.max(axis=1) >= THRESHOLD
    truth = y[indexes['test']]
    audit = metrics(truth, labels, accepted)
    old_profile = json.loads((ROOT / 'backend/model_profile_scenarios.json').read_text())
    old_dir = ROOT / old_profile['directory']
    if digest(old_dir / 'model1_scenario.joblib') != old_profile['model_sha256']:
        raise ValueError('Previous comparison model integrity check failed')
    previous = joblib.load(old_dir / 'model1_scenario.joblib')
    old_metadata = json.loads((old_dir / 'model1_metadata.json').read_text())
    old_probs = previous.predict_proba(X.iloc[indexes['test']])
    old_labels = previous.classes_[old_probs.argmax(axis=1)]
    old_accepted = old_probs.max(axis=1) >= old_metadata['threshold']
    rule_labels = []
    for i in indexes['test']:
        features = rows[i]['features']
        session = dict(sensor_healthy=True, features={k: features[k] for k in FEATURES},
                       scenario_evidence_schema=VERSION, scenario_evidence={k: features[k] for k in EXTRA_FEATURES})
        rule_labels.append(rule_scenario(session))
    rule_labels = np.array([label or 'ABSTAINED' for label in rule_labels])
    model_path = out / 'model1_scenario.joblib'
    joblib.dump(model, model_path, compress=3)
    metadata = dict(profile=PROFILE, schema=VERSION, features=columns,
                    aggregation_schema='iris-three-source-session-v1-window60', sklearn_version=sklearn.__version__,
                    model_sha256=digest(model_path), classes=list(model.classes_), algorithm='logistic_regression',
                    prediction_method='uncalibrated_experimental_model1', threshold=THRESHOLD, metrics=audit, synthetic=True,
                    categorical_vocab={key: sorted(X.iloc[indexes['fit']][key].unique().tolist()) for key in CATEGORICAL},
                    numeric_train_ranges={key: [float(X.iloc[indexes['fit']][key].min()), float(X.iloc[indexes['fit']][key].max())]
                                          for key in NUMERIC + EXTRA_FEATURES},
                    checks=dict(disjoint_campaigns=True, disjoint_templates=True, disjoint_identical_features=True,
                                all_classes_in_every_split=True, real_reviewed_data=False),
                    eligible_for_reviewed_advisory_release=False, source_identity_features_used=False,
                    training_labels_read_at_runtime=False, calibration='Not calibrated; fixed 0.5 threshold, no holdout tuning',
                    training_protocol=manifest['protocol'], annotation_review='unreviewed',
                    source_sha256=qualification['source_sha256'], labels_sha256=digest(labels_path))
    write_json(out / 'model1_metadata.json', metadata)
    write_jsonl(out / 'audit_predictions.jsonl', [dict(session_id=rows[i]['session_id'],
        experimental_group=rows[i]['experimental_group'], truth=str(t), top_candidate=str(label),
        prediction=str(label) if accept else 'ABSTAINED', confidence=float(probs.max()),
        class_probabilities={str(c): float(p) for c, p in zip(model.classes_, probs)})
        for i, t, label, accept, probs in zip(indexes['test'], truth, labels, accepted, probabilities)])
    release_blockers = ['Unreviewed synthetic annotations; no independently reviewed real data',
                        'Insufficient independent template support for the reviewed five-role protocol',
                        'Probability calibration has not been fitted or validated']
    if audit['benign_false_positive_rate'] > .05:
        release_blockers.append('Held-out benign false-positive rate exceeds the 5% review gate')
    results = dict(trained_at_utc=datetime.now(timezone.utc).isoformat(), model1=audit,
                   previous_model_same_holdout=metrics(truth, old_labels, old_accepted),
                   primary_rules_same_holdout=metrics(truth, rule_labels, rule_labels != 'ABSTAINED'),
                   model2=dict(status='retained_existing_grounded_model', refitted=False,
                               reason='No independently reviewed control targets; synthetic associations do not establish effectiveness'),
                   reviewed_five_role_protocol_ready=preparation['model1_ready_for_reviewed_synthetic_fitting'],
                   synthetic_experiment_completed=True, production_release_eligible=False,
                   labels_independently_reviewed=False, hyperparameters_tuned_on_test=False,
                   release_blockers=release_blockers,
                   limitations=['Only 14 connected groups; web exploitation appears in just two groups.',
                                'No separate selection/calibration/threshold fitting; fixed algorithm and threshold.',
                                'No independent label review or real-hospital validation.',
                                'Holdout metrics cannot establish deployment readiness or control effectiveness.'])
    write_json(out / 'RESULTS.json', results)
    profile = dict(profile=PROFILE, directory=str(out.relative_to(ROOT)).replace('\\', '/'),
                   metadata_sha256=digest(out / 'model1_metadata.json'), model_sha256=metadata['model_sha256'],
                   evidence_schema=VERSION, input_sha256=qualification['source_sha256'], mode='shadow_only', production_validated=False)
    write_json(ROOT / 'backend/model_profile_hospital.json', profile)
    print(json.dumps(dict(output=str(out), split_rows=manifest['rows'], model1=audit,
                          previous_model_same_holdout=results['previous_model_same_holdout'], model2=results['model2']), indent=2))
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=ROOT / 'datasets/iris_general_hospital_20261114')
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts/model_versions/iris_hospital_20261114')
    parser.add_argument('--experimental-synthetic', action='store_true')
    args = parser.parse_args()
    train(args.dataset.resolve(), args.out.resolve(), experimental_synthetic=args.experimental_synthetic)
