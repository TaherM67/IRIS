"""Run every session in an isolated backend and save exact coverage diagnostics.

This is an integration check, not a new accuracy evaluation or training run.
Existing accounts, approvals and databases are never opened or changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.config import Settings
from backend.core import Engine, INPUTS
from backend.coverage import session_outcome
from backend.model_adapter import ModelAdapter, digest
from backend.source_inputs import read_alerts

DATASETS = {'hospital': ROOT/'datasets/iris_general_hospital_20261114/data',
            'expanded': ROOT/'demo/scenarios_v2', 'legacy': ROOT/'demo/data',
            'v2': ROOT/'DATA/iris_dataset'}
PROFILES = ('auto', 'legacy', 'iris_models_20261030', 'iris_scenarios_20261109', 'iris_hospital_20261114')


def run_check(paths, profile='auto'):
    """Persist and read back all cases; source hashes must remain unchanged."""
    before = {key:digest(path) for key,path in paths.items()}
    with tempfile.TemporaryDirectory(prefix='iris-input-coverage-') as temp:
        keys = {role:('ISOLATED-TEST-ONLY-'+role).ljust(48, '0') for role in ('admin','soc','grc')}
        adapter = None if profile=='auto' else ModelAdapter(profile=profile)
        engine = Engine(Settings(Path(temp), keys), adapter=adapter, auto_profile=profile=='auto')
        summary = engine.run(paths, 'admin')
        cases = engine.store.cases(run_id=summary['run_id'], limit=engine.settings.max_sessions)
        assert cases['total'] == len(cases['items']) == summary['sessions']
        outcomes = [session_outcome(c['session'], c['prediction'], engine.adapter.metadata)
                    for c in cases['items']]
        event_ids = [eid for c in cases['items'] for eid in c['session']['source_event_ids']]
        assert len(event_ids) == len(set(event_ids)), 'An event belongs to multiple model sessions'
        for c in cases['items']:
            assert not c['prediction']['automatic_execution']
            assert not c['prediction']['official_risk_register_write']
    after = {key:digest(path) for key,path in paths.items()}
    assert before == after, 'Original input changed during the check'
    raw = read_alerts(paths['siem_alerts'])
    source_ids = {r.get('session_id') for r in raw if isinstance(r,dict) and r.get('session_id')}
    return {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
            'requested_profile': profile, 'selected_profile': summary['model_profile'],
            'model_coverage': summary['model_coverage'], 'integration': summary['integration'],
            'shadow_class_counts': summary['shadow_class_counts'],
            'raw_source_session_identifiers': len(source_ids) if source_ids else None,
            'events_in_model_sessions': len(event_ids), 'every_persisted_session_checked': True,
            'session_event_membership_unique': True, 'source_files_unchanged': True,
            'operational_source_sha256': before, 'existing_demo_state_opened': False,
            'training_labels_read': False, 'accuracy_evaluated': False,
            'model_weights_changed': False, 'automatic_execution': False}, outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=DATASETS, default='expanded')
    parser.add_argument('--model-profile', choices=PROFILES, default='auto')
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--risks', type=Path)
    parser.add_argument('--alerts', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    overrides = (args.assets, args.risks, args.alerts)
    if any(overrides) and not all(overrides):
        parser.error('Supply --assets, --risks and --alerts together')
    if all(overrides):
        paths = dict(zip(INPUTS, overrides))
    else:
        base = DATASETS[args.dataset]
        paths = {key:base/name for key,name in INPUTS.items()}
        if args.dataset == 'v2':
            paths['siem_alerts'] = base/'siem_alerts.json'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = args.out or ROOT/'.local/input_coverage'/(stamp+'-'+uuid.uuid4().hex[:6])
    if out.exists():
        parser.error('Choose a fresh --out directory; previous results are preserved')
    try:
        report, outcomes = run_check(paths, args.model_profile)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, 'Input coverage check: '+str(exc)+'\n')
    out.mkdir(parents=True, exist_ok=False)
    (out/'coverage.json').write_text(json.dumps(report, indent=2, allow_nan=False)+'\n', encoding='utf-8')
    with (out/'session_outcomes.jsonl').open('w', encoding='utf-8') as stream:
        for row in outcomes:
            stream.write(json.dumps(row, allow_nan=False)+'\n')
    print(json.dumps({'selected_profile':report['selected_profile'],
                     'model_coverage':report['model_coverage'],
                     'source_files_unchanged':True, 'results':str(out.resolve())}, indent=2))


if __name__ == '__main__':
    main()
