"""Versioned 2026-10-30 inference; rules and approval writes stay independent."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import sklearn

from .config import ROOT
from .grounded_context import GroundedContext, SCHEMA as CONTEXT_SCHEMA
from iris_models.contracts import CATEGORICAL, FEATURES, FEATURE_SCHEMA, NUMERIC, digest, frame, utc_now
from iris_models.runtime import ModelService

PROFILE = Path(__file__).with_name('model_profile_20261030.json')
LEGACY_CATALOGUE = ROOT / 'IRIS_Models_v2/iris_models/data/control_catalog.csv'
STATES = {'implemented', 'partial', 'missing', 'not_assessed', 'compensating', 'exception', 'unknown'}
VALID_TECHNIQUE = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?')


def not_run(reason, missing=()):
    return {'source': 'not_run', 'recommendations': [], 'reason': reason,
            'missing_fields': sorted(set(missing)), 'release_eligible': False,
            'automatic_execution': False, 'requires_human_approval': True,
            'validation_scope': 'Experimental synthetic association matching; not control efficacy'}


def public_review(review):
    """Business-facing review fields; no raw telemetry or learned scores."""
    fields = ('source', 'reason', 'missing_fields', 'validation_scope', 'membership_basis',
              'release_eligible', 'automatic_execution', 'requires_human_approval', 'score_meaning')
    result = {key: review[key] for key in fields if key in review}
    result['recommendations'] = [{key: item[key] for key in (
        'control_id', 'name', 'reason', 'source', 'current_state', 'action_type',
        'implementation_state_known', 'implementation_state_source', 'requires_human_approval', 'warnings') if key in item}
        for item in review.get('recommendations', [])]
    return result


class GroundedModelAdapter:
    def __init__(self, model_dir=None, profile_path=PROFILE):
        profile_path = Path(profile_path)
        profile = json.loads(profile_path.read_text(encoding='utf-8'))
        self.directory = Path(model_dir) if model_dir else ROOT / profile['directory']
        package_manifest = self.directory / 'SHA256.json'
        if digest(package_manifest) != profile['package_manifest_sha256']:
            raise ValueError('Pinned model package manifest mismatch')
        pinned = json.loads(package_manifest.read_text(encoding='utf-8'))
        for name, expected in pinned.items():
            path = (self.directory / name).resolve()
            if not path.is_relative_to(self.directory.resolve()) or digest(path) != expected:
                raise ValueError('Pinned model package mismatch: ' + name)
        m1 = json.loads((self.directory / 'model1_metadata.json').read_text(encoding='utf-8'))
        m2 = json.loads((self.directory / 'grounded_model2.json').read_text(encoding='utf-8'))
        if (m1['features'] != FEATURES or m1['feature_schema'] != FEATURE_SCHEMA
                or m1['aggregation_schema'] != profile['aggregation_schema']):
            raise ValueError('Model 1/session feature schema mismatch')
        if sklearn.__version__ != m1['sklearn_version']:
            raise ValueError('Use scikit-learn ' + m1['sklearn_version'] + '; no dependency changes were made')
        # All module and artifact bytes were checked before importing/loading.
        package_name = '_iris_grounded_' + hashlib.sha256(str(self.directory.resolve()).encode()).hexdigest()[:12]
        if package_name not in sys.modules:
            spec = importlib.util.spec_from_file_location(package_name, self.directory / 'reference_code/__init__.py',
                                                       submodule_search_locations=[str(self.directory / 'reference_code')])
            module = importlib.util.module_from_spec(spec)
            sys.modules[package_name] = module
            spec.loader.exec_module(module)
        self.reference = importlib.import_module(package_name + '.grounded_controls')
        if m2['schema'] != self.reference.SCHEMA or m2['features'] != self.reference.PAIR_FEATURES:
            raise ValueError('Model 2 candidate feature schema mismatch')
        self.catalogue = json.loads((self.directory / 'control_catalogue.json').read_text(encoding='utf-8'))
        self.controls = {row['control_id']: row for row in self.catalogue}
        if len(self.catalogue) != 120 or len(self.controls) != 120:
            raise ValueError('The pinned 120-control catalogue is required')
        self.scenario = joblib.load(self.directory / 'model1_scenario.joblib')
        self.grounded = self.reference.GroundedControlRecommender.load(self.directory / 'grounded_model2.joblib')
        if self.reference.catalogue_digest(self.catalogue) != self.grounded.artifact['catalogue_sha256']:
            raise ValueError('Model 2 catalogue digest mismatch')
        if list(self.scenario.classes_) != m1['classes'] or self.grounded.artifact['classifier'].n_features_in_ != 25:
            raise ValueError('Trained model feature/classes contract mismatch')
        combined = hashlib.sha256(json.dumps({'model1': m1['model_sha256'], 'model2': m2['model_sha256']}, sort_keys=True).encode()).hexdigest()
        self.metadata = {'model_sha256': combined, 'package_version': profile['profile'],
                         'aggregation_schema': profile['aggregation_schema'],
                         'data_quality': {'synthetic': True}, 'model1': m1, 'model2': m2}
        self.artifact_identity = hashlib.sha256((digest(profile_path) + digest(package_manifest) + profile['adapter_schema']).encode()).hexdigest()
        self.loaded_at = utc_now()
        # Keep the existing rule/catalogue advice, without running the old ML weights.
        primary_manifest = json.loads((ROOT / 'backend/model_manifest.json').read_text(encoding='utf-8'))
        if digest(LEGACY_CATALOGUE) != primary_manifest['catalogue_sha256']:
            raise ValueError('Pinned primary control catalogue mismatch')
        self.service = ModelService(None, LEGACY_CATALOGUE)
        self.service.load_error = None

    def enrich_sessions(self, sessions, paths):
        source = GroundedContext(paths)
        return [source.attach(session) for session in sessions]

    def _review(self, session):
        if session.get('data_provenance') != 'synthetic':
            return not_run('Model 2 is unreleased and accepts explicit synthetic provenance only', ['session.data_provenance=synthetic'])
        if session.get('sensor_healthy') is not True or session.get('aggregation_schema') != self.metadata['aggregation_schema']:
            return not_run('Model 2 requires healthy sensors and the pinned 60-second session contract')
        context = session.get('model2_context')
        if not isinstance(context, dict) or context.get('schema') != CONTEXT_SCHEMA:
            return not_run('Model 2 requires enriched runtime candidate context', ['model2_context'])
        missing = list(context.get('missing_fields', []))
        if missing:
            return not_run('Required Model 2 runtime fields are absent; no context was invented', missing)
        try:
            asset, alerts, risks = context['asset'], context['alerts'], context['registered_risks']
            if context.get('membership_basis') not in {'versioned_runtime_risk_snapshots', 'explicit_synthetic_static_membership'}:
                raise ValueError('Declare versioned links or an explicit synthetic static-membership assumption')
            groups = asset.get('control_groups')
            if not isinstance(groups, list) or any(not isinstance(value, str) for value in groups):
                raise ValueError('asset.control_groups must be an explicit string array')
            if not isinstance(alerts, list) or not alerts or not isinstance(risks, list) or not risks:
                raise ValueError('Explicit observed events and applicable registered risks are required')
            ids = [row['alert_id'] for row in alerts]
            if len(set(ids)) != len(ids) or set(ids) != set(session.get('source_event_ids', [])):
                raise ValueError('Observed events do not exactly match session membership')
            if len(alerts) != session['features']['event_count']:
                raise ValueError('Observed event count does not match the session features')
            if any(row.get('mitre_technique') is not None and
                   (not isinstance(row['mitre_technique'], str) or not VALID_TECHNIQUE.fullmatch(row['mitre_technique'])) for row in alerts):
                raise ValueError('Observed technique annotations must use explicit ATT&CK IDs')
            snapshots = {row['risk_id']: row for row in session.get('risk_snapshots', [])}
            if len({row['risk_id'] for row in risks}) != len(risks) or {row['risk_id'] for row in risks} != set(snapshots):
                raise ValueError('Candidate risk context must match the session pre-decision snapshots')
            if asset.get('asset_id') != session.get('asset_id'):
                raise ValueError('Candidate context belongs to a different asset')
            for risk in risks:
                snapshot = snapshots[risk['risk_id']]
                if risk.get('asset_id') != session['asset_id'] or risk.get('risk_version_id') != snapshot['risk_version_id']:
                    raise ValueError('Risk membership does not match the selected point-in-time version')
                for key in ('existing_control_ids', 'planned_control_ids', 'mitre_attack_techniques'):
                    values = risk.get(key)
                    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                        raise ValueError('Missing/invalid registered_risks.' + key)
                if any(cid not in self.controls for cid in risk['existing_control_ids'] + risk['planned_control_ids']):
                    raise ValueError('Registered control links must use IDs from the exact pinned catalogue')
                if any(not VALID_TECHNIQUE.fullmatch(value) for value in risk['mitre_attack_techniques']):
                    raise ValueError('Registered risk technique links must use explicit ATT&CK IDs')
            ctx = session.get('context')
            if not isinstance(ctx, dict) or any(isinstance(ctx.get(k), bool) or not isinstance(ctx.get(k), (int, float))
                    or not math.isfinite(ctx[k]) or not 1 <= ctx[k] <= 5
                    for k in ('asset_criticality', 'current_likelihood', 'impact')):
                raise ValueError('Explicit finite pre-decision criticality, likelihood and impact are required')
            result = self.grounded.recommend(session, alerts, asset, risks, self.catalogue)
            result['membership_basis'] = context['membership_basis']
            result['missing_fields'] = []
            for item in result['recommendations']:
                if not math.isfinite(item['model_score']) or not 0 <= item['model_score'] <= 1:
                    raise ValueError('Model 2 produced a non-finite or out-of-range relevance score')
                linked = [r for r in risks if item['control_id'] in r['existing_control_ids'] + r['planned_control_ids']
                          and any(self.reference.technique_match(a.get('mitre_technique'), t)
                                  for a in alerts for t in r['mitre_attack_techniques'])]
                states = [snapshots[r['risk_id']].get('control_states', {}).get(item['control_id'], 'unknown') for r in linked]
                state = states[0] if states and len(set(states)) == 1 and states[0] in STATES else 'unknown'
                if state == 'not_assessed':
                    state = 'unknown'
                item.update(current_state=state, implementation_state_known=state != 'unknown',
                            implementation_state_source='matched_runtime_risk_snapshots' if state != 'unknown' else 'not_observed',
                            action_type='review', catalogue_action='Review candidate against observed evidence', warnings=[])
            return result
        except (KeyError, TypeError, ValueError) as exc:
            return not_run('Model 2 context rejected: ' + str(exc))

    def predict(self, session):
        result = self.service.predict(session, mode='rules')
        result.update(mode='shadow', model_sha256=self.metadata['model_sha256'], model1_released=False, model2_released=False)
        features, m1 = result['evidence_features'], self.metadata['model1']
        usable = session.get('sensor_healthy') is True
        if session.get('data_provenance') != 'synthetic':
            usable = False
            result['warnings'].append('New models are experimental synthetic-only artifacts; real-data inference is blocked')
        if session.get('aggregation_schema') != self.metadata['aggregation_schema']:
            usable = False
            result['warnings'].append('Session contract differs from training; ML disabled')
        if any(features[key] not in m1['categorical_vocab'][key] for key in CATEGORICAL):
            usable = False
            result['warnings'].append('Unseen feature categories; Model 1 abstains')
        review = self._review(session)
        result['model2_review'] = review
        if usable:
            try:
                probs = self.scenario.predict_proba(frame([features]))[0]
                if not np.isfinite(probs).all() or not np.isclose(probs.sum(), 1) or np.any(probs < 0) or np.any(probs > 1):
                    raise ValueError('Invalid Model 1 probability vector')
                index = int(probs.argmax())
                label, score = str(self.scenario.classes_[index]), float(probs[index])
                accepted = score >= m1['threshold']
                result['shadow_candidate'] = {
                    'scenario_class': label if accepted else None, 'top_candidate': label, 'confidence': score,
                    'status': 'ASSESSED' if accepted else 'ABSTAINED', 'method': 'calibrated_model1',
                    'threshold': m1['threshold'], 'class_probabilities': {str(c): float(p) for c, p in zip(self.scenario.classes_, probs)},
                    'explanation': {'kind': 'observed_evidence_only', 'note': 'Input features are evidence, not causal attribution.'},
                    'controls': review,
                }
                for key in NUMERIC:
                    low, high = m1['numeric_train_ranges'][key]
                    if not low <= features[key] <= high:
                        result['warnings'].append(f'{key} outside fitted range [{low}, {high}]; review extrapolation')
            except (TypeError, ValueError) as exc:
                result['warnings'].append('Model 1 inference failed; rule baseline retained: ' + str(exc))
        if review['source'] == 'not_run':
            result['warnings'].append(review['reason'])
        return result

    def status(self):
        return {
            'loaded': True, 'loaded_at_utc': self.loaded_at, 'mode': 'shadow_only',
            'model_sha256': self.metadata['model_sha256'], 'artifact_manifest_sha256': self.artifact_identity,
            'package_version': self.metadata['package_version'], 'aggregation_schema': self.metadata['aggregation_schema'],
            'synthetic_training': True, 'algorithm': self.metadata['model1']['algorithm'],
            'model1_sha256': self.metadata['model1']['model_sha256'], 'model2_sha256': self.metadata['model2']['model_sha256'],
            'model1_metrics': self.metadata['model1']['metrics'], 'model1_checks': self.metadata['model1']['checks'],
            'model2_metrics': {'validation_scope': 'Experimental synthetic association matching; no demonstrated ML advantage over catalogue rules'},
            'model2_controls_with_positive_test_examples': None,
            'model2_audit_support_note': 'Per-control held-out audit support was not included in the model handoff metadata',
            'model2_positive_fit_support': self.grounded.artifact['positive_fit_support'],
            'model2_candidate_count': 120, 'model2_feature_count': 25,
            'model2_feature_schema': self.metadata['model2']['schema'],
            'model1_released': False, 'model2_released': False,
            'automatic_execution': False, 'official_risk_register_write': False,
            'rollback': 'Set IRIS_MODEL_PROFILE=legacy before starting the backend',
        }
