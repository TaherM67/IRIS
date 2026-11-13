"""Pinned expanded Model 1 with the existing grounded Model 2 and approvals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from .config import ROOT
from .grounded_adapter import GroundedModelAdapter
from .scenarios import CLASSES, EXTRA_FEATURES, RISK_CATEGORIES, VERSION, attach_evidence, feature_row, rule_scenario
from iris_models.contracts import CATEGORICAL, FEATURES, digest

PROFILE = Path(__file__).with_name('model_profile_scenarios.json')


class ScenarioModelAdapter(GroundedModelAdapter):
    def __init__(self, profile_path=PROFILE):
        super().__init__()
        profile_path = Path(profile_path)
        profile = json.loads(profile_path.read_text(encoding='utf-8'))
        directory = (ROOT / profile['directory']).resolve()
        if not directory.is_relative_to(ROOT / 'artifacts/model_versions'):
            raise ValueError('Expanded profile must refer to a versioned local artifact')
        metadata_path = directory / 'model1_metadata.json'
        model_path = directory / 'model1_scenario.joblib'
        if digest(metadata_path) != profile['metadata_sha256'] or digest(model_path) != profile['model_sha256']:
            raise ValueError('Pinned expanded scenario artifact mismatch')
        metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
        if (metadata['schema'] != VERSION or metadata['features'] != FEATURES + EXTRA_FEATURES
                or metadata['sklearn_version'] != sklearn.__version__
                or metadata['model_sha256'] != profile['model_sha256']
                or metadata['aggregation_schema'] != self.metadata['aggregation_schema']):
            raise ValueError('Expanded scenario feature/version contract mismatch')
        model = joblib.load(model_path)
        if list(model.classes_) != metadata['classes'] or set(model.classes_) != set(CLASSES):
            raise ValueError('Expanded model classes do not match the pinned contract')
        self.scenario = model
        self.metadata['model1'] = metadata
        self.metadata['package_version'] = profile['profile']
        self.metadata['model_sha256'] = hashlib.sha256((metadata['model_sha256'] + self.metadata['model2']['model_sha256']).encode()).hexdigest()
        self.artifact_identity = hashlib.sha256((self.artifact_identity + digest(profile_path) + VERSION).encode()).hexdigest()

    def enrich_sessions(self, sessions, paths):
        return attach_evidence(super().enrich_sessions(sessions, paths), paths)

    def predict(self, session):
        result = self.service.predict(session, mode='rules')
        result.update(mode='shadow',model_sha256=self.metadata['model_sha256'],model1_released=False,model2_released=False)
        result['model2_review'] = self._review(session)
        result['shadow_candidate'] = None
        try:
            row = feature_row(session, FEATURES)
            label = rule_scenario(session)
            result['soc_assessment'] = dict(scenario_class=label,confidence=None,
                status='ASSESSED' if label else 'ABSTAINED',method='rule_baseline',rule_version=VERSION)
            usable = session.get('sensor_healthy') is True and session.get('aggregation_schema') == self.metadata['aggregation_schema']
            if session.get('scenario_evidence_complete') is not True:
                usable = False
                result['warnings'].append('Expanded sensor measurements are incomplete; Model 1 abstains')
            if session.get('data_provenance') != 'synthetic':
                usable = False
                result['warnings'].append('Expanded model has synthetic training only; real-data inference is blocked')
            if any(row[k] not in self.metadata['model1']['categorical_vocab'][k] for k in CATEGORICAL):
                usable = False
                result['warnings'].append('Unseen telemetry category; expanded Model 1 abstains')
            if usable:
                probabilities = self.scenario.predict_proba(pd.DataFrame([row],columns=FEATURES+EXTRA_FEATURES))[0]
                if (not np.isfinite(probabilities).all() or not np.isclose(probabilities.sum(),1)
                        or np.any(probabilities < 0) or np.any(probabilities > 1)):
                    raise ValueError('Invalid expanded model probability vector')
                i = int(probabilities.argmax())
                label, score = str(self.scenario.classes_[i]), float(probabilities[i])
                threshold = self.metadata['model1']['threshold']
                result['shadow_candidate'] = dict(scenario_class=label if score >= threshold else None,top_candidate=label,
                    confidence=score,status='ASSESSED' if score >= threshold else 'ABSTAINED',
                    method='calibrated_model1',threshold=threshold,
                    class_probabilities={str(c):float(p) for c,p in zip(self.scenario.classes_,probabilities)},
                    controls=result['model2_review'],explanation=dict(kind='observed_evidence_only',note='Synthetic model comparison; not a causal explanation.'))
            self._primary_controls(result,session)
        except (KeyError,TypeError,ValueError) as exc:
            result['soc_assessment'] = dict(scenario_class=None,confidence=None,status='ABSTAINED',method='no_usable_evidence')
            result['warnings'].append('Expanded evidence rejected: ' + str(exc))
        return result

    def _primary_controls(self,result,session):
        """Names and state come from explicit applicable risk/control links."""
        label = result['soc_assessment']['scenario_class']
        context = session.get('model2_context',{})
        if (context.get('missing_fields') or not context.get('registered_risks')
                or result['model2_review']['source'] == 'not_run'):
            return
        matched = [r for r in session.get('risk_snapshots',[]) if r['risk_category'] in RISK_CATEGORIES.get(label,set())]
        if len(matched) != 1:
            return
        raw = next((r for r in context['registered_risks'] if r['risk_id']==matched[0]['risk_id']),None)
        if raw is None:
            return
        ids = set(raw['existing_control_ids'] + raw['planned_control_ids'])
        result['grc_control_review'] = dict(source='registered_risk_catalogue_policy',warnings=[],recommendations=[
            dict(control_id=cid,name=self.controls[cid]['name'],catalogue_action='Review registered control coverage against observed evidence')
            for cid in sorted(ids) if cid in self.controls])

    def status(self):
        result = super().status()
        result.update(supported_scenarios=list(CLASSES),scenario_feature_schema=VERSION,
                      scenario_feature_count=len(FEATURES+EXTRA_FEATURES),
                      rollback='Use --dataset legacy --model-profile legacy')
        return result
