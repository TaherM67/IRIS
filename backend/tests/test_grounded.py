"""Trusted handoff, candidate adapter, API and preservation regressions."""
import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from backend.config import ROOT, Settings
from backend.core import Engine, INPUTS, view
from backend.grounded_adapter import GroundedModelAdapter
from backend.grounded_context import SCHEMA
from backend.model_adapter import ModelAdapter
from backend.policy import evaluate
from demo_app.engine import DemoEngine

PACKAGE = ROOT / 'artifacts/model_versions/iris_models_20261030'
KEYS = {role: ('GROUND-TEST-ONLY-' + role).ljust(48, '0') for role in ('admin', 'soc', 'grc')}


def request_fixture():
    return json.loads((PACKAGE / 'smoke_test_request.json').read_text(encoding='utf-8'))


def direct_session():
    request = request_fixture()
    session = request['session']
    snapshots = {r['risk_id']: r for r in session['risk_snapshots']}
    risks = [{**{k: snapshots[r['risk_id']][k] for k in ('risk_id', 'risk_version_id', 'asset_id')},
              **{k: r[k] for k in ('existing_control_ids', 'planned_control_ids', 'mitre_attack_techniques')}}
             for r in request['registered_risks']]
    session['model2_context'] = {'schema': SCHEMA, 'asset': {k: request['asset'][k] for k in ('asset_id', 'control_groups')},
                                 'alerts': request['alerts'], 'registered_risks': risks, 'missing_fields': [],
                                 'membership_basis': 'explicit_synthetic_static_membership'}
    return session


def runtime_inputs(directory):
    """Canonical existing API inputs, with explicit optional candidate context."""
    request = request_fixture()
    session = request['session']
    asset = {**session['asset_snapshot'], 'control_groups': request['asset']['control_groups']}
    raw_risks = {r['risk_id']: r for r in request['registered_risks']}
    risks = [{**r, **{k: raw_risks[r['risk_id']][k] for k in (
        'existing_control_ids', 'planned_control_ids', 'mitre_attack_techniques')}} for r in session['risk_snapshots']]
    alert = {'event_id': session['source_event_ids'][0], 'timestamp': session['start_utc'],
             'asset_id': asset['asset_id'], 'destination_ip': asset['ip_addresses'][0],
             'source_ip': '192.0.2.10', 'account': 'synthetic-review',
             'event_family': 'authentication', 'protocol': 'TCP', 'outcome': 'failed',
             'rule_id': 'OBSERVED-TEST-RULE', 'rule_level': 5, 'sensor_healthy': True,
             'campaign_id': 'SYN-ADAPTER-TEST', 'run_id': 'SYN-TEST-RUN',
             'data_provenance': 'synthetic', 'mitre_technique': request['alerts'][0]['mitre_technique']}
    paths = {key: directory / name for key, name in INPUTS.items()}
    directory.mkdir(parents=True)
    paths['asset_inventory'].write_text(json.dumps({'schema_version': 'iris-asset-inventory-v1',
        'data_provenance': 'synthetic', 'records': [asset]}), encoding='utf-8')
    paths['risk_register'].write_text(json.dumps({'schema_version': 'iris-risk-register-v1',
        'data_provenance': 'synthetic', 'records': risks}), encoding='utf-8')
    paths['siem_alerts'].write_text(json.dumps(alert) + '\n', encoding='utf-8')
    return paths


class GroundedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = ModelAdapter()

    def setUp(self):
        self.session = direct_session()

    def test_both_new_artifacts_and_fixed_candidate_schema_loaded(self):
        status = self.adapter.status()
        self.assertEqual(status['package_version'], 'iris_models_20261030')
        self.assertEqual(status['model1_sha256'], 'ae8ca09ded11a3d7e10be68fbc29999028cf6c456874e4376697a1e7c8fb7bb1')
        self.assertEqual(status['model2_sha256'], 'e29b2879b6c25a02605df4740265c5fdb7eb22849b45dcbf6f34e59736817dea')
        self.assertEqual((status['model2_candidate_count'], status['model2_feature_count']), (120, 25))
        self.assertFalse(status['model1_released'] or status['model2_released'])

    def test_packaged_example_returns_named_candidates_with_unknown_states(self):
        result = self.adapter.predict(self.session)
        self.assertEqual(result['shadow_candidate']['scenario_class'], 'credential_access')
        review = result['model2_review']
        self.assertEqual({r['control_id'] for r in review['recommendations']}, {'CTL-IAM-002'})
        withheld = next(r for r in review['withheld_candidates'] if r['control_id'] == 'CTL-MON-004')
        self.assertIn('catalogue_technique_mismatch', withheld['reason_codes'])
        for row in review['recommendations']:
            self.assertTrue(row['name'] and row['reason'] and row['source'])
            self.assertEqual((row['current_state'], row['action_type']), ('unknown', 'review'))
            self.assertFalse(row['implementation_state_known'])
        self.assertFalse(result['automatic_execution'] or review['automatic_execution'])

    def test_state_is_known_only_from_explicit_matched_runtime_risk_record(self):
        for risk in self.session['risk_snapshots']:
            risk['control_states'] = {'CTL-MON-004': 'implemented', 'CTL-IAM-002': 'partial'}
        rows = self.adapter.predict(self.session)['model2_review']['recommendations']
        self.assertEqual({r['current_state'] for r in rows}, {'partial'})
        self.assertTrue(all(r['implementation_state_known'] and r['action_type'] == 'review' for r in rows))
        for risk in self.session['risk_snapshots']:
            risk['control_states'] = {'CTL-IAM-002': 'implemented'}
        rows = self.adapter.predict(self.session)['model2_review']['recommendations']
        self.assertEqual({r['current_state'] for r in rows}, {'implemented'})
        for risk in self.session['risk_snapshots']:
            risk['control_states'] = {'CTL-MON-004': 'not_assessed', 'CTL-IAM-002': 'unknown'}
        rows = self.adapter.predict(self.session)['model2_review']['recommendations']
        self.assertTrue(all(r['current_state'] == 'unknown' and not r['implementation_state_known'] for r in rows))

    def test_oracle_labels_and_associations_never_enter_candidate_matrix(self):
        active = self.adapter._active
        context = self.session['model2_context']
        args = (self.session, context['alerts'], context['asset'], context['registered_risks'], active.catalogue)
        _, before, _ = active.reference.candidate_features(*args)
        self.session['offline_label'] = 'invented attack'
        self.session['annotation_primary_asset_id'] = 'WRONG-ORACLE-ASSET'
        for row in context['alerts'] + context['registered_risks']:
            row.update(associations={'control_ids': list(active.controls)}, scenario_tag='benign', training_label='poison')
        _, after, _ = active.reference.candidate_features(*args)
        np.testing.assert_array_equal(before, after)

    def test_real_provenance_and_unhealthy_sensor_do_not_run_models(self):
        self.session['data_provenance'] = 'operational'
        result = self.adapter.predict(self.session)
        self.assertIsNone(result['shadow_candidate'])
        self.assertEqual(result['model2_review']['source'], 'not_run')
        self.session['data_provenance'] = 'synthetic'
        self.session['sensor_healthy'] = False
        result = self.adapter.predict(self.session)
        self.assertIsNone(result['shadow_candidate'])
        self.assertEqual(result['model2_review']['source'], 'not_run')

    def test_missing_runtime_context_is_reported_not_fabricated(self):
        del self.session['model2_context']
        review = self.adapter.predict(self.session)['model2_review']
        self.assertEqual(review['source'], 'not_run')
        self.assertIn('model2_context', review['missing_fields'])
        self.assertEqual(review['recommendations'], [])

    def test_foreign_membership_or_unknown_catalogue_ids_are_rejected(self):
        for change in ('event', 'asset', 'risk_version', 'control'):
            session = copy.deepcopy(self.session)
            context = session['model2_context']
            if change == 'event': context['alerts'][0]['alert_id'] = 'OTHER-EVENT'
            if change == 'asset': context['asset']['asset_id'] = 'OTHER-ASSET'
            if change == 'risk_version': context['registered_risks'][0]['risk_version_id'] = 'FUTURE-VERSION'
            if change == 'control': context['registered_risks'][0]['existing_control_ids'] = ['SC005']
            self.assertEqual(self.adapter.predict(session)['model2_review']['source'], 'not_run', change)

    def test_model_outputs_do_not_change_primary_policy(self):
        prediction = self.adapter.predict(self.session)
        before = evaluate(self.session, prediction)
        prediction['shadow_candidate']['scenario_class'] = 'reconnaissance'
        prediction['model2_review']['recommendations'][0]['model_score'] = 1.0
        self.assertEqual(evaluate(self.session, prediction), before)
        self.assertNotEqual(prediction['soc_assessment']['method'], 'calibrated_model1')

    def test_corruption_is_rejected_before_joblib_load(self):
        with tempfile.TemporaryDirectory(prefix='iris-model-corruption-') as directory:
            target = Path(directory) / 'models'
            shutil.copytree(PACKAGE, target)
            (target / 'grounded_model2.joblib').write_bytes(b'corrupt')
            with mock.patch('backend.grounded_adapter.joblib.load') as loader:
                with self.assertRaisesRegex(ValueError, 'Pinned model package mismatch'):
                    GroundedModelAdapter(target)
                loader.assert_not_called()

    def test_legacy_configuration_is_still_available(self):
        with mock.patch.dict(os.environ, {'IRIS_MODEL_PROFILE': 'legacy'}):
            legacy = ModelAdapter()
        self.assertEqual(legacy.metadata['model_sha256'], '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950')
        self.assertIsNone(legacy._active)

    def test_three_input_workflow_retains_optional_context_and_separates_roles(self):
        with tempfile.TemporaryDirectory(prefix='iris-grounded-workflow-') as directory:
            root = Path(directory)
            paths = runtime_inputs(root / 'inputs')
            engine = Engine(Settings(root / 'state', KEYS), self.adapter)
            run = engine.run(paths, 'admin')
            case = engine.store.cases()['items'][0]
            review = view(case, 'grc')['model2_review']
            self.assertEqual(run['sessions'], 1)
            self.assertEqual(review['source'], 'experimental_grounded_candidate_model')
            self.assertTrue(review['recommendations'])
            self.assertNotIn('model2_review', view(case, 'soc'))
            self.assertNotIn('controls', view(case, 'soc')['shadow_candidate'])
            self.assertNotIn('model_score', json.dumps(review))
            self.assertTrue(engine.run(paths, 'admin')['reused_existing_run'])
            engine.store.review(case['case_id'], 'approve_follow_up', 'Human follow-up review only', 'grc')
            restarted = Engine(Settings(root / 'state', KEYS), self.adapter)
            self.assertEqual(restarted.store.case(case['case_id'])['review']['actor'], 'grc')

    def test_demo_grc_projection_has_review_details_but_no_model_scores(self):
        prediction = self.adapter.predict(self.session)
        evidence = {'hostname': 'test', 'asset_id': self.session['asset_id'], 'asset_criticality': 5,
                    'session_id': self.session['session_id'], 'session_time': self.session['start_utc'],
                    'decision_basis': 'Rules and human approval', 'primary_assessment': prediction['soc_assessment'],
                    'primary_controls': {'recommendations': []}, 'model2_review': prediction['model2_review'],
                    'ml_shadow': {'scenario': 'credential_access', 'confidence': .9, 'status': 'ASSESSED'},
                    'features': self.session['features'], 'warnings': []}
        payload = {'evidence': evidence}
        grc = DemoEngine._team_payload('grc', payload)['evidence']
        self.assertIn('model2_review', grc)
        self.assertNotIn('model_score', json.dumps(grc))
        self.assertNotIn('model2_review', DemoEngine._team_payload('soc', payload)['evidence'])


class GroundedHTTPTests(unittest.TestCase):
    def test_upload_review_role_guards_and_restart_with_actual_models(self):
        from fastapi.testclient import TestClient
        from backend.app import create_app
        with tempfile.TemporaryDirectory(prefix='iris-grounded-http-') as directory:
            root = Path(directory)
            paths = runtime_inputs(root / 'inputs')
            settings = Settings(root / 'state', KEYS)
            with TestClient(create_app(settings)) as client:
                files = {key: (path.name, path.read_bytes()) for key, path in paths.items()}
                self.assertEqual(client.post('/api/runs', files=files).status_code, 401)
                response = client.post('/api/runs', headers={'X-IRIS-Key': KEYS['admin']}, files=files)
                self.assertEqual(response.status_code, 200, response.text)
                for role in ('admin', 'grc'):
                    cases = client.get('/api/grc/cases', headers={'X-IRIS-Key': KEYS[role]}).json()
                    case = cases['items'][0]
                    self.assertTrue(case['model2_review']['recommendations'])
                    self.assertFalse(case['automatic_execution'])
                self.assertEqual(client.get('/api/grc/cases', headers={'X-IRIS-Key': KEYS['soc']}).status_code, 403)
                review = client.post('/api/grc/cases/' + case['case_id'] + '/review', headers={'X-IRIS-Key': KEYS['grc']},
                                     json={'disposition': 'approve_follow_up', 'comment': 'Reviewed actual candidate evidence'})
                self.assertEqual(review.status_code, 200, review.text)
                self.assertFalse(review.json()['automatic_execution'])
            with TestClient(create_app(settings)) as client:
                stored = client.get('/api/grc/cases', headers={'X-IRIS-Key': KEYS['grc']}).json()['items'][0]
                self.assertEqual(stored['review']['actor'], 'grc')


if __name__ == '__main__':
    unittest.main()
