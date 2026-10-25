from __future__ import annotations

import asyncio
import copy
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.config import Settings, initialize
from backend.core import BusyError, Engine, INPUTS, view
from backend.model_adapter import MODEL_DIR, MODEL_PROJECT, ModelAdapter
from backend.policy import evaluate, primary_controls
from backend.security import Guard

KEYS = {role: "TEST-ONLY-NOT-A-DEPLOYMENT-SECRET-" + role for role in ("admin", "soc", "grc")}


def small_inputs(directory: Path) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    with (MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl').open() as stream:
        first = json.loads(next(stream))
    asset = first['asset_snapshot']
    asset_payload = {"schema_version": "iris-asset-inventory-v1", "data_provenance": "synthetic", "records": [asset]}
    risk_payload = {"schema_version": "iris-risk-register-v1", "data_provenance": "synthetic", "records": first['risk_snapshots']}
    event = {"event_id": "HTTP-TEST-EVENT-1", "timestamp": first['start_utc'], "asset_id": asset['asset_id'],
             "destination_ip": asset['ip_addresses'][0], "agent_name": asset['hostname'],
             "source_ip": "198.51.100.50", "account": "synthetic-test", "event_family": "network",
             "protocol": "TCP", "rule_id": "10001", "rule_level": 8, "outcome": "unknown",
             "sensor_healthy": True, "campaign_id": "SYN-HTTP-TEST", "run_id": "SYN-HTTP-RUN", "data_provenance": "synthetic"}
    payloads = {"asset_inventory": json.dumps(asset_payload), "risk_register": json.dumps(risk_payload), "siem_alerts": json.dumps(event) + '\n'}
    paths = {key: directory / name for key, name in INPUTS.items()}
    for key, path in paths.items():
        path.write_text(payloads[key], encoding='utf-8')
    return paths


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = ModelAdapter()
        rows = MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl'
        with rows.open() as stream:
            cls.sessions = [json.loads(line) for line in stream]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='iris-core-test-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.paths = small_inputs(self.directory / 'inputs')
        self.settings = Settings(self.directory / 'state', KEYS)
        self.engine = Engine(self.settings, self.adapter)

    def test_actual_user_artifact_shadow_prediction(self):
        prediction = self.adapter.predict(self.sessions[0])
        self.assertIsNotNone(prediction['shadow_candidate'])
        self.assertFalse(prediction['automatic_execution'])
        self.assertFalse(prediction['official_risk_register_write'])
        self.assertFalse(prediction['model1_released'])
        self.assertFalse(prediction['model2_released'])
        self.assertNotEqual(prediction['soc_assessment']['method'], 'calibrated_model1')
        self.assertEqual(self.adapter.metadata['model_sha256'], '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950')

    def test_corruption_rejected_before_model_loading(self):
        target = self.directory / 'bad_model'
        shutil.copytree(MODEL_DIR, target)
        (target / 'models.joblib').write_bytes(b'not a trusted model')
        with mock.patch('backend.model_adapter.ModelService') as loader:
            with self.assertRaisesRegex(ValueError, 'Pinned model'):
                ModelAdapter(target)
            loader.assert_not_called()

    def test_unhealthy_sensor_abstains(self):
        session = copy.deepcopy(self.sessions[0])
        session['sensor_healthy'] = False
        prediction = self.adapter.predict(session)
        self.assertIsNone(prediction['shadow_candidate'])
        self.assertEqual(evaluate(session, prediction)['priority'], 'Needs Review')

    def test_wrong_session_contract_disables_ml(self):
        session = copy.deepcopy(self.sessions[0])
        session['aggregation_schema'] = 'old-or-unknown-contract'
        prediction = self.adapter.predict(session)
        self.assertIsNone(prediction['shadow_candidate'])
        self.assertTrue(any('contract' in warning for warning in prediction['warnings']))

    def test_shadow_class_does_not_drive_risk_policy(self):
        session = next(s for s in self.sessions if s['features']['event_family'] == 'network' and s['features']['distinct_rules'] >= 4 and s['features']['event_count'] >= 15)
        prediction = self.adapter.predict(session)
        before = evaluate(session, prediction)
        prediction['shadow_candidate']['scenario_class'] = 'credential_access'
        self.assertEqual(before, evaluate(session, prediction))

    def test_ambiguous_risk_never_guessed(self):
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['event_family'] == 'network' and s['features']['distinct_rules'] >= 4 and s['features']['event_count'] >= 15))
        risk = copy.deepcopy(next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Reconnaissance'))
        risk.update(risk_id='ANOTHER-REGISTERED-RISK', risk_version_id='ANOTHER-VERSION')
        session['risk_snapshots'].append(risk)
        result = evaluate(session, self.adapter.predict(session))
        self.assertEqual(result['mapping_status'], 'AMBIGUOUS')
        self.assertIsNone(result['matched_risk_id'])
        self.assertIsNone(result['proposed_likelihood'])

    def test_benign_critical_asset_stays_low(self):
        session = copy.deepcopy(self.sessions[0])
        session['asset_snapshot']['criticality'] = 5
        prediction = self.adapter.predict(session)
        prediction['soc_assessment'].update(scenario_class='benign', status='ASSESSED', method='rule_baseline')
        self.assertEqual(evaluate(session, prediction)['priority'], 'Low')

    def test_missing_risk_does_not_invent_likelihood(self):
        session = copy.deepcopy(self.sessions[0])
        session['risk_snapshots'] = []
        prediction = self.adapter.predict(session)
        prediction['soc_assessment'].update(scenario_class='reconnaissance', status='ASSESSED', method='rule_baseline')
        result = evaluate(session, prediction)
        self.assertIsNone(result['baseline_risk_0_1'])
        self.assertIsNone(result['proposed_likelihood'])

    def test_primary_controls_use_actual_matched_risk_states(self):
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['failed_count'] >= 12 and s['features']['failure_ratio'] >= .75))
        matched = next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized Access')
        session['context']['controls'] = {'SC005': 'implemented'}
        matched['control_states']['SC005'] = 'missing'
        prediction = self.adapter.predict(session)
        advice = primary_controls(session, prediction, evaluate(session, prediction))
        control = next(r for r in advice['recommendations'] if r['control_id'] == 'SC005')
        self.assertEqual((control['current_state'], control['action_type']), ('missing', 'install'))
        self.assertEqual(advice['control_state_risk_id'], matched['risk_id'])

    def test_active_matched_risk_exception_requires_review(self):
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['failed_count'] >= 12 and s['features']['failure_ratio'] >= .75))
        matched = next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized Access')
        matched['active_exception_control_ids'] = ['SC005']
        prediction = self.adapter.predict(session)
        advice = primary_controls(session, prediction, evaluate(session, prediction))
        self.assertEqual(next(r for r in advice['recommendations'] if r['control_id'] == 'SC005')['action_type'], 'review')

    def test_complete_batch_persists_evidence_without_labels(self):
        result = self.engine.run(self.paths, 'admin')
        self.assertEqual(result['sessions'], 1)
        self.assertFalse(result['training_labels_read'])
        self.assertFalse(result['official_risk_register_write'])
        self.assertEqual(self.engine.store.health()['cases'], 1)
        inputs = self.settings.state_dir / 'runs' / result['run_id'] / 'inputs'
        self.assertEqual({p.name for p in inputs.iterdir()}, set(INPUTS.values()))
        self.assertTrue((inputs.parent / 'prepared/unified_events.jsonl').is_file())

    def test_repeated_identical_batch_reuses_completed_run(self):
        first = self.engine.run(self.paths, 'admin')
        with mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Must not predict again')):
            second = self.engine.run(self.paths, 'soc')
        self.assertEqual(first['run_id'], second['run_id'])
        self.assertTrue(second['reused_existing_run'])
        self.assertEqual(self.engine.store.health()['runs'], 1)

    def test_reuse_survives_engine_restart(self):
        first = self.engine.run(self.paths, 'admin')
        replacement = Engine(self.settings, self.adapter)
        self.assertEqual(replacement.run(self.paths, 'admin')['run_id'], first['run_id'])

    def test_grc_cannot_submit_batch(self):
        with self.assertRaises(PermissionError):
            self.engine.run(self.paths, 'grc')
        self.assertEqual(self.engine.store.health()['runs'], 0)

    def test_fourth_runtime_input_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Exactly'):
            self.engine.run({**self.paths, 'labels': self.paths['siem_alerts']}, 'admin')

    def test_invalid_source_records_failure_not_partial_cases(self):
        self.paths['asset_inventory'].write_text('{}')
        with self.assertRaises(ValueError):
            self.engine.run(self.paths, 'admin')
        self.assertEqual(self.engine.store.runs()[0]['status'], 'failed')
        self.assertEqual(self.engine.store.health()['cases'], 0)

    def test_alert_count_bound(self):
        content = self.paths['siem_alerts'].read_text()
        self.paths['siem_alerts'].write_text(content + content)
        engine = Engine(Settings(self.directory / 'limited', KEYS, max_alert_rows=1), self.adapter)
        with self.assertRaisesRegex(ValueError, 'alert-row'):
            engine.run(self.paths, 'admin')

    def test_risk_context_expansion_bound_before_preparation(self):
        payload = json.loads(self.paths['risk_register'].read_text())
        template = payload['records'][0]
        payload['records'] = [{**template, 'risk_id': f'EXCESS-{i}', 'risk_version_id': f'EXCESS-{i}-V1'} for i in range(11)]
        self.paths['risk_register'].write_text(json.dumps(payload))
        with mock.patch('backend.core.prepare_three') as prepare:
            with self.assertRaisesRegex(ValueError, 'expansion limit'):
                self.engine.run(self.paths, 'admin')
            prepare.assert_not_called()

    def test_concurrent_batch_is_rejected_without_releasing_other_lock(self):
        self.engine.lock.acquire()
        try:
            with self.assertRaises(BusyError):
                self.engine.run(self.paths, 'admin')
            self.assertTrue(self.engine.lock.locked())
        finally:
            self.engine.lock.release()

    def test_review_is_local_and_append_only(self):
        self.engine.run(self.paths, 'admin')
        case = self.engine.store.cases()['items'][0]
        original = copy.deepcopy(case['session'])
        self.engine.store.review(case['case_id'], 'approve_follow_up', 'Reviewed for follow-up only', 'grc')
        with self.assertRaisesRegex(ValueError, 'already'):
            self.engine.store.review(case['case_id'], 'reject_suggestion', 'Cannot overwrite prior review', 'grc')
        saved = self.engine.store.case(case['case_id'])
        self.assertEqual(saved['session'], original)
        self.assertFalse(saved['prediction']['official_risk_register_write'])

    def test_admin_cannot_impersonate_grc_reviewer(self):
        self.engine.run(self.paths, 'admin')
        case = self.engine.store.cases()['items'][0]
        with self.assertRaises(ValueError):
            self.engine.store.review(case['case_id'], 'approve_follow_up', 'Not an authorized risk reviewer', 'admin')

    def test_role_views_are_separate(self):
        self.engine.run(self.paths, 'admin')
        case = self.engine.store.cases()['items'][0]
        self.assertIn('source_event_ids', view(case, 'soc'))
        self.assertNotIn('risk_snapshots', view(case, 'soc'))
        self.assertIn('risk_snapshots', view(case, 'grc'))
        self.assertNotIn('source_event_ids', view(case, 'grc'))

    def test_initialize_preserves_credentials(self):
        path = self.directory / 'private/access.json'
        initialize(path)
        original = path.read_bytes()
        settings = Settings.load(path)
        self.assertEqual(set(settings.role_keys), {'soc', 'grc', 'admin'})
        with self.assertRaises(FileExistsError):
            initialize(path)
        self.assertEqual(original, path.read_bytes())
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_duplicate_role_keys_rejected(self):
        with self.assertRaises(ValueError):
            Settings(self.directory, {r: 'x' * 40 for r in KEYS})


class GuardTests(unittest.TestCase):
    def invoke(self, headers=None, messages=None, path='/api/model', method='GET', cap=1024):
        sent, seen = [], []
        body = list(messages or [{'type': 'http.request', 'body': b'', 'more_body': False}])
        reads = []
        async def receive():
            reads.append(True)
            return body.pop(0) if body else {'type': 'http.disconnect'}
        async def send(message):
            sent.append(message)
        async def app(scope, receive, send):
            seen.append(scope.get('state', {}).get('principal'))
            if method == 'POST':
                seen.append((await receive()).get('body'))
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'ok'})
        scope = {'type': 'http', 'path': path, 'method': method,
                 'headers': [(b'host', b'testserver'), *(headers or [])]}
        asyncio.run(Guard(app, Settings(Path('.'), KEYS, max_body_bytes=cap))(scope, receive, send))
        return sent[0]['status'], seen, len(reads)

    def test_auth_before_any_upload_read(self):
        code, seen, reads = self.invoke(method='POST')
        self.assertEqual((code, seen, reads), (401, [], 0))

    def test_role_is_derived_from_key(self):
        code, seen, _ = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())])
        self.assertEqual((code, seen), (200, ['soc']))

    def test_duplicate_keys_rejected(self):
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'x-iris-key', KEYS['admin'].encode())])[0], 401)

    def test_non_ascii_key_is_not_a_server_error(self):
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', b'\xff' * 40)])[0], 401)

    def test_foreign_origin_rejected(self):
        self.assertEqual(self.invoke(headers=[(b'origin', b'https://untrusted.example'), (b'x-iris-key', KEYS['admin'].encode())])[0], 403)

    def test_content_length_limit_before_body_read(self):
        code, _, reads = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'content-length', b'100')], method='POST', cap=10)
        self.assertEqual((code, reads), (413, 0))

    def test_chunked_body_limit_without_length_header(self):
        messages = [{'type': 'http.request', 'body': b'123456', 'more_body': True}, {'type': 'http.request', 'body': b'78901', 'more_body': False}]
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages, method='POST', cap=10)[0], 413)

    def test_buffered_body_is_replayed(self):
        messages = [{'type': 'http.request', 'body': b'ab', 'more_body': True}, {'type': 'http.request', 'body': b'cd', 'more_body': False}]
        code, seen, _ = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages, method='POST')
        self.assertEqual((code, seen), (200, ['soc', b'abcd']))

    def test_public_health_does_not_require_a_key(self):
        self.assertEqual(self.invoke(path='/health')[0], 200)


if __name__ == '__main__':
    unittest.main()
