# IRIS EXPLAIN: File purpose: Tests the real saved model, core integration, explicit policy, SQLite evidence, local credentials,
# IRIS EXPLAIN: and the ASGI guard without requiring FastAPI.
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import asyncio to drive asynchronous ASGI test calls.
import asyncio
# IRIS EXPLAIN: Import copy to create independent fixtures or estimators without mutating the original.
import copy
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import os to create private files exclusively and inspect platform/file flags.
import os
# IRIS EXPLAIN: Import shutil to copy immutable inputs or clean test-owned temporary directories.
import shutil
# IRIS EXPLAIN: Import stat to check Unix private-file permissions in tests.
import stat
# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import unittest to define regression assertions and controlled test mocks.
import unittest
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import mock from unittest to define regression assertions and controlled test mocks.
from unittest import mock

# IRIS EXPLAIN: Import Settings, initialize from backend.config to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from backend.config import Settings, initialize
# IRIS EXPLAIN: Import BusyError, Engine, INPUTS, view from backend.core to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from backend.core import BusyError, Engine, INPUTS, view
# IRIS EXPLAIN: Import MODEL_DIR, MODEL_PROJECT, ModelAdapter from backend.model_adapter to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from backend.model_adapter import MODEL_DIR, MODEL_PROJECT, ModelAdapter
# IRIS EXPLAIN: Import evaluate, primary_controls from backend.policy to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from backend.policy import evaluate, primary_controls
# IRIS EXPLAIN: Import Guard from backend.security to reuse the shared project contract/implementation rather than duplicate it.
from backend.security import Guard

# IRIS EXPLAIN: Store the comprehension {role: 'TEST-ONLY-NOT-A-DEPLOYMENT-SECRET-' + role for role in ('admin', 'soc', 'grc')}
# IRIS EXPLAIN: in KEYS; later lines use this named result.
KEYS = {role: "TEST-ONLY-NOT-A-DEPLOYMENT-SECRET-" + role for role in ("admin", "soc", "grc")}


# IRIS EXPLAIN: Function small_inputs: Build a minimal three-file synthetic fixture compatible with the exact observed-session
# IRIS EXPLAIN: contract.
# IRIS EXPLAIN: Inputs: directory: a fresh fixture-owned or explicitly selected local directory.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def small_inputs(directory: Path) -> dict:
    # IRIS EXPLAIN: Call directory.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
    # IRIS EXPLAIN: existing flags.
    directory.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Enter (MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl').open() as stream; its
    # IRIS EXPLAIN: context manager supplies the existing cleanup/transaction/expected-exception behavior.
    with (MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl').open() as stream:
        # IRIS EXPLAIN: Store the result of json.loads(next(stream)) (decode the existing JSON text) in first; later lines use
        # IRIS EXPLAIN: this named result.
        first = json.loads(next(stream))
    # IRIS EXPLAIN: Store first['asset_snapshot'] in asset; later lines use this named result.
    asset = first['asset_snapshot']
    # IRIS EXPLAIN: Store a mapping containing schema_version, data_provenance, records in asset_payload; later lines use this
    # IRIS EXPLAIN: named result.
    asset_payload = {"schema_version": "iris-asset-inventory-v1", "data_provenance": "synthetic", "records": [asset]}
    # IRIS EXPLAIN: Store a mapping containing schema_version, data_provenance, records in risk_payload; later lines use this
    # IRIS EXPLAIN: named result.
    risk_payload = {"schema_version": "iris-risk-register-v1", "data_provenance": "synthetic", "records": first['risk_snapshots']}
    # IRIS EXPLAIN: Store a mapping containing event_id, timestamp, asset_id, destination_ip, agent_name, source_ip, account and
    # IRIS EXPLAIN: additional fields in event; later lines use this named result.
    event = {"event_id": "HTTP-TEST-EVENT-1", "timestamp": first['start_utc'], "asset_id": asset['asset_id'],
             # IRIS EXPLAIN: Continue the current record with destination_ip, agent_name; each value comes from the expression
             # IRIS EXPLAIN: shown on this unchanged line.
             "destination_ip": asset['ip_addresses'][0], "agent_name": asset['hostname'],
             # IRIS EXPLAIN: Set/describe these existing record fields: event_family: observed telemetry family; a Model 1
             # IRIS EXPLAIN: categorical predictor, not a truth label.
             "source_ip": "198.51.100.50", "account": "synthetic-test", "event_family": "network",
             # IRIS EXPLAIN: Continue the current record with protocol, rule_id, rule_level, outcome; each value comes from the
             # IRIS EXPLAIN: expression shown on this unchanged line.
             "protocol": "TCP", "rule_id": "10001", "rule_level": 8, "outcome": "unknown",
             # IRIS EXPLAIN: Set/describe these existing record fields: sensor_healthy: explicit health evidence; a
             # IRIS EXPLAIN: missing/false value must not be treated as benign; campaign_id: group provenance retained for
             # IRIS EXPLAIN: split/session identity; not a telemetry predictor; run_id: run/batch provenance retained for
             # IRIS EXPLAIN: traceability; not a hidden attack-label feature; data_provenance: explicit
             # IRIS EXPLAIN: synthetic/cyber_range/operational source identity.
             "sensor_healthy": True, "campaign_id": "SYN-HTTP-TEST", "run_id": "SYN-HTTP-RUN", "data_provenance": "synthetic"}
    # IRIS EXPLAIN: Store a mapping containing asset_inventory, risk_register, siem_alerts in payloads; later lines use this
    # IRIS EXPLAIN: named result.
    payloads = {"asset_inventory": json.dumps(asset_payload), "risk_register": json.dumps(risk_payload), "siem_alerts": json.dumps(event) + '\n'}
    # IRIS EXPLAIN: Store the comprehension {key: directory / name for key, name in INPUTS.items()} in paths; later lines use
    # IRIS EXPLAIN: this named result.
    paths = {key: directory / name for key, name in INPUTS.items()}
    # IRIS EXPLAIN: Iterate paths.items(), binding each item to (key, path); process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for key, path in paths.items():
        # IRIS EXPLAIN: Call path.write_text(payloads[key], encoding='utf-8'): write the existing text payload.
        path.write_text(payloads[key], encoding='utf-8')
    # IRIS EXPLAIN: Return paths to the caller; this ends the current function path.
    return paths


# IRIS EXPLAIN: Class CoreTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_ methods
# IRIS EXPLAIN: independently.
class CoreTests(unittest.TestCase):
    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function CoreTests.setUpClass: Prepare shared trusted-model/synthetic test fixtures once for this class.
    def setUpClass(cls):
        # IRIS EXPLAIN: Store the result of ModelAdapter() in cls.adapter; later lines use this named result.
        cls.adapter = ModelAdapter()
        # IRIS EXPLAIN: Store the computed value MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl'
        # IRIS EXPLAIN: in rows; later lines use this named result.
        rows = MODEL_PROJECT / 'examples/three_input_training/prepared/model_sessions.jsonl'
        # IRIS EXPLAIN: Enter rows.open() as stream; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with rows.open() as stream:
            # IRIS EXPLAIN: Store the comprehension [json.loads(line) for line in stream] in cls.sessions; later lines use this
            # IRIS EXPLAIN: named result.
            cls.sessions = [json.loads(line) for line in stream]

    # IRIS EXPLAIN: Function CoreTests.setUp: Prepare an isolated synthetic fixture for this test and register cleanup; do not
    # IRIS EXPLAIN: modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory(prefix='iris-core-test-') in self.temporary; later lines
        # IRIS EXPLAIN: use this named result.
        self.temporary = tempfile.TemporaryDirectory(prefix='iris-core-test-')
        # IRIS EXPLAIN: Call self.addCleanup(self.temporary.cleanup): register fixture cleanup even if a test fails.
        self.addCleanup(self.temporary.cleanup)
        # IRIS EXPLAIN: Store the result of Path(self.temporary.name) in self.directory; later lines use this named result.
        self.directory = Path(self.temporary.name)
        # IRIS EXPLAIN: Store the result of small_inputs(self.directory / 'inputs') in self.paths; later lines use this named
        # IRIS EXPLAIN: result.
        self.paths = small_inputs(self.directory / 'inputs')
        # IRIS EXPLAIN: Store the result of Settings(self.directory / 'state', KEYS) in self.settings; later lines use this
        # IRIS EXPLAIN: named result.
        self.settings = Settings(self.directory / 'state', KEYS)
        # IRIS EXPLAIN: Store the result of Engine(self.settings, self.adapter) in self.engine; later lines use this named
        # IRIS EXPLAIN: result.
        self.engine = Engine(self.settings, self.adapter)

    # IRIS EXPLAIN: Function CoreTests.test_actual_user_artifact_shadow_prediction: Regression test: verify that actual user
    # IRIS EXPLAIN: artifact shadow prediction; the assertions below define the exact expected behavior.
    def test_actual_user_artifact_shadow_prediction(self):
        # IRIS EXPLAIN: Store the result of self.adapter.predict(self.sessions[0]) (obtain the configured prediction result
        # IRIS EXPLAIN: without training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(self.sessions[0])
        # IRIS EXPLAIN: Call self.assertIsNotNone(prediction['shadow_candidate']): assert that the value is available rather
        # IRIS EXPLAIN: than None.
        self.assertIsNotNone(prediction['shadow_candidate'])
        # IRIS EXPLAIN: Call self.assertFalse(prediction['automatic_execution']): assert that the stated condition is false.
        self.assertFalse(prediction['automatic_execution'])
        # IRIS EXPLAIN: Call self.assertFalse(prediction['official_risk_register_write']): assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(prediction['official_risk_register_write'])
        # IRIS EXPLAIN: Call self.assertFalse(prediction['model1_released']): assert that the stated condition is false.
        self.assertFalse(prediction['model1_released'])
        # IRIS EXPLAIN: Call self.assertFalse(prediction['model2_released']): assert that the stated condition is false.
        self.assertFalse(prediction['model2_released'])
        # IRIS EXPLAIN: Call self.assertNotEqual(prediction['soc_assessment']['method'], 'calibrated_model1'): assert that the
        # IRIS EXPLAIN: values differ.
        self.assertNotEqual(prediction['soc_assessment']['method'], 'calibrated_model1')
        # IRIS EXPLAIN: Call self.assertEqual(self.adapter.metadata['model_sha256'],
        # IRIS EXPLAIN: '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950'): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.adapter.metadata['model_sha256'], '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950')

    # IRIS EXPLAIN: Function CoreTests.test_corruption_rejected_before_model_loading: Regression test: verify that corruption
    # IRIS EXPLAIN: rejected before model loading; the assertions below define the exact expected behavior.
    def test_corruption_rejected_before_model_loading(self):
        # IRIS EXPLAIN: Store the computed value self.directory / 'bad_model' in target; later lines use this named result.
        target = self.directory / 'bad_model'
        # IRIS EXPLAIN: Call shutil.copytree(MODEL_DIR, target) using the existing explicit arguments.
        shutil.copytree(MODEL_DIR, target)
        # IRIS EXPLAIN: Call (target / 'models.joblib').write_bytes(b'not a trusted model'): write the existing byte payload.
        (target / 'models.joblib').write_bytes(b'not a trusted model')
        # IRIS EXPLAIN: Enter mock.patch('backend.model_adapter.ModelService') as loader; its context manager supplies the
        # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
        with mock.patch('backend.model_adapter.ModelService') as loader:
            # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'Pinned model'); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaisesRegex(ValueError, 'Pinned model'):
                # IRIS EXPLAIN: Call ModelAdapter(target) using the existing explicit arguments.
                ModelAdapter(target)
            # IRIS EXPLAIN: Call loader.assert_not_called(): verify that the mocked forbidden path was never invoked.
            loader.assert_not_called()

    # IRIS EXPLAIN: Function CoreTests.test_unhealthy_sensor_abstains: Regression test: verify that unhealthy sensor abstains;
    # IRIS EXPLAIN: the assertions below define the exact expected behavior.
    def test_unhealthy_sensor_abstains(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sessions[0]) (make an independent nested copy for this fixture)
        # IRIS EXPLAIN: in session; later lines use this named result.
        session = copy.deepcopy(self.sessions[0])
        # IRIS EXPLAIN: Store False in session['sensor_healthy']; later lines use this named result.
        session['sensor_healthy'] = False
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Call self.assertIsNone(prediction['shadow_candidate']): assert that the value is exactly None.
        self.assertIsNone(prediction['shadow_candidate'])
        # IRIS EXPLAIN: Call self.assertEqual(evaluate(session, prediction)['priority'], 'Needs Review'): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(evaluate(session, prediction)['priority'], 'Needs Review')

    # IRIS EXPLAIN: Function CoreTests.test_wrong_session_contract_disables_ml: Regression test: verify that wrong session
    # IRIS EXPLAIN: contract disables ml; the assertions below define the exact expected behavior.
    def test_wrong_session_contract_disables_ml(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sessions[0]) (make an independent nested copy for this fixture)
        # IRIS EXPLAIN: in session; later lines use this named result.
        session = copy.deepcopy(self.sessions[0])
        # IRIS EXPLAIN: Store 'old-or-unknown-contract' in session['aggregation_schema']; later lines use this named result.
        session['aggregation_schema'] = 'old-or-unknown-contract'
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Call self.assertIsNone(prediction['shadow_candidate']): assert that the value is exactly None.
        self.assertIsNone(prediction['shadow_candidate'])
        # IRIS EXPLAIN: Call self.assertTrue(any(('contract' in warning for warning in prediction['warnings']))): assert that
        # IRIS EXPLAIN: the stated condition is true.
        self.assertTrue(any('contract' in warning for warning in prediction['warnings']))

    # IRIS EXPLAIN: Function CoreTests.test_shadow_class_does_not_drive_risk_policy: Regression test: verify that shadow class
    # IRIS EXPLAIN: does not drive risk policy; the assertions below define the exact expected behavior.
    def test_shadow_class_does_not_drive_risk_policy(self):
        # IRIS EXPLAIN: Store the result of next((s for s in self.sessions if s['features']['event_family'] == 'network' and
        # IRIS EXPLAIN: s['features']['distinct_ru... in session; later lines use this named result.
        session = next(s for s in self.sessions if s['features']['event_family'] == 'network' and s['features']['distinct_rules'] >= 4 and s['features']['event_count'] >= 15)
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Store the result of evaluate(session, prediction) in before; later lines use this named result.
        before = evaluate(session, prediction)
        # IRIS EXPLAIN: Store 'credential_access' in prediction['shadow_candidate']['scenario_class']; later lines use this
        # IRIS EXPLAIN: named result.
        prediction['shadow_candidate']['scenario_class'] = 'credential_access'
        # IRIS EXPLAIN: Call self.assertEqual(before, evaluate(session, prediction)): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(before, evaluate(session, prediction))

    # IRIS EXPLAIN: Function CoreTests.test_ambiguous_risk_never_guessed: Regression test: verify that ambiguous risk never
    # IRIS EXPLAIN: guessed; the assertions below define the exact expected behavior.
    def test_ambiguous_risk_never_guessed(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(next((s for s in self.sessions if s['features']['event_family'] ==
        # IRIS EXPLAIN: 'network' and s['features']['distinct_rules'] >= 4 ... (make an independent nested copy for this
        # IRIS EXPLAIN: fixture) in session; later lines use this named result.
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['event_family'] == 'network' and s['features']['distinct_rules'] >= 4 and s['features']['event_count'] >= 15))
        # IRIS EXPLAIN: Store the result of copy.deepcopy(next((r for r in session['risk_snapshots'] if r['risk_category'] ==
        # IRIS EXPLAIN: 'Reconnaissance'))) (make an independent nested copy for this fixture) in risk; later lines use this
        # IRIS EXPLAIN: named result.
        risk = copy.deepcopy(next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Reconnaissance'))
        # IRIS EXPLAIN: Call risk.update(risk_id='ANOTHER-REGISTERED-RISK', risk_version_id='ANOTHER-VERSION'): merge the
        # IRIS EXPLAIN: supplied fields into this existing mapping.
        risk.update(risk_id='ANOTHER-REGISTERED-RISK', risk_version_id='ANOTHER-VERSION')
        # IRIS EXPLAIN: Call session['risk_snapshots'].append(risk): append one item to the working list.
        session['risk_snapshots'].append(risk)
        # IRIS EXPLAIN: Store the result of evaluate(session, self.adapter.predict(session)) in result; later lines use this
        # IRIS EXPLAIN: named result.
        result = evaluate(session, self.adapter.predict(session))
        # IRIS EXPLAIN: Call self.assertEqual(result['mapping_status'], 'AMBIGUOUS'): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(result['mapping_status'], 'AMBIGUOUS')
        # IRIS EXPLAIN: Call self.assertIsNone(result['matched_risk_id']): assert that the value is exactly None.
        self.assertIsNone(result['matched_risk_id'])
        # IRIS EXPLAIN: Call self.assertIsNone(result['proposed_likelihood']): assert that the value is exactly None.
        self.assertIsNone(result['proposed_likelihood'])

    # IRIS EXPLAIN: Function CoreTests.test_benign_critical_asset_stays_low: Regression test: verify that benign critical asset
    # IRIS EXPLAIN: stays low; the assertions below define the exact expected behavior.
    def test_benign_critical_asset_stays_low(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sessions[0]) (make an independent nested copy for this fixture)
        # IRIS EXPLAIN: in session; later lines use this named result.
        session = copy.deepcopy(self.sessions[0])
        # IRIS EXPLAIN: Store 5 in session['asset_snapshot']['criticality']; later lines use this named result.
        session['asset_snapshot']['criticality'] = 5
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Call prediction['soc_assessment'].update(scenario_class='benign', status='ASSESSED',
        # IRIS EXPLAIN: method='rule_baseline'): merge the supplied fields into this existing mapping.
        prediction['soc_assessment'].update(scenario_class='benign', status='ASSESSED', method='rule_baseline')
        # IRIS EXPLAIN: Call self.assertEqual(evaluate(session, prediction)['priority'], 'Low'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(evaluate(session, prediction)['priority'], 'Low')

    # IRIS EXPLAIN: Function CoreTests.test_missing_risk_does_not_invent_likelihood: Regression test: verify that missing risk
    # IRIS EXPLAIN: does not invent likelihood; the assertions below define the exact expected behavior.
    def test_missing_risk_does_not_invent_likelihood(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(self.sessions[0]) (make an independent nested copy for this fixture)
        # IRIS EXPLAIN: in session; later lines use this named result.
        session = copy.deepcopy(self.sessions[0])
        # IRIS EXPLAIN: Store [] in session['risk_snapshots']; later lines use this named result.
        session['risk_snapshots'] = []
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Call prediction['soc_assessment'].update(scenario_class='reconnaissance', status='ASSESSED',
        # IRIS EXPLAIN: method='rule_baseline'): merge the supplied fields into this existing mapping.
        prediction['soc_assessment'].update(scenario_class='reconnaissance', status='ASSESSED', method='rule_baseline')
        # IRIS EXPLAIN: Store the result of evaluate(session, prediction) in result; later lines use this named result.
        result = evaluate(session, prediction)
        # IRIS EXPLAIN: Call self.assertIsNone(result['baseline_risk_0_1']): assert that the value is exactly None.
        self.assertIsNone(result['baseline_risk_0_1'])
        # IRIS EXPLAIN: Call self.assertIsNone(result['proposed_likelihood']): assert that the value is exactly None.
        self.assertIsNone(result['proposed_likelihood'])

    # IRIS EXPLAIN: Function CoreTests.test_primary_controls_use_actual_matched_risk_states: Regression test: verify that
    # IRIS EXPLAIN: primary controls use actual matched risk states; the assertions below define the exact expected behavior.
    def test_primary_controls_use_actual_matched_risk_states(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(next((s for s in self.sessions if s['features']['failed_count'] >= 12
        # IRIS EXPLAIN: and s['features']['failure_ratio'] >= 0.75))) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: session; later lines use this named result.
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['failed_count'] >= 12 and s['features']['failure_ratio'] >= .75))
        # IRIS EXPLAIN: Store the result of next((r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized
        # IRIS EXPLAIN: Access')) in matched; later lines use this named result.
        matched = next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized Access')
        # IRIS EXPLAIN: Store a mapping containing SC005 in session['context']['controls']; later lines use this named result.
        session['context']['controls'] = {'SC005': 'implemented'}
        # IRIS EXPLAIN: Store 'missing' in matched['control_states']['SC005']; later lines use this named result.
        matched['control_states']['SC005'] = 'missing'
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Store the result of primary_controls(session, prediction, evaluate(session, prediction)) in advice;
        # IRIS EXPLAIN: later lines use this named result.
        advice = primary_controls(session, prediction, evaluate(session, prediction))
        # IRIS EXPLAIN: Store the result of next((r for r in advice['recommendations'] if r['control_id'] == 'SC005')) in
        # IRIS EXPLAIN: control; later lines use this named result.
        control = next(r for r in advice['recommendations'] if r['control_id'] == 'SC005')
        # IRIS EXPLAIN: Call self.assertEqual((control['current_state'], control['action_type']), ('missing', 'install')):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual((control['current_state'], control['action_type']), ('missing', 'install'))
        # IRIS EXPLAIN: Call self.assertEqual(advice['control_state_risk_id'], matched['risk_id']): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(advice['control_state_risk_id'], matched['risk_id'])

    # IRIS EXPLAIN: Function CoreTests.test_active_matched_risk_exception_requires_review: Regression test: verify that active
    # IRIS EXPLAIN: matched risk exception requires review; the assertions below define the exact expected behavior.
    def test_active_matched_risk_exception_requires_review(self):
        # IRIS EXPLAIN: Store the result of copy.deepcopy(next((s for s in self.sessions if s['features']['failed_count'] >= 12
        # IRIS EXPLAIN: and s['features']['failure_ratio'] >= 0.75))) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: session; later lines use this named result.
        session = copy.deepcopy(next(s for s in self.sessions if s['features']['failed_count'] >= 12 and s['features']['failure_ratio'] >= .75))
        # IRIS EXPLAIN: Store the result of next((r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized
        # IRIS EXPLAIN: Access')) in matched; later lines use this named result.
        matched = next(r for r in session['risk_snapshots'] if r['risk_category'] == 'Unauthorized Access')
        # IRIS EXPLAIN: Store ['SC005'] in matched['active_exception_control_ids']; later lines use this named result.
        matched['active_exception_control_ids'] = ['SC005']
        # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result without
        # IRIS EXPLAIN: training on this call) in prediction; later lines use this named result.
        prediction = self.adapter.predict(session)
        # IRIS EXPLAIN: Store the result of primary_controls(session, prediction, evaluate(session, prediction)) in advice;
        # IRIS EXPLAIN: later lines use this named result.
        advice = primary_controls(session, prediction, evaluate(session, prediction))
        # IRIS EXPLAIN: Call self.assertEqual(next((r for r in advice['recommendations'] if r['control_id'] ==
        # IRIS EXPLAIN: 'SC005'))['action_type'], 'review'): assert that the actual and expected values are equal.
        self.assertEqual(next(r for r in advice['recommendations'] if r['control_id'] == 'SC005')['action_type'], 'review')

    # IRIS EXPLAIN: Function CoreTests.test_complete_batch_persists_evidence_without_labels: Regression test: verify that
    # IRIS EXPLAIN: complete batch persists evidence without labels; the assertions below define the exact expected behavior.
    def test_complete_batch_persists_evidence_without_labels(self):
        # IRIS EXPLAIN: Store the result of self.engine.run(self.paths, 'admin') in result; later lines use this named result.
        result = self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Call self.assertEqual(result['sessions'], 1): assert that the actual and expected values are equal.
        self.assertEqual(result['sessions'], 1)
        # IRIS EXPLAIN: Call self.assertFalse(result['training_labels_read']): assert that the stated condition is false.
        self.assertFalse(result['training_labels_read'])
        # IRIS EXPLAIN: Call self.assertFalse(result['official_risk_register_write']): assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(result['official_risk_register_write'])
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.store.health()['cases'], 1): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.engine.store.health()['cases'], 1)
        # IRIS EXPLAIN: Store the computed value self.settings.state_dir / 'runs' / result['run_id'] / 'inputs' in inputs; later
        # IRIS EXPLAIN: lines use this named result.
        inputs = self.settings.state_dir / 'runs' / result['run_id'] / 'inputs'
        # IRIS EXPLAIN: Call self.assertEqual({p.name for p in inputs.iterdir()}, set(INPUTS.values())): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual({p.name for p in inputs.iterdir()}, set(INPUTS.values()))
        # IRIS EXPLAIN: Call self.assertTrue((inputs.parent / 'prepared/unified_events.jsonl').is_file()): assert that the
        # IRIS EXPLAIN: stated condition is true.
        self.assertTrue((inputs.parent / 'prepared/unified_events.jsonl').is_file())

    # IRIS EXPLAIN: Function CoreTests.test_repeated_identical_batch_reuses_completed_run: Regression test: verify that repeated
    # IRIS EXPLAIN: identical batch reuses completed run; the assertions below define the exact expected behavior.
    def test_repeated_identical_batch_reuses_completed_run(self):
        # IRIS EXPLAIN: Store the result of self.engine.run(self.paths, 'admin') in first; later lines use this named result.
        first = self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Enter mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Must not predict again'));
        # IRIS EXPLAIN: its context manager supplies the existing cleanup/transaction/expected-exception behavior.
        with mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Must not predict again')):
            # IRIS EXPLAIN: Store the result of self.engine.run(self.paths, 'soc') in second; later lines use this named result.
            second = self.engine.run(self.paths, 'soc')
        # IRIS EXPLAIN: Call self.assertEqual(first['run_id'], second['run_id']): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(first['run_id'], second['run_id'])
        # IRIS EXPLAIN: Call self.assertTrue(second['reused_existing_run']): assert that the stated condition is true.
        self.assertTrue(second['reused_existing_run'])
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.store.health()['runs'], 1): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(self.engine.store.health()['runs'], 1)

    # IRIS EXPLAIN: Function CoreTests.test_reuse_survives_engine_restart: Regression test: verify that reuse survives engine
    # IRIS EXPLAIN: restart; the assertions below define the exact expected behavior.
    def test_reuse_survives_engine_restart(self):
        # IRIS EXPLAIN: Store the result of self.engine.run(self.paths, 'admin') in first; later lines use this named result.
        first = self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Store the result of Engine(self.settings, self.adapter) in replacement; later lines use this named
        # IRIS EXPLAIN: result.
        replacement = Engine(self.settings, self.adapter)
        # IRIS EXPLAIN: Call self.assertEqual(replacement.run(self.paths, 'admin')['run_id'], first['run_id']): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(replacement.run(self.paths, 'admin')['run_id'], first['run_id'])

    # IRIS EXPLAIN: Function CoreTests.test_grc_cannot_submit_batch: Regression test: verify that grc cannot submit batch; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_grc_cannot_submit_batch(self):
        # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(PermissionError):
            # IRIS EXPLAIN: Call self.engine.run(self.paths, 'grc') using the existing explicit arguments.
            self.engine.run(self.paths, 'grc')
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.store.health()['runs'], 0): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(self.engine.store.health()['runs'], 0)

    # IRIS EXPLAIN: Function CoreTests.test_fourth_runtime_input_rejected: Regression test: verify that fourth runtime input
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_fourth_runtime_input_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'Exactly'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, 'Exactly'):
            # IRIS EXPLAIN: Call self.engine.run({**self.paths, 'labels': self.paths['siem_alerts']}, 'admin') using the
            # IRIS EXPLAIN: existing explicit arguments.
            self.engine.run({**self.paths, 'labels': self.paths['siem_alerts']}, 'admin')

    # IRIS EXPLAIN: Function CoreTests.test_invalid_source_records_failure_not_partial_cases: Regression test: verify that
    # IRIS EXPLAIN: invalid source records failure not partial cases; the assertions below define the exact expected behavior.
    def test_invalid_source_records_failure_not_partial_cases(self):
        # IRIS EXPLAIN: Call self.paths['asset_inventory'].write_text('{}'): write the existing text payload.
        self.paths['asset_inventory'].write_text('{}')
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
            self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.store.runs()[0]['status'], 'failed'): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.engine.store.runs()[0]['status'], 'failed')
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.store.health()['cases'], 0): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.engine.store.health()['cases'], 0)

    # IRIS EXPLAIN: Function CoreTests.test_alert_count_bound: Regression test: verify that alert count bound; the assertions
    # IRIS EXPLAIN: below define the exact expected behavior.
    def test_alert_count_bound(self):
        # IRIS EXPLAIN: Store the result of self.paths['siem_alerts'].read_text() (read text from the selected file) in content;
        # IRIS EXPLAIN: later lines use this named result.
        content = self.paths['siem_alerts'].read_text()
        # IRIS EXPLAIN: Call self.paths['siem_alerts'].write_text(content + content): write the existing text payload.
        self.paths['siem_alerts'].write_text(content + content)
        # IRIS EXPLAIN: Store the result of Engine(Settings(self.directory / 'limited', KEYS, max_alert_rows=1), self.adapter)
        # IRIS EXPLAIN: in engine; later lines use this named result.
        engine = Engine(Settings(self.directory / 'limited', KEYS, max_alert_rows=1), self.adapter)
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'alert-row'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, 'alert-row'):
            # IRIS EXPLAIN: Call engine.run(self.paths, 'admin') using the existing explicit arguments.
            engine.run(self.paths, 'admin')

    # IRIS EXPLAIN: Function CoreTests.test_risk_context_expansion_bound_before_preparation: Regression test: verify that risk
    # IRIS EXPLAIN: context expansion bound before preparation; the assertions below define the exact expected behavior.
    def test_risk_context_expansion_bound_before_preparation(self):
        # IRIS EXPLAIN: Store the result of json.loads(self.paths['risk_register'].read_text()) (decode the existing JSON text)
        # IRIS EXPLAIN: in payload; later lines use this named result.
        payload = json.loads(self.paths['risk_register'].read_text())
        # IRIS EXPLAIN: Store payload['records'][0] in template; later lines use this named result.
        template = payload['records'][0]
        # IRIS EXPLAIN: Store the comprehension [{**template, 'risk_id': f'EXCESS-{i}', 'risk_version_id': f'EXCESS-{i}-V1'} for
        # IRIS EXPLAIN: i in range(11)] in payload['records']; later lines use this named result.
        payload['records'] = [{**template, 'risk_id': f'EXCESS-{i}', 'risk_version_id': f'EXCESS-{i}-V1'} for i in range(11)]
        # IRIS EXPLAIN: Call self.paths['risk_register'].write_text(json.dumps(payload)): write the existing text payload.
        self.paths['risk_register'].write_text(json.dumps(payload))
        # IRIS EXPLAIN: Enter mock.patch('backend.core.prepare_three') as prepare; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with mock.patch('backend.core.prepare_three') as prepare:
            # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'expansion limit'); its context manager supplies the
            # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
            with self.assertRaisesRegex(ValueError, 'expansion limit'):
                # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
                self.engine.run(self.paths, 'admin')
            # IRIS EXPLAIN: Call prepare.assert_not_called(): verify that the mocked forbidden path was never invoked.
            prepare.assert_not_called()

    # IRIS EXPLAIN: Function CoreTests.test_concurrent_batch_is_rejected_without_releasing_other_lock: Regression test: verify
    # IRIS EXPLAIN: that concurrent batch is rejected without releasing other lock; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_concurrent_batch_is_rejected_without_releasing_other_lock(self):
        # IRIS EXPLAIN: Call self.engine.lock.acquire(): attempt to acquire the operation lock using the existing blocking
        # IRIS EXPLAIN: setting.
        self.engine.lock.acquire()
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Enter self.assertRaises(BusyError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(BusyError):
                # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
                self.engine.run(self.paths, 'admin')
            # IRIS EXPLAIN: Call self.assertTrue(self.engine.lock.locked()): assert that the stated condition is true.
            self.assertTrue(self.engine.lock.locked())
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call self.engine.lock.release(): release the acquired lock.
            self.engine.lock.release()

    # IRIS EXPLAIN: Function CoreTests.test_review_is_local_and_append_only: Regression test: verify that review is local and
    # IRIS EXPLAIN: append only; the assertions below define the exact expected behavior.
    def test_review_is_local_and_append_only(self):
        # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
        self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Store self.engine.store.cases()['items'][0] in case; later lines use this named result.
        case = self.engine.store.cases()['items'][0]
        # IRIS EXPLAIN: Store the result of copy.deepcopy(case['session']) (make an independent nested copy for this fixture) in
        # IRIS EXPLAIN: original; later lines use this named result.
        original = copy.deepcopy(case['session'])
        # IRIS EXPLAIN: Call self.engine.store.review(case['case_id'], 'approve_follow_up', 'Reviewed for follow-up only',
        # IRIS EXPLAIN: 'grc') using the existing explicit arguments.
        self.engine.store.review(case['case_id'], 'approve_follow_up', 'Reviewed for follow-up only', 'grc')
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'already'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, 'already'):
            # IRIS EXPLAIN: Call self.engine.store.review(case['case_id'], 'reject_suggestion', 'Cannot overwrite prior review',
            # IRIS EXPLAIN: 'grc') using the existing explicit arguments.
            self.engine.store.review(case['case_id'], 'reject_suggestion', 'Cannot overwrite prior review', 'grc')
        # IRIS EXPLAIN: Store the result of self.engine.store.case(case['case_id']) in saved; later lines use this named result.
        saved = self.engine.store.case(case['case_id'])
        # IRIS EXPLAIN: Call self.assertEqual(saved['session'], original): assert that the actual and expected values are equal.
        self.assertEqual(saved['session'], original)
        # IRIS EXPLAIN: Call self.assertFalse(saved['prediction']['official_risk_register_write']): assert that the stated
        # IRIS EXPLAIN: condition is false.
        self.assertFalse(saved['prediction']['official_risk_register_write'])

    # IRIS EXPLAIN: Function CoreTests.test_admin_cannot_impersonate_grc_reviewer: Regression test: verify that admin cannot
    # IRIS EXPLAIN: impersonate grc reviewer; the assertions below define the exact expected behavior.
    def test_admin_cannot_impersonate_grc_reviewer(self):
        # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
        self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Store self.engine.store.cases()['items'][0] in case; later lines use this named result.
        case = self.engine.store.cases()['items'][0]
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call self.engine.store.review(case['case_id'], 'approve_follow_up', 'Not an authorized risk
            # IRIS EXPLAIN: reviewer', 'admin') using the existing explicit arguments.
            self.engine.store.review(case['case_id'], 'approve_follow_up', 'Not an authorized risk reviewer', 'admin')

    # IRIS EXPLAIN: Function CoreTests.test_role_views_are_separate: Regression test: verify that role views are separate; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_role_views_are_separate(self):
        # IRIS EXPLAIN: Call self.engine.run(self.paths, 'admin') using the existing explicit arguments.
        self.engine.run(self.paths, 'admin')
        # IRIS EXPLAIN: Store self.engine.store.cases()['items'][0] in case; later lines use this named result.
        case = self.engine.store.cases()['items'][0]
        # IRIS EXPLAIN: Call self.assertIn('source_event_ids', view(case, 'soc')): assert that the item belongs to the expected
        # IRIS EXPLAIN: collection.
        self.assertIn('source_event_ids', view(case, 'soc'))
        # IRIS EXPLAIN: Call self.assertNotIn('risk_snapshots', view(case, 'soc')): assert that the item is absent.
        self.assertNotIn('risk_snapshots', view(case, 'soc'))
        # IRIS EXPLAIN: Call self.assertIn('risk_snapshots', view(case, 'grc')): assert that the item belongs to the expected
        # IRIS EXPLAIN: collection.
        self.assertIn('risk_snapshots', view(case, 'grc'))
        # IRIS EXPLAIN: Call self.assertNotIn('source_event_ids', view(case, 'grc')): assert that the item is absent.
        self.assertNotIn('source_event_ids', view(case, 'grc'))

    # IRIS EXPLAIN: Function CoreTests.test_initialize_preserves_credentials: Regression test: verify that initialize preserves
    # IRIS EXPLAIN: credentials; the assertions below define the exact expected behavior.
    def test_initialize_preserves_credentials(self):
        # IRIS EXPLAIN: Store the computed value self.directory / 'private/access.json' in path; later lines use this named
        # IRIS EXPLAIN: result.
        path = self.directory / 'private/access.json'
        # IRIS EXPLAIN: Call initialize(path) using the existing explicit arguments.
        initialize(path)
        # IRIS EXPLAIN: Store the result of path.read_bytes() (read the exact file bytes) in original; later lines use this
        # IRIS EXPLAIN: named result.
        original = path.read_bytes()
        # IRIS EXPLAIN: Store the result of Settings.load(path) in settings; later lines use this named result.
        settings = Settings.load(path)
        # IRIS EXPLAIN: Call self.assertEqual(set(settings.role_keys), {'soc', 'grc', 'admin'}): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(set(settings.role_keys), {'soc', 'grc', 'admin'})
        # IRIS EXPLAIN: Enter self.assertRaises(FileExistsError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(FileExistsError):
            # IRIS EXPLAIN: Call initialize(path) using the existing explicit arguments.
            initialize(path)
        # IRIS EXPLAIN: Call self.assertEqual(original, path.read_bytes()): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(original, path.read_bytes())
        # IRIS EXPLAIN: Enter this branch only when os.name == 'posix'.
        if os.name == 'posix':
            # IRIS EXPLAIN: Call self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 63, 0): assert that the actual and
            # IRIS EXPLAIN: expected values are equal.
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    # IRIS EXPLAIN: Function CoreTests.test_duplicate_role_keys_rejected: Regression test: verify that duplicate role keys
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_duplicate_role_keys_rejected(self):
        # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ValueError):
            # IRIS EXPLAIN: Call Settings(self.directory, {r: 'x' * 40 for r in KEYS}) using the existing explicit arguments.
            Settings(self.directory, {r: 'x' * 40 for r in KEYS})


# IRIS EXPLAIN: Class GuardTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_ methods
# IRIS EXPLAIN: independently.
class GuardTests(unittest.TestCase):
    # IRIS EXPLAIN: Function GuardTests.invoke: Drive the actual ASGI guard with explicit synthetic headers/body chunks and
    # IRIS EXPLAIN: collect its response messages.
    # IRIS EXPLAIN: Inputs: headers: the explicit headers input used by the unchanged statements below; messages: the explicit
    # IRIS EXPLAIN: messages input used by the unchanged statements below; path: the explicit local file path used by this
    # IRIS EXPLAIN: helper; method: the parsed HTTP verb routed by the local adapter; cap: the explicit cap input used by the
    # IRIS EXPLAIN: unchanged statements below.
    def invoke(self, headers=None, messages=None, path='/api/model', method='GET', cap=1024):
        # IRIS EXPLAIN: Store ([], []) in (sent, seen); later lines use this named result.
        sent, seen = [], []
        # IRIS EXPLAIN: Store list(messages or [{'type': 'http.request', 'body': b'', 'more_body': False}]) in body; later lines
        # IRIS EXPLAIN: use this named result.
        body = list(messages or [{'type': 'http.request', 'body': b'', 'more_body': False}])
        # IRIS EXPLAIN: Store [] in reads; later lines use this named result.
        reads = []
        # IRIS EXPLAIN: Function GuardTests.receive: Provide the next synthetic ASGI request chunk to the boundary test.
        async def receive():
            # IRIS EXPLAIN: Call reads.append(True): append one item to the working list.
            reads.append(True)
            # IRIS EXPLAIN: Return the result of body.pop(0) (remove and return the selected item) when body; otherwise a
            # IRIS EXPLAIN: mapping containing type to the caller; this ends the current function path.
            return body.pop(0) if body else {'type': 'http.disconnect'}
        # IRIS EXPLAIN: Function GuardTests.send: Collect the actual ASGI response messages produced by the boundary under test.
        # IRIS EXPLAIN: Inputs: message: the explicit message input used by the unchanged statements below.
        async def send(message):
            # IRIS EXPLAIN: Call sent.append(message): append one item to the working list.
            sent.append(message)
        # IRIS EXPLAIN: Function GuardTests.app: Minimal downstream ASGI fixture verifying what the real guard passes through.
        # IRIS EXPLAIN: Inputs: scope: ASGI connection/request metadata; receive: the upstream ASGI input callback; send: the
        # IRIS EXPLAIN: downstream ASGI response callback.
        async def app(scope, receive, send):
            # IRIS EXPLAIN: Call seen.append(scope.get('state', {}).get('principal')): append one item to the working list.
            seen.append(scope.get('state', {}).get('principal'))
            # IRIS EXPLAIN: Enter this branch only when method == 'POST'.
            if method == 'POST':
                # IRIS EXPLAIN: Call seen.append((await receive()).get('body')): append one item to the working list.
                seen.append((await receive()).get('body'))
            # IRIS EXPLAIN: Await send({'type': 'http.response.start', 'status': 200, 'headers': []}): send the already prepared
            # IRIS EXPLAIN: response/message.
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            # IRIS EXPLAIN: Await send({'type': 'http.response.body', 'body': b'ok'}): send the already prepared
            # IRIS EXPLAIN: response/message.
            await send({'type': 'http.response.body', 'body': b'ok'})
        # IRIS EXPLAIN: Store a mapping containing type, path, method, headers in scope; later lines use this named result.
        scope = {'type': 'http', 'path': path, 'method': method,
                 # IRIS EXPLAIN: Continue the current record with headers; each value comes from the expression shown on this
                 # IRIS EXPLAIN: unchanged line.
                 'headers': [(b'host', b'testserver'), *(headers or [])]}
        # IRIS EXPLAIN: Call asyncio.run(Guard(app, Settings(Path('.'), KEYS, max_body_bytes=cap))(scope, receive, send)) using
        # IRIS EXPLAIN: the existing explicit arguments.
        asyncio.run(Guard(app, Settings(Path('.'), KEYS, max_body_bytes=cap))(scope, receive, send))
        # IRIS EXPLAIN: Return (sent[0]['status'], seen, len(reads)) to the caller; this ends the current function path.
        return sent[0]['status'], seen, len(reads)

    # IRIS EXPLAIN: Function GuardTests.test_auth_before_any_upload_read: Regression test: verify that auth before any upload
    # IRIS EXPLAIN: read; the assertions below define the exact expected behavior.
    def test_auth_before_any_upload_read(self):
        # IRIS EXPLAIN: Store the result of self.invoke(method='POST') in (code, seen, reads); later lines use this named
        # IRIS EXPLAIN: result.
        code, seen, reads = self.invoke(method='POST')
        # IRIS EXPLAIN: Call self.assertEqual((code, seen, reads), (401, [], 0)): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual((code, seen, reads), (401, [], 0))

    # IRIS EXPLAIN: Function GuardTests.test_role_is_derived_from_key: Regression test: verify that role is derived from key;
    # IRIS EXPLAIN: the assertions below define the exact expected behavior.
    def test_role_is_derived_from_key(self):
        # IRIS EXPLAIN: Store the result of self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())]) in (code, seen, _);
        # IRIS EXPLAIN: later lines use this named result.
        code, seen, _ = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())])
        # IRIS EXPLAIN: Call self.assertEqual((code, seen), (200, ['soc'])): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual((code, seen), (200, ['soc']))

    # IRIS EXPLAIN: Function GuardTests.test_duplicate_keys_rejected: Regression test: verify that duplicate keys rejected; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_duplicate_keys_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'x-iris-key',
        # IRIS EXPLAIN: KEYS['admin'].encode())])[0], 401): assert that the actual and expected values are equal.
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'x-iris-key', KEYS['admin'].encode())])[0], 401)

    # IRIS EXPLAIN: Function GuardTests.test_non_ascii_key_is_not_a_server_error: Regression test: verify that non ascii key is
    # IRIS EXPLAIN: not a server error; the assertions below define the exact expected behavior.
    def test_non_ascii_key_is_not_a_server_error(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.invoke(headers=[(b'x-iris-key', b'\xff' * 40)])[0], 401): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', b'\xff' * 40)])[0], 401)

    # IRIS EXPLAIN: Function GuardTests.test_foreign_origin_rejected: Regression test: verify that foreign origin rejected; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_foreign_origin_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.invoke(headers=[(b'origin', b'https://untrusted.example'), (b'x-iris-key',
        # IRIS EXPLAIN: KEYS['admin'].encode())])[0], 403): assert that the actual and expected values are equal.
        self.assertEqual(self.invoke(headers=[(b'origin', b'https://untrusted.example'), (b'x-iris-key', KEYS['admin'].encode())])[0], 403)

    # IRIS EXPLAIN: Function GuardTests.test_content_length_limit_before_body_read: Regression test: verify that content length
    # IRIS EXPLAIN: limit before body read; the assertions below define the exact expected behavior.
    def test_content_length_limit_before_body_read(self):
        # IRIS EXPLAIN: Store the result of self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'content-length',
        # IRIS EXPLAIN: b'100')], method='POST', ca... in (code, _, reads); later lines use this named result.
        code, _, reads = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode()), (b'content-length', b'100')], method='POST', cap=10)
        # IRIS EXPLAIN: Call self.assertEqual((code, reads), (413, 0)): assert that the actual and expected values are equal.
        self.assertEqual((code, reads), (413, 0))

    # IRIS EXPLAIN: Function GuardTests.test_chunked_body_limit_without_length_header: Regression test: verify that chunked body
    # IRIS EXPLAIN: limit without length header; the assertions below define the exact expected behavior.
    def test_chunked_body_limit_without_length_header(self):
        # IRIS EXPLAIN: Store [{'type': 'http.request', 'body': b'123456', 'more_body': True}, {'type': 'http.request', 'body':
        # IRIS EXPLAIN: b'78901', 'more_body': False}] in messages; later lines use this named result.
        messages = [{'type': 'http.request', 'body': b'123456', 'more_body': True}, {'type': 'http.request', 'body': b'78901', 'more_body': False}]
        # IRIS EXPLAIN: Call self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages,
        # IRIS EXPLAIN: method='POST', cap=10)[0], 413): assert that the actual and expected values are equal.
        self.assertEqual(self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages, method='POST', cap=10)[0], 413)

    # IRIS EXPLAIN: Function GuardTests.test_buffered_body_is_replayed: Regression test: verify that buffered body is replayed;
    # IRIS EXPLAIN: the assertions below define the exact expected behavior.
    def test_buffered_body_is_replayed(self):
        # IRIS EXPLAIN: Store [{'type': 'http.request', 'body': b'ab', 'more_body': True}, {'type': 'http.request', 'body':
        # IRIS EXPLAIN: b'cd', 'more_body': False}] in messages; later lines use this named result.
        messages = [{'type': 'http.request', 'body': b'ab', 'more_body': True}, {'type': 'http.request', 'body': b'cd', 'more_body': False}]
        # IRIS EXPLAIN: Store the result of self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages,
        # IRIS EXPLAIN: method='POST') in (code, seen, _); later lines use this named result.
        code, seen, _ = self.invoke(headers=[(b'x-iris-key', KEYS['soc'].encode())], messages=messages, method='POST')
        # IRIS EXPLAIN: Call self.assertEqual((code, seen), (200, ['soc', b'abcd'])): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual((code, seen), (200, ['soc', b'abcd']))

    # IRIS EXPLAIN: Function GuardTests.test_public_health_does_not_require_a_key: Regression test: verify that public health
    # IRIS EXPLAIN: does not require a key; the assertions below define the exact expected behavior.
    def test_public_health_does_not_require_a_key(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.invoke(path='/health')[0], 200): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(self.invoke(path='/health')[0], 200)


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == '__main__':
    # IRIS EXPLAIN: Call unittest.main() using the existing explicit arguments.
    unittest.main()
