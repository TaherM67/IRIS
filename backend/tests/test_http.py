# IRIS EXPLAIN: File purpose: Prepared HTTP tests for the earlier FastAPI interface; these require its web dependencies and are
# IRIS EXPLAIN: separate from the executed active-demo HTTP suite.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""TARGET-COMPUTER TESTS: requires the complete requirements-backend.txt.

These are deliberately not silently skipped when dependencies are missing.
HTTP tests were not run in the build environment; PyPI returned 403.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import unittest to define regression assertions and controlled test mocks.
import unittest
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import mock from unittest to define regression assertions and controlled test mocks.
from unittest import mock

# IRIS EXPLAIN: Import TestClient from fastapi.testclient to declare the earlier HTTP routes, uploads, authorization responses
# IRIS EXPLAIN: and schemas.
from fastapi.testclient import TestClient

# IRIS EXPLAIN: Import create_app from backend.app to reuse the shared project contract/implementation rather than duplicate it.
from backend.app import create_app
# IRIS EXPLAIN: Import Settings from backend.config to reuse the shared project contract/implementation rather than duplicate
# IRIS EXPLAIN: it.
from backend.config import Settings
# IRIS EXPLAIN: Import KEYS, small_inputs from backend.tests.test_core to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from backend.tests.test_core import KEYS, small_inputs


# IRIS EXPLAIN: Class HTTPTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_ methods
# IRIS EXPLAIN: independently.
class HTTPTests(unittest.TestCase):
    # IRIS EXPLAIN: Function HTTPTests.setUp: Prepare an isolated synthetic fixture for this test and register cleanup; do not
    # IRIS EXPLAIN: modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory(prefix='iris-http-test-') in self.temporary; later lines
        # IRIS EXPLAIN: use this named result.
        self.temporary = tempfile.TemporaryDirectory(prefix='iris-http-test-')
        # IRIS EXPLAIN: Store the result of Path(self.temporary.name) in self.directory; later lines use this named result.
        self.directory = Path(self.temporary.name)
        # IRIS EXPLAIN: Store the result of small_inputs(self.directory / 'inputs') in self.paths; later lines use this named
        # IRIS EXPLAIN: result.
        self.paths = small_inputs(self.directory / 'inputs')
        # IRIS EXPLAIN: Store the result of Settings(self.directory / 'state', KEYS) in self.settings; later lines use this
        # IRIS EXPLAIN: named result.
        self.settings = Settings(self.directory / 'state', KEYS)
        # IRIS EXPLAIN: Store the result of TestClient(create_app(self.settings)) in self.client; later lines use this named
        # IRIS EXPLAIN: result.
        self.client = TestClient(create_app(self.settings))
        # IRIS EXPLAIN: Call self.client.__enter__() using the existing explicit arguments.
        self.client.__enter__()

    # IRIS EXPLAIN: Function HTTPTests.tearDown: Close test-owned clients/servers or temporary fixtures so no resources or
    # IRIS EXPLAIN: mutable test state leak to later tests.
    def tearDown(self):
        # IRIS EXPLAIN: Call self.client.__exit__(None, None, None) using the existing explicit arguments.
        self.client.__exit__(None, None, None)
        # IRIS EXPLAIN: Call self.temporary.cleanup(): remove only this fixture-owned temporary directory.
        self.temporary.cleanup()

    # IRIS EXPLAIN: Function HTTPTests.headers: Build request headers containing the explicitly chosen synthetic test key.
    # IRIS EXPLAIN: Inputs: role: the authenticated role or explicitly constructed test fixture role.
    def headers(self, role='soc'):
        # IRIS EXPLAIN: Return a mapping containing X-IRIS-Key to the caller; this ends the current function path.
        return {'X-IRIS-Key': KEYS[role]}

    # IRIS EXPLAIN: Function HTTPTests.files: Build exactly the three named synthetic multipart file parts for the HTTP test.
    def files(self):
        # IRIS EXPLAIN: Return the comprehension {key: (path.name, path.read_bytes(), 'application/octet-stream') for key, path
        # IRIS EXPLAIN: in self.paths.items()} to the caller; this ends the current function path.
        return {key: (path.name, path.read_bytes(), 'application/octet-stream') for key, path in self.paths.items()}

    # IRIS EXPLAIN: Function HTTPTests.submit: Send the test-owned three-file batch to the earlier HTTP endpoint.
    def submit(self):
        # IRIS EXPLAIN: Store the result of self.client.post('/api/runs', headers=self.headers(), files=self.files()) in
        # IRIS EXPLAIN: response; later lines use this named result.
        response = self.client.post('/api/runs', headers=self.headers(), files=self.files())
        # IRIS EXPLAIN: Call self.assertEqual(response.status_code, 200, response.text): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(response.status_code, 200, response.text)
        # IRIS EXPLAIN: Return the result of response.json() to the caller; this ends the current function path.
        return response.json()

    # IRIS EXPLAIN: Function HTTPTests.test_health_and_static_ui: Regression test: verify that health and static ui; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_health_and_static_ui(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/health').status_code, 200): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.client.get('/health').status_code, 200)
        # IRIS EXPLAIN: Call self.assertIn('SHADOW', self.client.get('/').text): assert that the item belongs to the expected
        # IRIS EXPLAIN: collection.
        self.assertIn('SHADOW', self.client.get('/').text)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/static/app.js').status_code, 200): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.client.get('/static/app.js').status_code, 200)
        # IRIS EXPLAIN: Call self.assertIn("script-src 'self'", self.client.get('/').headers['content-security-policy']): assert
        # IRIS EXPLAIN: that the item belongs to the expected collection.
        self.assertIn("script-src 'self'", self.client.get('/').headers['content-security-policy'])

    # IRIS EXPLAIN: Function HTTPTests.test_unauthenticated_api_rejected: Regression test: verify that unauthenticated api
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_unauthenticated_api_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/model').status_code, 401): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.client.get('/api/model').status_code, 401)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post('/api/runs', files=self.files()).status_code, 401): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual(self.client.post('/api/runs', files=self.files()).status_code, 401)

    # IRIS EXPLAIN: Function HTTPTests.test_role_access_enforced_by_backend: Regression test: verify that role access enforced
    # IRIS EXPLAIN: by backend; the assertions below define the exact expected behavior.
    def test_role_access_enforced_by_backend(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/admin/status', headers=self.headers('soc')).status_code,
        # IRIS EXPLAIN: 403): assert that the actual and expected values are equal.
        self.assertEqual(self.client.get('/api/admin/status', headers=self.headers('soc')).status_code, 403)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/grc/cases', headers=self.headers('soc')).status_code, 403):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual(self.client.get('/api/grc/cases', headers=self.headers('soc')).status_code, 403)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/soc/cases', headers=self.headers('grc')).status_code, 403):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual(self.client.get('/api/soc/cases', headers=self.headers('grc')).status_code, 403)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post('/api/runs', headers=self.headers('grc'),
        # IRIS EXPLAIN: files=self.files()).status_code, 403): assert that the actual and expected values are equal.
        self.assertEqual(self.client.post('/api/runs', headers=self.headers('grc'), files=self.files()).status_code, 403)

    # IRIS EXPLAIN: Function HTTPTests.test_three_file_shadow_run_and_separate_views: Regression test: verify that three file
    # IRIS EXPLAIN: shadow run and separate views; the assertions below define the exact expected behavior.
    def test_three_file_shadow_run_and_separate_views(self):
        # IRIS EXPLAIN: Store the result of self.submit() in run; later lines use this named result.
        run = self.submit()
        # IRIS EXPLAIN: Call self.assertEqual(run['sessions'], 1): assert that the actual and expected values are equal.
        self.assertEqual(run['sessions'], 1)
        # IRIS EXPLAIN: Call self.assertFalse(run['training_labels_read']): assert that the stated condition is false.
        self.assertFalse(run['training_labels_read'])
        # IRIS EXPLAIN: Call self.assertFalse(run['official_risk_register_write']): assert that the stated condition is false.
        self.assertFalse(run['official_risk_register_write'])
        # IRIS EXPLAIN: Store self.client.get('/api/soc/cases', headers=self.headers()).json()['items'][0] in soc; later lines
        # IRIS EXPLAIN: use this named result.
        soc = self.client.get('/api/soc/cases', headers=self.headers()).json()['items'][0]
        # IRIS EXPLAIN: Store self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0] in grc; later
        # IRIS EXPLAIN: lines use this named result.
        grc = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]
        # IRIS EXPLAIN: Call self.assertEqual(soc['case_id'], grc['case_id']): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(soc['case_id'], grc['case_id'])
        # IRIS EXPLAIN: Call self.assertIn('source_event_ids', soc): assert that the item belongs to the expected collection.
        self.assertIn('source_event_ids', soc)
        # IRIS EXPLAIN: Call self.assertNotIn('risk_snapshots', soc): assert that the item is absent.
        self.assertNotIn('risk_snapshots', soc)
        # IRIS EXPLAIN: Call self.assertIn('risk_snapshots', grc): assert that the item belongs to the expected collection.
        self.assertIn('risk_snapshots', grc)
        # IRIS EXPLAIN: Call self.assertIsNotNone(soc['shadow_candidate']): assert that the value is available rather than None.
        self.assertIsNotNone(soc['shadow_candidate'])
        # IRIS EXPLAIN: Call self.assertNotEqual(soc['primary_assessment']['method'], 'calibrated_model1'): assert that the
        # IRIS EXPLAIN: values differ.
        self.assertNotEqual(soc['primary_assessment']['method'], 'calibrated_model1')

    # IRIS EXPLAIN: Function HTTPTests.test_labels_or_mode_cannot_be_extra_runtime_inputs: Regression test: verify that labels
    # IRIS EXPLAIN: or mode cannot be extra runtime inputs; the assertions below define the exact expected behavior.
    def test_labels_or_mode_cannot_be_extra_runtime_inputs(self):
        # IRIS EXPLAIN: Store the result of self.files() in files; later lines use this named result.
        files = self.files()
        # IRIS EXPLAIN: Store ('labels.jsonl', b'{}\n', 'application/octet-stream') in files['labels']; later lines use this
        # IRIS EXPLAIN: named result.
        files['labels'] = ('labels.jsonl', b'{}\n', 'application/octet-stream')
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=files).status_code,
        # IRIS EXPLAIN: 422): assert that the actual and expected values are equal.
        self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=files).status_code, 422)
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=self.files(),
        # IRIS EXPLAIN: data={'mode': 'advisory'}).status_code, 422): assert that the actual and expected values are equal.
        self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=self.files(), data={'mode': 'advisory'}).status_code, 422)

    # IRIS EXPLAIN: Function HTTPTests.test_duplicate_batch_reuses_same_run: Regression test: verify that duplicate batch reuses
    # IRIS EXPLAIN: same run; the assertions below define the exact expected behavior.
    def test_duplicate_batch_reuses_same_run(self):
        # IRIS EXPLAIN: Store (self.submit(), self.submit()) in (first, second); later lines use this named result.
        first, second = self.submit(), self.submit()
        # IRIS EXPLAIN: Call self.assertEqual(first['run_id'], second['run_id']): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(first['run_id'], second['run_id'])
        # IRIS EXPLAIN: Call self.assertTrue(second['reused_existing_run']): assert that the stated condition is true.
        self.assertTrue(second['reused_existing_run'])

    # IRIS EXPLAIN: Function HTTPTests.test_model_loaded_once_across_requests: Regression test: verify that model loaded once
    # IRIS EXPLAIN: across requests; the assertions below define the exact expected behavior.
    def test_model_loaded_once_across_requests(self):
        # IRIS EXPLAIN: Store self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc'] in before; later
        # IRIS EXPLAIN: lines use this named result.
        before = self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc']
        # IRIS EXPLAIN: Call self.submit() using the existing explicit arguments.
        self.submit()
        # IRIS EXPLAIN: Store self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc'] in after; later
        # IRIS EXPLAIN: lines use this named result.
        after = self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc']
        # IRIS EXPLAIN: Call self.assertEqual(before, after): assert that the actual and expected values are equal.
        self.assertEqual(before, after)

    # IRIS EXPLAIN: Function HTTPTests.test_grc_review_is_local_only_and_cannot_be_overwritten: Regression test: verify that grc
    # IRIS EXPLAIN: review is local only and cannot be overwritten; the assertions below define the exact expected behavior.
    def test_grc_review_is_local_only_and_cannot_be_overwritten(self):
        # IRIS EXPLAIN: Call self.submit() using the existing explicit arguments.
        self.submit()
        # IRIS EXPLAIN: Store self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id'] in
        # IRIS EXPLAIN: case_id; later lines use this named result.
        case_id = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id']
        # IRIS EXPLAIN: Store the formatted text f'/api/grc/cases/{case_id}/review' in path; later lines use this named result.
        path = f'/api/grc/cases/{case_id}/review'
        # IRIS EXPLAIN: Store a mapping containing disposition, comment in body; later lines use this named result.
        body = {'disposition': 'approve_follow_up', 'comment': 'Reviewed evidence; follow-up only'}
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post(path, headers=self.headers('admin'), json=body).status_code,
        # IRIS EXPLAIN: 403): assert that the actual and expected values are equal.
        self.assertEqual(self.client.post(path, headers=self.headers('admin'), json=body).status_code, 403)
        # IRIS EXPLAIN: Store the result of self.client.post(path, headers=self.headers('grc'), json=body) in response; later
        # IRIS EXPLAIN: lines use this named result.
        response = self.client.post(path, headers=self.headers('grc'), json=body)
        # IRIS EXPLAIN: Call self.assertEqual(response.status_code, 200, response.text): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(response.status_code, 200, response.text)
        # IRIS EXPLAIN: Call self.assertFalse(response.json()['official_risk_register_write']): assert that the stated condition
        # IRIS EXPLAIN: is false.
        self.assertFalse(response.json()['official_risk_register_write'])
        # IRIS EXPLAIN: Call self.assertFalse(response.json()['external_delivery']): assert that the stated condition is false.
        self.assertFalse(response.json()['external_delivery'])
        # IRIS EXPLAIN: Call self.assertEqual(self.client.post(path, headers=self.headers('grc'), json=body).status_code, 409):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual(self.client.post(path, headers=self.headers('grc'), json=body).status_code, 409)

    # IRIS EXPLAIN: Function HTTPTests.test_caller_cannot_supply_review_actor: Regression test: verify that caller cannot supply
    # IRIS EXPLAIN: review actor; the assertions below define the exact expected behavior.
    def test_caller_cannot_supply_review_actor(self):
        # IRIS EXPLAIN: Call self.submit() using the existing explicit arguments.
        self.submit()
        # IRIS EXPLAIN: Store self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id'] in
        # IRIS EXPLAIN: case_id; later lines use this named result.
        case_id = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id']
        # IRIS EXPLAIN: Store the result of self.client.post(f'/api/grc/cases/{case_id}/review', headers=self.headers('grc'),
        # IRIS EXPLAIN: json={'disposition': 'app... in response; later lines use this named result.
        response = self.client.post(f'/api/grc/cases/{case_id}/review', headers=self.headers('grc'),
                                    # IRIS EXPLAIN: Continue the current record with disposition, comment, actor; each value
                                    # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                    json={'disposition': 'approve_follow_up', 'comment': 'Reviewed evidence', 'actor': 'admin'})
        # IRIS EXPLAIN: Call self.assertEqual(response.status_code, 422): assert that the actual and expected values are equal.
        self.assertEqual(response.status_code, 422)

    # IRIS EXPLAIN: Function HTTPTests.test_sample_route_uses_same_pipeline: Regression test: verify that sample route uses same
    # IRIS EXPLAIN: pipeline; the assertions below define the exact expected behavior.
    def test_sample_route_uses_same_pipeline(self):
        # IRIS EXPLAIN: Enter mock.patch('backend.model_adapter.SAMPLES', self.directory / 'inputs'); its context manager
        # IRIS EXPLAIN: supplies the existing cleanup/transaction/expected-exception behavior.
        with mock.patch('backend.model_adapter.SAMPLES', self.directory / 'inputs'):
            # IRIS EXPLAIN: Store the result of self.client.post('/api/runs/sample', headers=self.headers('admin')) in response;
            # IRIS EXPLAIN: later lines use this named result.
            response = self.client.post('/api/runs/sample', headers=self.headers('admin'))
        # IRIS EXPLAIN: Call self.assertEqual(response.status_code, 200, response.text): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(response.status_code, 200, response.text)
        # IRIS EXPLAIN: Call self.assertEqual(response.json()['sessions'], 1): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(response.json()['sessions'], 1)

    # IRIS EXPLAIN: Function HTTPTests.test_unknown_case_is_404: Regression test: verify that unknown case is 404; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_unknown_case_is_404(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/soc/cases/CASE-does-not-exist',
        # IRIS EXPLAIN: headers=self.headers()).status_code, 404): assert that the actual and expected values are equal.
        self.assertEqual(self.client.get('/api/soc/cases/CASE-does-not-exist', headers=self.headers()).status_code, 404)

    # IRIS EXPLAIN: Function HTTPTests.test_cross_origin_requests_rejected: Regression test: verify that cross origin requests
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_cross_origin_requests_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.client.get('/api/model', headers={**self.headers(), 'Origin':
        # IRIS EXPLAIN: 'https://foreign.example'}).status_code, 403): assert that the actual and expected values are equal.
        self.assertEqual(self.client.get('/api/model', headers={**self.headers(), 'Origin': 'https://foreign.example'}).status_code, 403)


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == '__main__':
    # IRIS EXPLAIN: Call unittest.main() using the existing explicit arguments.
    unittest.main()
