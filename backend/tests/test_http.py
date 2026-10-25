"""TARGET-COMPUTER TESTS: requires the complete requirements-backend.txt.

These are deliberately not silently skipped when dependencies are missing.
HTTP tests were not run in the build environment; PyPI returned 403.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.tests.test_core import KEYS, small_inputs


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='iris-http-test-')
        self.directory = Path(self.temporary.name)
        self.paths = small_inputs(self.directory / 'inputs')
        self.settings = Settings(self.directory / 'state', KEYS)
        self.client = TestClient(create_app(self.settings))
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temporary.cleanup()

    def headers(self, role='soc'):
        return {'X-IRIS-Key': KEYS[role]}

    def files(self):
        return {key: (path.name, path.read_bytes(), 'application/octet-stream') for key, path in self.paths.items()}

    def submit(self):
        response = self.client.post('/api/runs', headers=self.headers(), files=self.files())
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_health_and_static_ui(self):
        self.assertEqual(self.client.get('/health').status_code, 200)
        self.assertIn('SHADOW', self.client.get('/').text)
        self.assertEqual(self.client.get('/static/app.js').status_code, 200)
        self.assertIn("script-src 'self'", self.client.get('/').headers['content-security-policy'])

    def test_unauthenticated_api_rejected(self):
        self.assertEqual(self.client.get('/api/model').status_code, 401)
        self.assertEqual(self.client.post('/api/runs', files=self.files()).status_code, 401)

    def test_role_access_enforced_by_backend(self):
        self.assertEqual(self.client.get('/api/admin/status', headers=self.headers('soc')).status_code, 403)
        self.assertEqual(self.client.get('/api/grc/cases', headers=self.headers('soc')).status_code, 403)
        self.assertEqual(self.client.get('/api/soc/cases', headers=self.headers('grc')).status_code, 403)
        self.assertEqual(self.client.post('/api/runs', headers=self.headers('grc'), files=self.files()).status_code, 403)

    def test_three_file_shadow_run_and_separate_views(self):
        run = self.submit()
        self.assertEqual(run['sessions'], 1)
        self.assertFalse(run['training_labels_read'])
        self.assertFalse(run['official_risk_register_write'])
        soc = self.client.get('/api/soc/cases', headers=self.headers()).json()['items'][0]
        grc = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]
        self.assertEqual(soc['case_id'], grc['case_id'])
        self.assertIn('source_event_ids', soc)
        self.assertNotIn('risk_snapshots', soc)
        self.assertIn('risk_snapshots', grc)
        self.assertIsNotNone(soc['shadow_candidate'])
        self.assertNotEqual(soc['primary_assessment']['method'], 'calibrated_model1')

    def test_labels_or_mode_cannot_be_extra_runtime_inputs(self):
        files = self.files()
        files['labels'] = ('labels.jsonl', b'{}\n', 'application/octet-stream')
        self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=files).status_code, 422)
        self.assertEqual(self.client.post('/api/runs', headers=self.headers(), files=self.files(), data={'mode': 'advisory'}).status_code, 422)

    def test_duplicate_batch_reuses_same_run(self):
        first, second = self.submit(), self.submit()
        self.assertEqual(first['run_id'], second['run_id'])
        self.assertTrue(second['reused_existing_run'])

    def test_model_loaded_once_across_requests(self):
        before = self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc']
        self.submit()
        after = self.client.get('/api/model', headers=self.headers()).json()['loaded_at_utc']
        self.assertEqual(before, after)

    def test_grc_review_is_local_only_and_cannot_be_overwritten(self):
        self.submit()
        case_id = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id']
        path = f'/api/grc/cases/{case_id}/review'
        body = {'disposition': 'approve_follow_up', 'comment': 'Reviewed evidence; follow-up only'}
        self.assertEqual(self.client.post(path, headers=self.headers('admin'), json=body).status_code, 403)
        response = self.client.post(path, headers=self.headers('grc'), json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['official_risk_register_write'])
        self.assertFalse(response.json()['external_delivery'])
        self.assertEqual(self.client.post(path, headers=self.headers('grc'), json=body).status_code, 409)

    def test_caller_cannot_supply_review_actor(self):
        self.submit()
        case_id = self.client.get('/api/grc/cases', headers=self.headers('grc')).json()['items'][0]['case_id']
        response = self.client.post(f'/api/grc/cases/{case_id}/review', headers=self.headers('grc'),
                                    json={'disposition': 'approve_follow_up', 'comment': 'Reviewed evidence', 'actor': 'admin'})
        self.assertEqual(response.status_code, 422)

    def test_sample_route_uses_same_pipeline(self):
        with mock.patch('backend.model_adapter.SAMPLES', self.directory / 'inputs'):
            response = self.client.post('/api/runs/sample', headers=self.headers('admin'))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['sessions'], 1)

    def test_unknown_case_is_404(self):
        self.assertEqual(self.client.get('/api/soc/cases/CASE-does-not-exist', headers=self.headers()).status_code, 404)

    def test_cross_origin_requests_rejected(self):
        self.assertEqual(self.client.get('/api/model', headers={**self.headers(), 'Origin': 'https://foreign.example'}).status_code, 403)


if __name__ == '__main__':
    unittest.main()
