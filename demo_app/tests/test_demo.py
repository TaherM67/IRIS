from __future__ import annotations

import http.client
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from backend.config import Settings
from backend.core import BusyError
from backend.model_adapter import ModelAdapter, digest
from demo_app.engine import DATA, ConflictError, DemoEngine
from demo_app.server import DemoServer

KEYS = {role: ('SYNTHETIC-UNIT-TEST-FIXTURE-' + role).ljust(48, '0') for role in ('admin', 'soc', 'grc')}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory(prefix='iris-active-demo-template-')
        cls.addClassCleanup(cls.base.cleanup)
        cls.adapter = ModelAdapter()
        cls.template = DemoEngine(Settings(Path(cls.base.name), KEYS), adapter=cls.adapter)
        cls.summary = cls.template.analyze('admin')
        cls.hashes = {path.name: digest(path) for path in cls.template.inputs.values()}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='iris-active-demo-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        shutil.copyfile(self.template.store.path, self.directory / 'iris.sqlite3')
        self.settings = Settings(self.directory, KEYS)
        self.engine = DemoEngine(self.settings, adapter=self.adapter)

    def proposal(self, role, hostname='identity-server'):
        return next(item for item in self.engine.proposals(role)['items'] if item['payload']['evidence']['hostname'] == hostname)

    def approve(self, role, proposal=None):
        selected = proposal or self.proposal(role)
        return self.engine.review(role, selected['proposal_id'], 'approve', 'Reviewed synthetic evidence; approve the demonstration change.')


class ActiveCoreTests(Fixture):
    def test_baseline_three_inputs_and_actual_model(self):
        state = self.engine.status('admin')
        self.assertEqual((state['counts']['risks'], state['counts']['alerts']), (60, 2355))
        self.assertEqual(self.summary['sessions'], 132)
        self.assertEqual(state['model']['model_sha256'], '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950')
        self.assertFalse(state['model']['model1_released'])
        self.assertFalse(state['model']['model2_released'])
        self.assertEqual(self.summary['integration']['exact_duplicate_rows_removed'], 6)
        self.assertEqual(self.summary['integration']['unresolved_asset_events'], 3)
        self.assertFalse(self.summary['training_labels_read'])

    def test_analysis_does_not_change_working_risks_or_alert_priorities(self):
        counts = self.engine.status('admin')['counts']
        self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (0, 0))
        self.assertEqual((counts['pending_soc'], counts['pending_grc']), (123, 63))

    def test_actual_grc_approval_updates_register_not_just_review_flag(self):
        result = self.approve('grc')
        risk = next(item for item in self.engine.risks('grc')['items'] if item['risk_id'] == 'DEMO-R001-1')
        self.assertEqual((risk['baseline_likelihood'], risk['current_likelihood'], risk['impact']), (3, 4, 5))
        self.assertEqual((risk['baseline_score'], risk['current_score'], risk['version']), (0.6, 0.8, 2))
        self.assertEqual(result['demo_records_written'], 1)
        self.assertEqual(risk['updated_by'], 'grc')
        self.assertFalse(result['external_writes'])

    def test_actual_soc_approval_updates_19_alerts_and_sorted_queue(self):
        selected = self.proposal('soc')
        self.assertEqual(selected['payload']['changed_alerts'], 19)
        result = self.approve('soc', selected)
        changed = self.engine.alerts('soc', changed_only=True)
        self.assertEqual((result['demo_records_written'], changed['total']), (19, 19))
        self.assertTrue(all(row['current_priority'] == 'Critical' for row in changed['items']))
        self.assertTrue(all(row['current_priority'] != row['baseline_priority'] for row in changed['items']))
        self.assertTrue(all(row['version'] == 2 and row['updated_by'] == 'soc' for row in changed['items']))
        queue = self.engine.alerts('soc', limit=100)['items']
        self.assertEqual(queue[0]['hostname'], 'identity-server')
        self.assertTrue(all(row['current_priority'] == 'Critical' for row in queue[:19]))

    def test_both_teams_see_same_saved_change_counts(self):
        self.approve('soc')
        self.approve('grc')
        self.assertEqual(self.engine.status('soc')['counts'], self.engine.status('grc')['counts'])
        counts = self.engine.status('admin')['counts']
        self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (1, 19))

    def test_changes_and_approvals_survive_restart(self):
        self.approve('soc')
        self.approve('grc')
        restarted = DemoEngine(self.settings, adapter=self.adapter)
        self.assertEqual(restarted.status('admin')['counts'], self.engine.status('admin')['counts'])
        self.assertEqual(restarted.export_risks('grc'), self.engine.export_risks('grc'))

    def test_rejection_is_audited_without_changing_working_state(self):
        chosen = self.proposal('grc')
        result = self.engine.review('grc', chosen['proposal_id'], 'reject', 'Rejecting this synthetic proposal for demonstration.')
        self.assertEqual(result['demo_records_written'], 0)
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)
        self.assertEqual(self.engine.changes('grc')['items'], [])
        self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_rejected')

    def test_admin_cannot_approve_as_grc_or_soc(self):
        for role in ('soc', 'grc'):
            with self.assertRaises(PermissionError):
                self.engine.review('admin', self.proposal(role)['proposal_id'], 'approve', 'Attempted admin impersonation')

    def test_teams_cannot_approve_each_others_changes(self):
        for actor, target in (('soc', 'grc'), ('grc', 'soc')):
            with self.assertRaises(PermissionError):
                self.engine.review(actor, self.proposal(target)['proposal_id'], 'approve', 'Attempted cross-team approval')

    def test_review_requires_valid_nonempty_reason(self):
        for reason in ('', 'tiny', None, ['not text']):
            with self.assertRaises(ValueError):
                self.engine.review('grc', self.proposal('grc')['proposal_id'], 'approve', reason)
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)

    def test_approval_idempotency_does_not_double_apply_or_duplicate_audit(self):
        chosen = self.proposal('grc')
        self.approve('grc', chosen)
        size = len(self.engine.audit('admin'))
        repeated = self.approve('grc', chosen)
        self.assertTrue(repeated['already_applied'])
        self.assertEqual(repeated['demo_records_written'], 0)
        self.assertEqual(len(self.engine.audit('admin')), size)
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 1)

    def test_reviewed_decision_cannot_be_overwritten(self):
        chosen = self.proposal('soc')
        self.approve('soc', chosen)
        with self.assertRaises(ConflictError):
            self.engine.review('soc', chosen['proposal_id'], 'reject', 'Cannot rewrite an earlier approval')

    def test_approval_stales_other_proposals_for_same_registered_risk(self):
        chosen = self.proposal('grc')
        others = [item for item in self.engine.proposals('grc')['items'] if item['target_id'] == chosen['target_id'] and item['proposal_id'] != chosen['proposal_id']]
        self.assertTrue(others)
        self.approve('grc', chosen)
        with self.assertRaises(ConflictError):
            self.approve('grc', others[0])
        self.assertTrue(any(item['proposal_id'] == others[0]['proposal_id'] for item in self.engine.proposals('grc', status='stale')['items']))

    def test_optimistic_risk_version_check_prevents_stale_write(self):
        chosen = self.proposal('grc')
        with self.engine.store.connection() as db:
            db.execute('UPDATE demo_risks SET version=version+1 WHERE risk_id=?', (chosen['target_id'],))
        with self.assertRaises(ConflictError):
            self.approve('grc', chosen)
        self.assertEqual(self.engine.changes('grc')['items'], [])
        self.assertTrue(any(item['proposal_id'] == chosen['proposal_id'] for item in self.engine.proposals('grc', status='stale')['items']))

    def test_soc_batch_is_atomic_if_one_target_version_is_stale(self):
        chosen = self.proposal('soc')
        with self.engine.store.connection() as db:
            db.execute('UPDATE demo_alerts SET version=version+1 WHERE event_id=?', (chosen['payload']['changes'][-1]['event_id'],))
        with self.assertRaises(ConflictError):
            self.approve('soc', chosen)
        self.assertEqual(self.engine.changes('soc')['items'], [])
        with self.engine.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_alerts WHERE current_priority<>baseline_priority').fetchone()[0], 0)

    def test_concurrent_mutation_is_bounded(self):
        self.engine.lock.acquire()
        try:
            with self.assertRaises(BusyError):
                self.approve('grc')
            self.assertTrue(self.engine.lock.locked())
        finally:
            self.engine.lock.release()

    def test_no_grc_proposal_for_unmapped_ambiguous_or_unhealthy_showcases(self):
        proposals = self.engine.proposals('grc')['items']
        self.assertFalse(any(row['payload']['evidence']['hostname'] in {'legacy-server', 'shared-server', 'backup-server'} and row['payload']['evidence']['session_time'].startswith('2026-10-23') for row in proposals))

    def test_audit_has_saved_before_after_actor_and_reason(self):
        self.approve('grc')
        change = self.engine.changes('grc')['items'][0]
        self.assertEqual((change['before']['score'], change['after']['score']), (0.6, 0.8))
        self.assertEqual(change['actor'], 'grc')
        self.assertTrue(change['reason'] and change['changed_at'])
        self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_approved')

    def test_exports_contain_current_approved_state(self):
        self.approve('grc')
        self.approve('soc')
        register = self.engine.export_risks('grc')
        risk = next(row for row in register['records'] if row['risk_id'] == 'DEMO-R001-1')
        self.assertEqual(risk['likelihood'], 4)
        self.assertTrue(risk['risk_version_id'].endswith('DEMO-REV2'))
        alerts = self.engine.export_alerts('soc')['records']
        self.assertEqual(sum(row['version'] > 1 for row in alerts), 19)
        self.assertTrue(register['demo_only'])

    def test_original_three_inputs_never_change(self):
        self.approve('soc')
        self.approve('grc')
        self.assertEqual({path.name: digest(path) for path in self.engine.inputs.values()}, self.hashes)

    def test_reanalysis_reuses_frozen_cases_and_preserves_approved_state(self):
        self.approve('grc')
        before = self.engine.status('admin')['counts']
        with mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Identical analysis must be reused')):
            summary = self.engine.analyze('admin')
        self.assertTrue(summary['reused_existing_run'])
        self.assertEqual(self.engine.status('admin')['counts'], before)

    def test_new_rehearsal_resets_by_copying_not_deleting_history(self):
        self.approve('grc')
        old = self.engine.status('admin')['exercise_id']
        self.engine.new_exercise('admin', 'Second examiner rehearsal')
        state = self.engine.status('admin')
        self.assertNotEqual(state['exercise_id'], old)
        self.assertEqual(state['counts']['changed_risks'], 0)
        self.assertFalse(state['analyzed'])
        self.assertEqual(len(state['exercise_history']), 2)
        with self.engine.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_changes WHERE exercise_id=?', (old,)).fetchone()[0], 1)

    def test_old_exercise_proposal_cannot_change_new_exercise(self):
        chosen = self.proposal('grc')
        self.engine.new_exercise('admin', 'Isolated second rehearsal')
        with self.assertRaises(KeyError):
            self.approve('grc', chosen)

    def test_only_admin_can_create_rehearsal_and_grc_cannot_analyze(self):
        for role in ('grc', 'soc'):
            with self.assertRaises(PermissionError):
                self.engine.new_exercise(role, 'Unauthorized rehearsal')
        with self.assertRaises(PermissionError):
            self.engine.analyze('grc')

    def test_input_tampering_rejected_before_loading_model(self):
        data = self.directory / 'bad_data'
        shutil.copytree(DATA, data)
        path = data / 'risk_register.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            DemoEngine(self.settings, data_dir=data, adapter=self.adapter)

    def test_role_read_boundaries(self):
        for function, role in ((self.engine.risks, 'soc'), (self.engine.alerts, 'grc'), (self.engine.audit, 'soc'),
                               (self.engine.export_risks, 'soc'), (self.engine.export_alerts, 'grc')):
            with self.assertRaises(PermissionError):
                function(role)


class ActiveHTTPTests(Fixture):
    def setUp(self):
        super().setUp()
        self.server = DemoServer(('127.0.0.1', 0), self.engine)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, path, role='admin', method='GET', body=None, headers=None, port=None):
        h = {'X-IRIS-Key': KEYS[role]} if role else {}
        if body is not None:
            h['Content-Type'] = 'application/json'
            body = json.dumps(body)
        h.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', port or self.server.server_port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=h)
            response = connection.getresponse()
            content = response.read()
            result = json.loads(content) if response.getheader('Content-Type', '').startswith('application/json') else content
            return response.status, result, dict(response.getheaders())
        finally:
            connection.close()

    def test_three_dashboard_routes_and_local_assets(self):
        for path in ('/admin', '/soc', '/grc', '/demo-static/app.js', '/demo-static/style.css'):
            status, body, headers = self.request(path, None)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
            self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_api_requires_valid_key(self):
        self.assertEqual(self.request('/api/demo/state', None)[0], 401)
        self.assertEqual(self.request('/api/demo/state', None, headers={'X-IRIS-Key': 'wrong'})[0], 401)

    def test_authentication_happens_before_body_validation(self):
        status, _, _ = self.request('/api/demo/analyze', None, 'POST', headers={'Content-Length': '99999999'})
        self.assertEqual(status, 401)

    def test_wrong_roles_cannot_read_team_tables_or_audit(self):
        self.assertEqual(self.request('/api/demo/risks', 'soc')[0], 403)
        self.assertEqual(self.request('/api/demo/alerts', 'grc')[0], 403)
        self.assertEqual(self.request('/api/demo/audit', 'grc')[0], 403)

    def test_foreign_host_and_origin_rejected(self):
        self.assertEqual(self.request('/api/demo/state', headers={'Host': 'evil.example'})[0], 400)
        self.assertEqual(self.request('/api/demo/state', headers={'Origin': 'https://evil.example'})[0], 403)

    def test_oversized_command_rejected(self):
        self.assertEqual(self.request('/api/demo/analyze', method='POST', body={'large': 'x'*9000})[0], 413)

    def test_caller_cannot_supply_priority_likelihood_or_actor(self):
        chosen = self.proposal('grc')
        status, _, _ = self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review', 'grc', 'POST',
                                    {'decision': 'approve', 'reason': 'Human approval example', 'likelihood': 5, 'actor': 'admin'})
        self.assertEqual(status, 422)
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)

    def test_bad_pagination_and_duplicate_query_rejected(self):
        for path in ('/api/demo/alerts?limit=101', '/api/demo/alerts?offset=-1', '/api/demo/alerts?limit=5&limit=6',
                     '/api/demo/state?role=admin', '/api/demo/alerts?changed_only=maybe'):
            self.assertEqual(self.request(path)[0], 422)

    def test_unknown_routes_and_path_traversal_not_served(self):
        for path in ('/demo-static/../engine.py', '/.local/active_demo/access.json', '/api/demo/unknown'):
            self.assertEqual(self.request(path)[0], 404)

    def test_human_review_applies_actual_database_change_over_http(self):
        chosen = self.proposal('grc')
        path = '/api/demo/proposals/' + chosen['proposal_id'] + '/review'
        self.assertEqual(self.request(path, 'soc', 'POST', {'decision': 'approve', 'reason': 'Attempted wrong-team approval'})[0], 403)
        status, result, _ = self.request(path, 'grc', 'POST', {'decision': 'approve', 'reason': 'Examiner demo: approved after evidence review.'})
        self.assertEqual(status, 200)
        self.assertEqual(result['demo_records_written'], 1)
        _, register, _ = self.request('/api/demo/risks', 'grc')
        row = next(item for item in register['items'] if item['risk_id'] == 'DEMO-R001-1')
        self.assertEqual((row['current_score'], row['version']), (0.8, 2))

    def test_real_fresh_http_analysis_then_both_team_approvals_and_exports(self):
        fresh = DemoEngine(Settings(self.directory / 'fresh_http', KEYS), adapter=self.adapter)
        with DemoServer(('127.0.0.1', 0), fresh) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            thread.start()
            try:
                port = server.server_port
                self.assertFalse(self.request('/api/demo/state', port=port)[1]['analyzed'])
                status, analysis, _ = self.request('/api/demo/analyze', method='POST', body={}, port=port)
                self.assertEqual(status, 200)
                self.assertEqual(analysis['sessions'], 132)
                self.assertFalse(analysis['reused_existing_run'])
                for role in ('grc', 'soc'):
                    _, proposals, _ = self.request('/api/demo/proposals', role, port=port)
                    chosen = next(item for item in proposals['items'] if item['payload']['evidence']['hostname'] == 'identity-server')
                    status, applied, _ = self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review',
                                                     role, 'POST', {'decision': 'approve', 'reason': 'HTTP demonstration approval by authorized team.'}, port=port)
                    self.assertEqual(status, 200)
                    self.assertGreater(applied['demo_records_written'], 0)
                _, state, _ = self.request('/api/demo/state', port=port)
                self.assertEqual((state['counts']['changed_risks'], state['counts']['reprioritized_alerts']), (1, 19))
                self.assertTrue(self.request('/api/demo/export/risks', 'grc', port=port)[1]['demo_only'])
                self.assertEqual(len(self.request('/api/demo/export/alerts', 'soc', port=port)[1]['records']), 2355)
            finally:
                server.shutdown()
                thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
