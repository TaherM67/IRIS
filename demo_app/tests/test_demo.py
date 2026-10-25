# IRIS EXPLAIN: File purpose: Exercises actual pinned models, approval-gated database writes, stale-state protection, exports,
# IRIS EXPLAIN: persistence, and real loopback HTTP requests.
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import http.client to serve or test actual loopback HTTP requests using the standard library.
import http.client
import hashlib
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# Standard-library markup inspection keeps GUI checks independent of browser packages.
from html.parser import HTMLParser
# IRIS EXPLAIN: Import shutil to copy immutable inputs or clean test-owned temporary directories.
import shutil
# IRIS EXPLAIN: Import tempfile to create fresh isolated run/upload/test directories.
import tempfile
# IRIS EXPLAIN: Import threading to coordinate the batch/approval lock or run a local HTTP test server.
import threading
# IRIS EXPLAIN: Import unittest to define regression assertions and controlled test mocks.
import unittest
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import mock from unittest to define regression assertions and controlled test mocks.
from unittest import mock

# IRIS EXPLAIN: Import Settings from backend.config to reuse the shared project contract/implementation rather than duplicate
# IRIS EXPLAIN: it.
from backend.config import Settings
# IRIS EXPLAIN: Import BusyError from backend.core to reuse the shared project contract/implementation rather than duplicate it.
from backend.core import BusyError
# IRIS EXPLAIN: Import ModelAdapter, digest from backend.model_adapter to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from backend.model_adapter import ModelAdapter, digest
# IRIS EXPLAIN: Import DATA, ConflictError, DemoEngine from demo_app.engine to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from demo_app.engine import DATA, ConflictError, DemoEngine
# IRIS EXPLAIN: Import DemoServer from demo_app.server to reuse the shared project contract/implementation rather than duplicate
# IRIS EXPLAIN: it.
from demo_app.server import DemoServer

# IRIS EXPLAIN: Store the comprehension {role: ('SYNTHETIC-UNIT-TEST-FIXTURE-' + role).ljust(48, '0') for role in ('admin',
# IRIS EXPLAIN: 'soc', 'grc')} in KEYS; later lines use this named result.
KEYS = {role: ('SYNTHETIC-UNIT-TEST-FIXTURE-' + role).ljust(48, '0') for role in ('admin', 'soc', 'grc')}


class PageStructure(HTMLParser):
    """Inspect real served markup without a browser dependency."""
    def __init__(self, markup):
        super().__init__()
        self.ids, self.counts, self.links = [], set(), set()
        self.body_role = None
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        # Comments are ignored; only actual element attributes count.
        attributes = dict(attrs)
        if tag == 'body':
            self.body_role = attributes.get('data-role')
        if 'id' in attributes:
            self.ids.append(attributes['id'])
        if 'data-count' in attributes:
            self.counts.add(attributes['data-count'])
        if tag == 'a':
            self.links.add(attributes.get('href'))


# IRIS EXPLAIN: Class Fixture: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_ methods
# IRIS EXPLAIN: independently.
class Fixture(unittest.TestCase):
    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function Fixture.setUpClass: Prepare shared trusted-model/synthetic test fixtures once for this class.
    def setUpClass(cls):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory(prefix='iris-active-demo-template-') in cls.base; later
        # IRIS EXPLAIN: lines use this named result.
        cls.base = tempfile.TemporaryDirectory(prefix='iris-active-demo-template-')
        # IRIS EXPLAIN: Call cls.addClassCleanup(cls.base.cleanup): register shared fixture cleanup after the test class.
        cls.addClassCleanup(cls.base.cleanup)
        # IRIS EXPLAIN: Store the result of ModelAdapter() in cls.adapter; later lines use this named result.
        cls.adapter = ModelAdapter()
        # IRIS EXPLAIN: Store the result of DemoEngine(Settings(Path(cls.base.name), KEYS), adapter=cls.adapter) in
        # IRIS EXPLAIN: cls.template; later lines use this named result.
        cls.template = DemoEngine(Settings(Path(cls.base.name), KEYS), adapter=cls.adapter)
        # IRIS EXPLAIN: Store the result of cls.template.analyze('admin') in cls.summary; later lines use this named result.
        cls.summary = cls.template.analyze('admin')
        # IRIS EXPLAIN: Store the comprehension {path.name: digest(path) for path in cls.template.inputs.values()} in
        # IRIS EXPLAIN: cls.hashes; later lines use this named result.
        cls.hashes = {path.name: digest(path) for path in cls.template.inputs.values()}

    # IRIS EXPLAIN: Function Fixture.setUp: Prepare an isolated synthetic fixture for this test and register cleanup; do not
    # IRIS EXPLAIN: modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Store the result of tempfile.TemporaryDirectory(prefix='iris-active-demo-test-') in self.temp; later
        # IRIS EXPLAIN: lines use this named result.
        self.temp = tempfile.TemporaryDirectory(prefix='iris-active-demo-test-')
        # IRIS EXPLAIN: Call self.addCleanup(self.temp.cleanup): register fixture cleanup even if a test fails.
        self.addCleanup(self.temp.cleanup)
        # IRIS EXPLAIN: Store the result of Path(self.temp.name) in self.directory; later lines use this named result.
        self.directory = Path(self.temp.name)
        # IRIS EXPLAIN: Call shutil.copyfile(self.template.store.path, self.directory / 'iris.sqlite3') using the existing
        # IRIS EXPLAIN: explicit arguments.
        shutil.copyfile(self.template.store.path, self.directory / 'iris.sqlite3')
        # IRIS EXPLAIN: Store the result of Settings(self.directory, KEYS) in self.settings; later lines use this named result.
        self.settings = Settings(self.directory, KEYS)
        # IRIS EXPLAIN: Store the result of DemoEngine(self.settings, adapter=self.adapter) in self.engine; later lines use this
        # IRIS EXPLAIN: named result.
        self.engine = DemoEngine(self.settings, adapter=self.adapter)

    # IRIS EXPLAIN: Function Fixture.proposal: Select an existing pending synthetic team proposal by its hostname for the
    # IRIS EXPLAIN: approval tests.
    # IRIS EXPLAIN: Inputs: role: the authenticated role or explicitly constructed test fixture role; hostname: the explicit
    # IRIS EXPLAIN: hostname input used by the unchanged statements below.
    def proposal(self, role, hostname='identity-server'):
        # IRIS EXPLAIN: Return the result of next((item for item in self.engine.proposals(role)['items'] if
        # IRIS EXPLAIN: item['payload']['evidence']['hostname'] == h... to the caller; this ends the current function path.
        return next(item for item in self.engine.proposals(role)['items'] if item['payload']['evidence']['hostname'] == hostname)

    # IRIS EXPLAIN: Function Fixture.approve: Submit an explicit synthetic human approval through the actual demo review path.
    # IRIS EXPLAIN: Inputs: role: the authenticated role or explicitly constructed test fixture role; proposal: the existing
    # IRIS EXPLAIN: pending proposal identity.
    def approve(self, role, proposal=None):
        # IRIS EXPLAIN: Store proposal or self.proposal(role) in selected; later lines use this named result.
        selected = proposal or self.proposal(role)
        # IRIS EXPLAIN: Return the result of self.engine.review(role, selected['proposal_id'], 'approve', 'Reviewed synthetic
        # IRIS EXPLAIN: evidence; approve the demo... to the caller; this ends the current function path.
        return self.engine.review(role, selected['proposal_id'], 'approve', 'Reviewed synthetic evidence; approve the demonstration change.')


# IRIS EXPLAIN: Class ActiveCoreTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_
# IRIS EXPLAIN: methods independently.
class ActiveCoreTests(Fixture):
    # IRIS EXPLAIN: Function ActiveCoreTests.test_baseline_three_inputs_and_actual_model: Regression test: verify that baseline
    # IRIS EXPLAIN: three inputs and actual model; the assertions below define the exact expected behavior.
    def test_baseline_three_inputs_and_actual_model(self):
        # IRIS EXPLAIN: Store the result of self.engine.status('admin') in state; later lines use this named result.
        state = self.engine.status('admin')
        # IRIS EXPLAIN: Call self.assertEqual((state['counts']['risks'], state['counts']['alerts']), (60, 2355)): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual((state['counts']['risks'], state['counts']['alerts']), (60, 2355))
        # IRIS EXPLAIN: Call self.assertEqual(self.summary['sessions'], 132): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(self.summary['sessions'], 132)
        # IRIS EXPLAIN: Call self.assertEqual(state['model']['model_sha256'],
        # IRIS EXPLAIN: '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950'): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(state['model']['model_sha256'], '12e76f280bcaa4854e9f08df9ea05839ea43cbb7691a7d44bfbd9d473eb39950')
        # IRIS EXPLAIN: Call self.assertFalse(state['model']['model1_released']): assert that the stated condition is false.
        self.assertFalse(state['model']['model1_released'])
        # IRIS EXPLAIN: Call self.assertFalse(state['model']['model2_released']): assert that the stated condition is false.
        self.assertFalse(state['model']['model2_released'])
        # IRIS EXPLAIN: Call self.assertEqual(self.summary['integration']['exact_duplicate_rows_removed'], 6): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(self.summary['integration']['exact_duplicate_rows_removed'], 6)
        # IRIS EXPLAIN: Call self.assertEqual(self.summary['integration']['unresolved_asset_events'], 3): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.summary['integration']['unresolved_asset_events'], 3)
        # IRIS EXPLAIN: Call self.assertFalse(self.summary['training_labels_read']): assert that the stated condition is false.
        self.assertFalse(self.summary['training_labels_read'])

    # IRIS EXPLAIN: Function ActiveCoreTests.test_analysis_does_not_change_working_risks_or_alert_priorities: Regression test:
    # IRIS EXPLAIN: verify that analysis does not change working risks or alert priorities; the assertions below define the
    # IRIS EXPLAIN: exact expected behavior.
    def test_analysis_does_not_change_working_risks_or_alert_priorities(self):
        # IRIS EXPLAIN: Store self.engine.status('admin')['counts'] in counts; later lines use this named result.
        counts = self.engine.status('admin')['counts']
        # IRIS EXPLAIN: Call self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (0, 0)): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (0, 0))
        # IRIS EXPLAIN: Call self.assertEqual((counts['pending_soc'], counts['pending_grc']), (123, 63)): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual((counts['pending_soc'], counts['pending_grc']), (123, 63))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_actual_grc_approval_updates_register_not_just_review_flag: Regression test:
    # IRIS EXPLAIN: verify that actual grc approval updates register not just review flag; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_actual_grc_approval_updates_register_not_just_review_flag(self):
        # IRIS EXPLAIN: Store the result of self.approve('grc') in result; later lines use this named result.
        result = self.approve('grc')
        # IRIS EXPLAIN: Store the result of next((item for item in self.engine.risks('grc')['items'] if item['risk_id'] ==
        # IRIS EXPLAIN: 'DEMO-R001-1')) in risk; later lines use this named result.
        risk = next(item for item in self.engine.risks('grc')['items'] if item['risk_id'] == 'DEMO-R001-1')
        # IRIS EXPLAIN: Call self.assertEqual((risk['baseline_likelihood'], risk['current_likelihood'], risk['impact']), (3, 4,
        # IRIS EXPLAIN: 5)): assert that the actual and expected values are equal.
        self.assertEqual((risk['baseline_likelihood'], risk['current_likelihood'], risk['impact']), (3, 4, 5))
        # IRIS EXPLAIN: Call self.assertEqual((risk['baseline_score'], risk['current_score'], risk['version']), (0.6, 0.8, 2)):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual((risk['baseline_score'], risk['current_score'], risk['version']), (0.6, 0.8, 2))
        # IRIS EXPLAIN: Call self.assertEqual(result['demo_records_written'], 1): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(result['demo_records_written'], 1)
        # IRIS EXPLAIN: Call self.assertEqual(risk['updated_by'], 'grc'): assert that the actual and expected values are equal.
        self.assertEqual(risk['updated_by'], 'grc')
        # IRIS EXPLAIN: Call self.assertFalse(result['external_writes']): assert that the stated condition is false.
        self.assertFalse(result['external_writes'])

    # IRIS EXPLAIN: Function ActiveCoreTests.test_actual_soc_approval_updates_19_alerts_and_sorted_queue: Regression test:
    # IRIS EXPLAIN: verify that actual soc approval updates 19 alerts and sorted queue; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_actual_soc_approval_updates_19_alerts_and_sorted_queue(self):
        # IRIS EXPLAIN: Store the result of self.proposal('soc') in selected; later lines use this named result.
        selected = self.proposal('soc')
        # IRIS EXPLAIN: Call self.assertEqual(selected['payload']['changed_alerts'], 19): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(selected['payload']['changed_alerts'], 19)
        # IRIS EXPLAIN: Store the result of self.approve('soc', selected) in result; later lines use this named result.
        result = self.approve('soc', selected)
        # IRIS EXPLAIN: Store the result of self.engine.alerts('soc', changed_only=True) in changed; later lines use this named
        # IRIS EXPLAIN: result.
        changed = self.engine.alerts('soc', changed_only=True)
        # IRIS EXPLAIN: Call self.assertEqual((result['demo_records_written'], changed['total']), (19, 19)): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual((result['demo_records_written'], changed['total']), (19, 19))
        # IRIS EXPLAIN: Call self.assertTrue(all((row['current_priority'] == 'Critical' for row in changed['items']))): assert
        # IRIS EXPLAIN: that the stated condition is true.
        self.assertTrue(all(row['current_priority'] == 'Critical' for row in changed['items']))
        # IRIS EXPLAIN: Call self.assertTrue(all((row['current_priority'] != row['baseline_priority'] for row in
        # IRIS EXPLAIN: changed['items']))): assert that the stated condition is true.
        self.assertTrue(all(row['current_priority'] != row['baseline_priority'] for row in changed['items']))
        # IRIS EXPLAIN: Call self.assertTrue(all((row['version'] == 2 and row['updated_by'] == 'soc' for row in
        # IRIS EXPLAIN: changed['items']))): assert that the stated condition is true.
        self.assertTrue(all(row['version'] == 2 and row['updated_by'] == 'soc' for row in changed['items']))
        # IRIS EXPLAIN: Store self.engine.alerts('soc', limit=100)['items'] in queue; later lines use this named result.
        queue = self.engine.alerts('soc', limit=100)['items']
        # IRIS EXPLAIN: Call self.assertEqual(queue[0]['hostname'], 'identity-server'): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(queue[0]['hostname'], 'identity-server')
        # IRIS EXPLAIN: Call self.assertTrue(all((row['current_priority'] == 'Critical' for row in queue[:19]))): assert that
        # IRIS EXPLAIN: the stated condition is true.
        self.assertTrue(all(row['current_priority'] == 'Critical' for row in queue[:19]))

    # Each team sees its own consistent counters; only Admin sees both domains.
    def test_teams_see_only_their_own_consistent_change_counts(self):
        # IRIS EXPLAIN: Call self.approve('soc') using the existing explicit arguments.
        self.approve('soc')
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        soc = self.engine.status('soc')['counts']
        grc = self.engine.status('grc')['counts']
        self.assertEqual(soc['reprioritized_alerts'], 19)
        self.assertEqual(grc['changed_risks'], 1)
        self.assertEqual(set(soc), {'alerts', 'reprioritized_alerts', 'pending_soc'})
        self.assertEqual(set(grc), {'risks', 'changed_risks', 'pending_grc'})
        # IRIS EXPLAIN: Store self.engine.status('admin')['counts'] in counts; later lines use this named result.
        counts = self.engine.status('admin')['counts']
        # IRIS EXPLAIN: Call self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (1, 19)): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual((counts['changed_risks'], counts['reprioritized_alerts']), (1, 19))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_changes_and_approvals_survive_restart: Regression test: verify that changes
    # IRIS EXPLAIN: and approvals survive restart; the assertions below define the exact expected behavior.
    def test_changes_and_approvals_survive_restart(self):
        # IRIS EXPLAIN: Call self.approve('soc') using the existing explicit arguments.
        self.approve('soc')
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Store the result of DemoEngine(self.settings, adapter=self.adapter) in restarted; later lines use this
        # IRIS EXPLAIN: named result.
        restarted = DemoEngine(self.settings, adapter=self.adapter)
        # IRIS EXPLAIN: Call self.assertEqual(restarted.status('admin')['counts'], self.engine.status('admin')['counts']):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual(restarted.status('admin')['counts'], self.engine.status('admin')['counts'])
        # IRIS EXPLAIN: Call self.assertEqual(restarted.export_risks('grc'), self.engine.export_risks('grc')): assert that the
        # IRIS EXPLAIN: actual and expected values are equal.
        self.assertEqual(restarted.export_risks('grc'), self.engine.export_risks('grc'))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_rejection_is_audited_without_changing_working_state: Regression test: verify
    # IRIS EXPLAIN: that rejection is audited without changing working state; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_rejection_is_audited_without_changing_working_state(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Store the result of self.engine.review('grc', chosen['proposal_id'], 'reject', 'Rejecting this synthetic
        # IRIS EXPLAIN: proposal for demonstra... in result; later lines use this named result.
        result = self.engine.review('grc', chosen['proposal_id'], 'reject', 'Rejecting this synthetic proposal for demonstration.')
        # IRIS EXPLAIN: Call self.assertEqual(result['demo_records_written'], 0): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(result['demo_records_written'], 0)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.changes('grc')['items'], []): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.engine.changes('grc')['items'], [])
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_rejected'): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_rejected')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_admin_cannot_approve_as_grc_or_soc: Regression test: verify that admin cannot
    # IRIS EXPLAIN: approve as grc or soc; the assertions below define the exact expected behavior.
    def test_admin_cannot_approve_as_grc_or_soc(self):
        # IRIS EXPLAIN: Iterate ('soc', 'grc'), binding each item to role; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for role in ('soc', 'grc'):
            # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(PermissionError):
                # IRIS EXPLAIN: Call self.engine.review('admin', self.proposal(role)['proposal_id'], 'approve', 'Attempted admin
                # IRIS EXPLAIN: impersonation') using the existing explicit arguments.
                self.engine.review('admin', self.proposal(role)['proposal_id'], 'approve', 'Attempted admin impersonation')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_teams_cannot_approve_each_others_changes: Regression test: verify that teams
    # IRIS EXPLAIN: cannot approve each others changes; the assertions below define the exact expected behavior.
    def test_teams_cannot_approve_each_others_changes(self):
        # IRIS EXPLAIN: Iterate (('soc', 'grc'), ('grc', 'soc')), binding each item to (actor, target); process only the
        # IRIS EXPLAIN: existing observed/fixture collection.
        for actor, target in (('soc', 'grc'), ('grc', 'soc')):
            # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(PermissionError):
                # IRIS EXPLAIN: Call self.engine.review(actor, self.proposal(target)['proposal_id'], 'approve', 'Attempted
                # IRIS EXPLAIN: cross-team approval') using the existing explicit arguments.
                self.engine.review(actor, self.proposal(target)['proposal_id'], 'approve', 'Attempted cross-team approval')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_review_requires_valid_nonempty_reason: Regression test: verify that review
    # IRIS EXPLAIN: requires valid nonempty reason; the assertions below define the exact expected behavior.
    def test_review_requires_valid_nonempty_reason(self):
        # IRIS EXPLAIN: Iterate ('', 'tiny', None, ['not text']), binding each item to reason; process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for reason in ('', 'tiny', None, ['not text']):
            # IRIS EXPLAIN: Enter self.assertRaises(ValueError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(ValueError):
                # IRIS EXPLAIN: Call self.engine.review('grc', self.proposal('grc')['proposal_id'], 'approve', reason) using the
                # IRIS EXPLAIN: existing explicit arguments.
                self.engine.review('grc', self.proposal('grc')['proposal_id'], 'approve', reason)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_approval_idempotency_does_not_double_apply_or_duplicate_audit: Regression
    # IRIS EXPLAIN: test: verify that approval idempotency does not double apply or duplicate audit; the assertions below define
    # IRIS EXPLAIN: the exact expected behavior.
    def test_approval_idempotency_does_not_double_apply_or_duplicate_audit(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Call self.approve('grc', chosen) using the existing explicit arguments.
        self.approve('grc', chosen)
        # IRIS EXPLAIN: Store len(self.engine.audit('admin')) in size; later lines use this named result.
        size = len(self.engine.audit('admin'))
        # IRIS EXPLAIN: Store the result of self.approve('grc', chosen) in repeated; later lines use this named result.
        repeated = self.approve('grc', chosen)
        # IRIS EXPLAIN: Call self.assertTrue(repeated['already_applied']): assert that the stated condition is true.
        self.assertTrue(repeated['already_applied'])
        # IRIS EXPLAIN: Call self.assertEqual(repeated['demo_records_written'], 0): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(repeated['demo_records_written'], 0)
        # IRIS EXPLAIN: Call self.assertEqual(len(self.engine.audit('admin')), size): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(len(self.engine.audit('admin')), size)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 1): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 1)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_reviewed_decision_cannot_be_overwritten: Regression test: verify that reviewed
    # IRIS EXPLAIN: decision cannot be overwritten; the assertions below define the exact expected behavior.
    def test_reviewed_decision_cannot_be_overwritten(self):
        # IRIS EXPLAIN: Store the result of self.proposal('soc') in chosen; later lines use this named result.
        chosen = self.proposal('soc')
        # IRIS EXPLAIN: Call self.approve('soc', chosen) using the existing explicit arguments.
        self.approve('soc', chosen)
        # IRIS EXPLAIN: Enter self.assertRaises(ConflictError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ConflictError):
            # IRIS EXPLAIN: Call self.engine.review('soc', chosen['proposal_id'], 'reject', 'Cannot rewrite an earlier
            # IRIS EXPLAIN: approval') using the existing explicit arguments.
            self.engine.review('soc', chosen['proposal_id'], 'reject', 'Cannot rewrite an earlier approval')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_approval_stales_other_proposals_for_same_registered_risk: Regression test:
    # IRIS EXPLAIN: verify that approval stales other proposals for same registered risk; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_approval_stales_other_proposals_for_same_registered_risk(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Store the comprehension [item for item in self.engine.proposals('grc')['items'] if item['target_id'] ==
        # IRIS EXPLAIN: chosen['target_id'] and item['proposal_id'] != chosen['proposal_id']] in others; later lines use this
        # IRIS EXPLAIN: named result.
        others = [item for item in self.engine.proposals('grc')['items'] if item['target_id'] == chosen['target_id'] and item['proposal_id'] != chosen['proposal_id']]
        # IRIS EXPLAIN: Call self.assertTrue(others): assert that the stated condition is true.
        self.assertTrue(others)
        # IRIS EXPLAIN: Call self.approve('grc', chosen) using the existing explicit arguments.
        self.approve('grc', chosen)
        # IRIS EXPLAIN: Enter self.assertRaises(ConflictError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ConflictError):
            # IRIS EXPLAIN: Call self.approve('grc', others[0]) using the existing explicit arguments.
            self.approve('grc', others[0])
        # IRIS EXPLAIN: Call self.assertTrue(any((item['proposal_id'] == others[0]['proposal_id'] for item in
        # IRIS EXPLAIN: self.engine.proposals('grc', status='stale')['items']))): assert that the stated condition is true.
        self.assertTrue(any(item['proposal_id'] == others[0]['proposal_id'] for item in self.engine.proposals('grc', status='stale')['items']))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_optimistic_risk_version_check_prevents_stale_write: Regression test: verify
    # IRIS EXPLAIN: that optimistic risk version check prevents stale write; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_optimistic_risk_version_check_prevents_stale_write(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Enter self.engine.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.engine.store.connection() as db:
            # IRIS EXPLAIN: Call db.execute('UPDATE demo_risks SET version=version+1 WHERE risk_id=?', (chosen['target_id'],)):
            # IRIS EXPLAIN: run the existing SQL with its separately supplied parameters.
            db.execute('UPDATE demo_risks SET version=version+1 WHERE risk_id=?', (chosen['target_id'],))
        # IRIS EXPLAIN: Enter self.assertRaises(ConflictError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ConflictError):
            # IRIS EXPLAIN: Call self.approve('grc', chosen) using the existing explicit arguments.
            self.approve('grc', chosen)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.changes('grc')['items'], []): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.engine.changes('grc')['items'], [])
        # IRIS EXPLAIN: Call self.assertTrue(any((item['proposal_id'] == chosen['proposal_id'] for item in
        # IRIS EXPLAIN: self.engine.proposals('grc', status='stale')['items']))): assert that the stated condition is true.
        self.assertTrue(any(item['proposal_id'] == chosen['proposal_id'] for item in self.engine.proposals('grc', status='stale')['items']))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_soc_batch_is_atomic_if_one_target_version_is_stale: Regression test: verify
    # IRIS EXPLAIN: that soc batch is atomic if one target version is stale; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_soc_batch_is_atomic_if_one_target_version_is_stale(self):
        # IRIS EXPLAIN: Store the result of self.proposal('soc') in chosen; later lines use this named result.
        chosen = self.proposal('soc')
        # IRIS EXPLAIN: Enter self.engine.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.engine.store.connection() as db:
            # IRIS EXPLAIN: Call db.execute('UPDATE demo_alerts SET version=version+1 WHERE event_id=?',
            # IRIS EXPLAIN: (chosen['payload']['changes'][-1]['event_id'],)): run the existing SQL with its separately supplied
            # IRIS EXPLAIN: parameters.
            db.execute('UPDATE demo_alerts SET version=version+1 WHERE event_id=?', (chosen['payload']['changes'][-1]['event_id'],))
        # IRIS EXPLAIN: Enter self.assertRaises(ConflictError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(ConflictError):
            # IRIS EXPLAIN: Call self.approve('soc', chosen) using the existing explicit arguments.
            self.approve('soc', chosen)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.changes('soc')['items'], []): assert that the actual and expected
        # IRIS EXPLAIN: values are equal.
        self.assertEqual(self.engine.changes('soc')['items'], [])
        # IRIS EXPLAIN: Enter self.engine.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.engine.store.connection() as db:
            # IRIS EXPLAIN: Call self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_alerts WHERE
            # IRIS EXPLAIN: current_priority<>baseline_priority').fetchone()[0], 0): assert that the actual and expected values
            # IRIS EXPLAIN: are equal.
            self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_alerts WHERE current_priority<>baseline_priority').fetchone()[0], 0)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_concurrent_mutation_is_bounded: Regression test: verify that concurrent
    # IRIS EXPLAIN: mutation is bounded; the assertions below define the exact expected behavior.
    def test_concurrent_mutation_is_bounded(self):
        # IRIS EXPLAIN: Call self.engine.lock.acquire(): attempt to acquire the operation lock using the existing blocking
        # IRIS EXPLAIN: setting.
        self.engine.lock.acquire()
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Enter self.assertRaises(BusyError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(BusyError):
                # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
                self.approve('grc')
            # IRIS EXPLAIN: Call self.assertTrue(self.engine.lock.locked()): assert that the stated condition is true.
            self.assertTrue(self.engine.lock.locked())
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call self.engine.lock.release(): release the acquired lock.
            self.engine.lock.release()

    # IRIS EXPLAIN: Function ActiveCoreTests.test_no_grc_proposal_for_unmapped_ambiguous_or_unhealthy_showcases: Regression
    # IRIS EXPLAIN: test: verify that no grc proposal for unmapped ambiguous or unhealthy showcases; the assertions below define
    # IRIS EXPLAIN: the exact expected behavior.
    def test_no_grc_proposal_for_unmapped_ambiguous_or_unhealthy_showcases(self):
        # IRIS EXPLAIN: Store self.engine.proposals('grc')['items'] in proposals; later lines use this named result.
        proposals = self.engine.proposals('grc')['items']
        # IRIS EXPLAIN: Call self.assertFalse(any((row['payload']['evidence']['hostname'] in {'legacy-server', 'shared-server',
        # IRIS EXPLAIN: 'backup-server'} and row['payload']['evidence']['session_t...: assert that the stated condition is
        # IRIS EXPLAIN: false.
        self.assertFalse(any(row['payload']['evidence']['hostname'] in {'legacy-server', 'shared-server', 'backup-server'} and row['payload']['evidence']['session_time'].startswith('2026-10-23') for row in proposals))

    # IRIS EXPLAIN: Function ActiveCoreTests.test_audit_has_saved_before_after_actor_and_reason: Regression test: verify that
    # IRIS EXPLAIN: audit has saved before after actor and reason; the assertions below define the exact expected behavior.
    def test_audit_has_saved_before_after_actor_and_reason(self):
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Store self.engine.changes('grc')['items'][0] in change; later lines use this named result.
        change = self.engine.changes('grc')['items'][0]
        # IRIS EXPLAIN: Call self.assertEqual((change['before']['score'], change['after']['score']), (0.6, 0.8)): assert that
        # IRIS EXPLAIN: the actual and expected values are equal.
        self.assertEqual((change['before']['score'], change['after']['score']), (0.6, 0.8))
        # IRIS EXPLAIN: Call self.assertEqual(change['actor'], 'grc'): assert that the actual and expected values are equal.
        self.assertEqual(change['actor'], 'grc')
        # IRIS EXPLAIN: Call self.assertTrue(change['reason'] and change['changed_at']): assert that the stated condition is
        # IRIS EXPLAIN: true.
        self.assertTrue(change['reason'] and change['changed_at'])
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_approved'): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.audit('admin')[0]['action'], 'demo_approved')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_exports_contain_current_approved_state: Regression test: verify that exports
    # IRIS EXPLAIN: contain current approved state; the assertions below define the exact expected behavior.
    def test_exports_contain_current_approved_state(self):
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Call self.approve('soc') using the existing explicit arguments.
        self.approve('soc')
        # IRIS EXPLAIN: Store the result of self.engine.export_risks('grc') in register; later lines use this named result.
        register = self.engine.export_risks('grc')
        # IRIS EXPLAIN: Store the result of next((row for row in register['records'] if row['risk_id'] == 'DEMO-R001-1')) in
        # IRIS EXPLAIN: risk; later lines use this named result.
        risk = next(row for row in register['records'] if row['risk_id'] == 'DEMO-R001-1')
        # IRIS EXPLAIN: Call self.assertEqual(risk['likelihood'], 4): assert that the actual and expected values are equal.
        self.assertEqual(risk['likelihood'], 4)
        # IRIS EXPLAIN: Call self.assertTrue(risk['risk_version_id'].endswith('DEMO-REV2')): assert that the stated condition is
        # IRIS EXPLAIN: true.
        self.assertTrue(risk['risk_version_id'].endswith('DEMO-REV2'))
        # IRIS EXPLAIN: Store self.engine.export_alerts('soc')['records'] in alerts; later lines use this named result.
        alerts = self.engine.export_alerts('soc')['records']
        # IRIS EXPLAIN: Call self.assertEqual(sum((row['version'] > 1 for row in alerts)), 19): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(sum(row['version'] > 1 for row in alerts), 19)
        # IRIS EXPLAIN: Call self.assertTrue(register['demo_only']): assert that the stated condition is true.
        self.assertTrue(register['demo_only'])

    # IRIS EXPLAIN: Function ActiveCoreTests.test_original_three_inputs_never_change: Regression test: verify that original
    # IRIS EXPLAIN: three inputs never change; the assertions below define the exact expected behavior.
    def test_original_three_inputs_never_change(self):
        # IRIS EXPLAIN: Call self.approve('soc') using the existing explicit arguments.
        self.approve('soc')
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Call self.assertEqual({path.name: digest(path) for path in self.engine.inputs.values()}, self.hashes):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual({path.name: digest(path) for path in self.engine.inputs.values()}, self.hashes)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_reanalysis_reuses_frozen_cases_and_preserves_approved_state: Regression test:
    # IRIS EXPLAIN: verify that reanalysis reuses frozen cases and preserves approved state; the assertions below define the
    # IRIS EXPLAIN: exact expected behavior.
    def test_reanalysis_reuses_frozen_cases_and_preserves_approved_state(self):
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Store self.engine.status('admin')['counts'] in before; later lines use this named result.
        before = self.engine.status('admin')['counts']
        # IRIS EXPLAIN: Enter mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Identical analysis must be
        # IRIS EXPLAIN: reused')); its context manager supplies the existing cleanup/transaction/expected-exception behavior.
        with mock.patch.object(self.adapter, 'predict', side_effect=AssertionError('Identical analysis must be reused')):
            # IRIS EXPLAIN: Store the result of self.engine.analyze('admin') in summary; later lines use this named result.
            summary = self.engine.analyze('admin')
        # IRIS EXPLAIN: Call self.assertTrue(summary['reused_existing_run']): assert that the stated condition is true.
        self.assertTrue(summary['reused_existing_run'])
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.status('admin')['counts'], before): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.engine.status('admin')['counts'], before)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_new_rehearsal_resets_by_copying_not_deleting_history: Regression test: verify
    # IRIS EXPLAIN: that new rehearsal resets by copying not deleting history; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_new_rehearsal_resets_by_copying_not_deleting_history(self):
        # IRIS EXPLAIN: Call self.approve('grc') using the existing explicit arguments.
        self.approve('grc')
        # IRIS EXPLAIN: Store self.engine.status('admin')['exercise_id'] in old; later lines use this named result.
        old = self.engine.status('admin')['exercise_id']
        # IRIS EXPLAIN: Call self.engine.new_exercise('admin', 'Second examiner rehearsal') using the existing explicit
        # IRIS EXPLAIN: arguments.
        self.engine.new_exercise('admin', 'Second examiner rehearsal')
        # IRIS EXPLAIN: Store the result of self.engine.status('admin') in state; later lines use this named result.
        state = self.engine.status('admin')
        # IRIS EXPLAIN: Call self.assertNotEqual(state['exercise_id'], old): assert that the values differ.
        self.assertNotEqual(state['exercise_id'], old)
        # IRIS EXPLAIN: Call self.assertEqual(state['counts']['changed_risks'], 0): assert that the actual and expected values
        # IRIS EXPLAIN: are equal.
        self.assertEqual(state['counts']['changed_risks'], 0)
        # IRIS EXPLAIN: Call self.assertFalse(state['analyzed']): assert that the stated condition is false.
        self.assertFalse(state['analyzed'])
        # IRIS EXPLAIN: Call self.assertEqual(len(state['exercise_history']), 2): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(len(state['exercise_history']), 2)
        # IRIS EXPLAIN: Enter self.engine.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.engine.store.connection() as db:
            # IRIS EXPLAIN: Call self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_changes WHERE exercise_id=?',
            # IRIS EXPLAIN: (old,)).fetchone()[0], 1): assert that the actual and expected values are equal.
            self.assertEqual(db.execute('SELECT COUNT(*) FROM demo_changes WHERE exercise_id=?', (old,)).fetchone()[0], 1)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_old_exercise_proposal_cannot_change_new_exercise: Regression test: verify that
    # IRIS EXPLAIN: old exercise proposal cannot change new exercise; the assertions below define the exact expected behavior.
    def test_old_exercise_proposal_cannot_change_new_exercise(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Call self.engine.new_exercise('admin', 'Isolated second rehearsal') using the existing explicit
        # IRIS EXPLAIN: arguments.
        self.engine.new_exercise('admin', 'Isolated second rehearsal')
        # IRIS EXPLAIN: Enter self.assertRaises(KeyError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(KeyError):
            # IRIS EXPLAIN: Call self.approve('grc', chosen) using the existing explicit arguments.
            self.approve('grc', chosen)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_only_admin_can_create_rehearsal_and_grc_cannot_analyze: Regression test:
    # IRIS EXPLAIN: verify that only admin can create rehearsal and grc cannot analyze; the assertions below define the exact
    # IRIS EXPLAIN: expected behavior.
    def test_only_admin_can_create_rehearsal_and_grc_cannot_analyze(self):
        # IRIS EXPLAIN: Iterate ('grc', 'soc'), binding each item to role; process only the existing observed/fixture
        # IRIS EXPLAIN: collection.
        for role in ('grc', 'soc'):
            # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(PermissionError):
                # IRIS EXPLAIN: Call self.engine.new_exercise(role, 'Unauthorized rehearsal') using the existing explicit
                # IRIS EXPLAIN: arguments.
                self.engine.new_exercise(role, 'Unauthorized rehearsal')
        # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaises(PermissionError):
            # IRIS EXPLAIN: Call self.engine.analyze('grc') using the existing explicit arguments.
            self.engine.analyze('grc')

    # IRIS EXPLAIN: Function ActiveCoreTests.test_input_tampering_rejected_before_loading_model: Regression test: verify that
    # IRIS EXPLAIN: input tampering rejected before loading model; the assertions below define the exact expected behavior.
    def test_input_tampering_rejected_before_loading_model(self):
        # IRIS EXPLAIN: Store the computed value self.directory / 'bad_data' in data; later lines use this named result.
        data = self.directory / 'bad_data'
        # IRIS EXPLAIN: Call shutil.copytree(DATA, data) using the existing explicit arguments.
        shutil.copytree(DATA, data)
        # IRIS EXPLAIN: Store the computed value data / 'risk_register.json' in path; later lines use this named result.
        path = data / 'risk_register.json'
        # IRIS EXPLAIN: Call path.write_bytes(path.read_bytes() + b' '): write the existing byte payload.
        path.write_bytes(path.read_bytes() + b' ')
        # IRIS EXPLAIN: Enter self.assertRaisesRegex(ValueError, 'checksum'); its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.assertRaisesRegex(ValueError, 'checksum'):
            # IRIS EXPLAIN: Call DemoEngine(self.settings, data_dir=data, adapter=self.adapter) using the existing explicit
            # IRIS EXPLAIN: arguments.
            DemoEngine(self.settings, data_dir=data, adapter=self.adapter)

    # IRIS EXPLAIN: Function ActiveCoreTests.test_role_read_boundaries: Regression test: verify that role read boundaries; the
    # IRIS EXPLAIN: assertions below define the exact expected behavior.
    def test_role_read_boundaries(self):
        # IRIS EXPLAIN: Iterate ((self.engine.risks, 'soc'), (self.engine.alerts, 'grc'), (self.engine.audit, 'soc'),
        # IRIS EXPLAIN: (self.engine.export_risks, 'soc'), (self.engine.export_alerts, 'grc')), binding each item to (function,
        # IRIS EXPLAIN: role); process only the existing observed/fixture collection.
        for function, role in ((self.engine.risks, 'soc'), (self.engine.alerts, 'grc'), (self.engine.audit, 'soc'),
                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                               # IRIS EXPLAIN: arguments/items: (self.engine.export_risks, 'soc'), (self.engine.export_alerts,
                               # IRIS EXPLAIN: 'grc')):.
                               (self.engine.export_risks, 'soc'), (self.engine.export_alerts, 'grc')):
            # IRIS EXPLAIN: Enter self.assertRaises(PermissionError); its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.assertRaises(PermissionError):
                # IRIS EXPLAIN: Call function(role) using the existing explicit arguments.
                function(role)

    # Projection is enforced on server responses, not merely by hidden UI cards.
    def test_team_status_omits_admin_diagnostics_and_other_team_counts(self):
        for role, forbidden in (('soc', {'risks', 'changed_risks', 'pending_grc'}),
                                ('grc', {'alerts', 'reprioritized_alerts', 'pending_soc'})):
            state = self.engine.status(role)
            self.assertFalse(forbidden & set(state['counts']))
            self.assertFalse({'model', 'analysis', 'exercise_history'} & set(state))
        self.assertTrue({'model', 'analysis', 'exercise_history'} <= set(self.engine.status('admin')))

    def test_soc_proposals_exclude_grc_policy_risk_values_and_controls(self):
        proposal = self.proposal('soc')
        evidence = proposal['payload']['evidence']
        self.assertIn('features', evidence)
        self.assertIn('primary_assessment', evidence)
        self.assertIn('priority_reason', evidence)
        self.assertNotIn('policy', evidence)
        self.assertNotIn('primary_controls', evidence)
        self.assertNotIn('controls', evidence['ml_shadow'])
        self.assertNotIn('risk_reason', evidence)

    def test_grc_proposals_exclude_raw_telemetry_and_model_confidence(self):
        evidence = self.proposal('grc')['payload']['evidence']
        self.assertTrue({'controls', 'risk_category', 'risk_reason', 'observed_activity'} <= set(evidence))
        self.assertFalse({'features', 'ml_shadow', 'primary_assessment', 'warnings'} & set(evidence))
        self.assertTrue(evidence['controls'])
        self.assertNotIn('model_score', evidence['controls'][0])

    def test_admin_retains_full_proposal_evidence_for_both_teams(self):
        proposals = self.engine.proposals('admin')['items']
        self.assertEqual({item['kind'] for item in proposals}, {'soc', 'grc'})
        for item in proposals:
            self.assertTrue({'features', 'policy', 'ml_shadow', 'primary_controls'} <= set(item['payload']['evidence']))

    def test_projection_does_not_rewrite_saved_analysis_evidence(self):
        chosen = self.proposal('soc')
        with self.engine.store.connection() as db:
            before = db.execute('SELECT payload_json FROM demo_proposals WHERE proposal_id=?', (chosen['proposal_id'],)).fetchone()[0]
        self.engine.proposals('soc')
        self.engine.proposals('grc')
        with self.engine.store.connection() as db:
            after = db.execute('SELECT payload_json FROM demo_proposals WHERE proposal_id=?', (chosen['proposal_id'],)).fetchone()[0]
        self.assertEqual(before, after)
        self.assertIn('policy', json.loads(after)['evidence'])

    def test_analysis_is_an_admin_action_for_both_team_roles(self):
        for role in ('soc', 'grc'):
            with self.assertRaises(PermissionError):
                self.engine.analyze(role)


# IRIS EXPLAIN: Class ActiveHTTPTests: Groups regression checks and their isolated synthetic fixtures; unittest invokes test_
# IRIS EXPLAIN: methods independently.
class ActiveHTTPTests(Fixture):
    # IRIS EXPLAIN: Function ActiveHTTPTests.setUp: Prepare an isolated synthetic fixture for this test and register cleanup; do
    # IRIS EXPLAIN: not modify user data.
    def setUp(self):
        # IRIS EXPLAIN: Call super().setUp() using the existing explicit arguments.
        super().setUp()
        # IRIS EXPLAIN: Store the result of DemoServer(('127.0.0.1', 0), self.engine) in self.server; later lines use this named
        # IRIS EXPLAIN: result.
        self.server = DemoServer(('127.0.0.1', 0), self.engine)
        # IRIS EXPLAIN: Store the result of threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01},
        # IRIS EXPLAIN: daemon=True) in self.thread; later lines use this named result.
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        # IRIS EXPLAIN: Call self.thread.start(): start the background test server thread.
        self.thread.start()
        # IRIS EXPLAIN: Call self.addCleanup(self.stop_server): register fixture cleanup even if a test fails.
        self.addCleanup(self.stop_server)

    # IRIS EXPLAIN: Function ActiveHTTPTests.stop_server: Close test-owned clients/servers or temporary fixtures so no resources
    # IRIS EXPLAIN: or mutable test state leak to later tests.
    def stop_server(self):
        # IRIS EXPLAIN: Call self.server.shutdown(): stop the test-owned local HTTP server.
        self.server.shutdown()
        # IRIS EXPLAIN: Call self.server.server_close(): close the test-owned listening socket.
        self.server.server_close()
        # IRIS EXPLAIN: Call self.thread.join(timeout=3): wait within the existing limit for the test thread to end.
        self.thread.join(timeout=3)

    # IRIS EXPLAIN: Function ActiveHTTPTests.request: Send a real loopback HTTP request with the selected synthetic test key and
    # IRIS EXPLAIN: return its status, parsed body and headers.
    # IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper; role: the authenticated role or explicitly
    # IRIS EXPLAIN: constructed test fixture role; method: the parsed HTTP verb routed by the local adapter; body: the validated
    # IRIS EXPLAIN: command/review JSON payload; headers: the explicit headers input used by the unchanged statements below;
    # IRIS EXPLAIN: port: the explicit port input used by the unchanged statements below.
    def request(self, path, role='admin', method='GET', body=None, headers=None, port=None):
        # IRIS EXPLAIN: Store a mapping containing X-IRIS-Key when role; otherwise a mapping containing  in h; later lines use
        # IRIS EXPLAIN: this named result.
        h = {'X-IRIS-Key': KEYS[role]} if role else {}
        # IRIS EXPLAIN: Enter this branch only when body is not None.
        if body is not None:
            # IRIS EXPLAIN: Store 'application/json' in h['Content-Type']; later lines use this named result.
            h['Content-Type'] = 'application/json'
            # IRIS EXPLAIN: Store the result of json.dumps(body) (serialize the existing payload as JSON) in body; later lines
            # IRIS EXPLAIN: use this named result.
            body = json.dumps(body)
        # IRIS EXPLAIN: Call h.update(headers or {}): merge the supplied fields into this existing mapping.
        h.update(headers or {})
        # IRIS EXPLAIN: Store the result of http.client.HTTPConnection('127.0.0.1', port or self.server.server_port, timeout=30)
        # IRIS EXPLAIN: in connection; later lines use this named result.
        connection = http.client.HTTPConnection('127.0.0.1', port or self.server.server_port, timeout=30)
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Call connection.request(method, path, body=body, headers=h): send the stated HTTP request in this
            # IRIS EXPLAIN: test.
            connection.request(method, path, body=body, headers=h)
            # IRIS EXPLAIN: Store the result of connection.getresponse() (read the actual HTTP response) in response; later
            # IRIS EXPLAIN: lines use this named result.
            response = connection.getresponse()
            # IRIS EXPLAIN: Store the result of response.read() (read the requested chunk) in content; later lines use this
            # IRIS EXPLAIN: named result.
            content = response.read()
            # IRIS EXPLAIN: Store the result of json.loads(content) (decode the existing JSON text) when
            # IRIS EXPLAIN: response.getheader('Content-Type', '').startswith('application/json'); otherwise content in result;
            # IRIS EXPLAIN: later lines use this named result.
            result = json.loads(content) if response.getheader('Content-Type', '').startswith('application/json') else content
            # IRIS EXPLAIN: Return (response.status, result, dict(response.getheaders())) to the caller; this ends the current
            # IRIS EXPLAIN: function path.
            return response.status, result, dict(response.getheaders())
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call connection.close(): close the resource.
            connection.close()

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_three_dashboard_routes_and_local_assets: Regression test: verify that three
    # IRIS EXPLAIN: dashboard routes and local assets; the assertions below define the exact expected behavior.
    def test_three_dashboard_routes_and_local_assets(self):
        # IRIS EXPLAIN: Iterate ('/admin', '/soc', '/grc', '/demo-static/app.js', '/demo-static/style.css'), binding each item
        # IRIS EXPLAIN: to path; process only the existing observed/fixture collection.
        for path in ('/admin', '/soc', '/grc', '/demo-static/app.js', '/demo-static/style.css'):
            # IRIS EXPLAIN: Store the result of self.request(path, None) (send the stated HTTP request in this test) in (status,
            # IRIS EXPLAIN: body, headers); later lines use this named result.
            status, body, headers = self.request(path, None)
            # IRIS EXPLAIN: Call self.assertEqual(status, 200): assert that the actual and expected values are equal.
            self.assertEqual(status, 200)
            # IRIS EXPLAIN: Call self.assertTrue(body): assert that the stated condition is true.
            self.assertTrue(body)
            # IRIS EXPLAIN: Call self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy']): assert that the
            # IRIS EXPLAIN: item belongs to the expected collection.
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
            # IRIS EXPLAIN: Call self.assertEqual(headers['Cache-Control'], 'no-store'): assert that the actual and expected
            # IRIS EXPLAIN: values are equal.
            self.assertEqual(headers['Cache-Control'], 'no-store')

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_api_requires_valid_key: Regression test: verify that api requires valid key;
    # IRIS EXPLAIN: the assertions below define the exact expected behavior.
    def test_api_requires_valid_key(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/state', None)[0], 401): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.request('/api/demo/state', None)[0], 401)
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/state', None, headers={'X-IRIS-Key': 'wrong'})[0], 401):
        # IRIS EXPLAIN: assert that the actual and expected values are equal.
        self.assertEqual(self.request('/api/demo/state', None, headers={'X-IRIS-Key': 'wrong'})[0], 401)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_authentication_happens_before_body_validation: Regression test: verify that
    # IRIS EXPLAIN: authentication happens before body validation; the assertions below define the exact expected behavior.
    def test_authentication_happens_before_body_validation(self):
        # IRIS EXPLAIN: Store the result of self.request('/api/demo/analyze', None, 'POST', headers={'Content-Length':
        # IRIS EXPLAIN: '99999999'}) (send the stated HTTP request in this test) in (status, _, _); later lines use this named
        # IRIS EXPLAIN: result.
        status, _, _ = self.request('/api/demo/analyze', None, 'POST', headers={'Content-Length': '99999999'})
        # IRIS EXPLAIN: Call self.assertEqual(status, 401): assert that the actual and expected values are equal.
        self.assertEqual(status, 401)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_wrong_roles_cannot_read_team_tables_or_audit: Regression test: verify that
    # IRIS EXPLAIN: wrong roles cannot read team tables or audit; the assertions below define the exact expected behavior.
    def test_wrong_roles_cannot_read_team_tables_or_audit(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/risks', 'soc')[0], 403): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.request('/api/demo/risks', 'soc')[0], 403)
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/alerts', 'grc')[0], 403): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.request('/api/demo/alerts', 'grc')[0], 403)
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/audit', 'grc')[0], 403): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual(self.request('/api/demo/audit', 'grc')[0], 403)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_foreign_host_and_origin_rejected: Regression test: verify that foreign host
    # IRIS EXPLAIN: and origin rejected; the assertions below define the exact expected behavior.
    def test_foreign_host_and_origin_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/state', headers={'Host': 'evil.example'})[0], 400): assert
        # IRIS EXPLAIN: that the actual and expected values are equal.
        self.assertEqual(self.request('/api/demo/state', headers={'Host': 'evil.example'})[0], 400)
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/state', headers={'Origin': 'https://evil.example'})[0],
        # IRIS EXPLAIN: 403): assert that the actual and expected values are equal.
        self.assertEqual(self.request('/api/demo/state', headers={'Origin': 'https://evil.example'})[0], 403)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_oversized_command_rejected: Regression test: verify that oversized command
    # IRIS EXPLAIN: rejected; the assertions below define the exact expected behavior.
    def test_oversized_command_rejected(self):
        # IRIS EXPLAIN: Call self.assertEqual(self.request('/api/demo/analyze', method='POST', body={'large': 'x' * 9000})[0],
        # IRIS EXPLAIN: 413): assert that the actual and expected values are equal.
        self.assertEqual(self.request('/api/demo/analyze', method='POST', body={'large': 'x'*9000})[0], 413)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_caller_cannot_supply_priority_likelihood_or_actor: Regression test: verify
    # IRIS EXPLAIN: that caller cannot supply priority likelihood or actor; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_caller_cannot_supply_priority_likelihood_or_actor(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Store the result of self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review', 'grc',
        # IRIS EXPLAIN: 'POST', {'decision': 'approve', 'reason': 'Human app... (send the stated HTTP request in this test) in
        # IRIS EXPLAIN: (status, _, _); later lines use this named result.
        status, _, _ = self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review', 'grc', 'POST',
                                    # IRIS EXPLAIN: Set/describe these existing record fields: likelihood: the stored or
                                    # IRIS EXPLAIN: explicitly proposed 1-5 likelihood in this record, not an invented ML risk
                                    # IRIS EXPLAIN: probability.
                                    {'decision': 'approve', 'reason': 'Human approval example', 'likelihood': 5, 'actor': 'admin'})
        # IRIS EXPLAIN: Call self.assertEqual(status, 422): assert that the actual and expected values are equal.
        self.assertEqual(status, 422)
        # IRIS EXPLAIN: Call self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0): assert that the actual
        # IRIS EXPLAIN: and expected values are equal.
        self.assertEqual(self.engine.status('admin')['counts']['changed_risks'], 0)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_bad_pagination_and_duplicate_query_rejected: Regression test: verify that bad
    # IRIS EXPLAIN: pagination and duplicate query rejected; the assertions below define the exact expected behavior.
    def test_bad_pagination_and_duplicate_query_rejected(self):
        # IRIS EXPLAIN: Iterate ('/api/demo/alerts?limit=101', '/api/demo/alerts?offset=-1', '/api/demo/alerts?limit=5&limit=6',
        # IRIS EXPLAIN: '/api/demo/state?role=admin', '/api/demo/alerts?changed_only..., binding each item to path; process only
        # IRIS EXPLAIN: the existing observed/fixture collection.
        for path in ('/api/demo/alerts?limit=101', '/api/demo/alerts?offset=-1', '/api/demo/alerts?limit=5&limit=6',
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: '/api/demo/state?role=admin', '/api/demo/alerts?changed_only=maybe'):.
                     '/api/demo/state?role=admin', '/api/demo/alerts?changed_only=maybe'):
            # IRIS EXPLAIN: Call self.assertEqual(self.request(path)[0], 422): assert that the actual and expected values are
            # IRIS EXPLAIN: equal.
            self.assertEqual(self.request(path)[0], 422)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_unknown_routes_and_path_traversal_not_served: Regression test: verify that
    # IRIS EXPLAIN: unknown routes and path traversal not served; the assertions below define the exact expected behavior.
    def test_unknown_routes_and_path_traversal_not_served(self):
        # IRIS EXPLAIN: Iterate ('/demo-static/../engine.py', '/.local/active_demo/access.json', '/api/demo/unknown'), binding
        # IRIS EXPLAIN: each item to path; process only the existing observed/fixture collection.
        for path in ('/demo-static/../engine.py', '/.local/active_demo/access.json', '/api/demo/unknown'):
            # IRIS EXPLAIN: Call self.assertEqual(self.request(path)[0], 404): assert that the actual and expected values are
            # IRIS EXPLAIN: equal.
            self.assertEqual(self.request(path)[0], 404)

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_human_review_applies_actual_database_change_over_http: Regression test: verify
    # IRIS EXPLAIN: that human review applies actual database change over http; the assertions below define the exact expected
    # IRIS EXPLAIN: behavior.
    def test_human_review_applies_actual_database_change_over_http(self):
        # IRIS EXPLAIN: Store the result of self.proposal('grc') in chosen; later lines use this named result.
        chosen = self.proposal('grc')
        # IRIS EXPLAIN: Store the computed value '/api/demo/proposals/' + chosen['proposal_id'] + '/review' in path; later lines
        # IRIS EXPLAIN: use this named result.
        path = '/api/demo/proposals/' + chosen['proposal_id'] + '/review'
        # IRIS EXPLAIN: Call self.assertEqual(self.request(path, 'soc', 'POST', {'decision': 'approve', 'reason': 'Attempted
        # IRIS EXPLAIN: wrong-team approval'})[0], 403): assert that the actual and expected values are equal.
        self.assertEqual(self.request(path, 'soc', 'POST', {'decision': 'approve', 'reason': 'Attempted wrong-team approval'})[0], 403)
        # IRIS EXPLAIN: Store the result of self.request(path, 'grc', 'POST', {'decision': 'approve', 'reason': 'Examiner demo:
        # IRIS EXPLAIN: approved after evidence review.'}) (send the stated HTTP request in this test) in (status, result, _);
        # IRIS EXPLAIN: later lines use this named result.
        status, result, _ = self.request(path, 'grc', 'POST', {'decision': 'approve', 'reason': 'Examiner demo: approved after evidence review.'})
        # IRIS EXPLAIN: Call self.assertEqual(status, 200): assert that the actual and expected values are equal.
        self.assertEqual(status, 200)
        # IRIS EXPLAIN: Call self.assertEqual(result['demo_records_written'], 1): assert that the actual and expected values are
        # IRIS EXPLAIN: equal.
        self.assertEqual(result['demo_records_written'], 1)
        # IRIS EXPLAIN: Store the result of self.request('/api/demo/risks', 'grc') (send the stated HTTP request in this test)
        # IRIS EXPLAIN: in (_, register, _); later lines use this named result.
        _, register, _ = self.request('/api/demo/risks', 'grc')
        # IRIS EXPLAIN: Store the result of next((item for item in register['items'] if item['risk_id'] == 'DEMO-R001-1')) in
        # IRIS EXPLAIN: row; later lines use this named result.
        row = next(item for item in register['items'] if item['risk_id'] == 'DEMO-R001-1')
        # IRIS EXPLAIN: Call self.assertEqual((row['current_score'], row['version']), (0.8, 2)): assert that the actual and
        # IRIS EXPLAIN: expected values are equal.
        self.assertEqual((row['current_score'], row['version']), (0.8, 2))

    # IRIS EXPLAIN: Function ActiveHTTPTests.test_real_fresh_http_analysis_then_both_team_approvals_and_exports: Regression
    # IRIS EXPLAIN: test: verify that real fresh http analysis then both team approvals and exports; the assertions below define
    # IRIS EXPLAIN: the exact expected behavior.
    def test_real_fresh_http_analysis_then_both_team_approvals_and_exports(self):
        # IRIS EXPLAIN: Store the result of DemoEngine(Settings(self.directory / 'fresh_http', KEYS), adapter=self.adapter) in
        # IRIS EXPLAIN: fresh; later lines use this named result.
        fresh = DemoEngine(Settings(self.directory / 'fresh_http', KEYS), adapter=self.adapter)
        # IRIS EXPLAIN: Enter DemoServer(('127.0.0.1', 0), fresh) as server; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with DemoServer(('127.0.0.1', 0), fresh) as server:
            # IRIS EXPLAIN: Store the result of threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01},
            # IRIS EXPLAIN: daemon=True) in thread; later lines use this named result.
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            # IRIS EXPLAIN: Call thread.start(): start the background test server thread.
            thread.start()
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store server.server_port in port; later lines use this named result.
                port = server.server_port
                # IRIS EXPLAIN: Call self.assertFalse(self.request('/api/demo/state', port=port)[1]['analyzed']): assert that
                # IRIS EXPLAIN: the stated condition is false.
                self.assertFalse(self.request('/api/demo/state', port=port)[1]['analyzed'])
                # IRIS EXPLAIN: Store the result of self.request('/api/demo/analyze', method='POST', body={}, port=port) (send
                # IRIS EXPLAIN: the stated HTTP request in this test) in (status, analysis, _); later lines use this named
                # IRIS EXPLAIN: result.
                status, analysis, _ = self.request('/api/demo/analyze', method='POST', body={}, port=port)
                # IRIS EXPLAIN: Call self.assertEqual(status, 200): assert that the actual and expected values are equal.
                self.assertEqual(status, 200)
                # IRIS EXPLAIN: Call self.assertEqual(analysis['sessions'], 132): assert that the actual and expected values are
                # IRIS EXPLAIN: equal.
                self.assertEqual(analysis['sessions'], 132)
                # IRIS EXPLAIN: Call self.assertFalse(analysis['reused_existing_run']): assert that the stated condition is
                # IRIS EXPLAIN: false.
                self.assertFalse(analysis['reused_existing_run'])
                # IRIS EXPLAIN: Iterate ('grc', 'soc'), binding each item to role; process only the existing observed/fixture
                # IRIS EXPLAIN: collection.
                for role in ('grc', 'soc'):
                    # IRIS EXPLAIN: Store the result of self.request('/api/demo/proposals', role, port=port) (send the stated
                    # IRIS EXPLAIN: HTTP request in this test) in (_, proposals, _); later lines use this named result.
                    _, proposals, _ = self.request('/api/demo/proposals', role, port=port)
                    # IRIS EXPLAIN: Store the result of next((item for item in proposals['items'] if
                    # IRIS EXPLAIN: item['payload']['evidence']['hostname'] == 'identity-server')) in chosen; later lines use
                    # IRIS EXPLAIN: this named result.
                    chosen = next(item for item in proposals['items'] if item['payload']['evidence']['hostname'] == 'identity-server')
                    # IRIS EXPLAIN: Store the result of self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review',
                    # IRIS EXPLAIN: role, 'POST', {'decision': 'approve', 'reason': 'HTTP demon... (send the stated HTTP request
                    # IRIS EXPLAIN: in this test) in (status, applied, _); later lines use this named result.
                    status, applied, _ = self.request('/api/demo/proposals/' + chosen['proposal_id'] + '/review',
                                                     # IRIS EXPLAIN: Continue the current record with decision, reason; each value
                                                     # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                                     role, 'POST', {'decision': 'approve', 'reason': 'HTTP demonstration approval by authorized team.'}, port=port)
                    # IRIS EXPLAIN: Call self.assertEqual(status, 200): assert that the actual and expected values are equal.
                    self.assertEqual(status, 200)
                    # IRIS EXPLAIN: Call self.assertGreater(applied['demo_records_written'], 0): assert that the actual value
                    # IRIS EXPLAIN: exceeds the comparison value.
                    self.assertGreater(applied['demo_records_written'], 0)
                # IRIS EXPLAIN: Store the result of self.request('/api/demo/state', port=port) (send the stated HTTP request in
                # IRIS EXPLAIN: this test) in (_, state, _); later lines use this named result.
                _, state, _ = self.request('/api/demo/state', port=port)
                # IRIS EXPLAIN: Call self.assertEqual((state['counts']['changed_risks'],
                # IRIS EXPLAIN: state['counts']['reprioritized_alerts']), (1, 19)): assert that the actual and expected values
                # IRIS EXPLAIN: are equal.
                self.assertEqual((state['counts']['changed_risks'], state['counts']['reprioritized_alerts']), (1, 19))
                # IRIS EXPLAIN: Call self.assertTrue(self.request('/api/demo/export/risks', 'grc', port=port)[1]['demo_only']):
                # IRIS EXPLAIN: assert that the stated condition is true.
                self.assertTrue(self.request('/api/demo/export/risks', 'grc', port=port)[1]['demo_only'])
                # IRIS EXPLAIN: Call self.assertEqual(len(self.request('/api/demo/export/alerts', 'soc',
                # IRIS EXPLAIN: port=port)[1]['records']), 2355): assert that the actual and expected values are equal.
                self.assertEqual(len(self.request('/api/demo/export/alerts', 'soc', port=port)[1]['records']), 2355)
            # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
            finally:
                # IRIS EXPLAIN: Call server.shutdown(): stop the test-owned local HTTP server.
                server.shutdown()
                # IRIS EXPLAIN: Call thread.join(timeout=3): wait within the existing limit for the test thread to end.
                thread.join(timeout=3)


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
    def test_soc_html_has_only_soc_records_and_controls(self):
        status, body, _ = self.request('/soc', None)
        self.assertEqual(status, 200)
        page = PageStructure(body.decode())
        self.assertTrue({'alert-panel', 'export-alerts', 'review-panel'} <= set(page.ids))
        self.assertFalse({'risk-panel', 'export-risks', 'admin-actions', 'model-status', 'audit', 'admin-evidence'} & set(page.ids))
        self.assertEqual(page.counts, {'alerts', 'pending_soc', 'reprioritized_alerts'})
        self.assertFalse({'/admin', '/grc'} & page.links)

    def test_grc_html_has_only_grc_records_and_controls(self):
        status, body, _ = self.request('/grc', None)
        self.assertEqual(status, 200)
        page = PageStructure(body.decode())
        self.assertTrue({'risk-panel', 'export-risks', 'review-panel'} <= set(page.ids))
        self.assertFalse({'alert-panel', 'export-alerts', 'admin-actions', 'model-status', 'audit', 'admin-evidence'} & set(page.ids))
        self.assertEqual(page.counts, {'risks', 'pending_grc', 'changed_risks'})
        self.assertFalse({'/admin', '/soc'} & page.links)

    def test_admin_html_contains_both_working_systems_and_all_diagnostics(self):
        status, body, _ = self.request('/admin', None)
        self.assertEqual(status, 200)
        page = PageStructure(body.decode())
        self.assertTrue({'risk-panel', 'alert-panel', 'export-risks', 'export-alerts', 'admin-actions',
                         'model-status', 'audit', 'integration', 'history', 'proposal-evidence', 'proposal-summary'} <= set(page.ids))
        # The restored design keeps its original five-card strip; the fifth
        # card sums the two pending-team counts only for Admin.
        self.assertEqual(page.counts, {'risks', 'alerts', 'changed_risks', 'reprioritized_alerts', 'pending_total'})
        self.assertTrue({'/soc', '/grc'} <= page.links)

    def test_rendered_pages_have_unique_ids_and_resolved_template_slots(self):
        for role in ('admin', 'soc', 'grc'):
            _, body, _ = self.request('/' + role, None)
            markup = body.decode()
            page = PageStructure(markup)
            self.assertEqual(len(page.ids), len(set(page.ids)))
            self.assertNotIn('{{', markup)
            self.assertNotIn('<!-- IRIS:', markup)
            # Inspect the real body, not an example tag in an HTML comment.
            self.assertEqual(page.body_role, role)

    def test_source_and_served_pages_have_readable_text_not_placeholder_variables(self):
        """Raw HTML fallback and real HTTP responses must not show template tokens."""
        from demo_app.server import STATIC
        source = (STATIC / 'index.html').read_text(encoding='utf-8')
        self.assertNotIn('{{', source)
        self.assertIn('Approvals actively update the demo database.', source)
        self.assertIn('Inspect technical evidence, ML shadow and policy rationale', source)
        for role, title in [('admin', 'Admin · engine control'), ('soc', 'SOC · live alert queue'),
                            ('grc', 'GRC · live risk register')]:
            _, body, _ = self.request('/' + role, None)
            markup = body.decode()
            self.assertIn(f'<title>IRIS · {title}</title>', markup)
            self.assertIn(f'<h1 id="title">{title}', markup)
            self.assertNotIn('{{', markup)

    def test_http_team_status_does_not_deliver_admin_or_cross_team_fields(self):
        for role in ('soc', 'grc'):
            _, state, _ = self.request('/api/demo/state', role)
            self.assertFalse({'model', 'analysis', 'exercise_history'} & set(state))
            self.assertEqual(set(state['counts']), {'alerts', 'pending_soc', 'reprioritized_alerts'} if role == 'soc' else {'risks', 'pending_grc', 'changed_risks'})

    def test_http_team_proposals_are_projected_by_authenticated_key(self):
        _, soc, _ = self.request('/api/demo/proposals', 'soc')
        self.assertTrue(all(item['kind'] == 'soc' for item in soc['items']))
        self.assertTrue(all('policy' not in item['payload']['evidence'] and 'primary_controls' not in item['payload']['evidence'] for item in soc['items']))
        _, grc, _ = self.request('/api/demo/proposals', 'grc')
        self.assertTrue(all(item['kind'] == 'grc' for item in grc['items']))
        self.assertTrue(all('features' not in item['payload']['evidence'] and 'ml_shadow' not in item['payload']['evidence'] for item in grc['items']))

    def test_team_cannot_fetch_admin_analysis_response_or_rehearsal_commands(self):
        for role in ('soc', 'grc'):
            self.assertEqual(self.request('/api/demo/analyze', role, 'POST', {})[0], 403)
            self.assertEqual(self.request('/api/demo/exercises', role, 'POST', {'label': 'Unauthorized demo reset'})[0], 403)

    def test_query_parameters_cannot_expand_role_projection(self):
        for role in ('soc', 'grc'):
            self.assertEqual(self.request('/api/demo/proposals?actor=admin', role)[0], 422)
            self.assertEqual(self.request('/api/demo/state?role=admin', role)[0], 422)

    def test_raw_partial_templates_are_not_public_static_routes(self):
        for name in ('admin', 'soc', 'grc', 'reviews', 'index'):
            self.assertEqual(self.request('/demo-static/' + name + '.html', None)[0], 404)

    def test_original_dashboard_structure_is_restored_without_redesign_panels(self):
        """Keep the original dark layout and original review/table controls."""
        for role in ('admin', 'soc', 'grc'):
            _, body, _ = self.request('/' + role, None)
            markup = body.decode()
            page = PageStructure(markup)
            self.assertTrue({'title', 'subtitle', 'login-hint', 'proposal-title',
                             'proposal-summary', 'proposal-evidence', 'evidence-panel'} <= set(page.ids))
            self.assertFalse({'before-value', 'after-value', 'access-profile', 'toggle-key',
                              'login-error', 'proposal-status'} & set(page.ids))
            self.assertIn('class="hero"', markup)
            self.assertIn('Connect this dashboard', markup)
            self.assertNotIn('class="sidebar"', markup)
        # All original annotated theme rules remain byte-identical; only the
        # team-only three-counter rule is appended after this original prefix.
        _, stylesheet, _ = self.request('/demo-static/style.css', None)
        original = stylesheet.partition(b'\n/* Content-only scoping:')[0]
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         '94b07c7009dfa585037b3243670729463394b3d9c69f9d7157b08b4ce6deb11d')

    def test_restored_login_uses_no_new_build_or_session_prerequisites(self):
        """The original direct /state login works without the rejected gates."""
        _, body, _ = self.request('/demo-static/app.js', None)
        source = body.decode()
        self.assertIn('await api("/state")', source)
        self.assertNotIn('/api/demo/info', source)
        self.assertNotIn('api("/session")', source)
        self.assertEqual(self.request('/api/demo/info', None)[0], 401)
        self.assertEqual(self.request('/api/demo/session', 'admin')[0], 404)

    def test_activity_is_admin_only_and_read_only(self):
        for role in (None, 'soc', 'grc'):
            self.assertEqual(self.request('/api/demo/activity', role)[0], 401 if role is None else 403)
        self.assertEqual(self.request('/api/demo/activity', 'admin')[0], 200)
        self.assertEqual(self.request('/api/demo/activity?role=admin', 'soc')[0], 422)
        self.assertEqual(self.request('/api/demo/activity', 'admin', 'POST', {})[0], 404)

    def test_activity_polling_does_not_generate_command_events(self):
        _, first, _ = self.request('/api/demo/activity')
        _, second, _ = self.request('/api/demo/activity')
        self.assertEqual(first, second)
        self.assertEqual(first['active_commands'], 0)
        self.assertTrue(first['process_only'])

    def test_activity_reports_real_approval_writes(self):
        selected = self.proposal('soc')
        status, result, _ = self.request('/api/demo/proposals/' + selected['proposal_id'] + '/review',
            'soc', 'POST', {'decision': 'approve', 'reason': 'PRIVATE-REVIEW-NOTE should not enter the live monitor'})
        self.assertEqual(status, 200)
        _, feed, _ = self.request('/api/demo/activity')
        last = feed['events'][-1]
        self.assertEqual(last['demo_records_written'], result['demo_records_written'])
        self.assertEqual(last['demo_records_written'], 19)
        self.assertEqual((last['role'], last['action'], last['state']), ('soc', 'review', 'completed'))
        encoded = json.dumps(feed)
        self.assertNotIn('PRIVATE-REVIEW-NOTE', encoded)
        for key in KEYS.values():
            self.assertNotIn(key, encoded)

    def test_activity_failures_do_not_log_command_bodies(self):
        self.assertEqual(self.request('/api/demo/analyze', 'admin', 'POST', {'PRIVATE-BODY': 'SECRET'})[0], 422)
        _, feed, _ = self.request('/api/demo/activity')
        self.assertEqual(feed['events'][-1]['state'], 'failed')
        self.assertNotIn('PRIVATE-BODY', json.dumps(feed))
        self.assertNotIn('SECRET', json.dumps(feed))

    def test_activity_can_be_read_while_a_command_is_running(self):
        started, release = threading.Event(), threading.Event()
        result = []
        def waiting_analysis(actor):
            started.set()
            if not release.wait(3):
                raise ValueError('Test command not released')
            return {'sessions': 132}
        with mock.patch.object(self.engine, 'analyze', side_effect=waiting_analysis):
            thread = threading.Thread(target=lambda: result.append(self.request('/api/demo/analyze', 'admin', 'POST', {})))
            thread.start()
            try:
                self.assertTrue(started.wait(2))
                _, feed, _ = self.request('/api/demo/activity')
                self.assertEqual(feed['active_commands'], 1)
                self.assertEqual(feed['events'][-1]['state'], 'running')
            finally:
                release.set()
                thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result[0][0], 200)
        _, feed, _ = self.request('/api/demo/activity')
        self.assertEqual(feed['active_commands'], 0)
        self.assertEqual(feed['events'][-1]['sessions'], 132)

    def test_activity_window_is_in_admin_html_only(self):
        for role in ('admin', 'soc', 'grc'):
            _, markup, _ = self.request('/' + role, None)
            page = PageStructure(markup.decode())
            self.assertEqual('backend-monitor' in page.ids, role == 'admin')


if __name__ == '__main__':
    # IRIS EXPLAIN: Call unittest.main() using the existing explicit arguments.
    unittest.main()
