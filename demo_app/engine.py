"""Real local writes to synthetic SOC/GRC records, never to external systems.

Analysis uses backend.core.Engine and the pinned Colab models unchanged. Human
approvals execute explicit policy proposals against separately versioned demo
tables. Immutable model evidence and original input files are never rewritten.
"""
from __future__ import annotations

import json
import threading
import uuid
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from backend.config import ROOT, Settings
from backend.core import BusyError, Engine, INPUTS
from backend.model_adapter import digest, utc_now
from backend.storage import encoded
from iris_models.three_sources import integrate
from iris_models.telemetry import timestamp

DATA = ROOT / 'demo' / 'data'
PRIORITIES = ('Low', 'Medium', 'High', 'Critical')
MARKER = 'IRIS_SYNTHETIC_ACTIVE_DEMO_V1'


class ConflictError(ValueError):
    """The saved proposal no longer matches the target version."""


def require(actor, *roles):
    if actor not in roles:
        raise PermissionError('This action requires the ' + ' or '.join(roles).upper() + ' role')


def technical_priority(level):
    # Same technical severity bands as backend.policy, before business context.
    severity = level * 10 / 16
    return 'Low' if severity < 3 else 'Medium' if severity < 6 else 'High' if severity < 8 else 'Critical'


class DemoEngine:
    def __init__(self, settings: Settings, *, data_dir: Path = DATA, adapter=None):
        self.settings, self.data_dir = settings, Path(data_dir)
        self.inputs = {key: self.data_dir / name for key, name in INPUTS.items()}
        self.manifest = json.loads((self.data_dir / 'demo_manifest.json').read_text(encoding='utf-8'))
        self.check_inputs()
        self.core = Engine(settings, adapter)
        self.store = self.core.store
        self.lock = threading.Lock()
        self._schema()
        with self.store.connection() as db:
            marker = db.execute("SELECT value FROM demo_meta WHERE name='marker'").fetchone()
            saved = db.execute("SELECT value FROM demo_meta WHERE name='source_hashes'").fetchone()
            current = db.execute("SELECT value FROM demo_meta WHERE name='current_exercise'").fetchone()
            if marker and marker[0] != MARKER:
                raise ValueError('Not an IRIS synthetic-demo database')
            if saved and saved[0] != encoded(self.source_hashes):
                raise ValueError('Demo source identity changed; do not mix exercises with different sources')
        if not current:
            self.new_exercise('admin', 'Initial examiner demonstration')

    def check_inputs(self):
        if self.manifest.get('data_provenance') != 'synthetic':
            raise ValueError('The active demo accepts only the bundled synthetic inputs')
        expected = {item['upload_field']: item['sha256'] for item in self.manifest['inputs']}
        self.source_hashes = {key: digest(path) for key, path in self.inputs.items()}
        if self.source_hashes != expected:
            raise ValueError('Demo dataset checksum mismatch; restore the bundled three inputs')

    def _schema(self):
        with self.store.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS demo_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS demo_exercises (
                    exercise_id TEXT PRIMARY KEY, label TEXT NOT NULL, created_at TEXT NOT NULL,
                    run_id TEXT REFERENCES runs(run_id), summary_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS demo_risks (
                    exercise_id TEXT NOT NULL REFERENCES demo_exercises(exercise_id),
                    risk_id TEXT NOT NULL, asset_id TEXT NOT NULL, hostname TEXT NOT NULL,
                    source_version TEXT NOT NULL, source_json TEXT NOT NULL,
                    baseline_likelihood INTEGER NOT NULL, current_likelihood INTEGER NOT NULL,
                    impact INTEGER NOT NULL, version INTEGER NOT NULL,
                    updated_at TEXT, updated_by TEXT, last_proposal_id TEXT,
                    PRIMARY KEY(exercise_id, risk_id)
                );
                CREATE TABLE IF NOT EXISTS demo_alerts (
                    exercise_id TEXT NOT NULL REFERENCES demo_exercises(exercise_id),
                    event_id TEXT NOT NULL, asset_id TEXT NOT NULL, hostname TEXT NOT NULL,
                    event_time TEXT NOT NULL, rule_level REAL NOT NULL,
                    baseline_priority TEXT NOT NULL, current_priority TEXT NOT NULL,
                    version INTEGER NOT NULL, case_id TEXT REFERENCES cases(case_id),
                    updated_at TEXT, updated_by TEXT, last_proposal_id TEXT,
                    PRIMARY KEY(exercise_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS demo_proposals (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id TEXT NOT NULL UNIQUE,
                    exercise_id TEXT NOT NULL REFERENCES demo_exercises(exercise_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    kind TEXT NOT NULL, target_id TEXT, payload_json TEXT NOT NULL,
                    status TEXT NOT NULL, reason TEXT, reviewed_by TEXT, reviewed_at TEXT,
                    UNIQUE(exercise_id, case_id, kind)
                );
                CREATE TABLE IF NOT EXISTS demo_changes (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    exercise_id TEXT NOT NULL REFERENCES demo_exercises(exercise_id),
                    proposal_id TEXT NOT NULL REFERENCES demo_proposals(proposal_id),
                    target_kind TEXT NOT NULL, target_id TEXT NOT NULL,
                    before_json TEXT NOT NULL, after_json TEXT NOT NULL,
                    actor TEXT NOT NULL, reason TEXT NOT NULL, changed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS demo_queue ON demo_alerts(exercise_id,current_priority,event_time);
                CREATE INDEX IF NOT EXISTS demo_pending ON demo_proposals(exercise_id,kind,status);
            ''')

    @contextmanager
    def mutation(self):
        if not self.lock.acquire(blocking=False):
            raise BusyError('The demo is processing another action; wait and refresh')
        try:
            yield
        finally:
            self.lock.release()

    @staticmethod
    def current(db):
        row = db.execute("SELECT value FROM demo_meta WHERE name='current_exercise'").fetchone()
        if not row:
            raise ValueError('No current demonstration exercise')
        return row[0]

    def new_exercise(self, actor, label='Examiner demonstration'):
        require(actor, 'admin')
        if not isinstance(label, str) or not 3 <= len(label.strip()) <= 100:
            raise ValueError('Exercise label must contain 3..100 characters')
        with self.mutation():
            self.check_inputs()
            unified, _, report = integrate(**{
                'asset_path': self.inputs['asset_inventory'],
                'risk_path': self.inputs['risk_register'],
                'alerts_path': self.inputs['siem_alerts'],
            }, window_seconds=60)
            at = max(timestamp(event['timestamp']) for event in unified)
            asset_rows = json.loads(self.inputs['asset_inventory'].read_text())['records']
            risk_rows = json.loads(self.inputs['risk_register'].read_text())['records']
            def valid(row):
                return (timestamp(row['valid_from']) <= at and timestamp(row['recorded_at']) <= at
                        and (not row['valid_to'] or at < timestamp(row['valid_to'])))
            assets = {row['asset_id']: row for row in asset_rows if valid(row)}
            risks = [row for row in risk_rows if valid(row)]
            if len(assets) != 30 or len(risks) != 60:
                raise ValueError('Unexpected current demo inventory/register size')
            if any(event['data_provenance'] != 'synthetic' for event in unified):
                raise ValueError('Only synthetic demonstration events are allowed')
            eid, now = 'DEMO-' + uuid.uuid4().hex[:16], utc_now()
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT INTO demo_exercises VALUES (?,?,?,NULL,?)',
                           (eid, label.strip(), now, encoded({'seed_integration': report})))
                db.executemany('INSERT INTO demo_risks VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)', [
                    (eid, risk['risk_id'], risk['asset_id'], assets[risk['asset_id']]['hostname'],
                     risk['risk_version_id'], encoded(risk), risk['likelihood'], risk['likelihood'], risk['impact'], 1)
                    for risk in risks
                ])
                db.executemany('INSERT INTO demo_alerts VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)', [
                    (eid, event['event_id'], event['asset']['asset_id'], event['asset']['hostname'],
                     event['timestamp'], event['alert']['level'], technical_priority(event['alert']['level']),
                     technical_priority(event['alert']['level']), 1)
                    for event in unified if event['asset'] is not None
                ])
                for name, value in {'marker': MARKER, 'source_hashes': encoded(self.source_hashes), 'current_exercise': eid}.items():
                    db.execute('INSERT INTO demo_meta VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', (name, value))
                self.store.audit(db, actor, 'demo_exercise_created', eid,
                                 {'label': label.strip(), 'synthetic_only': True, 'previous_exercises_preserved': True})
            return {'exercise_id': eid, 'status': 'seeded', 'previous_exercises_preserved': True}

    def analyze(self, actor):
        require(actor, 'admin', 'soc')
        with self.mutation():
            self.check_inputs()
            with self.store.connection() as db:
                exercise = self.current(db)
            summary = self.core.run(self.inputs, actor)
            cases = self.store.cases(run_id=summary['run_id'], limit=2000)['items']
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                for case in cases:
                    session, prediction, policy = case['session'], case['prediction'], case['risk_review']
                    db.executemany('UPDATE demo_alerts SET case_id=? WHERE exercise_id=? AND event_id=?',
                                   [(case['case_id'], exercise, event_id) for event_id in session['source_event_ids']])
                    shadow = prediction['shadow_candidate']
                    evidence = {
                        'hostname': session['asset_snapshot']['hostname'], 'asset_id': session['asset_id'],
                        'asset_criticality': session['asset_snapshot']['criticality'],
                        'session_id': session['session_id'], 'session_time': session['start_utc'],
                        'primary_assessment': prediction['soc_assessment'], 'policy': policy,
                        'features': session['features'], 'primary_controls': case['primary_controls'],
                        'ml_shadow': ({'scenario': shadow['scenario_class'], 'confidence': shadow['confidence'],
                                       'status': shadow['status'], 'controls': shadow['controls']}
                                      if shadow else None),
                        'warnings': prediction['warnings'],
                        'decision_basis': 'Versioned primary rules and explicit business-risk policy; ML remains an unreleased shadow comparison.',
                    }
                    if policy['priority'] in PRIORITIES and prediction['soc_assessment']['status'] == 'ASSESSED':
                        alerts = db.execute('SELECT event_id,current_priority,version FROM demo_alerts WHERE exercise_id=? AND case_id=?',
                                            (exercise, case['case_id'])).fetchall()
                        changes = [{'event_id': row['event_id'], 'before': row['current_priority'],
                                    'version': row['version'], 'after': policy['priority']}
                                   for row in alerts if row['current_priority'] != policy['priority']]
                        if changes:
                            self._proposal(db, exercise, case, 'soc', None, {
                                'evidence': evidence, 'new_priority': policy['priority'], 'changes': changes,
                                'before_counts': dict(Counter(row['before'] for row in changes)),
                                'changed_alerts': len(changes),
                            })
                    if policy['mapping_status'] == 'MATCHED':
                        risk = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND risk_id=?',
                                          (exercise, policy['matched_risk_id'])).fetchone()
                        if (risk and risk['source_version'] == policy['matched_risk_version_id']
                                and policy['proposed_likelihood'] > risk['baseline_likelihood']):
                            self._proposal(db, exercise, case, 'grc', risk['risk_id'], {
                                'evidence': evidence, 'risk_id': risk['risk_id'], 'expected_version': 1,
                                'source_version': risk['source_version'],
                                'before': {'likelihood': risk['baseline_likelihood'], 'impact': risk['impact'],
                                           'score': round(risk['baseline_likelihood'] * risk['impact'] / 25, 4)},
                                'after': {'likelihood': policy['proposed_likelihood'], 'impact': risk['impact'],
                                          'score': policy['proposed_risk_0_1']},
                            })
                db.execute('UPDATE demo_exercises SET run_id=?,summary_json=? WHERE exercise_id=?',
                           (summary['run_id'], encoded(summary), exercise))
                self.store.audit(db, actor, 'demo_analysis_ready', exercise,
                                 {'run_id': summary['run_id'], 'sessions': summary['sessions'],
                                  'demo_records_changed_by_analysis': False, 'model_sha256': summary['model_sha256']})
            return {'exercise_id': exercise, **summary, 'demo_records_changed_by_analysis': False}

    @staticmethod
    def _proposal(db, exercise, case, kind, target, payload):
        db.execute('''INSERT OR IGNORE INTO demo_proposals
                   (proposal_id,exercise_id,case_id,kind,target_id,payload_json,status)
                   VALUES (?,?,?,?,?,?,'pending')''',
                   ('PROP-' + uuid.uuid4().hex, exercise, case['case_id'], kind, target, encoded(payload)))

    @staticmethod
    def _page(limit, offset):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
            raise ValueError('limit must be 1..100 and offset must be nonnegative')

    def status(self, actor):
        require(actor, 'admin', 'soc', 'grc')
        with self.store.connection() as db:
            eid = self.current(db)
            row = db.execute('SELECT * FROM demo_exercises WHERE exercise_id=?', (eid,)).fetchone()
            counts = {
                'risks': db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=?', (eid,)).fetchone()[0],
                'alerts': db.execute('SELECT COUNT(*) FROM demo_alerts WHERE exercise_id=?', (eid,)).fetchone()[0],
                'changed_risks': db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=? AND version>1', (eid,)).fetchone()[0],
                'reprioritized_alerts': db.execute('SELECT COUNT(*) FROM demo_alerts WHERE exercise_id=? AND version>1', (eid,)).fetchone()[0],
                'pending_soc': db.execute("SELECT COUNT(*) FROM demo_proposals WHERE exercise_id=? AND kind='soc' AND status='pending'", (eid,)).fetchone()[0],
                'pending_grc': db.execute("SELECT COUNT(*) FROM demo_proposals WHERE exercise_id=? AND kind='grc' AND status='pending'", (eid,)).fetchone()[0],
            }
            history = [dict(item) for item in db.execute('SELECT exercise_id,label,created_at FROM demo_exercises ORDER BY rowid DESC')]
        return {'role': actor, 'exercise_id': eid, 'label': row['label'], 'analyzed': row['run_id'] is not None,
                'analysis': json.loads(row['summary_json']), 'counts': counts, 'exercise_history': history,
                'model': self.core.adapter.status(), 'demo_only': True, 'external_writes': False,
                'security_control_execution': False, 'approval_writes_real_demo_records': True}

    def risks(self, actor, limit=100, offset=0):
        require(actor, 'admin', 'grc')
        self._page(limit, offset)
        with self.store.connection() as db:
            eid = self.current(db)
            total = db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=?', (eid,)).fetchone()[0]
            rows = db.execute('''SELECT * FROM demo_risks WHERE exercise_id=?
                       ORDER BY (version>1) DESC,current_likelihood*impact DESC,risk_id LIMIT ? OFFSET ?''',
                              (eid, limit, offset)).fetchall()
            items = [self._risk(row) for row in rows]
        return {'exercise_id': eid, 'total': total, 'items': items, 'limit': limit, 'offset': offset}

    @staticmethod
    def _risk(row):
        source = json.loads(row['source_json'])
        return {key: row[key] for key in ('risk_id', 'asset_id', 'hostname', 'baseline_likelihood',
                                         'current_likelihood', 'impact', 'version', 'updated_at', 'updated_by', 'last_proposal_id')} | {
            'category': source['risk_category'], 'baseline_score': round(row['baseline_likelihood'] * row['impact'] / 25, 4),
            'current_score': round(row['current_likelihood'] * row['impact'] / 25, 4),
        }

    def alerts(self, actor, limit=50, offset=0, *, changed_only=False):
        require(actor, 'admin', 'soc')
        self._page(limit, offset)
        if type(changed_only) is not bool:
            raise ValueError('changed_only must be a boolean')
        where = 'exercise_id=?' + (' AND version>1' if changed_only else '')
        with self.store.connection() as db:
            eid = self.current(db)
            total = db.execute(f'SELECT COUNT(*) FROM demo_alerts WHERE {where}', (eid,)).fetchone()[0]
            rows = db.execute(f'''SELECT * FROM demo_alerts WHERE {where}
                      ORDER BY CASE current_priority WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                      WHEN 'Medium' THEN 2 ELSE 1 END DESC,event_time DESC,event_id
                      LIMIT ? OFFSET ?''', (eid, limit, offset)).fetchall()
        return {'exercise_id': eid, 'total': total, 'items': [dict(row) for row in rows], 'limit': limit, 'offset': offset}

    def proposals(self, actor, *, status='pending'):
        require(actor, 'admin', 'soc', 'grc')
        if status not in {'pending', 'approved', 'rejected', 'stale', 'all'}:
            raise ValueError('Invalid proposal status')
        with self.store.connection() as db:
            eid = self.current(db)
            where, params = 'exercise_id=?', [eid]
            if actor != 'admin':
                where += ' AND kind=?'
                params.append(actor)
            if status != 'all':
                where += ' AND status=?'
                params.append(status)
            rows = db.execute(f'SELECT * FROM demo_proposals WHERE {where} ORDER BY sequence', params).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item['payload'] = json.loads(item.pop('payload_json'))
            items.append(item)
        return {'exercise_id': eid, 'items': items, 'total': len(items)}

    def review(self, actor, proposal_id, decision, reason):
        require(actor, 'soc', 'grc')
        if not isinstance(proposal_id, str) or not proposal_id.startswith('PROP-') or len(proposal_id) > 50:
            raise ValueError('Invalid proposal identifier')
        if decision not in {'approve', 'reject'}:
            raise ValueError('decision must be approve or reject')
        if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 1000:
            raise ValueError('A human-review reason of 5..1000 characters is required')
        conflict = None
        with self.mutation():
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                eid = self.current(db)
                row = db.execute('SELECT * FROM demo_proposals WHERE exercise_id=? AND proposal_id=?', (eid, proposal_id)).fetchone()
                if not row:
                    raise KeyError('Proposal not found in the current exercise')
                if row['kind'] != actor:
                    raise PermissionError('SOC approves alert changes; GRC approves risk changes')
                desired = 'approved' if decision == 'approve' else 'rejected'
                if row['status'] == desired:
                    return {'proposal_id': proposal_id, 'status': desired, 'already_applied': True,
                            'demo_records_written': 0, 'external_writes': False}
                if row['status'] != 'pending':
                    raise ConflictError('This proposal is already reviewed or stale; refresh the dashboard')
                payload = json.loads(row['payload_json'])
                now = utc_now()
                targets = []
                if decision == 'approve' and actor == 'soc':
                    for change in payload['changes']:
                        target = db.execute('SELECT current_priority,version FROM demo_alerts WHERE exercise_id=? AND event_id=?',
                                            (eid, change['event_id'])).fetchone()
                        if not target or target['version'] != change['version'] or target['current_priority'] != change['before']:
                            conflict = 'Alert state changed after analysis; this proposal is stale'
                            break
                        targets.append(change)
                elif decision == 'approve':
                    target = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND risk_id=?', (eid, payload['risk_id'])).fetchone()
                    if (not target or target['version'] != payload['expected_version']
                            or target['source_version'] != payload['source_version']
                            or target['current_likelihood'] != payload['before']['likelihood']
                            or target['impact'] != payload['before']['impact']):
                        conflict = 'Risk register changed after analysis; this proposal is stale'
                if conflict:
                    desired = 'stale'
                elif decision == 'approve' and actor == 'soc':
                    for change in targets:
                        db.execute('''UPDATE demo_alerts SET current_priority=?,version=version+1,
                                   updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND event_id=?''',
                                   (change['after'], now, actor, proposal_id, eid, change['event_id']))
                        self._change(db, eid, proposal_id, 'alert', change['event_id'],
                                     {'priority': change['before'], 'version': change['version']},
                                     {'priority': change['after'], 'version': change['version']+1}, actor, reason.strip(), now)
                elif decision == 'approve':
                    db.execute('''UPDATE demo_risks SET current_likelihood=?,version=version+1,
                               updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND risk_id=?''',
                               (payload['after']['likelihood'], now, actor, proposal_id, eid, payload['risk_id']))
                    self._change(db, eid, proposal_id, 'risk', payload['risk_id'],
                                 {**payload['before'], 'version': payload['expected_version']},
                                 {**payload['after'], 'version': payload['expected_version']+1}, actor, reason.strip(), now)
                    # One evidence batch cannot repeatedly increase the same risk.
                    db.execute('''UPDATE demo_proposals SET status='stale',reason=?,reviewed_at=?
                               WHERE exercise_id=? AND kind='grc' AND target_id=? AND status='pending'
                               AND proposal_id<>?''',
                               ('Superseded by an approved change to the same risk; new evidence is required.',
                                now, eid, payload['risk_id'], proposal_id))
                db.execute('UPDATE demo_proposals SET status=?,reason=?,reviewed_by=?,reviewed_at=? WHERE proposal_id=?',
                           (desired, conflict or reason.strip(), actor, now, proposal_id))
                written = 0 if conflict or decision == 'reject' else len(targets) if actor == 'soc' else 1
                self.store.audit(db, actor, 'demo_' + desired, proposal_id,
                                 {'exercise_id': eid, 'kind': actor, 'demo_records_written': written,
                                  'reason': conflict or reason.strip(), 'external_writes': False,
                                  'security_control_execution': False})
            if conflict:
                raise ConflictError(conflict)
        return {'proposal_id': proposal_id, 'status': desired, 'already_applied': False,
                'demo_records_written': written, 'external_writes': False, 'security_control_execution': False}

    @staticmethod
    def _change(db, eid, proposal, kind, target, before, after, actor, reason, at):
        db.execute('''INSERT INTO demo_changes
                   (exercise_id,proposal_id,target_kind,target_id,before_json,after_json,actor,reason,changed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)''', (eid, proposal, kind, target, encoded(before), encoded(after), actor, reason, at))

    def changes(self, actor):
        require(actor, 'admin', 'soc', 'grc')
        with self.store.connection() as db:
            eid = self.current(db)
            where, params = 'exercise_id=?', [eid]
            if actor != 'admin':
                where += ' AND target_kind=?'
                params.append('alert' if actor == 'soc' else 'risk')
            rows = db.execute(f'SELECT * FROM demo_changes WHERE {where} ORDER BY sequence DESC LIMIT 100', params).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item['before'] = json.loads(item.pop('before_json'))
            item['after'] = json.loads(item.pop('after_json'))
            items.append(item)
        return {'exercise_id': eid, 'items': items}

    def audit(self, actor):
        require(actor, 'admin')
        return self.store.audit_events(200)

    def export_risks(self, actor):
        require(actor, 'admin', 'grc')
        with self.store.connection() as db:
            eid = self.current(db)
            rows = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? ORDER BY risk_id', (eid,)).fetchall()
        records = []
        for row in rows:
            record = json.loads(row['source_json'])
            record['likelihood'] = row['current_likelihood']
            if row['version'] > 1:
                record['risk_version_id'] += '-DEMO-REV' + str(row['version'])
                record['valid_from'] = row['updated_at']
                record['recorded_at'] = row['updated_at']
            record['demo_approval'] = {'revision': row['version'], 'updated_by': row['updated_by'],
                                       'updated_at': row['updated_at'], 'proposal_id': row['last_proposal_id']}
            records.append(record)
        return {'schema_version': 'iris-risk-register-v1', 'data_provenance': 'synthetic',
                'demo_only': True, 'exercise_id': eid,
                'notice': 'Current simulated GRC system state. Approved demo revisions, not an official company register.',
                'records': records}

    def export_alerts(self, actor):
        require(actor, 'admin', 'soc')
        with self.store.connection() as db:
            eid = self.current(db)
            rows = db.execute('''SELECT event_id,asset_id,hostname,event_time,baseline_priority,
                              current_priority,version,updated_by,updated_at,last_proposal_id
                              FROM demo_alerts WHERE exercise_id=? ORDER BY event_id''', (eid,)).fetchall()
        return {'data_provenance': 'synthetic', 'demo_only': True, 'exercise_id': eid,
                'notice': 'Current simulated SOC priority state; not a raw SIEM source export.',
                'records': [dict(row) for row in rows]}
