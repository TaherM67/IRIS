# IRIS EXPLAIN: File purpose: Active synthetic-system adapter: keeps immutable analysis evidence while applying separately
# IRIS EXPLAIN: approved, version-checked changes to working demo SOC/GRC records.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Real local writes to synthetic SOC/GRC records, never to external systems.

Analysis uses backend.core.Engine and the pinned Colab models unchanged. Human
approvals execute explicit policy proposals against separately versioned demo
tables. Immutable model evidence and original input files are never rewritten.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import threading to coordinate the batch/approval lock or run a local HTTP test server.
import threading
# IRIS EXPLAIN: Import uuid to generate independent run, case-proposal and exercise identities.
import uuid
# IRIS EXPLAIN: Import Counter from collections to count values and build efficient grouping/history containers.
from collections import Counter
# IRIS EXPLAIN: Import contextmanager from contextlib to manage connection/lifespan/lock cleanup reliably.
from contextlib import contextmanager
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import ROOT, Settings from backend.config to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from backend.config import ROOT, Settings
# IRIS EXPLAIN: Import BusyError, Engine, INPUTS from backend.core to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from backend.core import BusyError, Engine, INPUTS
# IRIS EXPLAIN: Import digest, utc_now from backend.model_adapter to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from backend.model_adapter import digest, utc_now
# IRIS EXPLAIN: Import encoded from backend.storage to reuse the shared project contract/implementation rather than duplicate
# IRIS EXPLAIN: it.
from backend.storage import encoded
# IRIS EXPLAIN: Import integrate from iris_models.three_sources to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from iris_models.three_sources import integrate
# IRIS EXPLAIN: Import timestamp from iris_models.telemetry to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from iris_models.telemetry import timestamp

# IRIS EXPLAIN: Store the computed value ROOT / 'demo' / 'data' in DATA; later lines use this named result.
DATA = ROOT / 'demo' / 'data'
# IRIS EXPLAIN: Store ('Low', 'Medium', 'High', 'Critical') in PRIORITIES; later lines use this named result.
PRIORITIES = ('Low', 'Medium', 'High', 'Critical')
# IRIS EXPLAIN: Store 'IRIS_SYNTHETIC_ACTIVE_DEMO_V1' in MARKER; later lines use this named result.
MARKER = 'IRIS_SYNTHETIC_ACTIVE_DEMO_V1'


# IRIS EXPLAIN: Class ConflictError: Marker exception for a proposal whose saved expectations no longer match the target state.
class ConflictError(ValueError):
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """The saved proposal no longer matches the target version."""


# IRIS EXPLAIN: Function require: Require an authenticated actor role from the allowed set; callers cannot approve another
# IRIS EXPLAIN: team's changes.
# IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; roles: the explicit
# IRIS EXPLAIN: allowlisted role names for this operation.
def require(actor, *roles):
    # IRIS EXPLAIN: Enter this branch only when actor not in roles.
    if actor not in roles:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising PermissionError('This action requires the ' + ' or
        # IRIS EXPLAIN: '.join(roles).upper() + ' role'); the caller's existing boundary determines rollback or the HTTP
        # IRIS EXPLAIN: diagnostic.
        raise PermissionError('This action requires the ' + ' or '.join(roles).upper() + ' role')


# IRIS EXPLAIN: Function technical_priority: Map original SIEM rule severity to the prototype technical bands before business
# IRIS EXPLAIN: criticality is considered.
# IRIS EXPLAIN: Inputs: level: observed SIEM severity on the existing 0-16 scale.
def technical_priority(level):
    # Same technical severity bands as backend.policy, before business context.
    # IRIS EXPLAIN: Store the computed value level * 10 / 16 in severity; later lines use this named result.
    severity = level * 10 / 16
    # IRIS EXPLAIN: Return 'Low' when severity < 3; otherwise 'Medium' when severity < 6; otherwise 'High' when severity < 8;
    # IRIS EXPLAIN: otherwise 'Critical' to the caller; this ends the current function path.
    return 'Low' if severity < 3 else 'Medium' if severity < 6 else 'High' if severity < 8 else 'Critical'


# IRIS EXPLAIN: Class DemoEngine: Isolated synthetic working systems plus human-approval coordinator, reusing the unchanged
# IRIS EXPLAIN: shared model engine.
class DemoEngine:
    # IRIS EXPLAIN: Function DemoEngine.__init__: Verify the bundled synthetic data, open the shared real ML core and isolated
    # IRIS EXPLAIN: demo schema, and create an initial rehearsal only if none exists.
    # IRIS EXPLAIN: Inputs: settings: validated local credentials, state path and processing bounds; data_dir: bundled synthetic
    # IRIS EXPLAIN: input directory used by the isolated demo; adapter: optional existing trusted model adapter, reused by tests
    # IRIS EXPLAIN: rather than retrained.
    def __init__(self, settings: Settings, *, data_dir: Path = DATA, adapter=None):
        # IRIS EXPLAIN: Store (settings, Path(data_dir)) in (self.settings, self.data_dir); later lines use this named result.
        self.settings, self.data_dir = settings, Path(data_dir)
        # IRIS EXPLAIN: Store the comprehension {key: self.data_dir / name for key, name in INPUTS.items()} in self.inputs;
        # IRIS EXPLAIN: later lines use this named result.
        self.inputs = {key: self.data_dir / name for key, name in INPUTS.items()}
        # IRIS EXPLAIN: Store the result of json.loads((self.data_dir / 'demo_manifest.json').read_text(encoding='utf-8'))
        # IRIS EXPLAIN: (decode the existing JSON text) in self.manifest; later lines use this named result.
        self.manifest = json.loads((self.data_dir / 'demo_manifest.json').read_text(encoding='utf-8'))
        # IRIS EXPLAIN: Call self.check_inputs() using the existing explicit arguments.
        self.check_inputs()
        # IRIS EXPLAIN: Store the result of Engine(settings, adapter) in self.core; later lines use this named result.
        self.core = Engine(settings, adapter)
        # IRIS EXPLAIN: Store self.core.store in self.store; later lines use this named result.
        self.store = self.core.store
        # IRIS EXPLAIN: Store the result of threading.Lock() in self.lock; later lines use this named result.
        self.lock = threading.Lock()
        # IRIS EXPLAIN: Call self._schema() using the existing explicit arguments.
        self._schema()
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of db.execute("SELECT value FROM demo_meta WHERE name='marker'").fetchone() (read
            # IRIS EXPLAIN: one database result row) in marker; later lines use this named result.
            marker = db.execute("SELECT value FROM demo_meta WHERE name='marker'").fetchone()
            # IRIS EXPLAIN: Store the result of db.execute("SELECT value FROM demo_meta WHERE name='source_hashes'").fetchone()
            # IRIS EXPLAIN: (read one database result row) in saved; later lines use this named result.
            saved = db.execute("SELECT value FROM demo_meta WHERE name='source_hashes'").fetchone()
            # IRIS EXPLAIN: Store the result of db.execute("SELECT value FROM demo_meta WHERE
            # IRIS EXPLAIN: name='current_exercise'").fetchone() (read one database result row) in current; later lines use this
            # IRIS EXPLAIN: named result.
            current = db.execute("SELECT value FROM demo_meta WHERE name='current_exercise'").fetchone()
            # IRIS EXPLAIN: Enter this branch only when marker and marker[0] != MARKER.
            if marker and marker[0] != MARKER:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Not an IRIS synthetic-demo
                # IRIS EXPLAIN: database'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError('Not an IRIS synthetic-demo database')
            # IRIS EXPLAIN: Enter this branch only when saved and saved[0] != encoded(self.source_hashes).
            if saved and saved[0] != encoded(self.source_hashes):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Demo source identity changed;
                # IRIS EXPLAIN: do not mix exercises with different sources'); the caller's existing boundary determines
                # IRIS EXPLAIN: rollback or the HTTP diagnostic.
                raise ValueError('Demo source identity changed; do not mix exercises with different sources')
        # IRIS EXPLAIN: Enter this branch only when not current.
        if not current:
            # IRIS EXPLAIN: Call self.new_exercise('admin', 'Initial examiner demonstration') using the existing explicit
            # IRIS EXPLAIN: arguments.
            self.new_exercise('admin', 'Initial examiner demonstration')

    # IRIS EXPLAIN: Function DemoEngine.check_inputs: Require the bundled synthetic provenance and exact three source hashes;
    # IRIS EXPLAIN: reject altered or substituted input bytes.
    def check_inputs(self):
        # IRIS EXPLAIN: Enter this branch only when self.manifest.get('data_provenance') != 'synthetic'.
        if self.manifest.get('data_provenance') != 'synthetic':
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('The active demo accepts only the
            # IRIS EXPLAIN: bundled synthetic inputs'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError('The active demo accepts only the bundled synthetic inputs')
        # IRIS EXPLAIN: Store the comprehension {item['upload_field']: item['sha256'] for item in self.manifest['inputs']} in
        # IRIS EXPLAIN: expected; later lines use this named result.
        expected = {item['upload_field']: item['sha256'] for item in self.manifest['inputs']}
        # IRIS EXPLAIN: Store the comprehension {key: digest(path) for key, path in self.inputs.items()} in self.source_hashes;
        # IRIS EXPLAIN: later lines use this named result.
        self.source_hashes = {key: digest(path) for key, path in self.inputs.items()}
        # IRIS EXPLAIN: Enter this branch only when self.source_hashes != expected.
        if self.source_hashes != expected:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Demo dataset checksum mismatch;
            # IRIS EXPLAIN: restore the bundled three inputs'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError('Demo dataset checksum mismatch; restore the bundled three inputs')

    # IRIS EXPLAIN: Function DemoEngine._schema: Create separate demo working-record/proposal/change tables and indexes without
    # IRIS EXPLAIN: rewriting the immutable analysis tables.
    def _schema(self):
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Call db.executescript('\n CREATE TABLE IF NOT EXISTS demo_meta (name TEXT PRIMARY KEY, value TEXT
            # IRIS EXPLAIN: NOT NULL);\n CREATE TABLE IF NOT EXISTS demo_exercises (\n exerc...: initialize the declared SQL
            # IRIS EXPLAIN: schema.
            # IRIS EXPLAIN: Original embedded-text line 75: SQL: declare the demo_meta table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 76: SQL: declare the demo_exercises table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 77: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 78: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 79: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 80: SQL: declare the demo_risks table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 81: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 82: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 83: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 84: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 85: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 86: SQL: update only the named table/fields; the following placeholders
            # IRIS EXPLAIN: and WHERE clause bind the allowed targets.
            # IRIS EXPLAIN: Original embedded-text line 87: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 88: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 89: SQL: declare the demo_alerts table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 90: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 91: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 92: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 93: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 94: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 95: SQL: update only the named table/fields; the following placeholders
            # IRIS EXPLAIN: and WHERE clause bind the allowed targets.
            # IRIS EXPLAIN: Original embedded-text line 96: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 97: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 98: SQL: declare the demo_proposals table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 99: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 100: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 101: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 102: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 103: SQL: retain the stated column definitions, revision fields, or
            # IRIS EXPLAIN: query conditions.
            # IRIS EXPLAIN: Original embedded-text line 104: SQL: retain the stated column definitions, revision fields, or
            # IRIS EXPLAIN: query conditions.
            # IRIS EXPLAIN: Original embedded-text line 105: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 106: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 107: SQL: declare the demo_changes table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 108: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 109: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 110: SQL: keep the stated parent-record foreign-key relationship.
            # IRIS EXPLAIN: Original embedded-text line 111: SQL: retain the stated column definitions, revision fields, or
            # IRIS EXPLAIN: query conditions.
            # IRIS EXPLAIN: Original embedded-text line 112: SQL: retain the stated column definitions, revision fields, or
            # IRIS EXPLAIN: query conditions.
            # IRIS EXPLAIN: Original embedded-text line 113: SQL: retain the stated column definitions, revision fields, or
            # IRIS EXPLAIN: query conditions.
            # IRIS EXPLAIN: Original embedded-text line 114: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 115: SQL: define the existing lookup/uniqueness index for this table and
            # IRIS EXPLAIN: condition.
            # IRIS EXPLAIN: Original embedded-text line 116: SQL: define the existing lookup/uniqueness index for this table and
            # IRIS EXPLAIN: condition.
            # IRIS EXPLAIN: Original embedded-text line 117: SQL: close the table/query statement exactly as originally written.
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

    # IRIS EXPLAIN: Turn the following yield-based function into a context manager so its existing cleanup runs on exit.
    @contextmanager
    # IRIS EXPLAIN: Function DemoEngine.mutation: Serialize active demo mutations with a nonblocking lock and always release it,
    # IRIS EXPLAIN: including on failures.
    def mutation(self):
        # IRIS EXPLAIN: Enter this branch only when not self.lock.acquire(blocking=False).
        if not self.lock.acquire(blocking=False):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising BusyError('The demo is processing another
            # IRIS EXPLAIN: action; wait and refresh'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise BusyError('The demo is processing another action; wait and refresh')
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Yield control/value to the existing context/lifespan consumer; execution resumes here for the
            # IRIS EXPLAIN: declared cleanup when the consumer finishes.
            yield
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call self.lock.release(): release the acquired lock.
            self.lock.release()

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function DemoEngine.current: Read the current rehearsal identifier from demo metadata, rejecting an
    # IRIS EXPLAIN: uninitialized state.
    # IRIS EXPLAIN: Inputs: db: the caller-owned SQLite transaction.
    def current(db):
        # IRIS EXPLAIN: Store the result of db.execute("SELECT value FROM demo_meta WHERE name='current_exercise'").fetchone()
        # IRIS EXPLAIN: (read one database result row) in row; later lines use this named result.
        row = db.execute("SELECT value FROM demo_meta WHERE name='current_exercise'").fetchone()
        # IRIS EXPLAIN: Enter this branch only when not row.
        if not row:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('No current demonstration
            # IRIS EXPLAIN: exercise'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('No current demonstration exercise')
        # IRIS EXPLAIN: Return row[0] to the caller; this ends the current function path.
        return row[0]

    # IRIS EXPLAIN: Function DemoEngine.new_exercise: Admin-only: seed a new, isolated working risk register and alert queue
    # IRIS EXPLAIN: from the fixed synthetic inputs while preserving every earlier exercise and audit record.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; label: the
    # IRIS EXPLAIN: existing scenario/control label or human-readable rehearsal name in this context.
    def new_exercise(self, actor, label='Examiner demonstration'):
        # IRIS EXPLAIN: Call require(actor, 'admin') using the existing explicit arguments.
        require(actor, 'admin')
        # IRIS EXPLAIN: Enter this branch only when not isinstance(label, str) or not 3 <= len(label.strip()) <= 100.
        if not isinstance(label, str) or not 3 <= len(label.strip()) <= 100:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Exercise label must contain 3..100
            # IRIS EXPLAIN: characters'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('Exercise label must contain 3..100 characters')
        # IRIS EXPLAIN: Enter self.mutation(); its context manager supplies the existing cleanup/transaction/expected-exception
        # IRIS EXPLAIN: behavior.
        with self.mutation():
            # IRIS EXPLAIN: Call self.check_inputs() using the existing explicit arguments.
            self.check_inputs()
            # IRIS EXPLAIN: Store the result of integrate(**{'asset_path': self.inputs['asset_inventory'], 'risk_path':
            # IRIS EXPLAIN: self.inputs['risk_register'], 'aler... in (unified, _, report); later lines use this named result.
            unified, _, report = integrate(**{
                # IRIS EXPLAIN: Continue the current record with asset_path; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'asset_path': self.inputs['asset_inventory'],
                # IRIS EXPLAIN: Continue the current record with risk_path; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'risk_path': self.inputs['risk_register'],
                # IRIS EXPLAIN: Continue the current record with alerts_path; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'alerts_path': self.inputs['siem_alerts'],
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            }, window_seconds=60)
            # IRIS EXPLAIN: Store max((timestamp(event['timestamp']) for event in unified)) in at; later lines use this named
            # IRIS EXPLAIN: result.
            at = max(timestamp(event['timestamp']) for event in unified)
            # IRIS EXPLAIN: Store json.loads(self.inputs['asset_inventory'].read_text())['records'] in asset_rows; later lines
            # IRIS EXPLAIN: use this named result.
            asset_rows = json.loads(self.inputs['asset_inventory'].read_text())['records']
            # IRIS EXPLAIN: Store json.loads(self.inputs['risk_register'].read_text())['records'] in risk_rows; later lines use
            # IRIS EXPLAIN: this named result.
            risk_rows = json.loads(self.inputs['risk_register'].read_text())['records']
            # IRIS EXPLAIN: Function DemoEngine.valid: Check whether a snapshot is effective, unexpired and already recorded at
            # IRIS EXPLAIN: the selected demo event time.
            # IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence.
            def valid(row):
                # IRIS EXPLAIN: Return timestamp(row['valid_from']) <= at and timestamp(row['recorded_at']) <= at and (not
                # IRIS EXPLAIN: row['valid_to'] or at < timestamp(row['valid_to'])) to the caller; this ends the current
                # IRIS EXPLAIN: function path.
                return (timestamp(row['valid_from']) <= at and timestamp(row['recorded_at']) <= at
                        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                        # IRIS EXPLAIN: arguments/items: and (not row['valid_to'] or at < timestamp(row['valid_to']))).
                        and (not row['valid_to'] or at < timestamp(row['valid_to'])))
            # IRIS EXPLAIN: Store the comprehension {row['asset_id']: row for row in asset_rows if valid(row)} in assets; later
            # IRIS EXPLAIN: lines use this named result.
            assets = {row['asset_id']: row for row in asset_rows if valid(row)}
            # IRIS EXPLAIN: Store the comprehension [row for row in risk_rows if valid(row)] in risks; later lines use this
            # IRIS EXPLAIN: named result.
            risks = [row for row in risk_rows if valid(row)]
            # IRIS EXPLAIN: Enter this branch only when len(assets) != 30 or len(risks) != 60.
            if len(assets) != 30 or len(risks) != 60:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Unexpected current demo
                # IRIS EXPLAIN: inventory/register size'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError('Unexpected current demo inventory/register size')
            # IRIS EXPLAIN: Enter this branch only when any((event['data_provenance'] != 'synthetic' for event in unified)).
            if any(event['data_provenance'] != 'synthetic' for event in unified):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Only synthetic demonstration
                # IRIS EXPLAIN: events are allowed'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError('Only synthetic demonstration events are allowed')
            # IRIS EXPLAIN: Store ('DEMO-' + uuid.uuid4().hex[:16], utc_now()) in (eid, now); later lines use this named result.
            eid, now = 'DEMO-' + uuid.uuid4().hex[:16], utc_now()
            # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.store.connection() as db:
                # IRIS EXPLAIN: Call db.execute('BEGIN IMMEDIATE'): run the existing SQL with its separately supplied
                # IRIS EXPLAIN: parameters.
                db.execute('BEGIN IMMEDIATE')
                # IRIS EXPLAIN: Call db.execute('INSERT INTO demo_exercises VALUES (?,?,?,NULL,?)', (eid, label.strip(), now,
                # IRIS EXPLAIN: encoded({'seed_integration': report}))): run the existing SQL with its separately supplied
                # IRIS EXPLAIN: parameters.
                db.execute('INSERT INTO demo_exercises VALUES (?,?,?,NULL,?)',
                           # IRIS EXPLAIN: Continue the current record with seed_integration; each value comes from the
                           # IRIS EXPLAIN: expression shown on this unchanged line.
                           (eid, label.strip(), now, encoded({'seed_integration': report})))
                # IRIS EXPLAIN: Call db.executemany('INSERT INTO demo_risks VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)', [(eid,
                # IRIS EXPLAIN: risk['risk_id'], risk['asset_id'], assets[risk['asset_id']]['host...: run the existing
                # IRIS EXPLAIN: parameterized SQL for each supplied row.
                db.executemany('INSERT INTO demo_risks VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)', [
                    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                    # IRIS EXPLAIN: arguments/items: (eid, risk['risk_id'], risk['asset_id'],
                    # IRIS EXPLAIN: assets[risk['asset_id']]['hostname'],.
                    (eid, risk['risk_id'], risk['asset_id'], assets[risk['asset_id']]['hostname'],
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: risk['risk_version_id'], encoded(risk), risk['likelihood'],
                     # IRIS EXPLAIN: risk['likelihood'], risk['impact'], 1).
                     risk['risk_version_id'], encoded(risk), risk['likelihood'], risk['likelihood'], risk['impact'], 1)
                    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                    # IRIS EXPLAIN: arguments/items: for risk in risks.
                    for risk in risks
                # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
                # IRIS EXPLAIN: unchanged.
                ])
                # IRIS EXPLAIN: Call db.executemany('INSERT INTO demo_alerts VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)',
                # IRIS EXPLAIN: [(eid, event['event_id'], event['asset']['asset_id'], event['asset']...: run the existing
                # IRIS EXPLAIN: parameterized SQL for each supplied row.
                db.executemany('INSERT INTO demo_alerts VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)', [
                    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                    # IRIS EXPLAIN: arguments/items: (eid, event['event_id'], event['asset']['asset_id'],
                    # IRIS EXPLAIN: event['asset']['hostname'],.
                    (eid, event['event_id'], event['asset']['asset_id'], event['asset']['hostname'],
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: event['timestamp'], event['alert']['level'],
                     # IRIS EXPLAIN: technical_priority(event['alert']['level']),.
                     event['timestamp'], event['alert']['level'], technical_priority(event['alert']['level']),
                     # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                     # IRIS EXPLAIN: arguments/items: technical_priority(event['alert']['level']), 1).
                     technical_priority(event['alert']['level']), 1)
                    # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                    # IRIS EXPLAIN: arguments/items: for event in unified if event['asset'] is not None.
                    for event in unified if event['asset'] is not None
                # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
                # IRIS EXPLAIN: unchanged.
                ])
                # IRIS EXPLAIN: Iterate {'marker': MARKER, 'source_hashes': encoded(self.source_hashes), 'current_exercise':
                # IRIS EXPLAIN: eid}.items(), binding each item to (name, value); process only the existing observed/fixture
                # IRIS EXPLAIN: collection.
                for name, value in {'marker': MARKER, 'source_hashes': encoded(self.source_hashes), 'current_exercise': eid}.items():
                    # IRIS EXPLAIN: Call db.execute('INSERT INTO demo_meta VALUES (?,?) ON CONFLICT(name) DO UPDATE SET
                    # IRIS EXPLAIN: value=excluded.value', (name, value)): run the existing SQL with its separately supplied
                    # IRIS EXPLAIN: parameters.
                    db.execute('INSERT INTO demo_meta VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', (name, value))
                # IRIS EXPLAIN: Call self.store.audit(db, actor, 'demo_exercise_created', eid, {'label': label.strip(),
                # IRIS EXPLAIN: 'synthetic_only': True, 'previous_exercises_preserved': True}) using the existing explicit
                # IRIS EXPLAIN: arguments.
                self.store.audit(db, actor, 'demo_exercise_created', eid,
                                 # IRIS EXPLAIN: Continue the current record with label, synthetic_only,
                                 # IRIS EXPLAIN: previous_exercises_preserved; each value comes from the expression shown on
                                 # IRIS EXPLAIN: this unchanged line.
                                 {'label': label.strip(), 'synthetic_only': True, 'previous_exercises_preserved': True})
            # IRIS EXPLAIN: Return a mapping containing exercise_id, status, previous_exercises_preserved to the caller; this
            # IRIS EXPLAIN: ends the current function path.
            return {'exercise_id': eid, 'status': 'seeded', 'previous_exercises_preserved': True}

    # IRIS EXPLAIN: Function DemoEngine.analyze: Run/reuse the actual shared model analysis, associate working alerts with cases
    # IRIS EXPLAIN: and queue explicit-policy proposals; analysis alone does not mutate current risk or priority values.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def analyze(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc') using the existing explicit arguments.
        require(actor, 'admin', 'soc')
        # IRIS EXPLAIN: Enter self.mutation(); its context manager supplies the existing cleanup/transaction/expected-exception
        # IRIS EXPLAIN: behavior.
        with self.mutation():
            # IRIS EXPLAIN: Call self.check_inputs() using the existing explicit arguments.
            self.check_inputs()
            # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.store.connection() as db:
                # IRIS EXPLAIN: Store the result of self.current(db) in exercise; later lines use this named result.
                exercise = self.current(db)
            # IRIS EXPLAIN: Store the result of self.core.run(self.inputs, actor) in summary; later lines use this named result.
            summary = self.core.run(self.inputs, actor)
            # IRIS EXPLAIN: Store self.store.cases(run_id=summary['run_id'], limit=2000)['items'] in cases; later lines use this
            # IRIS EXPLAIN: named result.
            cases = self.store.cases(run_id=summary['run_id'], limit=2000)['items']
            # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.store.connection() as db:
                # IRIS EXPLAIN: Call db.execute('BEGIN IMMEDIATE'): run the existing SQL with its separately supplied
                # IRIS EXPLAIN: parameters.
                db.execute('BEGIN IMMEDIATE')
                # IRIS EXPLAIN: Iterate cases, binding each item to case; process only the existing observed/fixture collection.
                for case in cases:
                    # IRIS EXPLAIN: Store (case['session'], case['prediction'], case['risk_review']) in (session, prediction,
                    # IRIS EXPLAIN: policy); later lines use this named result.
                    session, prediction, policy = case['session'], case['prediction'], case['risk_review']
                    # IRIS EXPLAIN: Call db.executemany('UPDATE demo_alerts SET case_id=? WHERE exercise_id=? AND event_id=?',
                    # IRIS EXPLAIN: [(case['case_id'], exercise, event_id) for event_id in session['source_...: run the existing
                    # IRIS EXPLAIN: parameterized SQL for each supplied row.
                    db.executemany('UPDATE demo_alerts SET case_id=? WHERE exercise_id=? AND event_id=?',
                                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                   # IRIS EXPLAIN: existing arguments/items: [(case['case_id'], exercise, event_id) for event_id
                                   # IRIS EXPLAIN: in session['source_event_ids']]).
                                   [(case['case_id'], exercise, event_id) for event_id in session['source_event_ids']])
                    # IRIS EXPLAIN: Store prediction['shadow_candidate'] in shadow; later lines use this named result.
                    shadow = prediction['shadow_candidate']
                    # IRIS EXPLAIN: Store a mapping containing hostname, asset_id, asset_criticality, session_id, session_time,
                    # IRIS EXPLAIN: primary_assessment, policy and additional fields in evidence; later lines use this named
                    # IRIS EXPLAIN: result.
                    evidence = {
                        # IRIS EXPLAIN: Set/describe these existing record fields: asset_id: exact target-asset identity; not an
                        # IRIS EXPLAIN: attacker source-IP guess.
                        'hostname': session['asset_snapshot']['hostname'], 'asset_id': session['asset_id'],
                        # IRIS EXPLAIN: Set/describe these existing record fields: asset_criticality: pre-decision business
                        # IRIS EXPLAIN: criticality on the existing 1-5 scale; not a Model 1 telemetry input.
                        'asset_criticality': session['asset_snapshot']['criticality'],
                        # IRIS EXPLAIN: Set/describe these existing record fields: session_id: deterministic observed session
                        # IRIS EXPLAIN: identity linking evidence to separate reviews/cases.
                        'session_id': session['session_id'], 'session_time': session['start_utc'],
                        # IRIS EXPLAIN: Continue the current record with primary_assessment, policy; each value comes from the
                        # IRIS EXPLAIN: expression shown on this unchanged line.
                        'primary_assessment': prediction['soc_assessment'], 'policy': policy,
                        # IRIS EXPLAIN: Continue the current record with features, primary_controls; each value comes from the
                        # IRIS EXPLAIN: expression shown on this unchanged line.
                        'features': session['features'], 'primary_controls': case['primary_controls'],
                        # IRIS EXPLAIN: Set/describe these existing record fields: confidence: scenario classifier confidence;
                        # IRIS EXPLAIN: not control effectiveness or a risk-reduction estimate.
                        'ml_shadow': ({'scenario': shadow['scenario_class'], 'confidence': shadow['confidence'],
                                       # IRIS EXPLAIN: Set/describe these existing record fields: status: the stated
                                       # IRIS EXPLAIN: assessment/proposal/run state; an abstention must not be relabeled
                                       # IRIS EXPLAIN: benign; controls: control implementation context or separately identified
                                       # IRIS EXPLAIN: recommendations; labels remain offline-only targets.
                                       'status': shadow['status'], 'controls': shadow['controls']}
                                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                      # IRIS EXPLAIN: existing arguments/items: if shadow else None),.
                                      if shadow else None),
                        # IRIS EXPLAIN: Continue the current record with warnings; each value comes from the expression shown on
                        # IRIS EXPLAIN: this unchanged line.
                        'warnings': prediction['warnings'],
                        # IRIS EXPLAIN: Continue the current record with decision_basis; each value comes from the expression
                        # IRIS EXPLAIN: shown on this unchanged line.
                        'decision_basis': 'Versioned primary rules and explicit business-risk policy; ML remains an unreleased shadow comparison.',
                    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain
                    # IRIS EXPLAIN: remain unchanged.
                    }
                    # IRIS EXPLAIN: Enter this branch only when policy['priority'] in PRIORITIES and
                    # IRIS EXPLAIN: prediction['soc_assessment']['status'] == 'ASSESSED'.
                    if policy['priority'] in PRIORITIES and prediction['soc_assessment']['status'] == 'ASSESSED':
                        # IRIS EXPLAIN: Store the result of db.execute('SELECT event_id,current_priority,version FROM
                        # IRIS EXPLAIN: demo_alerts WHERE exercise_id=? AND case_id=?', (exercise, case['case_id']... (read all
                        # IRIS EXPLAIN: rows returned by this bounded query) in alerts; later lines use this named result.
                        alerts = db.execute('SELECT event_id,current_priority,version FROM demo_alerts WHERE exercise_id=? AND case_id=?',
                                            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                            # IRIS EXPLAIN: these existing arguments/items: (exercise,
                                            # IRIS EXPLAIN: case['case_id'])).fetchall().
                                            (exercise, case['case_id'])).fetchall()
                        # IRIS EXPLAIN: Store the comprehension [{'event_id': row['event_id'], 'before':
                        # IRIS EXPLAIN: row['current_priority'], 'version': row['version'], 'after': policy['priority']} for row
                        # IRIS EXPLAIN: in alerts if row['current_priority'] != po... in changes; later lines use this named
                        # IRIS EXPLAIN: result.
                        changes = [{'event_id': row['event_id'], 'before': row['current_priority'],
                                    # IRIS EXPLAIN: Set/describe these existing record fields: version: record revision or
                                    # IRIS EXPLAIN: declared package identity used for traceability/stale-update checks.
                                    'version': row['version'], 'after': policy['priority']}
                                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                   # IRIS EXPLAIN: existing arguments/items: for row in alerts if row['current_priority'] !=
                                   # IRIS EXPLAIN: policy['priority']].
                                   for row in alerts if row['current_priority'] != policy['priority']]
                        # IRIS EXPLAIN: Enter this branch only when changes.
                        if changes:
                            # IRIS EXPLAIN: Call self._proposal(db, exercise, case, 'soc', None, {'evidence': evidence,
                            # IRIS EXPLAIN: 'new_priority': policy['priority'], 'changes': changes, 'before_counts':
                            # IRIS EXPLAIN: dict(Counter(... using the existing explicit arguments.
                            self._proposal(db, exercise, case, 'soc', None, {
                                # IRIS EXPLAIN: Continue the current record with evidence, new_priority, changes; each value
                                # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                'evidence': evidence, 'new_priority': policy['priority'], 'changes': changes,
                                # IRIS EXPLAIN: Continue the current record with before_counts; each value comes from the
                                # IRIS EXPLAIN: expression shown on this unchanged line.
                                'before_counts': dict(Counter(row['before'] for row in changes)),
                                # IRIS EXPLAIN: Continue the current record with changed_alerts; each value comes from the
                                # IRIS EXPLAIN: expression shown on this unchanged line.
                                'changed_alerts': len(changes),
                            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call
                            # IRIS EXPLAIN: chain remain unchanged.
                            })
                    # IRIS EXPLAIN: Enter this branch only when policy['mapping_status'] == 'MATCHED'.
                    if policy['mapping_status'] == 'MATCHED':
                        # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND
                        # IRIS EXPLAIN: risk_id=?', (exercise, policy['matched_risk_id'])).fetchone() (read one database result
                        # IRIS EXPLAIN: row) in risk; later lines use this named result.
                        risk = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND risk_id=?',
                                          # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                          # IRIS EXPLAIN: these existing arguments/items: (exercise,
                                          # IRIS EXPLAIN: policy['matched_risk_id'])).fetchone().
                                          (exercise, policy['matched_risk_id'])).fetchone()
                        # IRIS EXPLAIN: Enter this branch only when risk and risk['source_version'] ==
                        # IRIS EXPLAIN: policy['matched_risk_version_id'] and (policy['proposed_likelihood'] >
                        # IRIS EXPLAIN: risk['baseline_likelihood']).
                        if (risk and risk['source_version'] == policy['matched_risk_version_id']
                                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                                # IRIS EXPLAIN: arguments/items: and policy['proposed_likelihood'] >
                                # IRIS EXPLAIN: risk['baseline_likelihood']):.
                                and policy['proposed_likelihood'] > risk['baseline_likelihood']):
                            # IRIS EXPLAIN: Call self._proposal(db, exercise, case, 'grc', risk['risk_id'], {'evidence':
                            # IRIS EXPLAIN: evidence, 'risk_id': risk['risk_id'], 'expected_version': 1, 'source_version':
                            # IRIS EXPLAIN: risk['... using the existing explicit arguments.
                            self._proposal(db, exercise, case, 'grc', risk['risk_id'], {
                                # IRIS EXPLAIN: Set/describe these existing record fields: risk_id: exact registered-risk
                                # IRIS EXPLAIN: identity; expected_version: saved working-record revision required before an
                                # IRIS EXPLAIN: approval can apply.
                                'evidence': evidence, 'risk_id': risk['risk_id'], 'expected_version': 1,
                                # IRIS EXPLAIN: Set/describe these existing record fields: source_version: original
                                # IRIS EXPLAIN: registered-risk version used to detect stale proposals.
                                'source_version': risk['source_version'],
                                # IRIS EXPLAIN: Set/describe these existing record fields: likelihood: the stored or explicitly
                                # IRIS EXPLAIN: proposed 1-5 likelihood in this record, not an invented ML risk probability;
                                # IRIS EXPLAIN: impact: the same registered risk's impact; it must not be independently
                                # IRIS EXPLAIN: maximized across risks.
                                'before': {'likelihood': risk['baseline_likelihood'], 'impact': risk['impact'],
                                           # IRIS EXPLAIN: Continue the current record with score; each value comes from the
                                           # IRIS EXPLAIN: expression shown on this unchanged line.
                                           'score': round(risk['baseline_likelihood'] * risk['impact'] / 25, 4)},
                                # IRIS EXPLAIN: Set/describe these existing record fields: likelihood: the stored or explicitly
                                # IRIS EXPLAIN: proposed 1-5 likelihood in this record, not an invented ML risk probability;
                                # IRIS EXPLAIN: impact: the same registered risk's impact; it must not be independently
                                # IRIS EXPLAIN: maximized across risks.
                                'after': {'likelihood': policy['proposed_likelihood'], 'impact': risk['impact'],
                                          # IRIS EXPLAIN: Continue the current record with score; each value comes from the
                                          # IRIS EXPLAIN: expression shown on this unchanged line.
                                          'score': policy['proposed_risk_0_1']},
                            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call
                            # IRIS EXPLAIN: chain remain unchanged.
                            })
                # IRIS EXPLAIN: Call db.execute('UPDATE demo_exercises SET run_id=?,summary_json=? WHERE exercise_id=?',
                # IRIS EXPLAIN: (summary['run_id'], encoded(summary), exercise)): run the existing SQL with its separately
                # IRIS EXPLAIN: supplied parameters.
                db.execute('UPDATE demo_exercises SET run_id=?,summary_json=? WHERE exercise_id=?',
                           # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                           # IRIS EXPLAIN: arguments/items: (summary['run_id'], encoded(summary), exercise)).
                           (summary['run_id'], encoded(summary), exercise))
                # IRIS EXPLAIN: Call self.store.audit(db, actor, 'demo_analysis_ready', exercise, {'run_id': summary['run_id'],
                # IRIS EXPLAIN: 'sessions': summary['sessions'], 'demo_records_changed_by_analysis... using the existing
                # IRIS EXPLAIN: explicit arguments.
                self.store.audit(db, actor, 'demo_analysis_ready', exercise,
                                 # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance
                                 # IRIS EXPLAIN: retained for traceability; not a hidden attack-label feature.
                                 {'run_id': summary['run_id'], 'sessions': summary['sessions'],
                                  # IRIS EXPLAIN: Set/describe these existing record fields: model_sha256: content identity of
                                  # IRIS EXPLAIN: the saved trusted model bundle.
                                  'demo_records_changed_by_analysis': False, 'model_sha256': summary['model_sha256']})
            # IRIS EXPLAIN: Return a mapping containing exercise_id, demo_records_changed_by_analysis to the caller; this ends
            # IRIS EXPLAIN: the current function path.
            return {'exercise_id': exercise, **summary, 'demo_records_changed_by_analysis': False}

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function DemoEngine._proposal: Insert one pending SOC/GRC proposal per case and rehearsal without
    # IRIS EXPLAIN: overwriting an earlier review.
    # IRIS EXPLAIN: Inputs: db: the caller-owned SQLite transaction; exercise: the current isolated rehearsal identity; case:
    # IRIS EXPLAIN: the explicit case input used by the unchanged statements below; kind: the existing SOC/GRC or alert/risk
    # IRIS EXPLAIN: target category; target: the saved record identity, never a caller-selected arbitrary update path; payload:
    # IRIS EXPLAIN: the saved finite JSON evidence/proposal payload.
    def _proposal(db, exercise, case, kind, target, payload):
        # IRIS EXPLAIN: Call db.execute("INSERT OR IGNORE INTO demo_proposals\n
        # IRIS EXPLAIN: (proposal_id,exercise_id,case_id,kind,target_id,payload_json,status)\n VALUES (?,?,?,?,?,?,'pending')",
        # IRIS EXPLAIN: ('...: run the existing SQL with its separately supplied parameters.
        # IRIS EXPLAIN: Original embedded-text line 242: Embedded text:
        # IRIS EXPLAIN: (proposal_id,exercise_id,case_id,kind,target_id,payload_json,status); kept as literal data, not a Python
        # IRIS EXPLAIN: comment inside the string.
        # IRIS EXPLAIN: Original embedded-text line 243: SQL: bind the already constructed parameter values; do not interpolate
        # IRIS EXPLAIN: an untrusted priority, role or identifier into the query text.
        db.execute('''INSERT OR IGNORE INTO demo_proposals
                   (proposal_id,exercise_id,case_id,kind,target_id,payload_json,status)
                   VALUES (?,?,?,?,?,?,'pending')''',
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: ('PROP-' + uuid.uuid4().hex, exercise, case['case_id'], kind, target,
                   # IRIS EXPLAIN: encoded(payload))).
                   ('PROP-' + uuid.uuid4().hex, exercise, case['case_id'], kind, target, encoded(payload)))

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function DemoEngine._page: Validate bounded page size and a nonnegative integer offset before querying
    # IRIS EXPLAIN: working records.
    # IRIS EXPLAIN: Inputs: limit: the bounded maximum result/preview count; offset: the nonnegative page offset.
    def _page(limit, offset):
        # IRIS EXPLAIN: Enter this branch only when type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int
        # IRIS EXPLAIN: or (offset < 0).
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('limit must be 1..100 and offset
            # IRIS EXPLAIN: must be nonnegative'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('limit must be 1..100 and offset must be nonnegative')

    # IRIS EXPLAIN: Function DemoEngine.status: Read the current exercise, live changed/pending counts and loaded-model status
    # IRIS EXPLAIN: for all three dashboards.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def status(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc', 'grc') using the existing explicit arguments.
        require(actor, 'admin', 'soc', 'grc')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_exercises WHERE exercise_id=?',
            # IRIS EXPLAIN: (eid,)).fetchone() (read one database result row) in row; later lines use this named result.
            row = db.execute('SELECT * FROM demo_exercises WHERE exercise_id=?', (eid,)).fetchone()
            # IRIS EXPLAIN: Store a mapping containing risks, alerts, changed_risks, reprioritized_alerts, pending_soc,
            # IRIS EXPLAIN: pending_grc in counts; later lines use this named result.
            counts = {
                # IRIS EXPLAIN: Continue the current record with risks; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'risks': db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=?', (eid,)).fetchone()[0],
                # IRIS EXPLAIN: Continue the current record with alerts; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'alerts': db.execute('SELECT COUNT(*) FROM demo_alerts WHERE exercise_id=?', (eid,)).fetchone()[0],
                # IRIS EXPLAIN: Continue the current record with changed_risks; each value comes from the expression shown on
                # IRIS EXPLAIN: this unchanged line.
                'changed_risks': db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=? AND version>1', (eid,)).fetchone()[0],
                # IRIS EXPLAIN: Continue the current record with reprioritized_alerts; each value comes from the expression
                # IRIS EXPLAIN: shown on this unchanged line.
                'reprioritized_alerts': db.execute('SELECT COUNT(*) FROM demo_alerts WHERE exercise_id=? AND version>1', (eid,)).fetchone()[0],
                # IRIS EXPLAIN: Continue the current record with pending_soc; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'pending_soc': db.execute("SELECT COUNT(*) FROM demo_proposals WHERE exercise_id=? AND kind='soc' AND status='pending'", (eid,)).fetchone()[0],
                # IRIS EXPLAIN: Continue the current record with pending_grc; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'pending_grc': db.execute("SELECT COUNT(*) FROM demo_proposals WHERE exercise_id=? AND kind='grc' AND status='pending'", (eid,)).fetchone()[0],
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            }
            # IRIS EXPLAIN: Store the comprehension [dict(item) for item in db.execute('SELECT exercise_id,label,created_at FROM
            # IRIS EXPLAIN: demo_exercises ORDER BY rowid DESC')] in history; later lines use this named result.
            history = [dict(item) for item in db.execute('SELECT exercise_id,label,created_at FROM demo_exercises ORDER BY rowid DESC')]
        # IRIS EXPLAIN: Return a mapping containing role, exercise_id, label, analyzed, analysis, counts, exercise_history and
        # IRIS EXPLAIN: additional fields to the caller; this ends the current function path.
        return {'role': actor, 'exercise_id': eid, 'label': row['label'], 'analyzed': row['run_id'] is not None,
                # IRIS EXPLAIN: Continue the current record with analysis, counts, exercise_history; each value comes from the
                # IRIS EXPLAIN: expression shown on this unchanged line.
                'analysis': json.loads(row['summary_json']), 'counts': counts, 'exercise_history': history,
                # IRIS EXPLAIN: Set/describe these existing record fields: demo_only: explicitly marks synthetic-system
                # IRIS EXPLAIN: operations as separate from real company systems; external_writes: whether any external system
                # IRIS EXPLAIN: was modified; this local demo reports False.
                'model': self.core.adapter.status(), 'demo_only': True, 'external_writes': False,
                # IRIS EXPLAIN: Set/describe these existing record fields: security_control_execution: whether a defensive
                # IRIS EXPLAIN: control was executed; the demo does not do this.
                'security_control_execution': False, 'approval_writes_real_demo_records': True}

    # IRIS EXPLAIN: Function DemoEngine.risks: Authorize GRC/Admin reads and page current synthetic risks, placing actually
    # IRIS EXPLAIN: changed revisions first.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; limit: the bounded
    # IRIS EXPLAIN: maximum result/preview count; offset: the nonnegative page offset.
    def risks(self, actor, limit=100, offset=0):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'grc') using the existing explicit arguments.
        require(actor, 'admin', 'grc')
        # IRIS EXPLAIN: Call self._page(limit, offset) using the existing explicit arguments.
        self._page(limit, offset)
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=?', (eid,)).fetchone()[0] in
            # IRIS EXPLAIN: total; later lines use this named result.
            total = db.execute('SELECT COUNT(*) FROM demo_risks WHERE exercise_id=?', (eid,)).fetchone()[0]
            # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_risks WHERE exercise_id=?\n ORDER BY (version>1)
            # IRIS EXPLAIN: DESC,current_likelihood*impact DESC,risk_id LIMIT ? ... (read all rows returned by this bounded
            # IRIS EXPLAIN: query) in rows; later lines use this named result.
            # IRIS EXPLAIN: Original embedded-text line 277: SQL: define the existing priority/order mapping used for the
            # IRIS EXPLAIN: returned queue/page.
            rows = db.execute('''SELECT * FROM demo_risks WHERE exercise_id=?
                       ORDER BY (version>1) DESC,current_likelihood*impact DESC,risk_id LIMIT ? OFFSET ?''',
                              # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                              # IRIS EXPLAIN: arguments/items: (eid, limit, offset)).fetchall().
                              (eid, limit, offset)).fetchall()
            # IRIS EXPLAIN: Store the comprehension [self._risk(row) for row in rows] in items; later lines use this named
            # IRIS EXPLAIN: result.
            items = [self._risk(row) for row in rows]
        # IRIS EXPLAIN: Return a mapping containing exercise_id, total, items, limit, offset to the caller; this ends the
        # IRIS EXPLAIN: current function path.
        return {'exercise_id': eid, 'total': total, 'items': items, 'limit': limit, 'offset': offset}

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function DemoEngine._risk: Project a stored working-risk row into original/current likelihood and score
    # IRIS EXPLAIN: fields for the live register.
    # IRIS EXPLAIN: Inputs: row: the existing input record to inspect without inventing missing evidence.
    def _risk(row):
        # IRIS EXPLAIN: Store the result of json.loads(row['source_json']) (decode the existing JSON text) in source; later
        # IRIS EXPLAIN: lines use this named result.
        source = json.loads(row['source_json'])
        # IRIS EXPLAIN: Return the computed value {key: row[key] for key in ('risk_id', 'asset_id', 'hostname',
        # IRIS EXPLAIN: 'baseline_likelihood', 'current_likelihood', 'impact', 'version', 'updated_at', ... to the caller; this
        # IRIS EXPLAIN: ends the current function path.
        return {key: row[key] for key in ('risk_id', 'asset_id', 'hostname', 'baseline_likelihood',
                                         # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                         # IRIS EXPLAIN: existing arguments/items: 'current_likelihood', 'impact', 'version',
                                         # IRIS EXPLAIN: 'updated_at', 'updated_by', 'last_proposal_id')} | {.
                                         'current_likelihood', 'impact', 'version', 'updated_at', 'updated_by', 'last_proposal_id')} | {
            # IRIS EXPLAIN: Continue the current record with category, baseline_score; each value comes from the expression
            # IRIS EXPLAIN: shown on this unchanged line.
            'category': source['risk_category'], 'baseline_score': round(row['baseline_likelihood'] * row['impact'] / 25, 4),
            # IRIS EXPLAIN: Continue the current record with current_score; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            'current_score': round(row['current_likelihood'] * row['impact'] / 25, 4),
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }

    # IRIS EXPLAIN: Function DemoEngine.alerts: Authorize SOC/Admin reads and sort the working queue by its stored current
    # IRIS EXPLAIN: priority, optionally showing only changed records.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; limit: the bounded
    # IRIS EXPLAIN: maximum result/preview count; offset: the nonnegative page offset; changed_only: whether to return only
    # IRIS EXPLAIN: genuinely revised working-alert rows.
    def alerts(self, actor, limit=50, offset=0, *, changed_only=False):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc') using the existing explicit arguments.
        require(actor, 'admin', 'soc')
        # IRIS EXPLAIN: Call self._page(limit, offset) using the existing explicit arguments.
        self._page(limit, offset)
        # IRIS EXPLAIN: Enter this branch only when type(changed_only) is not bool.
        if type(changed_only) is not bool:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('changed_only must be a boolean');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('changed_only must be a boolean')
        # IRIS EXPLAIN: Store the computed value 'exercise_id=?' + (' AND version>1' if changed_only else '') in where; later
        # IRIS EXPLAIN: lines use this named result.
        where = 'exercise_id=?' + (' AND version>1' if changed_only else '')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store db.execute(f'SELECT COUNT(*) FROM demo_alerts WHERE {where}', (eid,)).fetchone()[0] in total;
            # IRIS EXPLAIN: later lines use this named result.
            total = db.execute(f'SELECT COUNT(*) FROM demo_alerts WHERE {where}', (eid,)).fetchone()[0]
            # IRIS EXPLAIN: Store the result of db.execute(f"SELECT * FROM demo_alerts WHERE {where}\n ORDER BY CASE
            # IRIS EXPLAIN: current_priority WHEN 'Critical' THEN 4 WHEN 'High' THEN 3\n WH... (read all rows returned by this
            # IRIS EXPLAIN: bounded query) in rows; later lines use this named result.
            # IRIS EXPLAIN: Original embedded-text line 301: SQL: define the existing priority/order mapping used for the
            # IRIS EXPLAIN: returned queue/page.
            # IRIS EXPLAIN: Original embedded-text line 302: SQL: define the existing priority/order mapping used for the
            # IRIS EXPLAIN: returned queue/page.
            # IRIS EXPLAIN: Original embedded-text line 303: SQL: bound the returned page using separately validated pagination
            # IRIS EXPLAIN: parameters.
            rows = db.execute(f'''SELECT * FROM demo_alerts WHERE {where}
                      ORDER BY CASE current_priority WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                      WHEN 'Medium' THEN 2 ELSE 1 END DESC,event_time DESC,event_id
                      LIMIT ? OFFSET ?''', (eid, limit, offset)).fetchall()
        # IRIS EXPLAIN: Return a mapping containing exercise_id, total, items, limit, offset to the caller; this ends the
        # IRIS EXPLAIN: current function path.
        return {'exercise_id': eid, 'total': total, 'items': [dict(row) for row in rows], 'limit': limit, 'offset': offset}

    # IRIS EXPLAIN: Function DemoEngine.proposals: Return pending/reviewed proposals scoped to the current exercise and
    # IRIS EXPLAIN: authenticated team; Admin can read both but cannot approve as either.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; status: the
    # IRIS EXPLAIN: explicit HTTP response or saved proposal status.
    def proposals(self, actor, *, status='pending'):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc', 'grc') using the existing explicit arguments.
        require(actor, 'admin', 'soc', 'grc')
        # IRIS EXPLAIN: Enter this branch only when status not in {'pending', 'approved', 'rejected', 'stale', 'all'}.
        if status not in {'pending', 'approved', 'rejected', 'stale', 'all'}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid proposal status'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('Invalid proposal status')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store ('exercise_id=?', [eid]) in (where, params); later lines use this named result.
            where, params = 'exercise_id=?', [eid]
            # IRIS EXPLAIN: Enter this branch only when actor != 'admin'.
            if actor != 'admin':
                # IRIS EXPLAIN: Update where using the existing Add operation and 'AND kind=?'.
                where += ' AND kind=?'
                # IRIS EXPLAIN: Call params.append(actor): append one item to the working list.
                params.append(actor)
            # IRIS EXPLAIN: Enter this branch only when status != 'all'.
            if status != 'all':
                # IRIS EXPLAIN: Update where using the existing Add operation and 'AND status=?'.
                where += ' AND status=?'
                # IRIS EXPLAIN: Call params.append(status): append one item to the working list.
                params.append(status)
            # IRIS EXPLAIN: Store the result of db.execute(f'SELECT * FROM demo_proposals WHERE {where} ORDER BY sequence',
            # IRIS EXPLAIN: params).fetchall() (read all rows returned by this bounded query) in rows; later lines use this
            # IRIS EXPLAIN: named result.
            rows = db.execute(f'SELECT * FROM demo_proposals WHERE {where} ORDER BY sequence', params).fetchall()
        # IRIS EXPLAIN: Store [] in items; later lines use this named result.
        items = []
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Store dict(row) in item; later lines use this named result.
            item = dict(row)
            # IRIS EXPLAIN: Store the result of json.loads(item.pop('payload_json')) (decode the existing JSON text) in
            # IRIS EXPLAIN: item['payload']; later lines use this named result.
            item['payload'] = json.loads(item.pop('payload_json'))
            # IRIS EXPLAIN: Call items.append(item): append one item to the working list.
            items.append(item)
        # IRIS EXPLAIN: Return a mapping containing exercise_id, items, total to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return {'exercise_id': eid, 'items': items, 'total': len(items)}

    # IRIS EXPLAIN: Function DemoEngine.review: Validate the team, saved proposal and current revisions, then atomically apply
    # IRIS EXPLAIN: or reject a synthetic record change with before/after audit; stale/idempotent requests cannot double-apply.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles; proposal_id: the
    # IRIS EXPLAIN: existing pending proposal identity; decision: the saved-proposal approve/reject command; reason: the
    # IRIS EXPLAIN: required human decision explanation.
    def review(self, actor, proposal_id, decision, reason):
        # IRIS EXPLAIN: Call require(actor, 'soc', 'grc') using the existing explicit arguments.
        require(actor, 'soc', 'grc')
        # IRIS EXPLAIN: Enter this branch only when not isinstance(proposal_id, str) or not proposal_id.startswith('PROP-') or
        # IRIS EXPLAIN: len(proposal_id) > 50.
        if not isinstance(proposal_id, str) or not proposal_id.startswith('PROP-') or len(proposal_id) > 50:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid proposal identifier'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('Invalid proposal identifier')
        # IRIS EXPLAIN: Enter this branch only when decision not in {'approve', 'reject'}.
        if decision not in {'approve', 'reject'}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('decision must be approve or
            # IRIS EXPLAIN: reject'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('decision must be approve or reject')
        # IRIS EXPLAIN: Enter this branch only when not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 1000.
        if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 1000:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('A human-review reason of 5..1000
            # IRIS EXPLAIN: characters is required'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('A human-review reason of 5..1000 characters is required')
        # IRIS EXPLAIN: Store None (no result/value) in conflict; later lines use this named result.
        conflict = None
        # IRIS EXPLAIN: Enter self.mutation(); its context manager supplies the existing cleanup/transaction/expected-exception
        # IRIS EXPLAIN: behavior.
        with self.mutation():
            # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
            # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
            with self.store.connection() as db:
                # IRIS EXPLAIN: Call db.execute('BEGIN IMMEDIATE'): run the existing SQL with its separately supplied
                # IRIS EXPLAIN: parameters.
                db.execute('BEGIN IMMEDIATE')
                # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
                eid = self.current(db)
                # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_proposals WHERE exercise_id=? AND
                # IRIS EXPLAIN: proposal_id=?', (eid, proposal_id)).fetchone() (read one database result row) in row; later
                # IRIS EXPLAIN: lines use this named result.
                row = db.execute('SELECT * FROM demo_proposals WHERE exercise_id=? AND proposal_id=?', (eid, proposal_id)).fetchone()
                # IRIS EXPLAIN: Enter this branch only when not row.
                if not row:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising KeyError('Proposal not found in the
                    # IRIS EXPLAIN: current exercise'); the caller's existing boundary determines rollback or the HTTP
                    # IRIS EXPLAIN: diagnostic.
                    raise KeyError('Proposal not found in the current exercise')
                # IRIS EXPLAIN: Enter this branch only when row['kind'] != actor.
                if row['kind'] != actor:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising PermissionError('SOC approves alert
                    # IRIS EXPLAIN: changes; GRC approves risk changes'); the caller's existing boundary determines rollback or
                    # IRIS EXPLAIN: the HTTP diagnostic.
                    raise PermissionError('SOC approves alert changes; GRC approves risk changes')
                # IRIS EXPLAIN: Store 'approved' when decision == 'approve'; otherwise 'rejected' in desired; later lines use
                # IRIS EXPLAIN: this named result.
                desired = 'approved' if decision == 'approve' else 'rejected'
                # IRIS EXPLAIN: Enter this branch only when row['status'] == desired.
                if row['status'] == desired:
                    # IRIS EXPLAIN: Return a mapping containing proposal_id, status, already_applied, demo_records_written,
                    # IRIS EXPLAIN: external_writes to the caller; this ends the current function path.
                    return {'proposal_id': proposal_id, 'status': desired, 'already_applied': True,
                            # IRIS EXPLAIN: Set/describe these existing record fields: demo_records_written: number of synthetic
                            # IRIS EXPLAIN: working records actually changed by this approval; external_writes: whether any
                            # IRIS EXPLAIN: external system was modified; this local demo reports False.
                            'demo_records_written': 0, 'external_writes': False}
                # IRIS EXPLAIN: Enter this branch only when row['status'] != 'pending'.
                if row['status'] != 'pending':
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ConflictError('This proposal is already
                    # IRIS EXPLAIN: reviewed or stale; refresh the dashboard'); the caller's existing boundary determines
                    # IRIS EXPLAIN: rollback or the HTTP diagnostic.
                    raise ConflictError('This proposal is already reviewed or stale; refresh the dashboard')
                # IRIS EXPLAIN: Store the result of json.loads(row['payload_json']) (decode the existing JSON text) in payload;
                # IRIS EXPLAIN: later lines use this named result.
                payload = json.loads(row['payload_json'])
                # IRIS EXPLAIN: Store the result of utc_now() in now; later lines use this named result.
                now = utc_now()
                # IRIS EXPLAIN: Store [] in targets; later lines use this named result.
                targets = []
                # IRIS EXPLAIN: Enter this branch only when decision == 'approve' and actor == 'soc'.
                if decision == 'approve' and actor == 'soc':
                    # IRIS EXPLAIN: Iterate payload['changes'], binding each item to change; process only the existing
                    # IRIS EXPLAIN: observed/fixture collection.
                    for change in payload['changes']:
                        # IRIS EXPLAIN: Store the result of db.execute('SELECT current_priority,version FROM demo_alerts WHERE
                        # IRIS EXPLAIN: exercise_id=? AND event_id=?', (eid, change['event_id'])).fetchone() (read one database
                        # IRIS EXPLAIN: result row) in target; later lines use this named result.
                        target = db.execute('SELECT current_priority,version FROM demo_alerts WHERE exercise_id=? AND event_id=?',
                                            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                            # IRIS EXPLAIN: these existing arguments/items: (eid,
                                            # IRIS EXPLAIN: change['event_id'])).fetchone().
                                            (eid, change['event_id'])).fetchone()
                        # IRIS EXPLAIN: Enter this branch only when not target or target['version'] != change['version'] or
                        # IRIS EXPLAIN: target['current_priority'] != change['before'].
                        if not target or target['version'] != change['version'] or target['current_priority'] != change['before']:
                            # IRIS EXPLAIN: Store 'Alert state changed after analysis; this proposal is stale' in conflict;
                            # IRIS EXPLAIN: later lines use this named result.
                            conflict = 'Alert state changed after analysis; this proposal is stale'
                            # IRIS EXPLAIN: Stop the innermost loop on this condition; the surrounding code retains its existing
                            # IRIS EXPLAIN: unresolved/error handling.
                            break
                        # IRIS EXPLAIN: Call targets.append(change): append one item to the working list.
                        targets.append(change)
                # IRIS EXPLAIN: Check this alternative branch when decision == 'approve'.
                elif decision == 'approve':
                    # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND risk_id=?',
                    # IRIS EXPLAIN: (eid, payload['risk_id'])).fetchone() (read one database result row) in target; later lines
                    # IRIS EXPLAIN: use this named result.
                    target = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? AND risk_id=?', (eid, payload['risk_id'])).fetchone()
                    # IRIS EXPLAIN: Enter this branch only when not target or target['version'] != payload['expected_version']
                    # IRIS EXPLAIN: or target['source_version'] != payload['source_version'] or (target['current_likelihood'] !=
                    # IRIS EXPLAIN: payload['before']['likelihood']) or (target['impact'] != payload['befor....
                    if (not target or target['version'] != payload['expected_version']
                            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                            # IRIS EXPLAIN: arguments/items: or target['source_version'] != payload['source_version'].
                            or target['source_version'] != payload['source_version']
                            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                            # IRIS EXPLAIN: arguments/items: or target['current_likelihood'] != payload['before']['likelihood'].
                            or target['current_likelihood'] != payload['before']['likelihood']
                            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                            # IRIS EXPLAIN: arguments/items: or target['impact'] != payload['before']['impact']):.
                            or target['impact'] != payload['before']['impact']):
                        # IRIS EXPLAIN: Store 'Risk register changed after analysis; this proposal is stale' in conflict; later
                        # IRIS EXPLAIN: lines use this named result.
                        conflict = 'Risk register changed after analysis; this proposal is stale'
                # IRIS EXPLAIN: Enter this branch only when conflict.
                if conflict:
                    # IRIS EXPLAIN: Store 'stale' in desired; later lines use this named result.
                    desired = 'stale'
                # IRIS EXPLAIN: Check this alternative branch when decision == 'approve' and actor == 'soc'.
                elif decision == 'approve' and actor == 'soc':
                    # IRIS EXPLAIN: Iterate targets, binding each item to change; process only the existing observed/fixture
                    # IRIS EXPLAIN: collection.
                    for change in targets:
                        # IRIS EXPLAIN: Call db.execute('UPDATE demo_alerts SET current_priority=?,version=version+1,\n
                        # IRIS EXPLAIN: updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND event_id=?', ...:
                        # IRIS EXPLAIN: run the existing SQL with its separately supplied parameters.
                        # IRIS EXPLAIN: Original embedded-text line 374: SQL: update only the named table/fields; the following
                        # IRIS EXPLAIN: placeholders and WHERE clause bind the allowed targets.
                        db.execute('''UPDATE demo_alerts SET current_priority=?,version=version+1,
                                   updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND event_id=?''',
                                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                   # IRIS EXPLAIN: existing arguments/items: (change['after'], now, actor, proposal_id, eid,
                                   # IRIS EXPLAIN: change['event_id'])).
                                   (change['after'], now, actor, proposal_id, eid, change['event_id']))
                        # IRIS EXPLAIN: Call self._change(db, eid, proposal_id, 'alert', change['event_id'], {'priority':
                        # IRIS EXPLAIN: change['before'], 'version': change['version']}, {'priority': change['after'], '...
                        # IRIS EXPLAIN: using the existing explicit arguments.
                        self._change(db, eid, proposal_id, 'alert', change['event_id'],
                                     # IRIS EXPLAIN: Set/describe these existing record fields: priority: explicit policy
                                     # IRIS EXPLAIN: priority; in the active demo it is written only after SOC approval;
                                     # IRIS EXPLAIN: version: record revision or declared package identity used for
                                     # IRIS EXPLAIN: traceability/stale-update checks.
                                     {'priority': change['before'], 'version': change['version']},
                                     # IRIS EXPLAIN: Set/describe these existing record fields: priority: explicit policy
                                     # IRIS EXPLAIN: priority; in the active demo it is written only after SOC approval;
                                     # IRIS EXPLAIN: version: record revision or declared package identity used for
                                     # IRIS EXPLAIN: traceability/stale-update checks.
                                     {'priority': change['after'], 'version': change['version']+1}, actor, reason.strip(), now)
                # IRIS EXPLAIN: Check this alternative branch when decision == 'approve'.
                elif decision == 'approve':
                    # IRIS EXPLAIN: Call db.execute('UPDATE demo_risks SET current_likelihood=?,version=version+1,\n
                    # IRIS EXPLAIN: updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND risk_id=?', ...: run
                    # IRIS EXPLAIN: the existing SQL with its separately supplied parameters.
                    # IRIS EXPLAIN: Original embedded-text line 381: SQL: update only the named table/fields; the following
                    # IRIS EXPLAIN: placeholders and WHERE clause bind the allowed targets.
                    db.execute('''UPDATE demo_risks SET current_likelihood=?,version=version+1,
                               updated_at=?,updated_by=?,last_proposal_id=? WHERE exercise_id=? AND risk_id=?''',
                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                               # IRIS EXPLAIN: arguments/items: (payload['after']['likelihood'], now, actor, proposal_id, eid,
                               # IRIS EXPLAIN: payload['risk_id'])).
                               (payload['after']['likelihood'], now, actor, proposal_id, eid, payload['risk_id']))
                    # IRIS EXPLAIN: Call self._change(db, eid, proposal_id, 'risk', payload['risk_id'], {**payload['before'],
                    # IRIS EXPLAIN: 'version': payload['expected_version']}, {**payload['after'], 'version':... using the
                    # IRIS EXPLAIN: existing explicit arguments.
                    self._change(db, eid, proposal_id, 'risk', payload['risk_id'],
                                 # IRIS EXPLAIN: Set/describe these existing record fields: version: record revision or declared
                                 # IRIS EXPLAIN: package identity used for traceability/stale-update checks.
                                 {**payload['before'], 'version': payload['expected_version']},
                                 # IRIS EXPLAIN: Set/describe these existing record fields: version: record revision or declared
                                 # IRIS EXPLAIN: package identity used for traceability/stale-update checks.
                                 {**payload['after'], 'version': payload['expected_version']+1}, actor, reason.strip(), now)
                    # One evidence batch cannot repeatedly increase the same risk.
                    # IRIS EXPLAIN: Call db.execute("UPDATE demo_proposals SET status='stale',reason=?,reviewed_at=?\n WHERE
                    # IRIS EXPLAIN: exercise_id=? AND kind='grc' AND target_id=? AND status='pending'\n AND p...: run the
                    # IRIS EXPLAIN: existing SQL with its separately supplied parameters.
                    # IRIS EXPLAIN: Original embedded-text line 388: SQL: restrict the selected/mutated records to the stated
                    # IRIS EXPLAIN: identity, revision, role or status condition.
                    # IRIS EXPLAIN: Original embedded-text line 389: SQL: retain the stated column definitions, revision fields,
                    # IRIS EXPLAIN: or query conditions.
                    db.execute('''UPDATE demo_proposals SET status='stale',reason=?,reviewed_at=?
                               WHERE exercise_id=? AND kind='grc' AND target_id=? AND status='pending'
                               AND proposal_id<>?''',
                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                               # IRIS EXPLAIN: arguments/items: ('Superseded by an approved change to the same risk; new
                               # IRIS EXPLAIN: evidence is required.',.
                               ('Superseded by an approved change to the same risk; new evidence is required.',
                                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                                # IRIS EXPLAIN: arguments/items: now, eid, payload['risk_id'], proposal_id)).
                                now, eid, payload['risk_id'], proposal_id))
                # IRIS EXPLAIN: Call db.execute('UPDATE demo_proposals SET status=?,reason=?,reviewed_by=?,reviewed_at=? WHERE
                # IRIS EXPLAIN: proposal_id=?', (desired, conflict or reason.strip(), actor, now, p...: run the existing SQL
                # IRIS EXPLAIN: with its separately supplied parameters.
                db.execute('UPDATE demo_proposals SET status=?,reason=?,reviewed_by=?,reviewed_at=? WHERE proposal_id=?',
                           # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                           # IRIS EXPLAIN: arguments/items: (desired, conflict or reason.strip(), actor, now, proposal_id)).
                           (desired, conflict or reason.strip(), actor, now, proposal_id))
                # IRIS EXPLAIN: Store 0 when conflict or decision == 'reject'; otherwise len(targets) when actor == 'soc';
                # IRIS EXPLAIN: otherwise 1 in written; later lines use this named result.
                written = 0 if conflict or decision == 'reject' else len(targets) if actor == 'soc' else 1
                # IRIS EXPLAIN: Call self.store.audit(db, actor, 'demo_' + desired, proposal_id, {'exercise_id': eid, 'kind':
                # IRIS EXPLAIN: actor, 'demo_records_written': written, 'reason': conflict or reason... using the existing
                # IRIS EXPLAIN: explicit arguments.
                self.store.audit(db, actor, 'demo_' + desired, proposal_id,
                                 # IRIS EXPLAIN: Set/describe these existing record fields: demo_records_written: number of
                                 # IRIS EXPLAIN: synthetic working records actually changed by this approval.
                                 {'exercise_id': eid, 'kind': actor, 'demo_records_written': written,
                                  # IRIS EXPLAIN: Set/describe these existing record fields: external_writes: whether any
                                  # IRIS EXPLAIN: external system was modified; this local demo reports False.
                                  'reason': conflict or reason.strip(), 'external_writes': False,
                                  # IRIS EXPLAIN: Set/describe these existing record fields: security_control_execution: whether
                                  # IRIS EXPLAIN: a defensive control was executed; the demo does not do this.
                                  'security_control_execution': False})
            # IRIS EXPLAIN: Enter this branch only when conflict.
            if conflict:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ConflictError(conflict); the caller's
                # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
                raise ConflictError(conflict)
        # IRIS EXPLAIN: Return a mapping containing proposal_id, status, already_applied, demo_records_written, external_writes,
        # IRIS EXPLAIN: security_control_execution to the caller; this ends the current function path.
        return {'proposal_id': proposal_id, 'status': desired, 'already_applied': False,
                # IRIS EXPLAIN: Set/describe these existing record fields: demo_records_written: number of synthetic working
                # IRIS EXPLAIN: records actually changed by this approval; external_writes: whether any external system was
                # IRIS EXPLAIN: modified; this local demo reports False; security_control_execution: whether a defensive control
                # IRIS EXPLAIN: was executed; the demo does not do this.
                'demo_records_written': written, 'external_writes': False, 'security_control_execution': False}

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function DemoEngine._change: Append a before/after target snapshot, approver, reason and timestamp on the
    # IRIS EXPLAIN: same transaction as the working-record mutation.
    # IRIS EXPLAIN: Inputs: db: the caller-owned SQLite transaction; eid: the event or exercise identity in the enclosing scope;
    # IRIS EXPLAIN: proposal: the existing pending proposal identity; kind: the existing SOC/GRC or alert/risk target category;
    # IRIS EXPLAIN: target: the saved record identity, never a caller-selected arbitrary update path; before: the original/saved
    # IRIS EXPLAIN: target fields retained for comparison; after: the approved proposed target fields, not arbitrary
    # IRIS EXPLAIN: client-supplied values; actor: the server-authenticated role; tests use explicit synthetic fixture roles;
    # IRIS EXPLAIN: reason: the required human decision explanation; at: the timezone-aware event instant for a point-in-time
    # IRIS EXPLAIN: lookup.
    def _change(db, eid, proposal, kind, target, before, after, actor, reason, at):
        # IRIS EXPLAIN: Call db.execute('INSERT INTO demo_changes\n
        # IRIS EXPLAIN: (exercise_id,proposal_id,target_kind,target_id,before_json,after_json,actor,reason,changed_at)\n VALUES
        # IRIS EXPLAIN: (?,?,?,?,?,?,?...: run the existing SQL with its separately supplied parameters.
        # IRIS EXPLAIN: Original embedded-text line 407: Embedded text:
        # IRIS EXPLAIN: (exercise_id,proposal_id,target_kind,target_id,before_json,after_json,actor,reason,changed_at); kept as
        # IRIS EXPLAIN: literal data, not a Python comment inside the string.
        # IRIS EXPLAIN: Original embedded-text line 408: SQL: bind the already constructed parameter values; do not interpolate
        # IRIS EXPLAIN: an untrusted priority, role or identifier into the query text.
        db.execute('''INSERT INTO demo_changes
                   (exercise_id,proposal_id,target_kind,target_id,before_json,after_json,actor,reason,changed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)''', (eid, proposal, kind, target, encoded(before), encoded(after), actor, reason, at))

    # IRIS EXPLAIN: Function DemoEngine.changes: Read recent applied changes for the current exercise and authorized team; these
    # IRIS EXPLAIN: are persisted evidence, not browser-only colors.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def changes(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc', 'grc') using the existing explicit arguments.
        require(actor, 'admin', 'soc', 'grc')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store ('exercise_id=?', [eid]) in (where, params); later lines use this named result.
            where, params = 'exercise_id=?', [eid]
            # IRIS EXPLAIN: Enter this branch only when actor != 'admin'.
            if actor != 'admin':
                # IRIS EXPLAIN: Update where using the existing Add operation and 'AND target_kind=?'.
                where += ' AND target_kind=?'
                # IRIS EXPLAIN: Call params.append('alert' if actor == 'soc' else 'risk'): append one item to the working list.
                params.append('alert' if actor == 'soc' else 'risk')
            # IRIS EXPLAIN: Store the result of db.execute(f'SELECT * FROM demo_changes WHERE {where} ORDER BY sequence DESC
            # IRIS EXPLAIN: LIMIT 100', params).fetchall() (read all rows returned by this bounded query) in rows; later lines
            # IRIS EXPLAIN: use this named result.
            rows = db.execute(f'SELECT * FROM demo_changes WHERE {where} ORDER BY sequence DESC LIMIT 100', params).fetchall()
        # IRIS EXPLAIN: Store [] in items; later lines use this named result.
        items = []
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Store dict(row) in item; later lines use this named result.
            item = dict(row)
            # IRIS EXPLAIN: Store the result of json.loads(item.pop('before_json')) (decode the existing JSON text) in
            # IRIS EXPLAIN: item['before']; later lines use this named result.
            item['before'] = json.loads(item.pop('before_json'))
            # IRIS EXPLAIN: Store the result of json.loads(item.pop('after_json')) (decode the existing JSON text) in
            # IRIS EXPLAIN: item['after']; later lines use this named result.
            item['after'] = json.loads(item.pop('after_json'))
            # IRIS EXPLAIN: Call items.append(item): append one item to the working list.
            items.append(item)
        # IRIS EXPLAIN: Return a mapping containing exercise_id, items to the caller; this ends the current function path.
        return {'exercise_id': eid, 'items': items}

    # IRIS EXPLAIN: Function DemoEngine.audit: Require Admin and read the shared append-only audit history for analysis and demo
    # IRIS EXPLAIN: approvals.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def audit(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin') using the existing explicit arguments.
        require(actor, 'admin')
        # IRIS EXPLAIN: Return the result of self.store.audit_events(200) to the caller; this ends the current function path.
        return self.store.audit_events(200)

    # IRIS EXPLAIN: Function DemoEngine.export_risks: Export the current synthetic GRC register with actually approved
    # IRIS EXPLAIN: likelihoods/revisions; preserve the original source JSON as immutable input evidence.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def export_risks(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'grc') using the existing explicit arguments.
        require(actor, 'admin', 'grc')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM demo_risks WHERE exercise_id=? ORDER BY risk_id',
            # IRIS EXPLAIN: (eid,)).fetchall() (read all rows returned by this bounded query) in rows; later lines use this
            # IRIS EXPLAIN: named result.
            rows = db.execute('SELECT * FROM demo_risks WHERE exercise_id=? ORDER BY risk_id', (eid,)).fetchall()
        # IRIS EXPLAIN: Store [] in records; later lines use this named result.
        records = []
        # IRIS EXPLAIN: Iterate rows, binding each item to row; process only the existing observed/fixture collection.
        for row in rows:
            # IRIS EXPLAIN: Store the result of json.loads(row['source_json']) (decode the existing JSON text) in record; later
            # IRIS EXPLAIN: lines use this named result.
            record = json.loads(row['source_json'])
            # IRIS EXPLAIN: Store row['current_likelihood'] in record['likelihood']; later lines use this named result.
            record['likelihood'] = row['current_likelihood']
            # IRIS EXPLAIN: Enter this branch only when row['version'] > 1.
            if row['version'] > 1:
                # IRIS EXPLAIN: Update record['risk_version_id'] using the existing Add operation and the computed value
                # IRIS EXPLAIN: '-DEMO-REV' + str(row['version']).
                record['risk_version_id'] += '-DEMO-REV' + str(row['version'])
                # IRIS EXPLAIN: Store row['updated_at'] in record['valid_from']; later lines use this named result.
                record['valid_from'] = row['updated_at']
                # IRIS EXPLAIN: Store row['updated_at'] in record['recorded_at']; later lines use this named result.
                record['recorded_at'] = row['updated_at']
            # IRIS EXPLAIN: Store a mapping containing revision, updated_by, updated_at, proposal_id in record['demo_approval'];
            # IRIS EXPLAIN: later lines use this named result.
            record['demo_approval'] = {'revision': row['version'], 'updated_by': row['updated_by'],
                                       # IRIS EXPLAIN: Continue the current record with updated_at, proposal_id; each value
                                       # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                       'updated_at': row['updated_at'], 'proposal_id': row['last_proposal_id']}
            # IRIS EXPLAIN: Call records.append(record): append one item to the working list.
            records.append(record)
        # IRIS EXPLAIN: Return a mapping containing schema_version, data_provenance, demo_only, exercise_id, notice, records to
        # IRIS EXPLAIN: the caller; this ends the current function path.
        return {'schema_version': 'iris-risk-register-v1', 'data_provenance': 'synthetic',
                # IRIS EXPLAIN: Set/describe these existing record fields: demo_only: explicitly marks synthetic-system
                # IRIS EXPLAIN: operations as separate from real company systems.
                'demo_only': True, 'exercise_id': eid,
                # IRIS EXPLAIN: Continue the current record with notice; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'notice': 'Current simulated GRC system state. Approved demo revisions, not an official company register.',
                # IRIS EXPLAIN: Continue the current record with records; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'records': records}

    # IRIS EXPLAIN: Function DemoEngine.export_alerts: Export current synthetic SOC priorities and revision/approval metadata,
    # IRIS EXPLAIN: not a fabricated new raw SIEM export.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def export_alerts(self, actor):
        # IRIS EXPLAIN: Call require(actor, 'admin', 'soc') using the existing explicit arguments.
        require(actor, 'admin', 'soc')
        # IRIS EXPLAIN: Enter self.store.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.store.connection() as db:
            # IRIS EXPLAIN: Store the result of self.current(db) in eid; later lines use this named result.
            eid = self.current(db)
            # IRIS EXPLAIN: Store the result of db.execute('SELECT event_id,asset_id,hostname,event_time,baseline_priority,\n
            # IRIS EXPLAIN: current_priority,version,updated_by,updated_at,last_pr... (read all rows returned by this bounded
            # IRIS EXPLAIN: query) in rows; later lines use this named result.
            # IRIS EXPLAIN: Original embedded-text line 457: Embedded text:
            # IRIS EXPLAIN: current_priority,version,updated_by,updated_at,last_proposal_id; kept as literal data, not a Python
            # IRIS EXPLAIN: comment inside the string.
            # IRIS EXPLAIN: Original embedded-text line 458: SQL: restrict the selected/mutated records to the stated identity,
            # IRIS EXPLAIN: revision, role or status condition.
            rows = db.execute('''SELECT event_id,asset_id,hostname,event_time,baseline_priority,
                              current_priority,version,updated_by,updated_at,last_proposal_id
                              FROM demo_alerts WHERE exercise_id=? ORDER BY event_id''', (eid,)).fetchall()
        # IRIS EXPLAIN: Return a mapping containing data_provenance, demo_only, exercise_id, notice, records to the caller; this
        # IRIS EXPLAIN: ends the current function path.
        return {'data_provenance': 'synthetic', 'demo_only': True, 'exercise_id': eid,
                # IRIS EXPLAIN: Continue the current record with notice; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'notice': 'Current simulated SOC priority state; not a raw SIEM source export.',
                # IRIS EXPLAIN: Continue the current record with records; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                'records': [dict(row) for row in rows]}
