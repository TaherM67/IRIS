# IRIS EXPLAIN: File purpose: SQLite store for immutable runs/cases, append-once local follow-up reviews, and audit records;
# IRIS EXPLAIN: this module alone does not apply working-system changes.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""SQLite persistence for immutable case evidence and local-only reviews."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import sqlite3 to persist evidence and approval-gated working records transactionally.
import sqlite3
# IRIS EXPLAIN: Import contextmanager from contextlib to manage connection/lifespan/lock cleanup reliably.
from contextlib import contextmanager
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import utc_now from .model_adapter to reuse the shared project contract/implementation rather than duplicate it.
from .model_adapter import utc_now


# IRIS EXPLAIN: Function encoded: Serialize finite, compact JSON for SQLite payload/evidence fields.
# IRIS EXPLAIN: Inputs: value: the supplied value to validate/normalize/serialize.
def encoded(value):
    # IRIS EXPLAIN: Return the result of json.dumps(value, allow_nan=False, separators=(',', ':')) (serialize the existing
    # IRIS EXPLAIN: payload as JSON) to the caller; this ends the current function path.
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


# IRIS EXPLAIN: Class Store: Connection-per-operation SQLite evidence and local-review store.
class Store:
    # IRIS EXPLAIN: Function Store.__init__: Open/create the SQLite evidence store and its run, case, local-review and audit
    # IRIS EXPLAIN: tables without deleting existing records.
    # IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
    def __init__(self, path: Path):
        # IRIS EXPLAIN: Store path in self.path; later lines use this named result.
        self.path = path
        # IRIS EXPLAIN: Call path.parent.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
        # IRIS EXPLAIN: existing flags.
        path.parent.mkdir(parents=True, exist_ok=True)
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Call db.executescript("\n CREATE TABLE IF NOT EXISTS runs (\n run_id TEXT PRIMARY KEY, fingerprint
            # IRIS EXPLAIN: TEXT NOT NULL,\n status TEXT NOT NULL, created_at TEXT NOT NULL...: initialize the declared SQL
            # IRIS EXPLAIN: schema.
            # IRIS EXPLAIN: Original embedded-text line 22: SQL: declare the runs table if needed; existing rows are preserved.
            # IRIS EXPLAIN: Original embedded-text line 23: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 24: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 25: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 26: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 27: SQL: define the existing lookup/uniqueness index for this table and
            # IRIS EXPLAIN: condition.
            # IRIS EXPLAIN: Original embedded-text line 28: SQL: declare the cases table if needed; existing rows are preserved.
            # IRIS EXPLAIN: Original embedded-text line 29: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 30: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 31: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 32: SQL: declare the reviews table if needed; existing rows are
            # IRIS EXPLAIN: preserved.
            # IRIS EXPLAIN: Original embedded-text line 33: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 34: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 35: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 36: SQL: declare the audit table if needed; existing rows are preserved.
            # IRIS EXPLAIN: Original embedded-text line 37: SQL: declare identity/uniqueness constraints, including the stated
            # IRIS EXPLAIN: columns.
            # IRIS EXPLAIN: Original embedded-text line 38: SQL: retain the stated column definitions, revision fields, or query
            # IRIS EXPLAIN: conditions.
            # IRIS EXPLAIN: Original embedded-text line 39: SQL: close the table/query statement exactly as originally written.
            # IRIS EXPLAIN: Original embedded-text line 40: SQL: close the table/query statement exactly as originally written.
            db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, actor TEXT NOT NULL,
                    summary_json TEXT NOT NULL, error TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS completed_input ON runs(fingerprint) WHERE status='completed';
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
                    session_id TEXT NOT NULL, payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reviews (
                    case_id TEXT PRIMARY KEY REFERENCES cases(case_id),
                    disposition TEXT NOT NULL, comment TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL, details_json TEXT NOT NULL
                );
            """)

    # IRIS EXPLAIN: Turn the following yield-based function into a context manager so its existing cleanup runs on exit.
    @contextmanager
    # IRIS EXPLAIN: Function Store.connection: Yield a configured SQLite connection, commit successful writes or roll back
    # IRIS EXPLAIN: exceptions, and always close the connection.
    def connection(self):
        # IRIS EXPLAIN: Store the result of sqlite3.connect(self.path, timeout=15) (open the SQLite connection) in db; later
        # IRIS EXPLAIN: lines use this named result.
        db = sqlite3.connect(self.path, timeout=15)
        # IRIS EXPLAIN: Store sqlite3.Row in db.row_factory; later lines use this named result.
        db.row_factory = sqlite3.Row
        # IRIS EXPLAIN: Call db.execute('PRAGMA foreign_keys=ON'): run the existing SQL with its separately supplied parameters.
        db.execute("PRAGMA foreign_keys=ON")
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Enter db; its context manager supplies the existing cleanup/transaction/expected-exception behavior.
            with db:
                # IRIS EXPLAIN: Yield control/value to the existing context/lifespan consumer; execution resumes here for the
                # IRIS EXPLAIN: declared cleanup when the consumer finishes.
                yield db
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call db.close(): close the resource.
            db.close()

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function Store.audit: Append a timestamped actor/action/object/details event on the caller's transaction.
    # IRIS EXPLAIN: Inputs: db: the caller-owned SQLite transaction; actor: the server-authenticated role; tests use explicit
    # IRIS EXPLAIN: synthetic fixture roles; action: the persisted audit-event action name; object_id: the audited
    # IRIS EXPLAIN: run/case/proposal identity; details: the finite structured evidence stored with the audit event.
    def audit(db, actor, action, object_id, details):
        # IRIS EXPLAIN: Call db.execute('INSERT INTO audit(created_at,actor,action,object_id,details_json) VALUES (?,?,?,?,?)',
        # IRIS EXPLAIN: (utc_now(), actor, action, object_id, encoded(details))): run the existing SQL with its separately
        # IRIS EXPLAIN: supplied parameters.
        db.execute("INSERT INTO audit(created_at,actor,action,object_id,details_json) VALUES (?,?,?,?,?)",
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: (utc_now(), actor, action, object_id, encoded(details))).
                   (utc_now(), actor, action, object_id, encoded(details)))

    # IRIS EXPLAIN: Function Store.previous: Find a completed run with the same immutable input/model/policy fingerprint for
    # IRIS EXPLAIN: idempotent reuse.
    # IRIS EXPLAIN: Inputs: fingerprint: the deterministic source/model/policy identity for idempotent reuse.
    def previous(self, fingerprint):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Store the result of db.execute("SELECT summary_json FROM runs WHERE fingerprint=? AND
            # IRIS EXPLAIN: status='completed'", (fingerprint,)).fetchone() (read one database result row) in row; later lines
            # IRIS EXPLAIN: use this named result.
            row = db.execute("SELECT summary_json FROM runs WHERE fingerprint=? AND status='completed'", (fingerprint,)).fetchone()
            # IRIS EXPLAIN: Return the result of json.loads(row[0]) (decode the existing JSON text) when row; otherwise None (no
            # IRIS EXPLAIN: result/value) to the caller; this ends the current function path.
            return json.loads(row[0]) if row else None

    # IRIS EXPLAIN: Function Store.begin: Persist a processing run and its batch-start audit event before attempting inference.
    # IRIS EXPLAIN: Inputs: run_id: the saved batch/run identifier; fingerprint: the deterministic source/model/policy identity
    # IRIS EXPLAIN: for idempotent reuse; actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def begin(self, run_id, fingerprint, actor):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Call db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,NULL)', (run_id, fingerprint, 'processing',
            # IRIS EXPLAIN: utc_now(), actor, '{}')): run the existing SQL with its separately supplied parameters.
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,NULL)",
                       # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                       # IRIS EXPLAIN: arguments/items: (run_id, fingerprint, "processing", utc_now(), actor, "{}")).
                       (run_id, fingerprint, "processing", utc_now(), actor, "{}"))
            # IRIS EXPLAIN: Call self.audit(db, actor, 'batch_started', run_id, {'mode': 'shadow'}) using the existing explicit
            # IRIS EXPLAIN: arguments.
            self.audit(db, actor, "batch_started", run_id, {"mode": "shadow"})

    # IRIS EXPLAIN: Function Store.complete: Insert all immutable cases and mark the run completed in the same transaction with
    # IRIS EXPLAIN: a completion audit event.
    # IRIS EXPLAIN: Inputs: run_id: the saved batch/run identifier; cases: immutable session/prediction/policy case records;
    # IRIS EXPLAIN: summary: the completed batch or bounded API result summary; actor: the server-authenticated role; tests use
    # IRIS EXPLAIN: explicit synthetic fixture roles.
    def complete(self, run_id, cases, summary, actor):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Call db.executemany('INSERT INTO cases VALUES (?,?,?,?)', [(case['case_id'], run_id,
            # IRIS EXPLAIN: case['session']['session_id'], encoded(case)) for case in cases]): run the existing parameterized
            # IRIS EXPLAIN: SQL for each supplied row.
            db.executemany("INSERT INTO cases VALUES (?,?,?,?)", [
                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                # IRIS EXPLAIN: arguments/items: (case["case_id"], run_id, case["session"]["session_id"], encoded(case)) for
                # IRIS EXPLAIN: case in cases.
                (case["case_id"], run_id, case["session"]["session_id"], encoded(case)) for case in cases
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            ])
            # IRIS EXPLAIN: Call db.execute("UPDATE runs SET status='completed',summary_json=? WHERE run_id=?",
            # IRIS EXPLAIN: (encoded(summary), run_id)): run the existing SQL with its separately supplied parameters.
            db.execute("UPDATE runs SET status='completed',summary_json=? WHERE run_id=?", (encoded(summary), run_id))
            # IRIS EXPLAIN: Call self.audit(db, actor, 'batch_completed', run_id, {'cases': len(cases), 'model_sha256':
            # IRIS EXPLAIN: summary['model_sha256']}) using the existing explicit arguments.
            self.audit(db, actor, "batch_completed", run_id, {"cases": len(cases), "model_sha256": summary["model_sha256"]})

    # IRIS EXPLAIN: Function Store.fail: Mark a started run failed and record a bounded diagnostic without publishing partially
    # IRIS EXPLAIN: completed cases.
    # IRIS EXPLAIN: Inputs: run_id: the saved batch/run identifier; actor: the server-authenticated role; tests use explicit
    # IRIS EXPLAIN: synthetic fixture roles; reason: the required human decision explanation.
    def fail(self, run_id, actor, reason):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Call db.execute("UPDATE runs SET status='failed',error=? WHERE run_id=?", (reason[:500], run_id)):
            # IRIS EXPLAIN: run the existing SQL with its separately supplied parameters.
            db.execute("UPDATE runs SET status='failed',error=? WHERE run_id=?", (reason[:500], run_id))
            # IRIS EXPLAIN: Call self.audit(db, actor, 'batch_failed', run_id, {'reason': reason[:500]}) using the existing
            # IRIS EXPLAIN: explicit arguments.
            self.audit(db, actor, "batch_failed", run_id, {"reason": reason[:500]})

    # IRIS EXPLAIN: Function Store.runs: Read recent saved run statuses, summaries and diagnostics, newest first.
    # IRIS EXPLAIN: Inputs: limit: the bounded maximum result/preview count.
    def runs(self, limit=25):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Store the result of db.execute('SELECT * FROM runs ORDER BY created_at DESC LIMIT ?',
            # IRIS EXPLAIN: (limit,)).fetchall() (read all rows returned by this bounded query) in rows; later lines use this
            # IRIS EXPLAIN: named result.
            rows = db.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            # IRIS EXPLAIN: Return the comprehension [{'run_id': r['run_id'], 'status': r['status'], 'created_at_utc':
            # IRIS EXPLAIN: r['created_at'], 'summary': json.loads(r['summary_json']), 'error': r['error']} for r in rows] to
            # IRIS EXPLAIN: the caller; this ends the current function path.
            return [{"run_id": r["run_id"], "status": r["status"], "created_at_utc": r["created_at"],
                     # IRIS EXPLAIN: Continue the current record with summary, error; each value comes from the expression shown
                     # IRIS EXPLAIN: on this unchanged line.
                     "summary": json.loads(r["summary_json"]), "error": r["error"]} for r in rows]

    # IRIS EXPLAIN: Function Store.case: Read immutable case evidence plus its optional local follow-up review, or raise
    # IRIS EXPLAIN: KeyError if absent.
    # IRIS EXPLAIN: Inputs: case_id: the immutable saved analysis case identifier.
    def case(self, case_id):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Store the result of db.execute('SELECT payload_json FROM cases WHERE case_id=?',
            # IRIS EXPLAIN: (case_id,)).fetchone() (read one database result row) in row; later lines use this named result.
            row = db.execute("SELECT payload_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
            # IRIS EXPLAIN: Enter this branch only when not row.
            if not row:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising KeyError(case_id); the caller's existing
                # IRIS EXPLAIN: boundary determines rollback or the HTTP diagnostic.
                raise KeyError(case_id)
            # IRIS EXPLAIN: Store the result of json.loads(row[0]) (decode the existing JSON text) in case; later lines use this
            # IRIS EXPLAIN: named result.
            case = json.loads(row[0])
            # IRIS EXPLAIN: Store the result of db.execute('SELECT disposition,comment,actor,created_at FROM reviews WHERE
            # IRIS EXPLAIN: case_id=?', (case_id,)).fetchone() (read one database result row) in review; later lines use this
            # IRIS EXPLAIN: named result.
            review = db.execute("SELECT disposition,comment,actor,created_at FROM reviews WHERE case_id=?", (case_id,)).fetchone()
            # IRIS EXPLAIN: Store dict(review) when review; otherwise None (no result/value) in case['review']; later lines use
            # IRIS EXPLAIN: this named result.
            case["review"] = dict(review) if review else None
            # IRIS EXPLAIN: Return case to the caller; this ends the current function path.
            return case

    # IRIS EXPLAIN: Function Store.cases: Page through case IDs using parameterized filters, then attach each case's optional
    # IRIS EXPLAIN: review.
    # IRIS EXPLAIN: Inputs: run_id: the saved batch/run identifier; limit: the bounded maximum result/preview count; offset: the
    # IRIS EXPLAIN: nonnegative page offset.
    def cases(self, run_id=None, limit=25, offset=0):
        # IRIS EXPLAIN: Store ('WHERE run_id=?', [run_id]) when run_id; otherwise ('', []) in (where, params); later lines use
        # IRIS EXPLAIN: this named result.
        where, params = ("WHERE run_id=?", [run_id]) if run_id else ("", [])
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Store the result of db.execute(f'SELECT case_id FROM cases {where} ORDER BY rowid DESC LIMIT ?
            # IRIS EXPLAIN: OFFSET ?', [*params, limit, offset]).fetchall() (read all rows returned by this bounded query) in
            # IRIS EXPLAIN: rows; later lines use this named result.
            rows = db.execute(f"SELECT case_id FROM cases {where} ORDER BY rowid DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
            # IRIS EXPLAIN: Store db.execute(f'SELECT COUNT(*) FROM cases {where}', params).fetchone()[0] in total; later lines
            # IRIS EXPLAIN: use this named result.
            total = db.execute(f"SELECT COUNT(*) FROM cases {where}", params).fetchone()[0]
        # IRIS EXPLAIN: Return a mapping containing total, items, offset, limit to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return {"total": total, "items": [self.case(r[0]) for r in rows], "offset": offset, "limit": limit}

    # IRIS EXPLAIN: Function Store.review: Record one GRC-only local follow-up opinion; it is append-once and does not change
    # IRIS EXPLAIN: working or official risk records.
    # IRIS EXPLAIN: Inputs: case_id: the immutable saved analysis case identifier; disposition: the earlier backend local
    # IRIS EXPLAIN: follow-up review decision; comment: the required explanation of the local follow-up decision; actor: the
    # IRIS EXPLAIN: server-authenticated role; tests use explicit synthetic fixture roles.
    def review(self, case_id, disposition, comment, actor):
        # IRIS EXPLAIN: Enter this branch only when actor != 'grc' or disposition not in {'approve_follow_up',
        # IRIS EXPLAIN: 'reject_suggestion'}.
        if actor != "grc" or disposition not in {"approve_follow_up", "reject_suggestion"}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Only the GRC role may make a local
            # IRIS EXPLAIN: review'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Only the GRC role may make a local review")
        # IRIS EXPLAIN: Store the result of comment.strip() (remove surrounding whitespace) in comment; later lines use this
        # IRIS EXPLAIN: named result.
        comment = comment.strip()
        # IRIS EXPLAIN: Enter this branch only when not 5 <= len(comment) <= 2000.
        if not 5 <= len(comment) <= 2000:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Review comments must contain
            # IRIS EXPLAIN: 5..2000 characters'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Review comments must contain 5..2000 characters")
        # IRIS EXPLAIN: Call self.case(case_id) using the existing explicit arguments.
        self.case(case_id)
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Enter this branch only when db.execute('SELECT 1 FROM reviews WHERE case_id=?',
            # IRIS EXPLAIN: (case_id,)).fetchone().
            if db.execute("SELECT 1 FROM reviews WHERE case_id=?", (case_id,)).fetchone():
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('This case already has a review;
                # IRIS EXPLAIN: prior evidence/reviews are not overwritten'); the caller's existing boundary determines rollback
                # IRIS EXPLAIN: or the HTTP diagnostic.
                raise ValueError("This case already has a review; prior evidence/reviews are not overwritten")
            # IRIS EXPLAIN: Call db.execute('INSERT INTO reviews VALUES (?,?,?,?,?)', (case_id, disposition, comment, actor,
            # IRIS EXPLAIN: utc_now())): run the existing SQL with its separately supplied parameters.
            db.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (case_id, disposition, comment, actor, utc_now()))
            # IRIS EXPLAIN: Call self.audit(db, actor, 'local_review', case_id, {'disposition': disposition,
            # IRIS EXPLAIN: 'official_risk_register_write': False}) using the existing explicit arguments.
            self.audit(db, actor, "local_review", case_id, {"disposition": disposition, "official_risk_register_write": False})
        # IRIS EXPLAIN: Return self.case(case_id)['review'] to the caller; this ends the current function path.
        return self.case(case_id)["review"]

    # IRIS EXPLAIN: Function Store.health: Count saved runs, cases, reviews and audit entries for local status reporting.
    def health(self):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Return the comprehension {name: db.execute(f'SELECT COUNT(*) FROM {name}').fetchone()[0] for name in
            # IRIS EXPLAIN: ('runs', 'cases', 'reviews', 'audit')} to the caller; this ends the current function path.
            return {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ("runs", "cases", "reviews", "audit")}

    # IRIS EXPLAIN: Function Store.audit_events: Read a bounded recent audit-event list without exposing stored credentials.
    # IRIS EXPLAIN: Inputs: limit: the bounded maximum result/preview count.
    def audit_events(self, limit=100):
        # IRIS EXPLAIN: Enter self.connection() as db; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with self.connection() as db:
            # IRIS EXPLAIN: Return the comprehension [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY sequence DESC
            # IRIS EXPLAIN: LIMIT ?', (limit,))] to the caller; this ends the current function path.
            return [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY sequence DESC LIMIT ?", (limit,))]
