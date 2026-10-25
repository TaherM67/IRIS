"""SQLite persistence for immutable case evidence and local-only reviews."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .model_adapter import utc_now


def encoded(value):
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
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

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def audit(db, actor, action, object_id, details):
        db.execute("INSERT INTO audit(created_at,actor,action,object_id,details_json) VALUES (?,?,?,?,?)",
                   (utc_now(), actor, action, object_id, encoded(details)))

    def previous(self, fingerprint):
        with self.connection() as db:
            row = db.execute("SELECT summary_json FROM runs WHERE fingerprint=? AND status='completed'", (fingerprint,)).fetchone()
            return json.loads(row[0]) if row else None

    def begin(self, run_id, fingerprint, actor):
        with self.connection() as db:
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,NULL)",
                       (run_id, fingerprint, "processing", utc_now(), actor, "{}"))
            self.audit(db, actor, "batch_started", run_id, {"mode": "shadow"})

    def complete(self, run_id, cases, summary, actor):
        with self.connection() as db:
            db.executemany("INSERT INTO cases VALUES (?,?,?,?)", [
                (case["case_id"], run_id, case["session"]["session_id"], encoded(case)) for case in cases
            ])
            db.execute("UPDATE runs SET status='completed',summary_json=? WHERE run_id=?", (encoded(summary), run_id))
            self.audit(db, actor, "batch_completed", run_id, {"cases": len(cases), "model_sha256": summary["model_sha256"]})

    def fail(self, run_id, actor, reason):
        with self.connection() as db:
            db.execute("UPDATE runs SET status='failed',error=? WHERE run_id=?", (reason[:500], run_id))
            self.audit(db, actor, "batch_failed", run_id, {"reason": reason[:500]})

    def runs(self, limit=25):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [{"run_id": r["run_id"], "status": r["status"], "created_at_utc": r["created_at"],
                     "summary": json.loads(r["summary_json"]), "error": r["error"]} for r in rows]

    def case(self, case_id):
        with self.connection() as db:
            row = db.execute("SELECT payload_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                raise KeyError(case_id)
            case = json.loads(row[0])
            review = db.execute("SELECT disposition,comment,actor,created_at FROM reviews WHERE case_id=?", (case_id,)).fetchone()
            case["review"] = dict(review) if review else None
            return case

    def cases(self, run_id=None, limit=25, offset=0):
        where, params = ("WHERE run_id=?", [run_id]) if run_id else ("", [])
        with self.connection() as db:
            rows = db.execute(f"SELECT case_id FROM cases {where} ORDER BY rowid DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
            total = db.execute(f"SELECT COUNT(*) FROM cases {where}", params).fetchone()[0]
        return {"total": total, "items": [self.case(r[0]) for r in rows], "offset": offset, "limit": limit}

    def review(self, case_id, disposition, comment, actor):
        if actor != "grc" or disposition not in {"approve_follow_up", "reject_suggestion"}:
            raise ValueError("Only the GRC role may make a local review")
        comment = comment.strip()
        if not 5 <= len(comment) <= 2000:
            raise ValueError("Review comments must contain 5..2000 characters")
        self.case(case_id)
        with self.connection() as db:
            if db.execute("SELECT 1 FROM reviews WHERE case_id=?", (case_id,)).fetchone():
                raise ValueError("This case already has a review; prior evidence/reviews are not overwritten")
            db.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (case_id, disposition, comment, actor, utc_now()))
            self.audit(db, actor, "local_review", case_id, {"disposition": disposition, "official_risk_register_write": False})
        return self.case(case_id)["review"]

    def health(self):
        with self.connection() as db:
            return {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ("runs", "cases", "reviews", "audit")}

    def audit_events(self, limit=100):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY sequence DESC LIMIT ?", (limit,))]
