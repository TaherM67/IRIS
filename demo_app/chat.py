"""Persistent shared SOC/GRC conversation, monitored read-only by Admin."""
from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone
import sqlite3
import threading

from backend.model_adapter import utc_now

RETENTION_MONTHS = 3


def retention_deadline(timestamp):
    moment = datetime.fromisoformat(timestamp)
    if moment.tzinfo is None:
        raise ValueError('Chat timestamps must have an explicit timezone')
    moment = moment.astimezone(timezone.utc)
    year, month = divmod(moment.year * 12 + moment.month - 1 + RETENTION_MONTHS, 12)
    month += 1
    return moment.replace(year=year, month=month, day=min(moment.day, calendar.monthrange(year, month)[1]))


def chat_row(row):
    return {key: value for key, value in dict(row).items() if key != 'username' or value is not None}


class TeamChat:
    def __init__(self, store, *, clock=None):
        self.store = store
        self._clock = clock or (lambda: datetime.fromisoformat(utc_now()))
        self._maintenance_lock = threading.Lock()
        self._next_maintenance = None
        self.archive_warning = None
        with store.connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS demo_chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL CHECK(role IN ('soc', 'grc')),
                text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 2000),
                created_at TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS demo_chat_senders (
                message_id INTEGER PRIMARY KEY REFERENCES demo_chat(id),
                username TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS demo_chat_archive (
                id INTEGER PRIMARY KEY,
                role TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                username TEXT,
                archived_at TEXT NOT NULL,
                retained_until TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS demo_chat_views (
                viewer TEXT PRIMARY KEY,
                cleared_through INTEGER NOT NULL,
                cleared_at TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS demo_chat_clear_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                viewer TEXT NOT NULL,
                role TEXT NOT NULL,
                username TEXT,
                cleared_through INTEGER NOT NULL,
                cleared_at TEXT NOT NULL
            )''')
        self.maintain()

    def _now(self):
        return self._clock().astimezone(timezone.utc)

    def maintain(self):
        """Startup/hourly maintenance, also called by the running server loop."""
        now = self._now()
        if self._next_maintenance is not None and now < self._next_maintenance:
            return
        self._next_maintenance = now + timedelta(hours=1)
        try:
            self.archive_expired()
            self.archive_warning = None
        except (sqlite3.Error, OSError, ValueError):
            # The transaction preserves originals on failure. Retry next hour.
            self.archive_warning = 'Archive delayed. Saved message logs are preserved.'

    def archive_expired(self):
        """Atomically move due logs and sender identity to the permanent archive."""
        now = self._now()
        with self._maintenance_lock, self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            # Three calendar months span at least 89 days; check exact deadlines
            # in Python so month ends and leap years cannot shorten retention.
            rows = db.execute('SELECT c.*, s.username FROM demo_chat c LEFT JOIN demo_chat_senders s '
                              'ON s.message_id=c.id WHERE julianday(c.created_at)<=julianday(?) ORDER BY c.id',
                              ((now - timedelta(days=89)).isoformat(),)).fetchall()
            moved = 0
            for row in rows:
                try:
                    deadline = retention_deadline(row['created_at'])
                except ValueError:
                    continue  # Keep an invalid legacy timestamp; never guess its age.
                if deadline > now:
                    continue
                db.execute('INSERT INTO demo_chat_archive '
                           '(id,role,text,created_at,username,archived_at,retained_until) VALUES (?,?,?,?,?,?,?)',
                           (row['id'],row['role'],row['text'],row['created_at'],row['username'],
                            now.isoformat(),deadline.isoformat()))
                db.execute('DELETE FROM demo_chat_senders WHERE message_id=?', (row['id'],))
                db.execute('DELETE FROM demo_chat WHERE id=?', (row['id'],))
                moved += 1
            return moved

    @staticmethod
    def _viewer(actor, username):
        if actor not in {'admin', 'soc', 'grc'}:
            raise PermissionError('A demo role is required to read team chat')
        return 'user:' + username.casefold() if username is not None else 'role:' + actor

    def clear_view(self, actor, *, username=None):
        viewer, now = self._viewer(actor, username), self._now().isoformat()
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT seq FROM sqlite_sequence WHERE name='demo_chat'").fetchone()
            through = row['seq'] if row else 0
            db.execute('INSERT INTO demo_chat_views(viewer,cleared_through,cleared_at) VALUES (?,?,?) '
                       'ON CONFLICT(viewer) DO UPDATE SET cleared_through=excluded.cleared_through, '
                       'cleared_at=excluded.cleared_at', (viewer,through,now))
            db.execute('INSERT INTO demo_chat_clear_events(viewer,role,username,cleared_through,cleared_at) '
                       'VALUES (?,?,?,?,?)', (viewer,actor,username,through,now))
        return {'cleared_through':through, 'cleared_at':now, 'retention_months':RETENTION_MONTHS,
                'logs_preserved':True}

    def export_logs(self, actor):
        if actor != 'admin':
            raise PermissionError('Chat logs require the ADMIN role')
        self.maintain()
        with self.store.connection() as db:
            db.execute('BEGIN')
            active = db.execute('SELECT c.*, s.username FROM demo_chat c LEFT JOIN demo_chat_senders s '
                                'ON s.message_id=c.id ORDER BY c.id').fetchall()
            archive = db.execute('SELECT * FROM demo_chat_archive ORDER BY id').fetchall()
            clears = db.execute('SELECT * FROM demo_chat_clear_events ORDER BY id').fetchall()
        return {'exported_at':self._now().isoformat(), 'retention_months':RETENTION_MONTHS,
                'archive_policy':'Three calendar months, then archived indefinitely',
                'archive_warning':self.archive_warning,
                'active_logs':[chat_row(row) for row in active], 'archived_logs':[chat_row(row) for row in archive],
                'clear_events':[chat_row(row) for row in clears]}

    def messages(self, actor, *, after=None, limit=100, username=None):
        if actor not in {'admin', 'soc', 'grc'}:
            raise PermissionError('A demo role is required to read team chat')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Chat limit must be 1..100')
        if after is not None and (type(after) is not int or not 0 <= after <= 9223372036854775807):
            raise ValueError('Invalid chat cursor')
        self.maintain()
        with self.store.connection() as db:
            db.execute('BEGIN')
            view = db.execute('SELECT * FROM demo_chat_views WHERE viewer=?', (self._viewer(actor,username),)).fetchone()
            cleared = view['cleared_through'] if view else 0
            floor = max(after or 0,cleared)
            if after is None:
                rows = db.execute('SELECT c.*, s.username FROM demo_chat c LEFT JOIN demo_chat_senders s '
                                  'ON s.message_id=c.id WHERE c.id>? ORDER BY c.id DESC LIMIT ?', (cleared,limit)).fetchall()[::-1]
                more = False
            else:
                rows = db.execute('SELECT c.*, s.username FROM demo_chat c LEFT JOIN demo_chat_senders s '
                                  'ON s.message_id=c.id WHERE c.id>? ORDER BY c.id LIMIT ?',
                                  (floor, limit + 1)).fetchall()
                more = len(rows) > limit
                rows = rows[:limit]
        return {'items':[chat_row(row) for row in rows],
                'cursor':rows[-1]['id'] if rows else floor, 'has_more':more,
                'cleared_through':cleared, 'retention_months':RETENTION_MONTHS,
                'archive_warning':self.archive_warning if actor == 'admin' else None}

    def send(self, actor, text, *, username=None):
        if actor not in {'soc', 'grc'}:
            raise PermissionError('Only SOC and GRC can send messages; Admin monitors read-only')
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= 2000:
            raise ValueError('Chat messages must contain 1..2000 characters')
        text = text.strip()
        if any(ord(char) < 32 and char not in '\n\t' for char in text):
            raise ValueError('Invalid control character in chat message')
        self.maintain()
        with self.store.connection() as db:
            now = self._now().isoformat()
            cursor = db.execute('INSERT INTO demo_chat(role,text,created_at) VALUES (?,?,?)', (actor, text, now))
            result = {'id': cursor.lastrowid, 'role': actor, 'text': text, 'created_at': now}
            if username is not None:
                db.execute('INSERT INTO demo_chat_senders(message_id,username) VALUES (?,?)', (cursor.lastrowid, username))
                result['username'] = username
            return result
