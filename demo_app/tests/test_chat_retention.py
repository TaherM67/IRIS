"""Clear only one viewer; retain, atomically archive and export durable chat logs."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from backend.storage import Store
from demo_app.chat import TeamChat, retention_deadline


class ChatRetentionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='iris-chat-retention-')
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / 'chat.sqlite3')
        self.now = datetime(2026, 1, 31, 12, 0, tzinfo=timezone.utc)
        self.chat = TeamChat(self.store, clock=lambda:self.now)

    def counts(self):
        with self.store.connection() as db:
            return tuple(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                         for table in ('demo_chat','demo_chat_archive','demo_chat_senders'))

    def test_clear_is_per_account_persists_and_never_deletes_logs(self):
        first = self.chat.send('soc', 'Coordinate with GRC.', username='Abduallah')
        result = self.chat.clear_view('soc', username='Abduallah')
        self.assertEqual(result['cleared_through'], first['id'])
        self.assertTrue(result['logs_preserved'])
        self.assertEqual(self.counts(), (1,0,1))
        self.assertEqual(self.chat.messages('soc', username='Abduallah')['items'], [])
        self.assertEqual(len(self.chat.messages('soc', username='Abdualaziz')['items']), 1)
        self.assertEqual(len(self.chat.messages('admin', username='Taher')['items']), 1)
        reopened = TeamChat(Store(self.store.path), clock=lambda:self.now)
        self.assertEqual(reopened.messages('soc', username='ABDUALLAH')['items'], [])
        next_message = reopened.send('grc','Here is the business context.',username='Ahmed')
        self.assertEqual(reopened.messages('soc',username='Abduallah')['items'], [next_message])
        exported = reopened.export_logs('admin')
        self.assertEqual(len(exported['active_logs']),2)
        self.assertEqual(exported['clear_events'][0]['username'],'Abduallah')

    def test_calendar_deadlines_include_month_end_and_leap_year(self):
        examples = [('2026-01-31T12:00:00+00:00','2026-04-30T12:00:00+00:00'),
                    ('2023-11-30T12:00:00+00:00','2024-02-29T12:00:00+00:00'),
                    ('2026-08-31T12:00:00+00:00','2026-11-30T12:00:00+00:00')]
        for timestamp, expected in examples:
            self.assertEqual(retention_deadline(timestamp).isoformat(),expected)

    def test_logs_not_archived_before_three_months_then_preserved_indefinitely(self):
        sent = self.chat.send('grc','Original <plain text>\nمرحبا',username='Ahmed')
        deadline = retention_deadline(sent['created_at'])
        self.now = deadline - timedelta(microseconds=1)
        self.assertEqual(self.chat.archive_expired(),0)
        self.assertEqual(self.counts(),(1,0,1))
        self.now = deadline
        self.assertEqual(self.chat.archive_expired(),1)
        self.assertEqual(self.counts(),(0,1,0))
        row = self.chat.export_logs('admin')['archived_logs'][0]
        self.assertEqual({key:row[key] for key in sent},sent)
        self.assertEqual(row['retained_until'],deadline.isoformat())
        self.now += timedelta(days=1000)
        self.chat.archive_expired()
        self.assertEqual(self.chat.export_logs('admin')['archived_logs'][0]['text'],sent['text'])

    def test_cleared_logs_follow_same_retention_and_new_ids_do_not_reset(self):
        first = self.chat.send('soc','Keep this log.',username='Abduallah')
        self.chat.clear_view('soc',username='Abduallah')
        self.now = retention_deadline(first['created_at'])
        self.chat.archive_expired()
        second = self.chat.send('grc','New message.',username='Ahmed')
        self.assertGreater(second['id'],first['id'])
        self.assertEqual(self.chat.messages('soc',after=0,username='Abduallah')['items'],[second])
        self.assertEqual(len(self.chat.export_logs('admin')['archived_logs']),1)

    def test_archive_transaction_rolls_back_copy_and_removal_together_and_retries(self):
        self.chat.send('soc','First message.',username='Abduallah')
        second = self.chat.send('grc','Second message.',username='Ahmed')
        with self.store.connection() as db:
            db.execute('CREATE TRIGGER fail_archive BEFORE INSERT ON demo_chat_archive '
                       'WHEN NEW.id=' + str(second['id']) + " BEGIN SELECT RAISE(FAIL,'simulated archive failure'); END")
        self.now = retention_deadline(second['created_at'])
        with self.assertRaises(sqlite3.Error):
            self.chat.archive_expired()
        self.assertEqual(self.counts(),(2,0,2))
        self.chat.maintain()
        self.assertTrue(self.chat.archive_warning)
        self.assertEqual(self.counts(),(2,0,2))
        with self.store.connection() as db:
            db.execute('DROP TRIGGER fail_archive')
        self.now += timedelta(hours=1)
        self.chat.maintain()
        self.assertIsNone(self.chat.archive_warning)
        self.assertEqual(self.counts(),(0,2,0))

    def test_startup_catches_up_after_application_was_closed(self):
        first = self.chat.send('soc','Persist across shutdown.',username='Abduallah')
        self.now = retention_deadline(first['created_at'])
        reopened = TeamChat(Store(self.store.path),clock=lambda:self.now)
        self.assertEqual(reopened.messages('admin')['items'],[])
        self.assertEqual(reopened.export_logs('admin')['archived_logs'][0]['text'],first['text'])

    def test_invalid_legacy_timestamp_is_kept_instead_of_guessing_its_age(self):
        with self.store.connection() as db:
            db.execute('INSERT INTO demo_chat(role,text,created_at) VALUES (?,?,?)',('soc','Preserve unknown age','invalid date'))
        self.now += timedelta(days=1000)
        self.chat.archive_expired()
        self.assertEqual(self.counts(),(1,0,0))

    def test_export_is_admin_only_and_snapshot_contains_all_logs_after_clear(self):
        self.chat.send('soc','Retained record.',username='Abduallah')
        self.chat.clear_view('admin',username='Taher')
        for role in ('soc','grc','unknown'):
            with self.assertRaises(PermissionError):
                self.chat.export_logs(role)
        exported = self.chat.export_logs('admin')
        self.assertEqual(len(exported['active_logs']),1)
        self.assertEqual(exported['retention_months'],3)
        self.assertIn('Retained record.',json.dumps(exported))


if __name__ == '__main__':
    unittest.main()
