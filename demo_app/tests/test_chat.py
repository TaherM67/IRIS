"""Real HTTP chat tests with isolated SQLite; no user records or model run."""
import concurrent.futures
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from backend.storage import Store
from demo_app.chat import TeamChat
from demo_app.server import DemoServer, dashboard_html

KEYS = {role: ('CHAT-TEST-ONLY-' + role).ljust(48, '0') for role in ('admin', 'soc', 'grc')}


class ChatTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='iris-chat-test-')
        self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name) / 'chat.sqlite3')
        engine = SimpleNamespace(store=self.store, settings=SimpleNamespace(role_keys=KEYS))
        self.server = DemoServer(('127.0.0.1', 0), engine)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def request(self, role='soc', method='GET', body=None, query='', extra=None):
        headers = {'X-IRIS-Key': KEYS[role]} if role else {}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body)
        headers.update(extra or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        try:
            connection.request(method, '/api/demo/chat' + query, body, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_both_teams_send_and_admin_sees_same_ordered_conversation(self):
        for role, text in [('soc', 'Investigating identity-server.'), ('grc', 'Please share the alert context.')]:
            status, saved = self.request(role, 'POST', {'text': text})
            self.assertEqual(status, 201)
            self.assertEqual((saved['role'], saved['text']), (role, text))
            self.assertTrue(saved['created_at'])
        snapshots = [self.request(role)[1] for role in KEYS]
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[0], snapshots[2])
        self.assertEqual([row['role'] for row in snapshots[0]['items']], ['soc', 'grc'])

    def test_requires_authentication_for_read_and_send(self):
        for method, body in [('GET', None), ('POST', {'text': 'Not authenticated'})]:
            self.assertEqual(self.request(None, method, body)[0], 401)
            self.assertEqual(self.request(None, method, body, extra={'X-IRIS-Key': 'x' * 48})[0], 401)
        self.assertEqual(self.request()[1]['items'], [])

    def test_admin_is_read_only_and_sender_cannot_be_spoofed(self):
        self.assertEqual(self.request('admin', 'POST', {'text': 'Cannot send'})[0], 403)
        for field in ('role', 'created_at', 'id'):
            self.assertEqual(self.request('soc', 'POST', {'text': 'Forged', field: 'grc'})[0], 422)
        self.assertEqual(self.request()[1]['items'], [])

    def test_rejects_invalid_messages_and_unknown_query_fields(self):
        for text in ('', '  \n ', None, 123, ['text'], 'a' * 2001, 'bad\x00text'):
            self.assertEqual(self.request(body={'text': text}, method='POST')[0], 422)
        for query in ('?after=-1', '?after=x', '?after=1&after=2', '?role=admin', '?limit=0', '?limit=101', '?after=999999999999999999999999'):
            self.assertEqual(self.request(query=query)[0], 422)
        self.assertEqual(self.request(method='POST', body={})[0], 422)
        self.assertEqual(self.request(method='POST', body={'text': 'hello'}, query='?after=0')[0], 422)

    def test_messages_survive_reopening_and_are_plain_text(self):
        text = '<script>alert("test")</script>\nArabic: مرحبا'
        self.assertEqual(self.request(method='POST', body={'text': text})[0], 201)
        reopened = TeamChat(Store(self.store.path))
        self.assertEqual(reopened.messages('admin')['items'][0]['text'], text)

    def test_incremental_delivery_has_no_gaps_and_latest_history_is_bounded(self):
        for index in range(105):
            self.server.chat.send('soc', str(index))
        latest = self.request('admin')[1]
        self.assertEqual(len(latest['items']), 100)
        self.assertEqual(latest['items'][0]['text'], '5')
        first = self.request(query='?after=0&limit=100')[1]
        self.assertTrue(first['has_more'])
        second = self.request(query='?after=' + str(first['cursor']))[1]
        self.assertEqual([m['text'] for m in first['items'] + second['items']], [str(i) for i in range(105)])
        empty = self.request(query='?after=' + str(second['cursor']))[1]
        self.assertEqual(empty['items'], [])
        self.assertEqual(empty['cursor'], second['cursor'])

    def test_concurrent_messages_all_persist_once(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda n: self.request('soc' if n % 2 else 'grc', 'POST', {'text': str(n)}), range(12)))
        self.assertTrue(all(status == 201 for status, _ in results))
        items = self.request('admin')[1]['items']
        self.assertEqual(len({item['id'] for item in items}), 12)
        self.assertEqual({item['text'] for item in items}, {str(n) for n in range(12)})

    def test_cross_origin_posts_are_rejected(self):
        self.assertEqual(self.request(method='POST', body={'text': 'blocked'}, extra={'Origin': 'https://other.example'})[0], 403)
        self.assertEqual(self.request()[1]['items'], [])

    def test_chat_does_not_pollute_command_monitor_or_analysis_audit(self):
        before = self.server.activity.snapshot()
        self.request(method='POST', body={'text': 'Coordination only'})
        self.request('admin')
        self.assertEqual(before, self.server.activity.snapshot())
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], 0)

    def test_every_dashboard_has_chat_and_only_teams_have_a_composer(self):
        for role in KEYS:
            html = dashboard_html(role).decode()
            self.assertIn('id="chat-messages"', html)
            self.assertEqual('id="chat-form"' in html, role != 'admin')
            self.assertEqual('id="chat-readonly"' in html, role == 'admin')
            self.assertIn('id="chat-clear"',html)
            self.assertEqual('id="chat-logs"' in html,role == 'admin')

    def test_clear_endpoint_requires_authentication(self):
        connection = http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        try:
            connection.request('POST','/api/demo/chat/clear','{}',{'Content-Type':'application/json'})
            self.assertEqual(connection.getresponse().status,401)
        finally:
            connection.close()


if __name__ == '__main__':
    unittest.main()
