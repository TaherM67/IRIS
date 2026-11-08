"""Password hashing, per-tab sessions, and actual HTTPS account workflows."""
import copy
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

from demo_app.auth import AccountAuth, AuthenticationError, account_record, write_accounts, IDLE_SECONDS, LIFETIME_SECONDS
from demo_app.server import DemoServer
from demo_app.tests.test_demo import Fixture, KEYS
from demo_app.tests.test_https import CERT, KEY
from demo_app.tls import server_context

NAMES = {'Taher':'admin', 'Abduallah':'soc', 'Abdualaziz':'soc', 'Abduarhman':'grc', 'Ahmed':'grc'}
PASSWORD = 'Synthetic-account-test-only!'
RECORDS = [account_record(name, PASSWORD, role) for name, role in NAMES.items()]


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.auth = AccountAuth(copy.deepcopy(RECORDS), clock=lambda: self.now)

    def login(self, username='Taher', workspace=None):
        return self.auth.login(username, PASSWORD, workspace or NAMES[username])

    def test_all_five_users_have_correct_roles_and_case_insensitive_usernames(self):
        for name, role in NAMES.items():
            session = self.auth.login(name.swapcase(), PASSWORD, role)
            self.assertEqual(self.auth.authenticate(session['access_token']), {'username':name, 'role':role})

    def test_salts_differ_and_password_file_has_no_plaintext_or_old_key(self):
        self.assertEqual(len({row['salt'] for row in RECORDS}), 5)
        self.assertEqual(len({row['password_hash'] for row in RECORDS}), 5)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'users.json'
            write_accounts(path, RECORDS)
            self.assertNotIn(PASSWORD, path.read_text())
            self.assertNotIn('role_keys', path.read_text())
            loaded = AccountAuth.load(path)
            self.assertEqual(loaded.login('Ahmed', PASSWORD, 'grc')['role'], 'grc')
            with self.assertRaises(FileExistsError):
                write_accounts(path, RECORDS)

    def test_invalid_password_unknown_user_and_wrong_workspace_share_error(self):
        messages = []
        for username, password, role in [('Taher','wrong','admin'),('Unknown',PASSWORD,'admin'),('Taher',PASSWORD,'soc')]:
            with self.assertRaises(AuthenticationError) as failure:
                self.auth.login(username, password, role)
            self.assertEqual(failure.exception.status, 401)
            messages.append(failure.exception.detail)
        self.assertEqual(len(set(messages)), 1)
        self.assertFalse(self.auth.sessions)

    def test_logout_revokes_only_one_session_and_tokens_are_not_stored_raw(self):
        first, second = self.login('Abduallah'), self.login('Abdualaziz')
        self.assertNotIn(first['access_token'], self.auth.sessions)
        self.auth.logout(first['access_token'])
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate(first['access_token'])
        self.assertEqual(self.auth.authenticate(second['access_token'])['username'], 'Abdualaziz')

    def test_idle_and_absolute_expiry_and_server_restart(self):
        session = self.login()
        self.now += IDLE_SECONDS
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate(session['access_token'])
        session = self.login()
        start = self.now
        while self.now - start < LIFETIME_SECONDS - 100:
            self.now += 100
            self.auth.authenticate(session['access_token'])
        self.now = start + LIFETIME_SECONDS
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate(session['access_token'])
        fresh = AccountAuth(RECORDS)
        with self.assertRaises(AuthenticationError):
            fresh.authenticate(session['access_token'])

    def test_repeated_failures_are_limited_then_recover(self):
        for _ in range(5):
            with self.assertRaises(AuthenticationError) as failure:
                self.auth.login('Taher', 'wrong', 'admin')
            self.assertEqual(failure.exception.status, 401)
        with self.assertRaises(AuthenticationError) as failure:
            self.login()
        self.assertEqual(failure.exception.status, 429)
        self.assertEqual(self.login('Ahmed')['role'], 'grc')
        self.now += 61
        self.assertEqual(self.login()['role'], 'admin')

    def test_duplicate_accounts_or_invalid_password_records_rejected(self):
        with self.assertRaises(ValueError):
            AccountAuth(RECORDS + [RECORDS[0]])
        bad = copy.deepcopy(RECORDS)
        bad[0]['password_hash'] = '00'
        with self.assertRaises(ValueError):
            AccountAuth(bad)


@unittest.skipUnless(CERT.is_file() and KEY.is_file(), 'Prepare the local HTTPS certificate first')
class AccountHTTPSTests(Fixture):
    def setUp(self):
        super().setUp()
        self.auth = AccountAuth(RECORDS)
        self.server = DemoServer(('127.0.0.1', 0), self.engine, tls_context=server_context(CERT, KEY), auth=self.auth)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval':.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.context = ssl.create_default_context(cafile=str(CERT))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def request(self, path, token=None, method='GET', body=None, headers=None):
        request_headers = {'Authorization':'Bearer ' + token} if token else {}
        if body is not None:
            body = json.dumps(body)
            request_headers['Content-Type'] = 'application/json'
        request_headers.update(headers or {})
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=self.context, timeout=5)
        try:
            connection.request(method, '/api/demo' + path, body, request_headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def login(self, username):
        status, result = self.request('/auth/login', method='POST',
            body={'username':username, 'password':PASSWORD, 'workspace':NAMES[username]})
        self.assertEqual(status, 200, result)
        return result['access_token']

    def test_five_users_login_with_server_assigned_role_and_keys_are_rejected(self):
        for name, role in NAMES.items():
            token = self.login(name)
            status, state = self.request('/state', token)
            self.assertEqual((status, state['user'], state['role']), (200, {'username':name,'role':role}, role))
            self.assertNotIn(PASSWORD, json.dumps(state))
        for old_key in KEYS.values():
            self.assertEqual(self.request('/state', headers={'X-IRIS-Key':old_key})[0], 401)

    def test_login_validation_origins_and_role_separation(self):
        payload = {'username':'Taher','password':PASSWORD,'workspace':'admin'}
        self.assertEqual(self.request('/auth/login', method='POST', body={**payload,'role':'soc'})[0], 422)
        self.assertEqual(self.request('/auth/login', method='POST', body=payload,
                                     headers={'Origin':'https://evil.example'})[0], 403)
        self.assertEqual(self.request('/auth/login', method='POST', body={**payload,'workspace':'soc'})[0], 401)
        soc = self.login('Abduallah')
        self.assertEqual(self.request('/risks', soc)[0], 403)
        grc = self.login('Ahmed')
        self.assertEqual(self.request('/alerts', grc)[0], 403)

    def test_logout_and_session_revocation(self):
        first, second = self.login('Abduallah'), self.login('Abdualaziz')
        self.assertEqual(self.request('/auth/logout', first, 'POST', {})[0], 200)
        self.assertEqual(self.request('/state', first)[0], 401)
        self.assertEqual(self.request('/state', second)[0], 200)

    def test_chat_records_authenticated_username_and_preserves_legacy_rows(self):
        self.server.chat.send('soc', 'Existing team-only message')
        for name in ('Abduallah','Abdualaziz','Abduarhman','Ahmed'):
            token = self.login(name)
            status, saved = self.request('/chat', token, 'POST', {'text':'Test from ' + name})
            self.assertEqual((status,saved['username'],saved['role']), (201,name,NAMES[name]))
            self.assertEqual(self.request('/chat', token, 'POST', {'text':'spoof','username':'Taher'})[0], 422)
        admin = self.login('Taher')
        status, messages = self.request('/chat', admin)
        self.assertEqual(status, 200)
        self.assertNotIn('username', messages['items'][0])
        self.assertEqual({r['username'] for r in messages['items'][1:]}, set(NAMES) - {'Taher'})
        self.assertEqual(self.request('/chat', admin, 'POST', {'text':'blocked'})[0], 403)

    def test_approval_keeps_team_policy_and_records_individual_reviewer(self):
        proposal = self.proposal('grc')
        path = '/proposals/' + proposal['proposal_id'] + '/review'
        body = {'decision':'approve','reason':'Reviewed with an authenticated named GRC account.'}
        self.assertEqual(self.request(path, self.login('Taher'), 'POST', body)[0], 403)
        self.assertEqual(self.request(path, self.login('Abduallah'), 'POST', body)[0], 403)
        self.assertEqual(self.request(path, self.login('Ahmed'), 'POST', body)[0], 200)
        evidence = json.dumps(self.engine.audit('admin'))
        self.assertIn('reviewer_username', evidence)
        self.assertIn('Ahmed', evidence)
        self.assertNotIn(PASSWORD, evidence)

    def test_password_server_cannot_run_without_tls(self):
        with self.assertRaisesRegex(ValueError, 'requires HTTPS'):
            DemoServer(('127.0.0.1', 0), self.engine, auth=self.auth)

    def test_clear_uses_authenticated_user_and_admin_can_export_all_logs(self):
        first, second = self.login('Abduallah'), self.login('Abdualaziz')
        admin = self.login('Taher')
        status,saved = self.request('/chat',first,'POST',{'text':'Keep the original conversation log.'})
        self.assertEqual(status,201)
        for forged in ({'username':'Abdualaziz'},{'scope':'everyone'}):
            self.assertEqual(self.request('/chat/clear',first,'POST',forged)[0],422)
        self.assertEqual(self.request('/chat/clear',first,'POST',{})[0],200)
        self.assertEqual(self.request('/chat',first)[1]['items'],[])
        self.assertEqual(self.request('/chat',second)[1]['items'],[saved])
        replacement = self.login('Abduallah')
        self.assertEqual(self.request('/chat',replacement)[1]['items'],[])
        for token in (first,second,self.login('Ahmed')):
            self.assertEqual(self.request('/chat/logs',token)[0],403)
        status,logs = self.request('/chat/logs',admin)
        self.assertEqual(status,200)
        self.assertEqual(logs['active_logs'],[saved])
        self.assertEqual(logs['clear_events'][0]['username'],'Abduallah')
        self.assertNotIn(PASSWORD,json.dumps(logs))


if __name__ == '__main__':
    unittest.main()
