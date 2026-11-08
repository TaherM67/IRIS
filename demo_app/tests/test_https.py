"""Real, verified TLS requests against temporary demo state, never the user DB."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import unittest
from unittest import mock

from backend.config import ROOT
from demo_app.server import DemoServer
from demo_app.tls import server_context
from demo_app.tests.test_demo import Fixture, KEYS

CERT = Path(os.environ.get('IRIS_TEST_TLS_CERT', ROOT / '.local/active_demo/tls/localhost-cert.pem'))
KEY = Path(os.environ.get('IRIS_TEST_TLS_KEY', ROOT / '.local/active_demo/tls/localhost-key.pem'))


class TLSConfigurationTests(unittest.TestCase):
    def test_missing_certificate_fails_instead_of_downgrading(self):
        with self.assertRaisesRegex(ValueError, 'will not fall back to HTTP'):
            server_context(ROOT / '.local/no-such-https-certificate.pem', KEY)

    def test_invalid_cli_certificate_options_fail_before_opening_saved_state(self):
        import demo
        for arguments in (['--cert-file', 'only.pem'], ['--cert-file', 'cert.pem', '--key-file', 'key.pem']):
            with mock.patch('sys.argv', ['demo.py', *arguments]), mock.patch('demo.settings') as settings:
                with mock.patch('sys.stderr'), self.assertRaises(SystemExit) as failure:
                    demo.main()
                self.assertEqual(failure.exception.code, 1)
                settings.assert_not_called()


@unittest.skipUnless(CERT.is_file() and KEY.is_file(),
                     'Generate the local certificate first with scripts/New-LocalHttpsCertificate.ps1')
class HTTPSWorkflowTests(Fixture):
    def setUp(self):
        super().setUp()
        self.server = DemoServer(('127.0.0.1', 0), self.engine, tls_context=server_context(CERT, KEY))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        # Trust this one certificate for the test client only, never the OS.
        self.client_context = ssl.create_default_context(cafile=str(CERT))

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def request(self, path, role='admin', method='GET', body=None, headers=None):
        request_headers = {'X-IRIS-Key': KEYS[role]} if role else {}
        if body is not None:
            body = json.dumps(body)
            request_headers['Content-Type'] = 'application/json'
        request_headers.update(headers or {})
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                                                context=self.client_context, timeout=3)
        try:
            connection.request(method, path, body, request_headers)
            response = connection.getresponse()
            raw = response.read()
            value = json.loads(raw) if response.getheader('Content-Type', '').startswith('application/json') else raw
            return response.status, value
        finally:
            connection.close()

    def test_verified_tls_pages_keys_and_scheme_aware_origin_checks(self):
        for path in ('/admin', '/soc', '/grc', '/demo-static/app.js', '/health'):
            self.assertEqual(self.request(path, None)[0], 200)
        self.assertEqual(self.request('/api/demo/state', None)[0], 401)
        origin = 'https://127.0.0.1:' + str(self.server.server_port)
        self.assertEqual(self.request('/api/demo/state', 'grc', headers={'Origin': origin})[0], 200)
        for invalid in (origin.replace('https:', 'http:'), 'https://evil.example', origin + '0'):
            self.assertEqual(self.request('/api/demo/state', headers={'Origin': invalid})[0], 403)
        self.assertEqual(self.request('/api/demo/state', headers={'Host': 'evil.example'})[0], 400)

    def test_chat_and_role_separation_over_https(self):
        for role in ('soc', 'grc'):
            origin = 'https://127.0.0.1:' + str(self.server.server_port)
            self.assertEqual(self.request('/api/demo/chat', role, 'POST', {'text': role + ' HTTPS test'},
                                          {'Origin': origin})[0], 201)
        self.assertEqual(self.request('/api/demo/chat', 'admin', 'POST', {'text': 'blocked'})[0], 403)
        conversations = [self.request('/api/demo/chat', role)[1] for role in KEYS]
        self.assertEqual(conversations[0], conversations[1])
        self.assertEqual(conversations[0], conversations[2])

    def test_human_approval_and_export_over_https(self):
        proposal = self.proposal('grc')
        path = '/api/demo/proposals/' + proposal['proposal_id'] + '/review'
        payload = {'decision': 'approve', 'reason': 'Reviewed the saved synthetic evidence over verified TLS.'}
        self.assertEqual(self.request(path, 'soc', 'POST', payload)[0], 403)
        self.assertEqual(self.request(path, 'admin', 'POST', payload)[0], 403)
        self.assertEqual(self.request(path, 'grc', 'POST', payload)[0], 200)
        _, register = self.request('/api/demo/risks', 'grc')
        changed = next(row for row in register['items'] if row['risk_id'] == 'DEMO-R001-1')
        self.assertEqual((changed['current_score'], changed['version']), (.8, 2))
        status, exported = self.request('/api/demo/export/risks', 'grc')
        self.assertEqual(status, 200)
        self.assertTrue(exported)

    def test_plain_http_and_untrusted_certificate_are_not_accepted(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            with self.assertRaises((OSError, http.client.HTTPException)):
                connection.request('GET', '/health')
                connection.getresponse()
        finally:
            connection.close()
        # An empty trust store cannot verify this self-signed server.
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                                                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), timeout=2)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connection.request('GET', '/health')
        finally:
            connection.close()

    def test_stalled_handshake_does_not_block_other_clients(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2):
            self.assertEqual(self.request('/health', None)[0], 200)

    def test_certificate_hostname_is_verified(self):
        context = self.client_context
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2) as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname='other.example')


if __name__ == '__main__':
    unittest.main()
