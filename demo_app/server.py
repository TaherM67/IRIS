"""Loopback-only demonstration HTTP adapter, using Python's standard library.

Not an internet-facing or production HTTP service. Reuses the real shared ML
core without depending on the separately prepared FastAPI HTTP stack.
"""
from __future__ import annotations

import json
import re
import secrets
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from backend.core import BusyError
from .engine import ConflictError, DemoEngine

STATIC = Path(__file__).with_name('static')
MAX_BODY = 8192


class APIError(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, engine: DemoEngine):
        if address[0] != '127.0.0.1':
            raise ValueError('The synthetic demo must bind only to 127.0.0.1')
        self.engine = engine
        super().__init__(address, DemoHandler)


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'IRIS-Demo'
    sys_version = ''
    timeout = 10

    def log_message(self, format, *args):
        # Role keys, request bodies, and query strings are never printed.
        pass

    def send(self, status, value, content_type='application/json; charset=utf-8'):
        body = json.dumps(value, allow_nan=False).encode() if content_type.startswith('application/json') else value
        self.send_response(status)
        for key, val in {
            'Content-Type': content_type, 'Content-Length': str(len(body)),
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'Connection': 'close',
        }.items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)

    def boundary(self):
        hosts = self.headers.get_all('Host', [])
        expected = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if len(hosts) != 1 or hosts[0].lower() not in expected:
            raise APIError(400, 'Only the exact local demo host and port are accepted')
        origins = self.headers.get_all('Origin', [])
        if len(origins) > 1 or (origins and origins[0].lower() != 'http://' + hosts[0].lower()):
            raise APIError(403, 'Cross-origin requests are disabled')
        if self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
            raise APIError(403, 'Cross-site requests are disabled')
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise APIError(400, 'Use a local relative request path')
        return parsed

    def authenticate(self):
        values = self.headers.get_all('X-IRIS-Key', [])
        token = values[0] if len(values) == 1 else ''
        if not token.isascii() or not 32 <= len(token) <= 256:
            raise APIError(401, 'A valid local demo X-IRIS-Key is required')
        for role, expected in self.server.engine.settings.role_keys.items():
            if secrets.compare_digest(token, expected):
                return role
        raise APIError(401, 'A valid local demo X-IRIS-Key is required')

    def read_json(self):
        if self.headers.get_all('Transfer-Encoding', []):
            raise APIError(400, 'Transfer-Encoding is not supported by this local demo')
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0]):
            raise APIError(400, 'One valid Content-Length is required')
        size = int(lengths[0])
        if not 0 < size <= MAX_BODY:
            raise APIError(413, 'Demo commands must contain 1..8192 bytes')
        if self.headers.get_content_type() != 'application/json':
            raise APIError(415, 'Use application/json')
        body = self.rfile.read(size)
        if len(body) != size:
            raise APIError(400, 'Incomplete JSON request body')
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError('Duplicate JSON fields are not allowed')
                result[key] = value
            return result
        try:
            value = json.loads(body.decode('utf-8'), object_pairs_hook=pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON is invalid')))
        except (ValueError, UnicodeError):
            raise APIError(400, 'Malformed JSON or duplicate fields') from None
        if not isinstance(value, dict):
            raise APIError(422, 'The command must be a JSON object')
        return value

    def route(self, method):
        parsed = self.boundary()
        path = parsed.path
        if method == 'GET' and path in {'/', '/admin', '/soc', '/grc'}:
            return self.send(200, (STATIC / 'index.html').read_bytes(), 'text/html; charset=utf-8')
        files = {'/demo-static/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                 '/demo-static/style.css': ('style.css', 'text/css; charset=utf-8')}
        if method == 'GET' and path in files:
            name, kind = files[path]
            return self.send(200, (STATIC / name).read_bytes(), kind)
        if method == 'GET' and path == '/health':
            return self.send(200, {'status': 'ok', 'demo_only': True})
        if not path.startswith('/api/demo/'):
            raise APIError(404, 'Not found')
        actor = self.authenticate()  # Always before reading any mutation body.
        engine = self.server.engine
        query = parse_qs(parsed.query, keep_blank_values=True)
        allowed = {'/api/demo/alerts': {'limit', 'offset', 'changed_only'},
                   '/api/demo/risks': {'limit', 'offset'},
                   '/api/demo/proposals': {'status'}}.get(path, set())
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            raise APIError(422, 'Unexpected or duplicate query fields')
        def number(name, default):
            value = query.get(name, [str(default)])[0]
            if not re.fullmatch('[0-9]+', value):
                raise APIError(422, 'Pagination fields must be nonnegative integers')
            return int(value)
        if method == 'GET':
            if path == '/api/demo/state':
                return self.send(200, engine.status(actor))
            if path == '/api/demo/risks':
                return self.send(200, engine.risks(actor, number('limit', 100), number('offset', 0)))
            if path == '/api/demo/alerts':
                changed = query.get('changed_only', ['false'])[0]
                if changed not in {'true', 'false'}:
                    raise APIError(422, 'changed_only must be true or false')
                return self.send(200, engine.alerts(actor, number('limit', 50), number('offset', 0), changed_only=changed == 'true'))
            if path == '/api/demo/proposals':
                return self.send(200, engine.proposals(actor, status=query.get('status', ['pending'])[0]))
            if path == '/api/demo/changes':
                return self.send(200, engine.changes(actor))
            if path == '/api/demo/audit':
                return self.send(200, engine.audit(actor))
            if path == '/api/demo/export/risks':
                return self.send(200, engine.export_risks(actor))
            if path == '/api/demo/export/alerts':
                return self.send(200, engine.export_alerts(actor))
        if method == 'POST':
            body = self.read_json()
            if path == '/api/demo/analyze':
                if body:
                    raise APIError(422, 'Analysis accepts an empty JSON object only')
                return self.send(200, engine.analyze(actor))
            if path == '/api/demo/exercises':
                if set(body) != {'label'}:
                    raise APIError(422, 'Only label is accepted')
                return self.send(201, engine.new_exercise(actor, body['label']))
            match = re.fullmatch(r'/api/demo/proposals/(PROP-[a-f0-9]{32})/review', path)
            if match:
                if set(body) != {'decision', 'reason'}:
                    raise APIError(422, 'Only decision and reason are accepted; callers cannot supply a score, priority or role')
                return self.send(200, engine.review(actor, match[1], body['decision'], body['reason']))
        raise APIError(404, 'Not found')

    def dispatch(self, method):
        try:
            self.route(method)
        except APIError as exc:
            self.send(exc.status, {'detail': exc.detail})
        except PermissionError as exc:
            self.send(403, {'detail': str(exc)})
        except (ConflictError, BusyError) as exc:
            self.send(409, {'detail': str(exc)})
        except KeyError:
            self.send(404, {'detail': 'Record not found'})
        except (ValueError, TypeError):
            self.send(422, {'detail': 'Invalid command or demo input; check the guide and refresh'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except socket.timeout:
            self.send(408, {'detail': 'Request timed out'})
        except Exception:
            self.send(500, {'detail': 'Demo action failed; no uncommitted target changes were applied'})

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def do_PUT(self):
        self.send(405, {'detail': 'Method not supported'})

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_OPTIONS = do_PUT
