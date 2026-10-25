# IRIS EXPLAIN: File purpose: Standard-library, loopback-only HTTP adapter for the active demo; uses the real shared engine but
# IRIS EXPLAIN: is not an internet-facing production web server.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Loopback-only demonstration HTTP adapter, using Python's standard library.

Not an internet-facing or production HTTP service. Reuses the real shared ML
core without depending on the separately prepared FastAPI HTTP stack.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import re to match supported telemetry text or constrained local HTTP paths/arguments.
import re
# IRIS EXPLAIN: Import secrets to generate local role keys and compare them without ordinary equality timing.
import secrets
# IRIS EXPLAIN: Import socket to handle local HTTP connection/timeouts.
import socket
# IRIS EXPLAIN: Import BaseHTTPRequestHandler, ThreadingHTTPServer from http.server to serve or test actual loopback HTTP
# IRIS EXPLAIN: requests using the standard library.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import parse_qs, urlsplit from urllib.parse to parse local HTTP paths, origins and query arguments.
from urllib.parse import parse_qs, urlsplit

# IRIS EXPLAIN: Import BusyError from backend.core to reuse the shared project contract/implementation rather than duplicate it.
from backend.core import BusyError
# IRIS EXPLAIN: Import ConflictError, DemoEngine from .engine to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from .engine import ConflictError, DemoEngine
from .access import public_info

# IRIS EXPLAIN: Store the result of Path(__file__).with_name('static') in STATIC; later lines use this named result.
STATIC = Path(__file__).with_name('static')
# IRIS EXPLAIN: Store 8192 in MAX_BODY; later lines use this named result.
MAX_BODY = 8192


def dashboard_html(role):
    """Compose a fixed, role-specific public page without exposing other panels.

    Only this allowlisted role chooses a server-owned template. There is no
    user-supplied path or HTML, and API access still requires the matching key.
    """
    if role not in {'admin', 'soc', 'grc'}:
        raise ValueError('Unknown dashboard')
    shell = (STATIC / 'index.html').read_text(encoding='utf-8')
    content = (STATIC / f'{role}.html').read_text(encoding='utf-8')
    reviews = (STATIC / 'reviews.html').read_text(encoding='utf-8')
    content = content.replace('<!-- IRIS: reviews -->', reviews)
    # Fixed labels are not interpolated from source data or credentials.
    title = {'admin': 'Admin overview', 'soc': 'SOC workspace', 'grc': 'GRC workspace'}[role]
    description = {'admin': 'Run IRIS and monitor both teams.',
                   'soc': 'Review alerts and approve priority changes.',
                   'grc': 'Review risk updates and maintain the register.'}[role]
    for marker, value in {'{{ROLE}}': role, '{{TITLE}}': title, '{{DESCRIPTION}}': description,
                          '<!-- IRIS: workspace -->': content}.items():
        shell = shell.replace(marker, value)
    return shell.encode('utf-8')


# IRIS EXPLAIN: Class APIError: Local demo HTTP exception carrying an explicit status and safe public message.
class APIError(Exception):
    # IRIS EXPLAIN: Function APIError.__init__: Keep the intended HTTP error status and safe client-facing detail for the local
    # IRIS EXPLAIN: demo boundary.
    # IRIS EXPLAIN: Inputs: status: the explicit HTTP response or saved proposal status; detail: the bounded, safe client-facing
    # IRIS EXPLAIN: error message.
    def __init__(self, status, detail):
        # IRIS EXPLAIN: Store (status, detail) in (self.status, self.detail); later lines use this named result.
        self.status, self.detail = status, detail


# IRIS EXPLAIN: Class DemoServer: Loopback-only threaded demonstration HTTP server, not production infrastructure.
class DemoServer(ThreadingHTTPServer):
    # IRIS EXPLAIN: Store True in daemon_threads; later lines use this named result.
    daemon_threads = True
    # IRIS EXPLAIN: Store 8 in request_queue_size; later lines use this named result.
    request_queue_size = 8

    # IRIS EXPLAIN: Function DemoServer.__init__: Reject non-loopback binding and attach the shared demo engine to the
    # IRIS EXPLAIN: standard-library HTTP server.
    # IRIS EXPLAIN: Inputs: address: the bound loopback host/port; non-loopback hosts are rejected; engine: the existing shared
    # IRIS EXPLAIN: demo/model coordinator instance.
    def __init__(self, address, engine: DemoEngine):
        # IRIS EXPLAIN: Enter this branch only when address[0] != '127.0.0.1'.
        if address[0] != '127.0.0.1':
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('The synthetic demo must bind only
            # IRIS EXPLAIN: to 127.0.0.1'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('The synthetic demo must bind only to 127.0.0.1')
        # IRIS EXPLAIN: Store engine in self.engine; later lines use this named result.
        self.engine = engine
        # IRIS EXPLAIN: Call super().__init__(address, DemoHandler) using the existing explicit arguments.
        super().__init__(address, DemoHandler)


# IRIS EXPLAIN: Class DemoHandler: Bounded local HTTP request/response adapter with key-derived team roles.
class DemoHandler(BaseHTTPRequestHandler):
    # IRIS EXPLAIN: Store 'HTTP/1.0' in protocol_version; later lines use this named result.
    protocol_version = 'HTTP/1.0'
    # IRIS EXPLAIN: Store 'IRIS-Demo' in server_version; later lines use this named result.
    server_version = 'IRIS-Demo'
    # IRIS EXPLAIN: Store '' in sys_version; later lines use this named result.
    sys_version = ''
    # IRIS EXPLAIN: Store 10 in timeout; later lines use this named result.
    timeout = 10

    # IRIS EXPLAIN: Function DemoHandler.log_message: Intentionally suppress default request logging so role keys, body content
    # IRIS EXPLAIN: and query strings are not printed.
    # IRIS EXPLAIN: Inputs: format: the explicit format input used by the unchanged statements below; args: the explicit args
    # IRIS EXPLAIN: input used by the unchanged statements below.
    def log_message(self, format, *args):
        # Role keys, request bodies, and query strings are never printed.
        # IRIS EXPLAIN: Intentionally do nothing in this existing placeholder/no-op branch; no new behavior is added.
        pass

    # IRIS EXPLAIN: Function DemoHandler.send: Serialize a finite JSON or static-byte response and add length, no-store and
    # IRIS EXPLAIN: self-only content/security headers.
    # IRIS EXPLAIN: Inputs: status: the explicit HTTP response or saved proposal status; value: the supplied value to
    # IRIS EXPLAIN: validate/normalize/serialize; content_type: the stated JSON or static-asset media type.
    def send(self, status, value, content_type='application/json; charset=utf-8'):
        # IRIS EXPLAIN: Store the result of json.dumps(value, allow_nan=False).encode() when
        # IRIS EXPLAIN: content_type.startswith('application/json'); otherwise value in body; later lines use this named result.
        body = json.dumps(value, allow_nan=False).encode() if content_type.startswith('application/json') else value
        # IRIS EXPLAIN: Call self.send_response(status): start the HTTP response with the selected status.
        self.send_response(status)
        # IRIS EXPLAIN: Iterate {'Content-Type': content_type, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
        # IRIS EXPLAIN: 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-ref..., binding each item to (key, val);
        # IRIS EXPLAIN: process only the existing observed/fixture collection.
        for key, val in {
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: 'Content-Type': content_type, 'Content-Length': str(len(body)),.
            'Content-Type': content_type, 'Content-Length': str(len(body)),
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',.
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: 'Referrer-Policy': 'no-referrer',.
            'Referrer-Policy': 'no-referrer',
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src
            # IRIS EXPLAIN: 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",.
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            # IRIS EXPLAIN: Continue the current record with Connection; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            'Connection': 'close',
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }.items():
            # IRIS EXPLAIN: Call self.send_header(key, val): add the stated response header.
            self.send_header(key, val)
        # IRIS EXPLAIN: Call self.end_headers(): finish HTTP response headers.
        self.end_headers()
        # IRIS EXPLAIN: Call self.wfile.write(body): write the already prepared payload.
        self.wfile.write(body)

    # IRIS EXPLAIN: Function DemoHandler.boundary: Require the exact local host/port and same-origin browser context, then parse
    # IRIS EXPLAIN: a relative request path to prevent foreign-origin use.
    def boundary(self):
        # IRIS EXPLAIN: Store the result of self.headers.get_all('Host', []) in hosts; later lines use this named result.
        hosts = self.headers.get_all('Host', [])
        # IRIS EXPLAIN: Store {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'} in expected;
        # IRIS EXPLAIN: later lines use this named result.
        expected = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        # IRIS EXPLAIN: Enter this branch only when len(hosts) != 1 or hosts[0].lower() not in expected.
        if len(hosts) != 1 or hosts[0].lower() not in expected:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'Only the exact local demo host
            # IRIS EXPLAIN: and port are accepted'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(400, 'Only the exact local demo host and port are accepted')
        # IRIS EXPLAIN: Store the result of self.headers.get_all('Origin', []) in origins; later lines use this named result.
        origins = self.headers.get_all('Origin', [])
        # IRIS EXPLAIN: Enter this branch only when len(origins) > 1 or (origins and origins[0].lower() != 'http://' +
        # IRIS EXPLAIN: hosts[0].lower()).
        if len(origins) > 1 or (origins and origins[0].lower() != 'http://' + hosts[0].lower()):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(403, 'Cross-origin requests are
            # IRIS EXPLAIN: disabled'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(403, 'Cross-origin requests are disabled')
        # IRIS EXPLAIN: Enter this branch only when self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site'.
        if self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(403, 'Cross-site requests are
            # IRIS EXPLAIN: disabled'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(403, 'Cross-site requests are disabled')
        # IRIS EXPLAIN: Store the result of urlsplit(self.path) in parsed; later lines use this named result.
        parsed = urlsplit(self.path)
        # IRIS EXPLAIN: Enter this branch only when parsed.scheme or parsed.netloc or parsed.fragment.
        if parsed.scheme or parsed.netloc or parsed.fragment:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'Use a local relative request
            # IRIS EXPLAIN: path'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(400, 'Use a local relative request path')
        # IRIS EXPLAIN: Return parsed to the caller; this ends the current function path.
        return parsed

    # IRIS EXPLAIN: Function DemoHandler.authenticate: Require one ASCII local demo key and derive its server-configured role
    # IRIS EXPLAIN: using constant-time comparison.
    def authenticate(self):
        # IRIS EXPLAIN: Store the result of self.headers.get_all('X-IRIS-Key', []) in values; later lines use this named result.
        values = self.headers.get_all('X-IRIS-Key', [])
        # IRIS EXPLAIN: Store values[0] when len(values) == 1; otherwise '' in token; later lines use this named result.
        token = values[0] if len(values) == 1 else ''
        # IRIS EXPLAIN: Enter this branch only when not token.isascii() or not 32 <= len(token) <= 256.
        if not token.isascii() or not 32 <= len(token) <= 256:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(401, 'A valid local demo X-IRIS-Key is
            # IRIS EXPLAIN: required'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(401, 'A valid local demo X-IRIS-Key is required')
        # IRIS EXPLAIN: Iterate self.server.engine.settings.role_keys.items(), binding each item to (role, expected); process
        # IRIS EXPLAIN: only the existing observed/fixture collection.
        for role, expected in self.server.engine.settings.role_keys.items():
            # IRIS EXPLAIN: Enter this branch only when secrets.compare_digest(token, expected).
            if secrets.compare_digest(token, expected):
                # IRIS EXPLAIN: Return role to the caller; this ends the current function path.
                return role
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(401, 'A valid local demo X-IRIS-Key is
        # IRIS EXPLAIN: required'); the caller's existing boundary determines rollback or the HTTP diagnostic.
        raise APIError(401, 'A valid local demo X-IRIS-Key is required')

    # IRIS EXPLAIN: Function DemoHandler.read_json: Reject unsupported transfer framing and oversized/non-JSON commands, read
    # IRIS EXPLAIN: exactly the declared bounded body, and reject duplicate fields/non-finite JSON.
    def read_json(self):
        # IRIS EXPLAIN: Enter this branch only when self.headers.get_all('Transfer-Encoding', []).
        if self.headers.get_all('Transfer-Encoding', []):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'Transfer-Encoding is not
            # IRIS EXPLAIN: supported by this local demo'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise APIError(400, 'Transfer-Encoding is not supported by this local demo')
        # IRIS EXPLAIN: Store the result of self.headers.get_all('Content-Length', []) in lengths; later lines use this named
        # IRIS EXPLAIN: result.
        lengths = self.headers.get_all('Content-Length', [])
        # IRIS EXPLAIN: Enter this branch only when len(lengths) != 1 or not re.fullmatch('[0-9]+', lengths[0]).
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0]):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'One valid Content-Length is
            # IRIS EXPLAIN: required'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(400, 'One valid Content-Length is required')
        # IRIS EXPLAIN: Store int(lengths[0]) in size; later lines use this named result.
        size = int(lengths[0])
        # IRIS EXPLAIN: Enter this branch only when not 0 < size <= MAX_BODY.
        if not 0 < size <= MAX_BODY:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(413, 'Demo commands must contain
            # IRIS EXPLAIN: 1..8192 bytes'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(413, 'Demo commands must contain 1..8192 bytes')
        # IRIS EXPLAIN: Enter this branch only when self.headers.get_content_type() != 'application/json'.
        if self.headers.get_content_type() != 'application/json':
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(415, 'Use application/json'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(415, 'Use application/json')
        # IRIS EXPLAIN: Store the result of self.rfile.read(size) (read the requested chunk) in body; later lines use this named
        # IRIS EXPLAIN: result.
        body = self.rfile.read(size)
        # IRIS EXPLAIN: Enter this branch only when len(body) != size.
        if len(body) != size:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'Incomplete JSON request body');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(400, 'Incomplete JSON request body')
        # IRIS EXPLAIN: Function DemoHandler.pairs: Build a JSON object while rejecting repeated field names instead of silently
        # IRIS EXPLAIN: accepting the last duplicate.
        # IRIS EXPLAIN: Inputs: items: the explicit items input used by the unchanged statements below.
        def pairs(items):
            # IRIS EXPLAIN: Store a mapping containing  in result; later lines use this named result.
            result = {}
            # IRIS EXPLAIN: Iterate items, binding each item to (key, value); process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for key, value in items:
                # IRIS EXPLAIN: Enter this branch only when key in result.
                if key in result:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Duplicate JSON fields are
                    # IRIS EXPLAIN: not allowed'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                    raise ValueError('Duplicate JSON fields are not allowed')
                # IRIS EXPLAIN: Store value in result[key]; later lines use this named result.
                result[key] = value
            # IRIS EXPLAIN: Return result to the caller; this ends the current function path.
            return result
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of json.loads(body.decode('utf-8'), object_pairs_hook=pairs, parse_constant=lambda
            # IRIS EXPLAIN: _: (_ for _ in ()).throw(ValueError('Non-finite JSON... (decode the existing JSON text) in value;
            # IRIS EXPLAIN: later lines use this named result.
            value = json.loads(body.decode('utf-8'), object_pairs_hook=pairs,
                               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                               # IRIS EXPLAIN: arguments/items: parse_constant=lambda _: (_ for _ in
                               # IRIS EXPLAIN: ()).throw(ValueError('Non-finite JSON is invalid'))).
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON is invalid')))
        # IRIS EXPLAIN: Catch (ValueError, UnicodeError); execute the existing error/fallback path rather than silently treating
        # IRIS EXPLAIN: it as success.
        except (ValueError, UnicodeError):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(400, 'Malformed JSON or duplicate
            # IRIS EXPLAIN: fields'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(400, 'Malformed JSON or duplicate fields') from None
        # IRIS EXPLAIN: Enter this branch only when not isinstance(value, dict).
        if not isinstance(value, dict):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'The command must be a JSON
            # IRIS EXPLAIN: object'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(422, 'The command must be a JSON object')
        # IRIS EXPLAIN: Return value to the caller; this ends the current function path.
        return value

    # IRIS EXPLAIN: Function DemoHandler.route: Route only fixed demo/static endpoints, authenticate API calls before body
    # IRIS EXPLAIN: parsing, validate query/body fields and call the existing demo engine methods.
    # IRIS EXPLAIN: Inputs: method: the parsed HTTP verb routed by the local adapter.
    def route(self, method):
        # IRIS EXPLAIN: Store the result of self.boundary() in parsed; later lines use this named result.
        parsed = self.boundary()
        # IRIS EXPLAIN: Store parsed.path in path; later lines use this named result.
        path = parsed.path
        # IRIS EXPLAIN: Enter this branch only when method == 'GET' and path in {'/', '/admin', '/soc', '/grc'}.
        if method == 'GET' and path in {'/', '/admin', '/soc', '/grc'}:
            # Compose only this page's panels; no hidden cross-team tables or
            # Admin controls are sent inside the SOC/GRC HTML response.
            role = path.strip('/') or 'admin'
            return self.send(200, dashboard_html(role), 'text/html; charset=utf-8')
        # IRIS EXPLAIN: Store a mapping containing /demo-static/app.js, /demo-static/style.css in files; later lines use this
        # IRIS EXPLAIN: named result.
        files = {'/demo-static/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                 # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                 # IRIS EXPLAIN: arguments/items: '/demo-static/style.css': ('style.css', 'text/css; charset=utf-8')}.
                 '/demo-static/style.css': ('style.css', 'text/css; charset=utf-8')}
        # IRIS EXPLAIN: Enter this branch only when method == 'GET' and path in files.
        if method == 'GET' and path in files:
            # IRIS EXPLAIN: Store files[path] in (name, kind); later lines use this named result.
            name, kind = files[path]
            # IRIS EXPLAIN: Return the result of self.send(200, (STATIC / name).read_bytes(), kind) (send the already prepared
            # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
            return self.send(200, (STATIC / name).read_bytes(), kind)
        # IRIS EXPLAIN: Enter this branch only when method == 'GET' and path == '/health'.
        if method == 'GET' and path == '/health':
            # IRIS EXPLAIN: Return the result of self.send(200, {'status': 'ok', 'demo_only': True}) (send the already prepared
            # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
            return self.send(200, {'status': 'ok', 'demo_only': True})
        # A public non-secret build/profile label helps diagnose old servers and
        # keys from another extracted folder. It exposes no key or working data.
        if method == 'GET' and path == '/api/demo/info':
            if parsed.query:
                raise APIError(422, 'The demo info endpoint accepts no query fields')
            return self.send(200, public_info(self.server.engine.settings))
        # IRIS EXPLAIN: Enter this branch only when not path.startswith('/api/demo/').
        if not path.startswith('/api/demo/'):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(404, 'Not found'); the caller's
            # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(404, 'Not found')
        # IRIS EXPLAIN: Store the result of self.authenticate() in actor; later lines use this named result.
        actor = self.authenticate()  # Always before reading any mutation body.
        # IRIS EXPLAIN: Store self.server.engine in engine; later lines use this named result.
        engine = self.server.engine
        # IRIS EXPLAIN: Store the result of parse_qs(parsed.query, keep_blank_values=True) in query; later lines use this named
        # IRIS EXPLAIN: result.
        query = parse_qs(parsed.query, keep_blank_values=True)
        # IRIS EXPLAIN: Store the result of {'/api/demo/alerts': {'limit', 'offset', 'changed_only'}, '/api/demo/risks':
        # IRIS EXPLAIN: {'limit', 'offset'}, '/api/demo/proposals': {'status'}}... (read an optional mapping field using its
        # IRIS EXPLAIN: stated fallback) in allowed; later lines use this named result.
        allowed = {'/api/demo/alerts': {'limit', 'offset', 'changed_only'},
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: '/api/demo/risks': {'limit', 'offset'},.
                   '/api/demo/risks': {'limit', 'offset'},
                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                   # IRIS EXPLAIN: arguments/items: '/api/demo/proposals': {'status'}}.get(path, set()).
                   '/api/demo/proposals': {'status'}}.get(path, set())
        # IRIS EXPLAIN: Enter this branch only when set(query) - allowed or any((len(values) != 1 for values in
        # IRIS EXPLAIN: query.values())).
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'Unexpected or duplicate query
            # IRIS EXPLAIN: fields'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise APIError(422, 'Unexpected or duplicate query fields')
        # IRIS EXPLAIN: Function DemoHandler.number: Parse a nonnegative integer query argument, using the route's documented
        # IRIS EXPLAIN: default when absent.
        # IRIS EXPLAIN: Inputs: name: the field, record or test name used for the stated lookup/diagnostic; default: the
        # IRIS EXPLAIN: existing explicit fallback when a field/query value is absent.
        def number(name, default):
            # IRIS EXPLAIN: Store query.get(name, [str(default)])[0] in value; later lines use this named result.
            value = query.get(name, [str(default)])[0]
            # IRIS EXPLAIN: Enter this branch only when not re.fullmatch('[0-9]+', value).
            if not re.fullmatch('[0-9]+', value):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'Pagination fields must be
                # IRIS EXPLAIN: nonnegative integers'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise APIError(422, 'Pagination fields must be nonnegative integers')
            # IRIS EXPLAIN: Return int(value) to the caller; this ends the current function path.
            return int(value)
        # IRIS EXPLAIN: Enter this branch only when method == 'GET'.
        if method == 'GET':
            # Authenticate before returning even a role label. The UI verifies
            # this tiny response before requesting any dashboard records.
            if path == '/api/demo/session':
                return self.send(200, {'role': actor, **public_info(engine.settings)})
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/state'.
            if path == '/api/demo/state':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.status(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.status(actor))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/risks'.
            if path == '/api/demo/risks':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.risks(actor, number('limit', 100), number('offset',
                # IRIS EXPLAIN: 0))) (send the already prepared response/message) to the caller; this ends the current function
                # IRIS EXPLAIN: path.
                return self.send(200, engine.risks(actor, number('limit', 100), number('offset', 0)))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/alerts'.
            if path == '/api/demo/alerts':
                # IRIS EXPLAIN: Store query.get('changed_only', ['false'])[0] in changed; later lines use this named result.
                changed = query.get('changed_only', ['false'])[0]
                # IRIS EXPLAIN: Enter this branch only when changed not in {'true', 'false'}.
                if changed not in {'true', 'false'}:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'changed_only must be
                    # IRIS EXPLAIN: true or false'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                    raise APIError(422, 'changed_only must be true or false')
                # IRIS EXPLAIN: Return the result of self.send(200, engine.alerts(actor, number('limit', 50), number('offset',
                # IRIS EXPLAIN: 0), changed_only=changed == 'true')) (send the already prepared response/message) to the caller;
                # IRIS EXPLAIN: this ends the current function path.
                return self.send(200, engine.alerts(actor, number('limit', 50), number('offset', 0), changed_only=changed == 'true'))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/proposals'.
            if path == '/api/demo/proposals':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.proposals(actor, status=query.get('status',
                # IRIS EXPLAIN: ['pending'])[0])) (send the already prepared response/message) to the caller; this ends the
                # IRIS EXPLAIN: current function path.
                return self.send(200, engine.proposals(actor, status=query.get('status', ['pending'])[0]))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/changes'.
            if path == '/api/demo/changes':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.changes(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.changes(actor))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/audit'.
            if path == '/api/demo/audit':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.audit(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.audit(actor))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/export/risks'.
            if path == '/api/demo/export/risks':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.export_risks(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.export_risks(actor))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/export/alerts'.
            if path == '/api/demo/export/alerts':
                # IRIS EXPLAIN: Return the result of self.send(200, engine.export_alerts(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.export_alerts(actor))
        # IRIS EXPLAIN: Enter this branch only when method == 'POST'.
        if method == 'POST':
            # IRIS EXPLAIN: Store the result of self.read_json() in body; later lines use this named result.
            body = self.read_json()
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/analyze'.
            if path == '/api/demo/analyze':
                # IRIS EXPLAIN: Enter this branch only when body.
                if body:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'Analysis accepts an
                    # IRIS EXPLAIN: empty JSON object only'); the caller's existing boundary determines rollback or the HTTP
                    # IRIS EXPLAIN: diagnostic.
                    raise APIError(422, 'Analysis accepts an empty JSON object only')
                # IRIS EXPLAIN: Return the result of self.send(200, engine.analyze(actor)) (send the already prepared
                # IRIS EXPLAIN: response/message) to the caller; this ends the current function path.
                return self.send(200, engine.analyze(actor))
            # IRIS EXPLAIN: Enter this branch only when path == '/api/demo/exercises'.
            if path == '/api/demo/exercises':
                # IRIS EXPLAIN: Enter this branch only when set(body) != {'label'}.
                if set(body) != {'label'}:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'Only label is
                    # IRIS EXPLAIN: accepted'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                    raise APIError(422, 'Only label is accepted')
                # IRIS EXPLAIN: Return the result of self.send(201, engine.new_exercise(actor, body['label'])) (send the already
                # IRIS EXPLAIN: prepared response/message) to the caller; this ends the current function path.
                return self.send(201, engine.new_exercise(actor, body['label']))
            # IRIS EXPLAIN: Store the result of re.fullmatch('/api/demo/proposals/(PROP-[a-f0-9]{32})/review', path) in match;
            # IRIS EXPLAIN: later lines use this named result.
            match = re.fullmatch(r'/api/demo/proposals/(PROP-[a-f0-9]{32})/review', path)
            # IRIS EXPLAIN: Enter this branch only when match.
            if match:
                # IRIS EXPLAIN: Enter this branch only when set(body) != {'decision', 'reason'}.
                if set(body) != {'decision', 'reason'}:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(422, 'Only decision and reason
                    # IRIS EXPLAIN: are accepted; callers cannot supply a score, priority or role'); the caller's existing
                    # IRIS EXPLAIN: boundary determines rollback or the HTTP diagnostic.
                    raise APIError(422, 'Only decision and reason are accepted; callers cannot supply a score, priority or role')
                # IRIS EXPLAIN: Return the result of self.send(200, engine.review(actor, match[1], body['decision'],
                # IRIS EXPLAIN: body['reason'])) (send the already prepared response/message) to the caller; this ends the
                # IRIS EXPLAIN: current function path.
                return self.send(200, engine.review(actor, match[1], body['decision'], body['reason']))
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising APIError(404, 'Not found'); the caller's existing
        # IRIS EXPLAIN: boundary determines rollback or the HTTP diagnostic.
        raise APIError(404, 'Not found')

    # IRIS EXPLAIN: Function DemoHandler.dispatch: Translate boundary, authorization, stale-state and input failures into
    # IRIS EXPLAIN: bounded HTTP errors; do not expose internal tracebacks to clients.
    # IRIS EXPLAIN: Inputs: method: the parsed HTTP verb routed by the local adapter.
    def dispatch(self, method):
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Call self.route(method) using the existing explicit arguments.
            self.route(method)
        # IRIS EXPLAIN: Catch APIError as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except APIError as exc:
            # IRIS EXPLAIN: Call self.send(exc.status, {'detail': exc.detail}): send the already prepared response/message.
            self.send(exc.status, {'detail': exc.detail})
        # IRIS EXPLAIN: Catch PermissionError as exc; execute the existing error/fallback path rather than silently treating it
        # IRIS EXPLAIN: as success.
        except PermissionError as exc:
            # IRIS EXPLAIN: Call self.send(403, {'detail': str(exc)}): send the already prepared response/message.
            self.send(403, {'detail': str(exc)})
        # IRIS EXPLAIN: Catch (ConflictError, BusyError) as exc; execute the existing error/fallback path rather than silently
        # IRIS EXPLAIN: treating it as success.
        except (ConflictError, BusyError) as exc:
            # IRIS EXPLAIN: Call self.send(409, {'detail': str(exc)}): send the already prepared response/message.
            self.send(409, {'detail': str(exc)})
        # IRIS EXPLAIN: Catch KeyError; execute the existing error/fallback path rather than silently treating it as success.
        except KeyError:
            # IRIS EXPLAIN: Call self.send(404, {'detail': 'Record not found'}): send the already prepared response/message.
            self.send(404, {'detail': 'Record not found'})
        # IRIS EXPLAIN: Catch (ValueError, TypeError); execute the existing error/fallback path rather than silently treating it
        # IRIS EXPLAIN: as success.
        except (ValueError, TypeError):
            # IRIS EXPLAIN: Call self.send(422, {'detail': 'Invalid command or demo input; check the guide and refresh'}): send
            # IRIS EXPLAIN: the already prepared response/message.
            self.send(422, {'detail': 'Invalid command or demo input; check the guide and refresh'})
        # IRIS EXPLAIN: Catch (BrokenPipeError, ConnectionResetError); execute the existing error/fallback path rather than
        # IRIS EXPLAIN: silently treating it as success.
        except (BrokenPipeError, ConnectionResetError):
            # IRIS EXPLAIN: Intentionally do nothing in this existing placeholder/no-op branch; no new behavior is added.
            pass
        # IRIS EXPLAIN: Catch socket.timeout; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except socket.timeout:
            # IRIS EXPLAIN: Call self.send(408, {'detail': 'Request timed out'}): send the already prepared response/message.
            self.send(408, {'detail': 'Request timed out'})
        # IRIS EXPLAIN: Catch Exception; execute the existing error/fallback path rather than silently treating it as success.
        except Exception:
            # IRIS EXPLAIN: Call self.send(500, {'detail': 'Demo action failed; no uncommitted target changes were applied'}):
            # IRIS EXPLAIN: send the already prepared response/message.
            self.send(500, {'detail': 'Demo action failed; no uncommitted target changes were applied'})

    # IRIS EXPLAIN: Function DemoHandler.do_GET: Dispatch read-only HTTP requests through the demo boundary and route table.
    def do_GET(self):
        # IRIS EXPLAIN: Call self.dispatch('GET') using the existing explicit arguments.
        self.dispatch('GET')

    # IRIS EXPLAIN: Function DemoHandler.do_POST: Dispatch authenticated, bounded demo commands; only valid saved approvals can
    # IRIS EXPLAIN: change working records.
    def do_POST(self):
        # IRIS EXPLAIN: Call self.dispatch('POST') using the existing explicit arguments.
        self.dispatch('POST')

    # IRIS EXPLAIN: Function DemoHandler.do_PUT: Reject unsupported mutation methods; PATCH/DELETE/OPTIONS reuse this method and
    # IRIS EXPLAIN: cannot bypass the approved-command routes.
    def do_PUT(self):
        # IRIS EXPLAIN: Call self.send(405, {'detail': 'Method not supported'}): send the already prepared response/message.
        self.send(405, {'detail': 'Method not supported'})

    # IRIS EXPLAIN: Store do_PUT in do_DELETE; later lines use this named result.
    do_DELETE = do_PUT
    # IRIS EXPLAIN: Store do_PUT in do_PATCH; later lines use this named result.
    do_PATCH = do_PUT
    # IRIS EXPLAIN: Store do_PUT in do_OPTIONS; later lines use this named result.
    do_OPTIONS = do_PUT
