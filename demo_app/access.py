"""Non-secret access identification and read-only local sign-in diagnostics.

No role keys are written, reset, returned publicly or sent outside loopback.
The fingerprint identifies a credential set; it is not a credential itself.
"""
from __future__ import annotations

import hashlib
import http.client
import json

UI_VERSION = '2026.10.25.2'
SERVICE = 'iris-active-demo'


def access_profile(role_keys):
    """Produce the same short ID for the same three keys, regardless of order."""
    encoded = json.dumps(role_keys, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()[:12]


def public_info(settings):
    """Return only safe build/profile labels, never keys, paths or records."""
    return {'service': SERVICE, 'ui_version': UI_VERSION,
            'access_profile': access_profile(settings.role_keys)}


def inspect_access(settings, port=8010):
    """Check the running demo against local credentials without changing state.

    Each request is bounded to three seconds and 16 KiB. We verify the public
    service identity/profile BEFORE sending a key, never follow redirects, and
    use only the explicit IPv4 loopback address. Errors do not echo HTTP bodies
    or credentials. This is a diagnostic, not an authentication bypass.
    """
    checks = []
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return {'ok': False, 'checks': ['Port must be between 1 and 65535.']}

    def get(path, key=None):
        """Read one bounded JSON object from the requested local port."""
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            headers = {'X-IRIS-Key': key} if key else {}
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            content = response.read(16385)
            if len(content) > 16384:
                raise ValueError('Oversized diagnostic response')
            payload = json.loads(content)
            if not isinstance(payload, dict):
                raise ValueError('Expected a diagnostic object')
            return response.status, payload
        finally:
            connection.close()

    try:
        status, info = get('/api/demo/info')
        if status != 200 or info.get('service') != SERVICE:
            return {'ok': False, 'checks': [f'Port {port} is not the updated active demo. Stop the old server and run this folder\'s demo.py.']}
        checks.append(f'Active demo is reachable on 127.0.0.1:{port}.')
        if info.get('ui_version') != UI_VERSION:
            return {'ok': False, 'checks': checks + ['The running server is an older/different build. Restart it from the updated folder.']}
        if info.get('access_profile') != access_profile(settings.role_keys):
            return {'ok': False, 'checks': checks + ['Key profile mismatch: this folder\'s access file differs from the running server. Use the same folder, then restart the server; keep .local.']}
        checks.append('Running server and this folder use the same key profile.')
        for role in ('admin', 'soc', 'grc'):
            status, session = get('/api/demo/session', settings.role_keys[role])
            if (status != 200 or session.get('role') != role or
                    session.get('access_profile') != info['access_profile']):
                return {'ok': False, 'checks': checks + [f'{role.upper()} sign-in failed. Restart the server from this folder and use demo.py keys, not the older backend keys.']}
            checks.append(f'{role.upper()} key accepted with the correct role.')
        return {'ok': True, 'checks': checks}
    except (OSError, http.client.HTTPException):
        return {'ok': False, 'checks': checks + [f'Cannot reach the demo reliably on port {port}. Start python demo.py (or match --port) and keep it running.']}
    except (ValueError, UnicodeError, KeyError):
        return {'ok': False, 'checks': checks + ['This port did not return the updated demo API. Stop the old server and run the updated demo.py.']}
