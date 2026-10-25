# IRIS EXPLAIN: File purpose: ASGI boundary for the earlier FastAPI adapter: local host/origin checks, key-derived roles,
# IRIS EXPLAIN: bounded request bodies, and response security headers.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Small ASGI guard: authenticate before parsing uploads; bound request bodies.

Role keys are for a local lab prototype, not enterprise SSO or individual users.
This module is standard-library-only so its actual ASGI behavior can be tested
even when the FastAPI dependency cannot be installed in the build environment.
"""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import secrets to generate local role keys and compare them without ordinary equality timing.
import secrets
# IRIS EXPLAIN: Import urlsplit from urllib.parse to parse local HTTP paths, origins and query arguments.
from urllib.parse import urlsplit

# IRIS EXPLAIN: Import Settings from .config to reuse the shared project contract/implementation rather than duplicate it.
from .config import Settings


# IRIS EXPLAIN: Class Guard: ASGI middleware authenticating/bounding requests before the earlier FastAPI transport handles them.
class Guard:
    # IRIS EXPLAIN: Function Guard.__init__: Keep the downstream ASGI application and validated local role-key/body-limit
    # IRIS EXPLAIN: settings.
    # IRIS EXPLAIN: Inputs: app: the application instance; settings: validated local credentials, state path and processing
    # IRIS EXPLAIN: bounds.
    def __init__(self, app, settings: Settings):
        # IRIS EXPLAIN: Store (app, settings) in (self.app, self.settings); later lines use this named result.
        self.app, self.settings = app, settings

    # IRIS EXPLAIN: Expose the following helper without an implicit self argument; it uses only the explicit inputs.
    @staticmethod
    # IRIS EXPLAIN: Function Guard.reject: Send a bounded JSON error response with no-store and content-type protection headers.
    # IRIS EXPLAIN: Inputs: send: the downstream ASGI response callback; status: the explicit HTTP response or saved proposal
    # IRIS EXPLAIN: status; detail: the bounded, safe client-facing error message.
    async def reject(send, status, detail):
        # IRIS EXPLAIN: Store the result of json.dumps({'detail': detail}).encode() in body; later lines use this named result.
        body = json.dumps({"detail": detail}).encode()
        # IRIS EXPLAIN: Await send({'type': 'http.response.start', 'status': status, 'headers': [(b'content-type',
        # IRIS EXPLAIN: b'application/json'), (b'cache-control', b'no-store'), (b'content-length...: send the already prepared
        # IRIS EXPLAIN: response/message.
        await send({"type": "http.response.start", "status": status, "headers": [
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: (b"content-type", b"application/json"), (b"cache-control", b"no-store"),.
            (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
            # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
            # IRIS EXPLAIN: (b"content-length", str(len(body)).encode()), (b"x-content-type-options", b"nosniff").
            (b"content-length", str(len(body)).encode()), (b"x-content-type-options", b"nosniff")
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        ]})
        # IRIS EXPLAIN: Await send({'type': 'http.response.body', 'body': body}): send the already prepared response/message.
        await send({"type": "http.response.body", "body": body})

    # IRIS EXPLAIN: Function Guard.__call__: Pass non-HTTP events through; for HTTP validate local host/origin, authenticate API
    # IRIS EXPLAIN: roles before body reads, bound/replay mutations, and add response headers.
    # IRIS EXPLAIN: Inputs: scope: ASGI connection/request metadata; receive: the upstream ASGI input callback; send: the
    # IRIS EXPLAIN: downstream ASGI response callback.
    async def __call__(self, scope, receive, send):
        # IRIS EXPLAIN: Enter this branch only when scope['type'] != 'http'.
        if scope["type"] != "http":
            # IRIS EXPLAIN: Return the awaited result of the result of self.app(scope, receive, send) to the caller; this ends
            # IRIS EXPLAIN: the current function path.
            return await self.app(scope, receive, send)
        # IRIS EXPLAIN: Store the result of scope.get('headers', []) (read an optional mapping field using its stated fallback)
        # IRIS EXPLAIN: in pairs; later lines use this named result.
        pairs = scope.get("headers", [])
        # IRIS EXPLAIN: Store the comprehension {k.lower(): v for k, v in pairs} in headers; later lines use this named result.
        headers = {k.lower(): v for k, v in pairs}
        # IRIS EXPLAIN: Store the comprehension [v for k, v in pairs if k.lower() == b'host'] in hosts; later lines use this
        # IRIS EXPLAIN: named result.
        hosts = [v for k, v in pairs if k.lower() == b"host"]
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Store the result of hosts[0].decode('ascii').lower() when len(hosts) == 1; otherwise '' in host;
            # IRIS EXPLAIN: later lines use this named result.
            host = hosts[0].decode("ascii").lower() if len(hosts) == 1 else ""
            # IRIS EXPLAIN: Store the result of urlsplit('http://' + host) in parsed_host; later lines use this named result.
            parsed_host = urlsplit("http://" + host)
            # IRIS EXPLAIN: Store parsed_host.port in _; later lines use this named result.
            _ = parsed_host.port  # Reject malformed port values too.
            # IRIS EXPLAIN: Enter this branch only when parsed_host.hostname not in {'127.0.0.1', 'localhost', 'testserver'} or
            # IRIS EXPLAIN: parsed_host.username or parsed_host.path.
            if parsed_host.hostname not in {"127.0.0.1", "localhost", "testserver"} or parsed_host.username or parsed_host.path:
                # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 400, 'This prototype accepts local
                # IRIS EXPLAIN: hostnames only') to the caller; this ends the current function path.
                return await self.reject(send, 400, "This prototype accepts local hostnames only")
            # IRIS EXPLAIN: Enter this branch only when b'origin' in headers.
            if b"origin" in headers:
                # IRIS EXPLAIN: Store the result of urlsplit(headers[b'origin'].decode('ascii')) in origin; later lines use this
                # IRIS EXPLAIN: named result.
                origin = urlsplit(headers[b"origin"].decode("ascii"))
                # IRIS EXPLAIN: Enter this branch only when origin.scheme not in {'http', 'https'} or origin.netloc.lower() !=
                # IRIS EXPLAIN: host or origin.username.
                if origin.scheme not in {"http", "https"} or origin.netloc.lower() != host or origin.username:
                    # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 403, 'Cross-origin access is
                    # IRIS EXPLAIN: disabled') to the caller; this ends the current function path.
                    return await self.reject(send, 403, "Cross-origin access is disabled")
        # IRIS EXPLAIN: Catch (ValueError, UnicodeError); execute the existing error/fallback path rather than silently treating
        # IRIS EXPLAIN: it as success.
        except (ValueError, UnicodeError):
            # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 400, 'Invalid request origin or host')
            # IRIS EXPLAIN: to the caller; this ends the current function path.
            return await self.reject(send, 400, "Invalid request origin or host")
        # IRIS EXPLAIN: Store scope['path'] in path; later lines use this named result.
        path = scope["path"]
        # IRIS EXPLAIN: Enter this branch only when path == '/api' or path.startswith('/api/').
        if path == "/api" or path.startswith("/api/"):
            # IRIS EXPLAIN: Store the comprehension [v for k, v in pairs if k.lower() == b'x-iris-key'] in tokens; later lines
            # IRIS EXPLAIN: use this named result.
            tokens = [v for k, v in pairs if k.lower() == b"x-iris-key"]
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Store the result of tokens[0].decode('ascii') when len(tokens) == 1; otherwise '' in token;
                # IRIS EXPLAIN: later lines use this named result.
                token = tokens[0].decode("ascii") if len(tokens) == 1 else ""
            # IRIS EXPLAIN: Catch UnicodeError; execute the existing error/fallback path rather than silently treating it as
            # IRIS EXPLAIN: success.
            except UnicodeError:
                # IRIS EXPLAIN: Store '' in token; later lines use this named result.
                token = ""
            # IRIS EXPLAIN: Store None (no result/value) in role; later lines use this named result.
            role = None
            # IRIS EXPLAIN: Enter this branch only when 32 <= len(token) <= 256.
            if 32 <= len(token) <= 256:
                # IRIS EXPLAIN: Iterate self.settings.role_keys.items(), binding each item to (candidate, expected); process
                # IRIS EXPLAIN: only the existing observed/fixture collection.
                for candidate, expected in self.settings.role_keys.items():
                    # IRIS EXPLAIN: Enter this branch only when secrets.compare_digest(token, expected).
                    if secrets.compare_digest(token, expected):
                        # IRIS EXPLAIN: Store candidate in role; later lines use this named result.
                        role = candidate
            # IRIS EXPLAIN: Enter this branch only when role is None.
            if role is None:
                # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 401, 'A valid X-IRIS-Key is
                # IRIS EXPLAIN: required') to the caller; this ends the current function path.
                return await self.reject(send, 401, "A valid X-IRIS-Key is required")
            # IRIS EXPLAIN: Store a mapping containing state in scope; later lines use this named result.
            scope = {**scope, "state": {**scope.get("state", {}), "principal": role}}
            # IRIS EXPLAIN: Enter this branch only when scope['method'] in {'POST', 'PUT', 'PATCH'}.
            if scope["method"] in {"POST", "PUT", "PATCH"}:
                # IRIS EXPLAIN: Enter this branch only when b'content-length' in headers.
                if b"content-length" in headers:
                    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing
                    # IRIS EXPLAIN: except/finally blocks decide fallback and cleanup.
                    try:
                        # IRIS EXPLAIN: Store int(headers[b'content-length']) in length; later lines use this named result.
                        length = int(headers[b"content-length"])
                        # IRIS EXPLAIN: Enter this branch only when length < 0.
                        if length < 0:
                            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError; the caller's
                            # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
                            raise ValueError
                    # IRIS EXPLAIN: Catch ValueError; execute the existing error/fallback path rather than silently treating it
                    # IRIS EXPLAIN: as success.
                    except ValueError:
                        # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 400, 'Invalid
                        # IRIS EXPLAIN: Content-Length') to the caller; this ends the current function path.
                        return await self.reject(send, 400, "Invalid Content-Length")
                    # IRIS EXPLAIN: Enter this branch only when length > self.settings.max_body_bytes.
                    if length > self.settings.max_body_bytes:
                        # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 413, 'Request exceeds the
                        # IRIS EXPLAIN: 32 MiB batch limit') to the caller; this ends the current function path.
                        return await self.reject(send, 413, "Request exceeds the 32 MiB batch limit")
                # IRIS EXPLAIN: Store ([], 0) in (chunks, size); later lines use this named result.
                chunks, size = [], 0
                # IRIS EXPLAIN: Repeat while True; the block advances the read/window/history state.
                while True:
                    # IRIS EXPLAIN: Store the awaited result of the result of receive() (read the next ASGI request message) in
                    # IRIS EXPLAIN: message; later lines use this named result.
                    message = await receive()
                    # IRIS EXPLAIN: Enter this branch only when message['type'] == 'http.disconnect'.
                    if message["type"] == "http.disconnect":
                        # IRIS EXPLAIN: Exit this function now without an additional result; do not continue into the remaining
                        # IRIS EXPLAIN: branch.
                        return
                    # IRIS EXPLAIN: Enter this branch only when message['type'] != 'http.request'.
                    if message["type"] != "http.request":
                        # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 400, 'Invalid request
                        # IRIS EXPLAIN: body') to the caller; this ends the current function path.
                        return await self.reject(send, 400, "Invalid request body")
                    # IRIS EXPLAIN: Store the result of message.get('body', b'') (read an optional mapping field using its
                    # IRIS EXPLAIN: stated fallback) in piece; later lines use this named result.
                    piece = message.get("body", b"")
                    # IRIS EXPLAIN: Update size using the existing Add operation and len(piece).
                    size += len(piece)
                    # IRIS EXPLAIN: Enter this branch only when size > self.settings.max_body_bytes.
                    if size > self.settings.max_body_bytes:
                        # IRIS EXPLAIN: Return the awaited result of the result of self.reject(send, 413, 'Request exceeds the
                        # IRIS EXPLAIN: batch limit') to the caller; this ends the current function path.
                        return await self.reject(send, 413, "Request exceeds the batch limit")
                    # IRIS EXPLAIN: Call chunks.append(piece): append one item to the working list.
                    chunks.append(piece)
                    # IRIS EXPLAIN: Enter this branch only when not message.get('more_body', False).
                    if not message.get("more_body", False):
                        # IRIS EXPLAIN: Stop the innermost loop on this condition; the surrounding code retains its existing
                        # IRIS EXPLAIN: unresolved/error handling.
                        break
                # IRIS EXPLAIN: Store False in used; later lines use this named result.
                used = False
                # IRIS EXPLAIN: Store receive in upstream; later lines use this named result.
                upstream = receive

                # IRIS EXPLAIN: Function Guard.replay: Replay the already bounded request body exactly once, then delegate later
                # IRIS EXPLAIN: receive calls to the upstream ASGI receiver.
                async def replay():
                    # IRIS EXPLAIN: Use the enclosing function's used state rather than create a new local copy.
                    nonlocal used
                    # IRIS EXPLAIN: Enter this branch only when not used.
                    if not used:
                        # IRIS EXPLAIN: Store True in used; later lines use this named result.
                        used = True
                        # IRIS EXPLAIN: Return a mapping containing type, body, more_body to the caller; this ends the current
                        # IRIS EXPLAIN: function path.
                        return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
                    # IRIS EXPLAIN: Return the awaited result of the result of upstream() to the caller; this ends the current
                    # IRIS EXPLAIN: function path.
                    return await upstream()

                # IRIS EXPLAIN: Store replay in receive; later lines use this named result.
                receive = replay

        # IRIS EXPLAIN: Function Guard.secure_send: Add no-store/content-type/referrer protection and a self-only static-page
        # IRIS EXPLAIN: CSP before forwarding the ASGI response.
        # IRIS EXPLAIN: Inputs: message: the explicit message input used by the unchanged statements below.
        async def secure_send(message):
            # IRIS EXPLAIN: Enter this branch only when message['type'] == 'http.response.start'.
            if message["type"] == "http.response.start":
                # IRIS EXPLAIN: Store [(b'cache-control', b'no-store'), (b'x-content-type-options', b'nosniff'),
                # IRIS EXPLAIN: (b'referrer-policy', b'no-referrer')] in extra; later lines use this named result.
                extra = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                         # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                         # IRIS EXPLAIN: arguments/items: (b"referrer-policy", b"no-referrer")].
                         (b"referrer-policy", b"no-referrer")]
                # IRIS EXPLAIN: Enter this branch only when path == '/' or path.startswith('/static/').
                if path == "/" or path.startswith("/static/"):
                    # IRIS EXPLAIN: Call extra.append((b'content-security-policy', b"default-src 'self'; script-src 'self';
                    # IRIS EXPLAIN: style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'no...: append one
                    # IRIS EXPLAIN: item to the working list.
                    extra.append((b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))
                # IRIS EXPLAIN: Store a mapping containing headers in message; later lines use this named result.
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            # IRIS EXPLAIN: Await send(message): send the already prepared response/message.
            await send(message)

        # IRIS EXPLAIN: Await self.app(scope, receive, secure_send) using the existing explicit arguments.
        await self.app(scope, receive, secure_send)
