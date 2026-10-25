"""Small ASGI guard: authenticate before parsing uploads; bound request bodies.

Role keys are for a local lab prototype, not enterprise SSO or individual users.
This module is standard-library-only so its actual ASGI behavior can be tested
even when the FastAPI dependency cannot be installed in the build environment.
"""
from __future__ import annotations

import json
import secrets
from urllib.parse import urlsplit

from .config import Settings


class Guard:
    def __init__(self, app, settings: Settings):
        self.app, self.settings = app, settings

    @staticmethod
    async def reject(send, status, detail):
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode()), (b"x-content-type-options", b"nosniff")
        ]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        pairs = scope.get("headers", [])
        headers = {k.lower(): v for k, v in pairs}
        hosts = [v for k, v in pairs if k.lower() == b"host"]
        try:
            host = hosts[0].decode("ascii").lower() if len(hosts) == 1 else ""
            parsed_host = urlsplit("http://" + host)
            _ = parsed_host.port  # Reject malformed port values too.
            if parsed_host.hostname not in {"127.0.0.1", "localhost", "testserver"} or parsed_host.username or parsed_host.path:
                return await self.reject(send, 400, "This prototype accepts local hostnames only")
            if b"origin" in headers:
                origin = urlsplit(headers[b"origin"].decode("ascii"))
                if origin.scheme not in {"http", "https"} or origin.netloc.lower() != host or origin.username:
                    return await self.reject(send, 403, "Cross-origin access is disabled")
        except (ValueError, UnicodeError):
            return await self.reject(send, 400, "Invalid request origin or host")
        path = scope["path"]
        if path == "/api" or path.startswith("/api/"):
            tokens = [v for k, v in pairs if k.lower() == b"x-iris-key"]
            try:
                token = tokens[0].decode("ascii") if len(tokens) == 1 else ""
            except UnicodeError:
                token = ""
            role = None
            if 32 <= len(token) <= 256:
                for candidate, expected in self.settings.role_keys.items():
                    if secrets.compare_digest(token, expected):
                        role = candidate
            if role is None:
                return await self.reject(send, 401, "A valid X-IRIS-Key is required")
            scope = {**scope, "state": {**scope.get("state", {}), "principal": role}}
            if scope["method"] in {"POST", "PUT", "PATCH"}:
                if b"content-length" in headers:
                    try:
                        length = int(headers[b"content-length"])
                        if length < 0:
                            raise ValueError
                    except ValueError:
                        return await self.reject(send, 400, "Invalid Content-Length")
                    if length > self.settings.max_body_bytes:
                        return await self.reject(send, 413, "Request exceeds the 32 MiB batch limit")
                chunks, size = [], 0
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        return await self.reject(send, 400, "Invalid request body")
                    piece = message.get("body", b"")
                    size += len(piece)
                    if size > self.settings.max_body_bytes:
                        return await self.reject(send, 413, "Request exceeds the batch limit")
                    chunks.append(piece)
                    if not message.get("more_body", False):
                        break
                used = False
                upstream = receive

                async def replay():
                    nonlocal used
                    if not used:
                        used = True
                        return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
                    return await upstream()

                receive = replay

        async def secure_send(message):
            if message["type"] == "http.response.start":
                extra = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                         (b"referrer-policy", b"no-referrer")]
                if path == "/" or path.startswith("/static/"):
                    extra.append((b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

        await self.app(scope, receive, secure_send)
