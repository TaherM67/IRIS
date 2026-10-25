"""Access regressions using synthetic keys and real loopback HTTP, never models.

Run with ``python -m unittest demo_app.tests.test_access -v``. All listeners,
credentials and configuration paths in these tests belong to temporary fixtures.
"""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import demo
from backend.config import Settings
from demo_app.access import UI_VERSION, access_profile, inspect_access
from demo_app.server import DemoServer


# These deliberately recognizable strings are not credentials for any user demo.
KEYS = {role: f"SYNTHETIC-ACCESS-TEST-{role}-".ljust(48, "0")
        for role in ("admin", "soc", "grc")}


class AccessFixture(unittest.TestCase):
    """Own a private settings object and stop every listener after its test."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="iris-access-test-")
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(Path(self.temp.name) / "state", dict(KEYS))

    def listen(self, server):
        """Start only the supplied fixture server and register bounded cleanup."""
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        self.addCleanup(stop)
        return server.server_port

    def assert_secret_free(self, value):
        """Failure messages may identify a role/profile, but never its token."""
        rendered = json.dumps(value)
        for key in KEYS.values():
            self.assertNotIn(key, rendered)


class AccessEndpointTests(AccessFixture):
    """Exercise the actual request boundary with no demo engine or database."""

    def setUp(self):
        super().setUp()
        # Access routes must need only settings, not inventory or model state.
        self.port = self.listen(DemoServer(("127.0.0.1", 0),
                                          SimpleNamespace(settings=self.settings)))

    def request(self, path, role=None, headers=None, method="GET", body=None):
        """Read a real local JSON response with an optional fixture role key."""
        values = {"X-IRIS-Key": KEYS[role]} if role else {}
        values.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, headers=values, body=body)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    def test_public_info_is_only_a_nonsecret_server_identity(self):
        status, value, headers = self.request("/api/demo/info")
        self.assertEqual(status, 200)
        self.assertEqual(set(value), {"service", "ui_version", "access_profile"})
        self.assertEqual(value["service"], "iris-active-demo")
        self.assertEqual(value["ui_version"], UI_VERSION)
        self.assertEqual(value["access_profile"], access_profile(KEYS))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assert_secret_free(value)

    def test_session_requires_a_valid_key(self):
        self.assertEqual(self.request("/api/demo/session")[0], 401)
        self.assertEqual(self.request("/api/demo/session", headers={
            "X-IRIS-Key": "SYNTHETIC-UNKNOWN-KEY-".ljust(48, "0")})[0], 401)

    def test_each_role_is_derived_from_its_exact_key(self):
        for role in KEYS:
            with self.subTest(role=role):
                status, value, _ = self.request("/api/demo/session", role)
                self.assertEqual(status, 200)
                self.assertEqual(value["role"], role)
                self.assertEqual(value["access_profile"], access_profile(KEYS))
                self.assertLessEqual(set(value), {"role", "service", "ui_version", "access_profile"})
                self.assert_secret_free(value)

    def test_session_query_cannot_promote_the_authenticated_role(self):
        status, value, _ = self.request("/api/demo/session?role=admin", "soc")
        self.assertEqual(status, 422)
        self.assert_secret_free(value)

    def test_public_info_keeps_the_same_origin_boundary(self):
        status, value, _ = self.request("/api/demo/info", headers={
            "Origin": "https://foreign.example"})
        self.assertEqual(status, 403)
        self.assert_secret_free(value)

    def test_public_info_rejects_query_fields(self):
        status, value, _ = self.request("/api/demo/info?role=admin")
        self.assertEqual(status, 422)
        self.assert_secret_free(value)

    def test_access_routes_do_not_offer_a_post_authentication_bypass(self):
        for path in ("/api/demo/info", "/api/demo/session"):
            with self.subTest(path=path):
                status, value, _ = self.request(path, method="POST", body="{}",
                    headers={"Content-Type": "application/json"})
                self.assertEqual(status, 401)
                self.assert_secret_free(value)
                status, value, _ = self.request(path, "soc", method="POST", body="{}",
                    headers={"Content-Type": "application/json"})
                self.assertEqual(status, 404)
                self.assert_secret_free(value)

    def test_doctor_accepts_the_real_matching_server(self):
        result = inspect_access(self.settings, self.port)
        self.assertTrue(result["ok"], result["checks"])
        self.assertIsInstance(result["checks"], list)
        self.assertTrue(result["checks"])
        self.assert_secret_free(result)


class AccessDiagnosticTests(AccessFixture):
    """Controlled foreign/stale servers verify useful, read-only failures."""

    def fake_server(self, info=None, failure_role=None, claimed_role=None,
                    session_profile=None, non_json=False, info_status=200):
        """Serve tiny bounded replies; record every diagnostic method/path."""
        calls = []
        settings = self.settings
        public = {"service": "iris-active-demo", "ui_version": UI_VERSION,
                  "access_profile": access_profile(KEYS)}
        public.update(info or {})

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                calls.append(("GET", self.path))
                status = 200
                if self.path == "/api/demo/info":
                    status, value = info_status, public
                elif self.path == "/api/demo/session":
                    role = next((role for role, key in settings.role_keys.items()
                                 if self.headers.get("X-IRIS-Key") == key), None)
                    if role is None or role == failure_role:
                        status, value = 401, {"detail": "Fixture key rejected"}
                    else:
                        value = {"role": claimed_role or role,
                                 "access_profile": session_profile or access_profile(KEYS)}
                else:
                    status, value = 404, {"detail": "Unexpected fixture route"}
                body = b"not JSON" if non_json else json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if status == 302:
                    self.send_header("Location", "https://foreign.example/never-follow")
                self.end_headers()
                self.wfile.write(body)

        port = self.listen(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        return port, calls

    def test_profile_is_stable_order_independent_and_key_sensitive(self):
        first = access_profile(KEYS)
        self.assertRegex(first, r"^[0-9a-f]{12}$")
        self.assertEqual(first, access_profile(dict(reversed(list(KEYS.items())))))
        changed = {**KEYS, "soc": KEYS["soc"] + "changed"}
        self.assertNotEqual(first, access_profile(changed))
        self.assert_secret_free(first)

    def test_doctor_never_posts_or_reads_business_records(self):
        port, calls = self.fake_server()
        result = inspect_access(self.settings, port)
        self.assertTrue(result["ok"], result["checks"])
        self.assertEqual(calls, [("GET", "/api/demo/info")] +
                         [("GET", "/api/demo/session")] * 3)
        self.assert_secret_free(result)

    def test_wrong_service_is_not_reported_as_working_access(self):
        port, calls = self.fake_server(info={"service": "unrelated-service"})
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assertEqual(calls, [("GET", "/api/demo/info")])
        self.assert_secret_free(result)

    def test_stale_ui_is_not_reported_as_updated_access(self):
        port, _ = self.fake_server(info={"ui_version": "old-fixture-ui"})
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_other_project_profile_is_diagnosed_before_sending_keys(self):
        port, calls = self.fake_server(info={"access_profile": "0" * 12})
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assertEqual(calls, [("GET", "/api/demo/info")])
        self.assert_secret_free(result)

    def test_rejected_role_key_is_not_a_success(self):
        port, _ = self.fake_server(failure_role="soc")
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_incorrect_server_role_is_not_a_success(self):
        port, _ = self.fake_server(claimed_role="admin")
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_changed_session_profile_is_not_a_success(self):
        port, _ = self.fake_server(session_profile="f" * 12)
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_non_json_service_is_a_safe_failure(self):
        port, _ = self.fake_server(non_json=True)
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_stopped_server_is_a_safe_failure(self):
        # A mocked refusal avoids racing another process for an unused port.
        with mock.patch("http.client.HTTPConnection.request", side_effect=ConnectionRefusedError):
            result = inspect_access(self.settings, 8010)
        self.assertFalse(result["ok"])
        self.assert_secret_free(result)

    def test_redirect_does_not_receive_any_role_key(self):
        port, calls = self.fake_server(info_status=302)
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assertEqual(calls, [("GET", "/api/demo/info")])
        self.assert_secret_free(result)

    def test_oversized_public_response_is_rejected_before_authentication(self):
        port, calls = self.fake_server(info={"padding": "x" * 20000})
        result = inspect_access(self.settings, port)
        self.assertFalse(result["ok"])
        self.assertEqual(calls, [("GET", "/api/demo/info")])
        self.assert_secret_free(result)

    def test_invalid_ports_do_not_open_a_connection(self):
        with mock.patch("http.client.HTTPConnection") as connection:
            for port in (0, 65536, -1, True, "8010"):
                with self.subTest(port=port):
                    result = inspect_access(self.settings, port)
                    self.assertFalse(result["ok"])
                    self.assert_secret_free(result)
            connection.assert_not_called()


class AccessCommandTests(AccessFixture):
    """CLI access helpers must not initialize or run the machine-learning engine."""

    def invoke(self, *arguments):
        """Run the launcher in-process with captured output and private fixtures."""
        output = io.StringIO()
        with mock.patch.object(demo, "settings", return_value=self.settings) as settings_call, \
                mock.patch("sys.argv", ["demo.py", *arguments]), \
                mock.patch("demo_app.engine.DemoEngine", side_effect=AssertionError("Engine must not load")), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                demo.main()
                code = 0
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), settings_call

    def test_keys_role_prints_only_the_requested_credential(self):
        code, output, _ = self.invoke("keys", "--role", "soc")
        self.assertEqual(code, 0)
        self.assertIn(KEYS["soc"], output)
        self.assertNotIn(KEYS["admin"], output)
        self.assertNotIn(KEYS["grc"], output)
        self.assertIn(access_profile(KEYS), output)

    def test_doctor_succeeds_without_creating_keys_or_loading_models(self):
        server = DemoServer(("127.0.0.1", 0), SimpleNamespace(settings=self.settings))
        port = self.listen(server)
        code, output, settings_call = self.invoke("doctor", "--port", str(port))
        self.assertEqual(code, 0, output)
        settings_call.assert_called_once_with(create=False)
        self.assert_secret_free(output)

    def test_doctor_failure_exits_nonzero_without_printing_keys(self):
        with mock.patch("demo_app.access.inspect_access", return_value={
                "ok": False, "checks": ["Fixture server not running"]}):
            code, output, settings_call = self.invoke("doctor")
        self.assertNotEqual(code, 0)
        settings_call.assert_called_once_with(create=False)
        self.assert_secret_free(output)


class AccessSettingsTests(AccessFixture):
    """Read private fixture configurations without resetting keys or records."""

    def setUp(self):
        super().setUp()
        self.home = Path(self.temp.name) / "isolated-demo"
        self.access = self.home / "access.json"
        self.patch_home = mock.patch.object(demo, "DEMO_HOME", self.home)
        self.patch_access = mock.patch.object(demo, "ACCESS", self.access)
        self.patch_home.start()
        self.patch_access.start()
        self.addCleanup(self.patch_access.stop)
        self.addCleanup(self.patch_home.stop)

    def seed(self, bom=False):
        """Write only synthetic configuration bytes owned by this test fixture."""
        self.home.mkdir()
        payload = {"role_keys": KEYS, "state_dir": "ignored-generic-state"}
        encoded = json.dumps(payload, indent=2).encode("utf-8") + b"\n"
        self.access.write_bytes((b"\xef\xbb\xbf" if bom else b"") + encoded)

    def test_read_preserves_existing_keys_config_and_database_bytes(self):
        self.seed()
        state = self.home / "state"
        state.mkdir()
        database = state / "iris.sqlite3"
        # A settings read must never open or rewrite even these sentinel bytes.
        database.write_bytes(b"SYNTHETIC-DATABASE-SENTINEL\x00\x01")
        before = (self.access.read_bytes(), database.read_bytes())
        result = demo.settings(create=False)
        self.assertEqual(result.role_keys, KEYS)
        self.assertEqual(result.state_dir, state.resolve())
        self.assertEqual((self.access.read_bytes(), database.read_bytes()), before)

    def test_utf8_bom_is_read_without_rewriting_access_file(self):
        self.seed(bom=True)
        before = self.access.read_bytes()
        result = demo.settings(create=False)
        self.assertEqual(result.role_keys, KEYS)
        self.assertEqual(self.access.read_bytes(), before)
        self.assertFalse((self.home / "state").exists())

    def test_missing_readonly_config_does_not_create_keys_or_directories(self):
        self.assertFalse(self.home.exists())
        with self.assertRaises(ValueError) as caught:
            demo.settings(create=False)
        self.assertFalse(self.home.exists())
        self.assert_secret_free(str(caught.exception))

    def test_malformed_config_fails_safely_without_any_rewrite(self):
        self.home.mkdir()
        invalid = (b"not JSON", b"[]", b'{"role_keys": []}', b'{"role_keys": {}}')
        for content in invalid:
            with self.subTest(content=content):
                self.access.write_bytes(content)
                with self.assertRaises(ValueError) as caught:
                    demo.settings(create=False)
                self.assertEqual(self.access.read_bytes(), content)
                self.assertFalse((self.home / "state").exists())
                self.assert_secret_free(str(caught.exception))


if __name__ == "__main__":
    unittest.main()
