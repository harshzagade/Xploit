"""Tests for JSON-body injection probing (SQLi/XSS via OpenAPI-declared
JSON request bodies) and the JSON proof replay in retest."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xploit.openapi import JsonTarget, extract_json_targets
from xploit.retest import retest_findings
from xploit.scanner import WebScanner

BASE = "http://example.com/"


# --- extract_json_targets: unit tests ------------------------------------

def test_inline_properties_and_templates():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/users/{id}": {
                "post": {
                    "parameters": [{"name": "verbose", "in": "query"}],
                    "requestBody": {"content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "age": {"type": "integer"},
                        },
                    }}}},
                },
            },
        },
    }
    assert extract_json_targets(spec, BASE) == [
        JsonTarget(url="http://example.com/api/v1/users/1?verbose=xploit",
                   method="POST",
                   fields={"name": "xploit", "age": "xploit"}),
    ]


def test_ref_and_allof_resolution():
    spec = {
        "paths": {
            "/login": {
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/LoginRequest"}}}}},
                "put": {"requestBody": {"content": {"application/json": {
                    "schema": {"allOf": [
                        {"$ref": "#/components/schemas/Base"},
                        {"type": "object", "properties": {
                            "extra": {"type": "string"}}},
                    ]}}}}},
            },
        },
        "components": {"schemas": {
            "LoginRequest": {"type": "object", "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            }},
            "Base": {"type": "object", "properties": {
                "id": {"type": "string"}}},
        }},
    }
    assert extract_json_targets(spec, BASE) == [
        JsonTarget(url="http://example.com/login", method="POST",
                   fields={"username": "xploit", "password": "xploit"}),
        JsonTarget(url="http://example.com/login", method="PUT",
                   fields={"id": "xploit", "extra": "xploit"}),
    ]


def test_get_form_urlencoded_and_missing_body_ignored():
    spec = {"paths": {
        "/a": {"get": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"q": {}}}}}}}},
        "/b": {"post": {"requestBody": {"content": {
            "application/x-www-form-urlencoded": {"schema": {
                "properties": {"f": {}}}}}}}},
        "/c": {"post": {}},
        "/d": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"type": "object"}}}}}},
        "/e": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Missing"}}}}}},
    }}
    assert extract_json_targets(spec, BASE) == []


def test_vendor_json_media_type_accepted():
    spec = {"paths": {"/a": {"patch": {"requestBody": {"content": {
        "application/vnd.api+json": {"schema": {"properties": {
            "data": {}}}}}}}}}}
    assert extract_json_targets(spec, BASE) == [
        JsonTarget(url="http://example.com/a", method="PATCH",
                   fields={"data": "xploit"}),
    ]


def test_malformed_specs_yield_empty():
    assert extract_json_targets(None, BASE) == []
    assert extract_json_targets([], BASE) == []
    assert extract_json_targets({"paths": "nope"}, BASE) == []
    assert extract_json_targets({"paths": {}}, BASE) == []
    assert extract_json_targets(
        {"paths": {"": {"post": {}}, "/ok": "not a dict"}}, BASE) == []


def test_duplicate_operation_deduped():
    # Same (url, method) twice keeps the first field set.
    spec = {"paths": {"/a": {
        "post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"one": {}}}}}}},
    }}}
    # A dict cannot hold the same key twice; emulate the duplicate via two
    # identical specs merged by the scanner instead — here just assert the
    # single target is stable across repeated calls.
    first = extract_json_targets(spec, BASE)
    assert extract_json_targets(spec, BASE) == first
    assert len(first) == 1


# --- scanner integration: discovery populates json_targets ---------------

class _FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _scanner_with_spec(spec_text):
    scanner = WebScanner(BASE, depth=0, timeout=2)

    def fake_request(method, url, **kwargs):
        if url.endswith("/openapi.json"):
            return _FakeResp(200, spec_text)
        if url.endswith("/swagger.json"):
            return _FakeResp(404, "")
        return _FakeResp(404, "")

    scanner._request = fake_request
    return scanner


def test_discovery_collects_json_targets():
    spec = json.dumps({
        "servers": [{"url": "/api"}],
        "paths": {
            "/login": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"properties": {
                    "username": {}, "password": {}}}}}}}},
            "/items": {"get": {}},
        },
    })
    scanner = _scanner_with_spec(spec)
    scanner._discover_entry_points()
    assert scanner.json_targets == [
        JsonTarget(url="http://example.com/api/login", method="POST",
                   fields={"username": "xploit", "password": "xploit"}),
    ]


def test_discovery_drops_off_origin_json_targets():
    spec = json.dumps({
        "servers": [{"url": "http://other.example/api"}],
        "paths": {"/login": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "username": {}}}}}}}}},
    })
    scanner = _scanner_with_spec(spec)
    scanner._discover_entry_points()
    assert scanner.json_targets == []


# --- live fixture: SQLi + XSS through JSON bodies ------------------------

_SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "/api"}],
    "paths": {
        "/login": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            }}}}}}},
        "/comment": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {
                "comment": {"type": "string"},
            }}}}}}},
    },
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/openapi.json":
            self._send(200, "application/json", json.dumps(_SPEC).encode())
        elif self.path == "/":
            # Deliberately NOT text/html: this environment stubs bs4, so
            # an HTML root would make the crawl raise at parse time. The
            # page is still stored (modules iterate page URLs) and the
            # spec seeding below is what the tests exercise.
            self._send(200, "application/json", b'{"status": "ok"}')
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        if self.path == "/api/login":
            username = body.get("username", "")
            if "'" in str(username):
                # Deliberately 200, not 500: requests.Response.__bool__ is
                # .ok, so the modules' `if not res: continue` skips 4xx/5xx
                # responses — a 200 page carrying the error text is the
                # shape the error-based check is built to read.
                self._send(200, "text/plain",
                           b"You have an error in your SQL syntax near '''")
            else:
                self._send(200, "application/json", b'{"ok": true}')
        elif self.path == "/api/comment":
            self._send(200, "application/json",
                       json.dumps({"echo": body.get("comment", "")}).encode())
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _run_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_live_json_sqli_finding_and_proof():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5, modules=["sqli"])
        result = scanner.scan()
        sqli = [f for f in result.findings if f.id == "SQLI-001"]
        assert len(sqli) == 1
        finding = sqli[0]
        assert finding.method == "POST"
        assert finding.parameter == "username"
        assert finding.url == base + "api/login"
        assert finding.verified
        # Proof replays as a JSON body, not urlencoded form data.
        proof_body = json.loads(finding.proof_data)
        assert proof_body["username"] == "'"
        assert proof_body["password"] == "xploit"
    finally:
        server.shutdown()
        server.server_close()


def test_live_json_sqli_retest_confirms():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5, modules=["sqli"])
        result = scanner.scan()
        stats = retest_findings(scanner, result.findings)
        assert stats["confirmed"] == 1
        assert result.findings[0].retest_status == "confirmed"
    finally:
        server.shutdown()
        server.server_close()


def test_live_json_xss_reflection():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5, modules=["xss"])
        result = scanner.scan()
        xss = [f for f in result.findings if f.id == "XSS-003"]
        assert len(xss) == 1
        finding = xss[0]
        assert finding.parameter == "comment"
        assert finding.method == "POST"
        assert finding.severity == "MEDIUM"
        assert finding.verified
        assert json.loads(finding.proof_data)["comment"].startswith("xploit")
    finally:
        server.shutdown()
        server.server_close()


def test_dry_run_lists_json_targets():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5, dry_run=True)
        result = scanner.scan()
        assert result.status == "dry-run"
        json_entries = [e for e in result.entry_points if e["kind"] == "json"]
        assert {"kind": "json", "url": base + "api/login", "method": "POST",
                "parameters": ["password", "username"]} in json_entries
        assert {"kind": "json", "url": base + "api/comment", "method": "POST",
                "parameters": ["comment"]} in json_entries
    finally:
        server.shutdown()
        server.server_close()
