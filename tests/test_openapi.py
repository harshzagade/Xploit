"""Tests for OpenAPI/Swagger spec seeding of the crawl."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xploit.openapi import extract_openapi_paths
from xploit.scanner import WebScanner

BASE = "http://example.com/"


# --- extract_openapi_paths: unit tests -----------------------------------

def test_openapi3_relative_server_and_templates():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "verbose", "in": "query"}],
                "get": {
                    "parameters": [
                        {"name": "search", "in": "query"},
                        {"name": "verbose", "in": "query"},
                    ]
                },
            },
            "/health": {"get": {}},
        },
    }
    assert extract_openapi_paths(spec, BASE) == [
        "http://example.com/api/v1/users/1?verbose=xploit&search=xploit",
        "http://example.com/api/v1/health",
    ]


def test_openapi3_server_variable_default_and_enum():
    spec = {
        "servers": [{
            "url": "{protocol}://api.example.com/{version}",
            "variables": {
                "protocol": {"default": "https"},
                "version": {"enum": ["v2", "v1"]},
            },
        }],
        "paths": {"/items": {"get": {}}},
    }
    assert extract_openapi_paths(spec, BASE) == [
        "https://api.example.com/v2/items",
    ]


def test_openapi3_unresolvable_server_falls_back_to_base():
    spec = {
        "servers": [{"url": "{missing}/api"}],
        "paths": {"/items": {"get": {}}},
    }
    assert extract_openapi_paths(spec, BASE) == ["http://example.com/items"]


def test_swagger2_host_scheme_basepath():
    spec = {
        "swagger": "2.0",
        "host": "api.example.com",
        "schemes": ["https"],
        "basePath": "/v1",
        "paths": {"/users/{userId}": {"get": {}}},
    }
    assert extract_openapi_paths(spec, BASE) == [
        "https://api.example.com/v1/users/1",
    ]


def test_malformed_specs_yield_empty():
    assert extract_openapi_paths(None, BASE) == []
    assert extract_openapi_paths([], BASE) == []
    assert extract_openapi_paths({"paths": "nope"}, BASE) == []
    assert extract_openapi_paths({"paths": {}}, BASE) == []
    assert extract_openapi_paths(
        {"paths": {"": {"get": {}}, "/ok": "not a dict"}}, BASE) == []


def test_duplicate_paths_deduped_first_wins():
    spec = {"paths": {
        "/a": {"get": {}},
        "/a": {"get": {}},  # noqa: F601 — same key, kept for clarity
    }}
    assert extract_openapi_paths(spec, BASE) == ["http://example.com/a"]


def test_non_query_parameters_ignored():
    spec = {"paths": {"/items": {"get": {
        "parameters": [
            {"name": "id", "in": "path"},
            {"name": "token", "in": "header"},
            {"name": "q", "in": "query"},
        ],
    }}}}
    assert extract_openapi_paths(spec, BASE) == [
        "http://example.com/items?q=xploit",
    ]


# --- scanner integration -------------------------------------------------

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


def test_discovery_seeds_spec_paths_and_filters_off_origin():
    spec = json.dumps({
        "servers": [{"url": "/api"}],
        "paths": {
            "/users/{id}": {"get": {}},
            "/admin": {"get": {}},
        },
    })
    scanner = _scanner_with_spec(spec)
    found = scanner._discover_entry_points()
    assert "http://example.com/api/users/1" in found
    assert "http://example.com/api/admin" in found


def test_discovery_drops_off_origin_server_urls():
    spec = json.dumps({
        "servers": [{"url": "http://other.example/api"}],
        "paths": {"/users": {"get": {}}},
    })
    scanner = _scanner_with_spec(spec)
    found = scanner._discover_entry_points()
    assert not any("other.example" in u for u in found)


def test_discovery_survives_broken_spec_json():
    scanner = _scanner_with_spec("{broken json")
    found = scanner._discover_entry_points()
    assert found == [BASE]


def test_discovery_applies_exclude_patterns_to_seeded_urls():
    spec = json.dumps({
        "servers": [{"url": "/api"}],
        "paths": {"/users": {"get": {}}, "/logout": {"get": {}}},
    })
    scanner = _scanner_with_spec(spec)
    scanner._exclude_res = scanner._compile_exclude_patterns(["logout"])
    scanner.exclude = ["logout"]
    found = scanner._discover_entry_points()
    assert "http://example.com/api/users" in found
    assert not any("logout" in u for u in found)


# --- live fixture: spec served over HTTP ---------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/openapi.json":
            body = json.dumps({
                "openapi": "3.0.0",
                "servers": [{"url": "/api"}],
                "paths": {"/widgets/{id}": {"get": {}}},
            }).encode()
            self._send(200, "application/json", body)
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_live_spec_seeds_discovery():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5)
        found = scanner._discover_entry_points()
        assert base + "api/widgets/1" in found
    finally:
        server.shutdown()
        server.server_close()
