"""Tests for YAML OpenAPI spec seeding (stdlib-only yamlmini parser)."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xploit.openapi import extract_openapi_paths
from xploit.scanner import WebScanner
from xploit.yamlmini import parse_yaml_subset

BASE = "http://example.com/"

YAML_SPEC = """\
openapi: 3.0.0
info:
  title: Widgets API
  version: 1.0.0
servers:
  - url: /api
    description: Main server
paths:
  /widgets/{id}:
    get:
      parameters:
        - name: verbose
          in: query
        - name: token
          in: header
  /health:
    get: {}
"""

SWAGGER_YAML = """\
swagger: "2.0"
host: api.example.com
schemes:
  - https
basePath: /v1
paths:
  /users/{userId}:
    get: {}
"""


# --- parse_yaml_subset: unit tests ---------------------------------------

def test_nested_maps_sequences_and_templates():
    spec = parse_yaml_subset(YAML_SPEC)
    assert spec is not None
    assert spec["openapi"] == "3.0.0"
    assert spec["info"]["title"] == "Widgets API"
    assert spec["servers"] == [
        {"url": "/api", "description": "Main server"}
    ]
    assert extract_openapi_paths(spec, BASE) == [
        "http://example.com/api/widgets/1?verbose=xploit",
        "http://example.com/api/health",
    ]


def test_swagger2_yaml_shape():
    spec = parse_yaml_subset(SWAGGER_YAML)
    assert spec is not None
    assert extract_openapi_paths(spec, BASE) == [
        "https://api.example.com/v1/users/1",
    ]


def test_quoted_keys_and_values():
    text = """\
paths:
  '/users/{id}':
    get:
      parameters:
        - name: "q"
          in: query
servers:
  - url: 'https://api.example.com/v1'
"""
    spec = parse_yaml_subset(text)
    assert spec is not None
    assert extract_openapi_paths(spec, BASE) == [
        "https://api.example.com/v1/users/1?q=xploit",
    ]


def test_flow_collections_and_typed_scalars():
    spec = parse_yaml_subset("""\
openapi: 3.0.0
servers: [{url: /api/{version}, variables: {version: {default: 2}}}]
info: {title: Demo, stable: true, retries: 3, ratio: 1.5, note: null}
paths:
  /items:
    get: {}
""")
    assert spec is not None
    assert spec["info"]["stable"] is True
    assert spec["info"]["retries"] == 3
    assert spec["info"]["ratio"] == 1.5
    assert spec["info"]["note"] is None
    # Numeric server-variable default is stringified by openapi.py.
    assert extract_openapi_paths(spec, BASE) == [
        "http://example.com/api/2/items",
    ]


def test_block_scalars_comments_and_folding():
    spec = parse_yaml_subset("""\
# leading comment
openapi: 3.0.0  # trailing comment
info:
  title: Multi
    line title
  description: |
    first line
    second line
  summary: >
    folded
    text
paths:
  /ping:
    get: {}
""")
    assert spec is not None
    assert spec["info"]["title"] == "Multi line title"
    assert spec["info"]["description"] == "first line\nsecond line\n"
    assert spec["info"]["summary"] == "folded text\n"
    assert extract_openapi_paths(spec, BASE) == ["http://example.com/ping"]


def test_empty_block_scalar_is_empty_string():
    spec = parse_yaml_subset("info:\n  description: |\n  title: T\n")
    assert spec is not None
    assert spec["info"]["description"] == ""
    assert spec["info"]["title"] == "T"


def test_document_markers_and_blank_lines():
    spec = parse_yaml_subset("\n---\nopenapi: 3.0.0\npaths:\n  /a:\n    get: {}\n")
    assert spec is not None
    assert extract_openapi_paths(spec, BASE) == ["http://example.com/a"]


def test_unsupported_constructs_yield_none():
    # Anchors / aliases / tags / explicit keys are outside the subset.
    assert parse_yaml_subset("a: &x 1\nb: *x\n") is None
    assert parse_yaml_subset("a: !custom 1\n") is None
    assert parse_yaml_subset("? complex\n: key\n") is None
    # Tabs in indentation, multi-document files, unterminated quotes.
    assert parse_yaml_subset("a:\n\tb: 1\n") is None
    assert parse_yaml_subset("a: 1\n---\nb: 2\n") is None
    assert parse_yaml_subset('a: "unterminated\n') is None
    assert parse_yaml_subset("a: [1, 2\n") is None
    # Non-dict documents and empty input.
    assert parse_yaml_subset("- a\n- b\n") is None
    assert parse_yaml_subset("just a scalar\n") is None
    assert parse_yaml_subset("") is None
    assert parse_yaml_subset("   \n# only a comment\n") is None


def test_malformed_structure_yields_none():
    # An indented line after a scalar is a YAML continuation, not an
    # error — it folds into the value.
    assert parse_yaml_subset("a: 1\n  bad line\n") == {"a": "1 bad line"}
    # An empty key and a line that is not a mapping at all are errors.
    assert parse_yaml_subset(": value\n") is None
    assert parse_yaml_subset("a: 1\n? complex\n") is None


# --- scanner integration -------------------------------------------------

class _FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _scanner_with_yaml(yaml_text, json_text=None):
    scanner = WebScanner(BASE, depth=0, timeout=2)

    def fake_request(method, url, **kwargs):
        if url.endswith("/openapi.yaml"):
            return _FakeResp(200, yaml_text)
        if url.endswith("/swagger.yaml"):
            return _FakeResp(404, "")
        if url.endswith("/openapi.json"):
            if json_text is None:
                return _FakeResp(404, "")
            return _FakeResp(200, json_text)
        if url.endswith("/swagger.json"):
            return _FakeResp(404, "")
        return _FakeResp(404, "")

    scanner._request = fake_request
    return scanner


def test_discovery_seeds_yaml_spec_paths():
    scanner = _scanner_with_yaml(YAML_SPEC)
    found = scanner._discover_entry_points()
    assert "http://example.com/api/widgets/1?verbose=xploit" in found
    assert "http://example.com/api/health" in found


def test_discovery_survives_broken_yaml():
    scanner = _scanner_with_yaml("a: &x 1\nb: *x\n")
    assert scanner._discover_entry_points() == [BASE]


def test_discovery_prefers_neither_format():
    # JSON and YAML specs both seed when both are served.
    import json
    scanner = _scanner_with_yaml(
        YAML_SPEC,
        json.dumps({"servers": [{"url": "/api"}],
                    "paths": {"/json-only": {"get": {}}}}),
    )
    found = scanner._discover_entry_points()
    assert "http://example.com/api/widgets/1?verbose=xploit" in found
    assert "http://example.com/api/json-only" in found


# --- live fixture: YAML spec served over HTTP ----------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/openapi.yaml":
            body = YAML_SPEC.encode()
            self._send(200, "application/yaml", body)
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_live_yaml_spec_seeds_discovery():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=0, timeout=5)
        found = scanner._discover_entry_points()
        assert base + "api/widgets/1?verbose=xploit" in found
        assert base + "api/health" in found
    finally:
        server.shutdown()
        server.server_close()
