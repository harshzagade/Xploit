"""GraphQL introspection probe: a server that answers the __schema
introspection query leaks its whole API schema, so the report notes it
as one MEDIUM finding (GQL-001, CWE-200). Only a 200 whose body
parses as JSON carrying data.__schema flags — an errors-only answer,
a non-JSON body, a response without __schema, or a non-200 status
flags nothing. No replayable proof is attached: a --retest replay
cannot reproduce the JSON POST body, so the evidence carries the
exposed type count instead.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import MEDIUM

_INTROSPECTION_QUERY = "{ __schema { types { name } } }"


class Resp:
    """Minimal requests.Response stand-in."""
    def __init__(self, text="", status_code=200, headers=None, url="http://x/"):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()
        # _check_session_cookies reads res.raw.headers.getlist; a plain
        # dict has no getlist, so the fallback branch is taken.
        self.raw = SimpleNamespace(headers={})


def _schema_body(types=("Query", "User", "Post")):
    return json.dumps({
        "data": {
            "__schema": {
                "types": [{"name": name} for name in types],
            },
        },
    })


class FakeScanner:
    """Minimal scanner stub matching the pattern from test_stage3_context.py.

    ``graphql_handler`` decides the POST /graphql response; every other
    request returns an empty 200 so the sibling checks stay quiet.
    """
    def __init__(self, root="http://x/", graphql_handler=None):
        self.root = root
        self.param_hints = {}
        self.findings = []
        self.errors = []
        self._lock = threading.Lock()
        self._finding_keys = set()
        self.timeout = 10
        self.target_profile = {}
        self.pages = {}
        self.forms = []
        self.request_count = 0
        self.post_calls = []
        self.mode = "active"
        self.on_finding = None
        self.graphql_handler = graphql_handler or (lambda url, body: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if method == "POST" and url.endswith("/graphql"):
            body = kwargs.get("json")
            self.post_calls.append((method, url, body))
            return self.graphql_handler(url, body)
        return Resp("")

    def map_probes(self, func, items):
        for item in items:
            func(item)

    def add_finding_deduped(self, finding, key=None):
        with self._lock:
            self.findings.append(finding)

    def gate_and_add(self, finding):
        with self._lock:
            self.findings.append(finding)


def _run_graphql(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_graphql_introspection()
    return [f for f in scanner.findings if f.id == "GQL-001"]


class TestGraphqlIntrospection:
    def test_introspection_answered_flags_medium(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            _schema_body(), status_code=200, url=url,
        ))
        findings = _run_graphql(scanner)
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].category == "Information Disclosure"
        assert findings[0].cwe == "CWE-200"
        assert findings[0].url.endswith("/graphql")
        assert "3 type(s)" in findings[0].evidence
        assert "Query" in findings[0].evidence
        assert "User" in findings[0].evidence

    def test_probe_sends_introspection_query(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            _schema_body(), status_code=200, url=url,
        ))
        _run_graphql(scanner)
        assert len(scanner.post_calls) == 1
        method, url, body = scanner.post_calls[0]
        assert method == "POST"
        assert url == "http://x/graphql"
        assert body == {"query": _INTROSPECTION_QUERY}

    def test_schema_without_types_list_still_flags(self):
        # __schema present but no types array: the schema endpoint is
        # still live; the count is reported as zero.
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            json.dumps({"data": {"__schema": {}}}),
            status_code=200, url=url,
        ))
        findings = _run_graphql(scanner)
        assert len(findings) == 1
        assert "0 type(s)" in findings[0].evidence

    def test_errors_only_answer_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            json.dumps({"errors": [{"message": "Introspection disabled"}]}),
            status_code=200, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_data_without_schema_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            json.dumps({"data": {}}), status_code=200, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_null_data_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            json.dumps({"data": None}), status_code=200, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_non_json_body_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            "<html>not graphql</html>", status_code=200, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_json_list_body_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            "[1, 2, 3]", status_code=200, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_non_200_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            _schema_body(), status_code=400, url=url,
        ))
        assert _run_graphql(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: None)
        assert _run_graphql(scanner) == []

    def test_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            _schema_body(), status_code=200, url=url,
        ))
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.post_calls == []
        assert [f for f in scanner.findings if f.id == "GQL-001"] == []

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(graphql_handler=lambda url, body: Resp(
            _schema_body(), status_code=200, url=url,
        ))
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.post_calls) == 1
        assert [f for f in scanner.findings if f.id == "GQL-001"]

    def test_live_end_to_end_against_local_server(self):
        import requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if self.path == "/graphql":
                    try:
                        payload = json.loads(raw.decode())
                    except ValueError:
                        payload = {}
                    if payload.get("query") == _INTROSPECTION_QUERY:
                        data = _schema_body(("Query", "Account")).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"http://127.0.0.1:{port}/")

            def real_request(method, url, **kwargs):
                # Like test_robots_txt: drop the scanner-only kwargs
                # (quiet) and forward only what requests accepts.
                return requests.request(
                    method, url, timeout=5, json=kwargs.get("json"),
                )

            scanner._request = real_request
            findings = _run_graphql(scanner)
            assert len(findings) == 1
            assert "2 type(s)" in findings[0].evidence
            assert "Account" in findings[0].evidence
        finally:
            server.shutdown()
            server.server_close()
