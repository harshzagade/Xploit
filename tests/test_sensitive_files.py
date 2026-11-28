"""Sensitive-file exposure probe: files such as /.git/HEAD, /.env or
/.git/config that answer 200 with tell-tale content are flagged as one
HIGH finding each (DATA-001, CWE-200). The .git/HEAD probe uses the
real uppercase path — a lowercase /.git/head misses the file on
case-sensitive servers — and its pattern is anchored to the start of
the body, so a page merely mentioning "ref:" in prose flags nothing.
A soft-404 baseline guards against apps that answer 200 for every path.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse

from xploit.modules.exposure import ExposureModule
from xploit.scanner import HIGH


class Resp:
    """Minimal requests.Response stand-in."""
    def __init__(self, text="", status_code=200, headers=None, url="http://x/"):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()
        self.raw = SimpleNamespace(headers={})


class FakeScanner:
    """Minimal scanner stub.

    ``responses`` maps an exact URL path to the Resp (or None) the
    server returns for it; every unlisted path answers 404, and the
    random baseline path answers 404 too, so the soft-404 guard stays
    out of the way.
    """
    def __init__(self, root="http://x/", responses=None):
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
        self.probe_paths = []
        self.mode = "active"
        self.on_finding = None
        self.responses = responses or {}

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        path = urlparse(url).path
        self.probe_paths.append(path)
        return self.responses.get(path, Resp("Not Found", status_code=404, url=url))

    def _in_scope(self, url):
        return True

    def map_probes(self, func, items):
        for item in items:
            func(item)

    def add_finding_deduped(self, finding, key=None):
        with self._lock:
            self.findings.append(finding)

    def gate_and_add(self, finding):
        with self._lock:
            self.findings.append(finding)


def _run_sensitive_files(scanner: FakeScanner):
    module = ExposureModule(scanner)
    module._check_sensitive_files()
    return [f for f in scanner.findings if f.id == "DATA-001"]


class TestSensitiveFiles:
    def test_git_head_exposed_flags_high(self):
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp("ref: refs/heads/main\n", status_code=200),
        })
        findings = _run_sensitive_files(scanner)
        assert len(findings) == 1
        assert findings[0].severity == HIGH
        assert findings[0].name == "Git HEAD Disclosure"
        assert findings[0].category == "Sensitive Data Exposure"
        assert findings[0].cwe == "CWE-200"
        assert findings[0].url.endswith("/.git/HEAD")

    def test_probe_uses_uppercase_head_path(self):
        # The probe must ask for the real /.git/HEAD: a lowercase
        # /.git/head misses the file on case-sensitive servers.
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp("ref: refs/heads/main\n", status_code=200),
        })
        _run_sensitive_files(scanner)
        assert "/.git/HEAD" in scanner.probe_paths
        assert "/.git/head" not in scanner.probe_paths

    def test_case_sensitive_server_flags_only_via_uppercase(self):
        # Server 404s the lowercase path but serves the real file:
        # the old lowercase probe would have missed this entirely.
        scanner = FakeScanner(responses={
            "/.git/head": Resp("Not Found", status_code=404),
            "/.git/HEAD": Resp("ref: refs/heads/main\n", status_code=200),
        })
        assert len(_run_sensitive_files(scanner)) == 1

    def test_ref_not_at_start_does_not_flag(self):
        # The pattern is anchored: "ref:" buried in prose is not a
        # .git/HEAD file.
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp(
                "This page mentions ref: refs/heads/main in passing.\n",
                status_code=200,
            ),
        })
        assert _run_sensitive_files(scanner) == []

    def test_ref_prefix_is_case_insensitive(self):
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp("REF: refs/heads/main\n", status_code=200),
        })
        assert len(_run_sensitive_files(scanner)) == 1

    def test_missing_file_does_not_flag(self):
        scanner = FakeScanner(responses={})
        assert _run_sensitive_files(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(responses={
            "/.git/HEAD": None,
        })
        assert _run_sensitive_files(scanner) == []

    def test_other_sensitive_files_still_probed(self):
        # The table edit touched only the .git/HEAD row: /.env still flags.
        scanner = FakeScanner(responses={
            "/.env": Resp("DB_PASSWORD=hunter2\nAPP_KEY=base64:abc\n",
                          status_code=200),
        })
        findings = _run_sensitive_files(scanner)
        assert len(findings) == 1
        assert findings[0].name == "Environment File Exposure"

    def test_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp("ref: refs/heads/main\n", status_code=200),
        })
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        ExposureModule(scanner).run()
        assert "/.git/HEAD" not in scanner.probe_paths
        assert [f for f in scanner.findings if f.id == "DATA-001"] == []

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(responses={
            "/.git/HEAD": Resp("ref: refs/heads/main\n", status_code=200),
        })
        scanner.pages = {}
        scanner.forms = []
        ExposureModule(scanner).run()
        assert "/.git/HEAD" in scanner.probe_paths
        assert [f for f in scanner.findings if f.id == "DATA-001"]

    def test_live_end_to_end_against_local_server(self):
        import requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.git/HEAD":
                    data = b"ref: refs/heads/main\n"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
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
                # Drop scanner-only kwargs (quiet/allow_redirects is
                # accepted by requests; quiet is not).
                kwargs.pop("quiet", None)
                return requests.request(method, url, timeout=5, **kwargs)

            scanner._request = real_request
            findings = _run_sensitive_files(scanner)
            assert len(findings) == 1
            assert findings[0].name == "Git HEAD Disclosure"
            assert findings[0].url.endswith("/.git/HEAD")
        finally:
            server.shutdown()
            server.server_close()
