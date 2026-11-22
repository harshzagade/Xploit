"""robots.txt sensitive-path audit: a Disallow entry naming an
admin/backup/config-style path publishes hidden surface in a public file,
so the report notes it as one LOW finding (ROBOTS-001, CWE-200). A missing
file, a non-200 answer, a bare "Disallow: /", or a file with only ordinary
entries flags nothing — near-universal entries such as /login, /search or
/tmp are not leaks.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import LOW


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


class FakeScanner:
    """Minimal scanner stub matching the pattern from test_stage3_context.py.

    ``robots_handler`` decides the robots.txt response from the probed
    URL; every other method returns an empty 200 so the sibling checks
    stay quiet.
    """
    def __init__(self, root="http://x/", robots_handler=None):
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
        self.probe_calls = []
        self.mode = "active"
        self.on_finding = None
        self.robots_handler = robots_handler or (lambda url: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if "/robots.txt" in url:
            self.probe_calls.append(url)
            return self.robots_handler(url)
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


def _run_robots(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_robots_txt()
    return [f for f in scanner.findings if f.id == "ROBOTS-001"]


def _serve_robots(body: str) -> ThreadingHTTPServer:
    """Serve one robots.txt body from a local HTTP server on an ephemeral port."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                data = body.encode()
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
    return server


class TestRobotsTxt:
    def test_sensitive_paths_flag_low(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /backups/\n"
            "Disallow: /config/\n",
            status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert findings[0].severity == LOW
        assert findings[0].category == "Information Disclosure"
        assert findings[0].cwe == "CWE-200"
        assert "/admin/" in findings[0].evidence
        assert "/backups/" in findings[0].evidence
        assert "/config/" in findings[0].evidence
        assert findings[0].url.endswith("/robots.txt")

    def test_disallow_directive_is_case_insensitive(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDISALLOW: /wp-admin/\n",
            status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert "/wp-admin/" in findings[0].evidence

    def test_bare_disallow_slash_does_not_flag(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /\n",
            status_code=200, url=url,
        ))
        assert _run_robots(scanner) == []

    def test_ordinary_entries_do_not_flag(self):
        # /login, /search, /cart and /tmp are near-universal Disallow
        # entries, not leaks — the set stays tight on purpose.
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\n"
            "Disallow: /login\n"
            "Disallow: /search\n"
            "Disallow: /cart\n"
            "Disallow: /tmp/\n"
            "Disallow: /configure\n",
            status_code=200, url=url,
        ))
        assert _run_robots(scanner) == []

    def test_wildcard_pattern_flags(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /*.sql$\n",
            status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert "/*.sql$" in findings[0].evidence

    def test_dotfile_paths_flag(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /.git/\nDisallow: /.env\n",
            status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert "/.git/" in findings[0].evidence
        assert "/.env" in findings[0].evidence

    def test_more_than_five_paths_are_capped(self):
        body = (
            "User-agent: *\n"
            "Disallow: /admin/\nDisallow: /backups/\nDisallow: /config/\n"
            "Disallow: /private/\nDisallow: /staging/\nDisallow: /db/\n"
            "Disallow: /logs/\n"
        )
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            body, status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert "(+2 more)" in findings[0].evidence
        assert "/admin/" in findings[0].evidence
        assert "/logs/" not in findings[0].evidence

    def test_duplicate_disallow_lines_listed_once(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /admin/\nDisallow: /admin/\n",
            status_code=200, url=url,
        ))
        findings = _run_robots(scanner)
        assert len(findings) == 1
        assert findings[0].evidence.count("/admin/") == 1

    def test_missing_file_does_not_flag(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "Not Found", status_code=404, url=url,
        ))
        assert _run_robots(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(robots_handler=lambda url: None)
        assert _run_robots(scanner) == []

    def test_probe_targets_robots_path(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /admin/\n",
            status_code=200, url=url,
        ))
        _run_robots(scanner)
        assert len(scanner.probe_calls) == 1
        assert scanner.probe_calls[0] == "http://x/robots.txt"

    def test_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /admin/\n",
            status_code=200, url=url,
        ))
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.probe_calls == []
        assert [f for f in scanner.findings if f.id == "ROBOTS-001"] == []

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(robots_handler=lambda url: Resp(
            "User-agent: *\nDisallow: /admin/\n",
            status_code=200, url=url,
        ))
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.probe_calls) == 1
        assert [f for f in scanner.findings if f.id == "ROBOTS-001"]

    def test_live_end_to_end_against_local_server(self):
        import requests

        server = _serve_robots(
            "User-agent: *\nDisallow: /admin/\nDisallow: /backups/\n"
        )
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"http://127.0.0.1:{port}/")

            def real_request(method, url, **kwargs):
                return requests.request(method, url, timeout=5)

            scanner._request = real_request
            findings = _run_robots(scanner)
            assert len(findings) == 1
            assert "/admin/" in findings[0].evidence
            assert "/backups/" in findings[0].evidence
        finally:
            server.shutdown()
            server.server_close()
