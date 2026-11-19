"""HTTP TRACE method detection: a server that answers a TRACE request with
a 2xx status and echoes the request line back in the response body has the
TRACE method live (TRACE-001, cross-site tracing). A 405/501, a 2xx without
an echo, or a page that merely reflects the requested path (no "TRACE ..."
adjacency) is not flagged. The probe path token is the proof marker, so a
--retest replay (TRACE to the same URL) reproduces it.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import MEDIUM


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

    ``trace_handler`` decides the TRACE response from the probed URL; every
    other method returns an empty 200 so the sibling checks stay quiet.
    """
    def __init__(self, root="http://x/", trace_handler=None):
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
        self.trace_calls = []
        self.mode = "active"
        self.on_finding = None
        self.trace_handler = trace_handler or (lambda url: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if method == "TRACE":
            self.trace_calls.append(url)
            return self.trace_handler(url)
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


def _echo_trace(url: str, absolute_form: bool = False) -> Resp:
    """A conforming TRACE echo: the request line (plus headers) in the body."""
    from urllib.parse import urlparse

    path = urlparse(url).path
    request_line = f"TRACE http://x{path} HTTP/1.1" if absolute_form else f"TRACE {path} HTTP/1.1"
    return Resp(
        text=f"{request_line}\r\nHost: x\r\nUser-Agent: Xploit\r\n\r\n",
        status_code=200,
        url=url,
    )


def _run_trace(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_trace_method()
    return [f for f in scanner.findings if f.id == "TRACE-001"]


class TestTraceMethodFindings:
    def test_trace_echo_flags(self):
        scanner = FakeScanner(trace_handler=_echo_trace)
        findings = _run_trace(scanner)
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].cwe == "CWE-693"
        assert findings[0].category == "Security Misconfiguration"
        assert "TRACE" in findings[0].evidence
        # Proof is replayable: TRACE to the same URL echoes the same token.
        assert findings[0].verified is True
        assert findings[0].proof_method == "TRACE"
        assert findings[0].proof_marker in findings[0].proof_url
        assert findings[0].proof_marker in findings[0].url

    def test_absolute_form_echo_flags(self):
        scanner = FakeScanner(
            trace_handler=lambda url: _echo_trace(url, absolute_form=True)
        )
        assert len(_run_trace(scanner)) == 1

    def test_405_does_not_flag(self):
        scanner = FakeScanner(
            trace_handler=lambda url: Resp("Method Not Allowed", status_code=405)
        )
        assert _run_trace(scanner) == []

    def test_501_does_not_flag(self):
        scanner = FakeScanner(
            trace_handler=lambda url: Resp("Not Implemented", status_code=501)
        )
        assert _run_trace(scanner) == []

    def test_200_without_echo_does_not_flag(self):
        scanner = FakeScanner(
            trace_handler=lambda url: Resp(
                "<html><body>hello</body></html>", status_code=200
            )
        )
        assert _run_trace(scanner) == []

    def test_path_reflection_without_trace_adjacency_does_not_flag(self):
        # A page that merely reflects the requested path (404/debug page)
        # must not false-positive: the token is present but never adjacent
        # to the TRACE method name.
        def handler(url):
            from urllib.parse import urlparse

            return Resp(
                f"Page {urlparse(url).path} not found. Supported methods: GET, POST.",
                status_code=200,
                url=url,
            )

        scanner = FakeScanner(trace_handler=handler)
        assert _run_trace(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(trace_handler=lambda url: None)
        assert _run_trace(scanner) == []

    def test_error_status_with_echo_does_not_flag(self):
        # A 403 that happens to echo the request is not a live TRACE method.
        scanner = FakeScanner(
            trace_handler=lambda url: Resp(
                _echo_trace(url).text, status_code=403
            )
        )
        assert _run_trace(scanner) == []

    def test_probe_url_is_unique_per_run(self):
        seen = set()
        for _ in range(5):
            scanner = FakeScanner(trace_handler=_echo_trace)
            _run_trace(scanner)
            assert len(scanner.trace_calls) == 1
            seen.add(scanner.trace_calls[0])
        assert len(seen) == 5

    def test_trace_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(trace_handler=_echo_trace)
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.trace_calls == []
        assert [f for f in scanner.findings if f.id == "TRACE-001"] == []

    def test_trace_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(trace_handler=_echo_trace)
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.trace_calls) == 1
        assert [f for f in scanner.findings if f.id == "TRACE-001"]
