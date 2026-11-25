"""X-HTTP-Method-Override test: a server that routes a POST carrying
X-HTTP-Method-Override: PUT/DELETE as that method is flagged (MTHD-001,
method confusion that bypasses method-based access control). A control
POST (no header) and one override POST per method go to the root URL;
an override is honored only when the response differs from the control
in status AND either names the overridden method (word-boundary match,
so "INPUT" cannot fake it) or reaches a 2xx answer the control did not.
A server that ignores the header, or a header-echo page whose status
never changes, is not flagged.
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

    ``post_handler`` decides the POST response from (url, override_method),
    where override_method is the X-HTTP-Method-Override header value or
    None for the control POST. Every other method returns an empty 200 so
    the sibling checks stay quiet.
    """
    def __init__(self, root="http://x/", post_handler=None):
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
        self.post_handler = post_handler or (lambda url, override: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if method == "POST":
            headers = kwargs.get("headers") or {}
            override = headers.get("X-HTTP-Method-Override")
            self.post_calls.append((url, override))
            return self.post_handler(url, override)
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


def _run_override(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_method_override()
    return [f for f in scanner.findings if f.id == "MTHD-001"]


def _honoring_server(url, override):
    """A server that routes the override: control POST answers 200, a
    PUT override answers 405 naming the method, a DELETE override
    answers 204 (resource deleted)."""
    if override is None:
        return Resp("ok", status_code=200, url=url)
    if override == "PUT":
        return Resp("Method PUT not allowed here", status_code=405, url=url)
    if override == "DELETE":
        return Resp("", status_code=204, url=url)
    return Resp("ok", status_code=200, url=url)


class TestMethodOverrideFindings:
    def test_put_honored_via_body_mention_flags(self):
        def handler(url, override):
            if override is None:
                return Resp("ok", status_code=200, url=url)
            return Resp("Method PUT not allowed here", status_code=405, url=url)

        scanner = FakeScanner(post_handler=handler)
        findings = _run_override(scanner)
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].cwe == "CWE-650"
        assert findings[0].category == "Security Misconfiguration"
        assert "PUT" in findings[0].evidence
        assert "DELETE" not in findings[0].evidence
        # One control POST + one override POST per method.
        assert len(scanner.post_calls) == 3
        assert scanner.post_calls[0][1] is None
        assert {c[1] for c in scanner.post_calls[1:]} == {"PUT", "DELETE"}

    def test_delete_honored_via_success_status_flags(self):
        def handler(url, override):
            if override is None:
                return Resp("Method Not Allowed", status_code=405, url=url)
            if override == "DELETE":
                return Resp("", status_code=204, url=url)
            return Resp("Method Not Allowed", status_code=405, url=url)

        scanner = FakeScanner(post_handler=handler)
        findings = _run_override(scanner)
        assert len(findings) == 1
        assert "DELETE" in findings[0].evidence

    def test_both_methods_honored_lists_both(self):
        scanner = FakeScanner(post_handler=_honoring_server)
        findings = _run_override(scanner)
        assert len(findings) == 1
        assert "PUT" in findings[0].evidence
        assert "DELETE" in findings[0].evidence

    def test_201_vs_200_flags(self):
        # PUT creating a resource answers 201 where the control POST
        # answers 200: the routing changed even though both are 2xx.
        def handler(url, override):
            if override == "PUT":
                return Resp("", status_code=201, url=url)
            return Resp("ok", status_code=200, url=url)

        scanner = FakeScanner(post_handler=handler)
        assert len(_run_override(scanner)) == 1

    def test_header_ignored_does_not_flag(self):
        scanner = FakeScanner(
            post_handler=lambda url, override: Resp("ok", status_code=200, url=url)
        )
        assert _run_override(scanner) == []

    def test_same_status_with_method_mention_does_not_flag(self):
        # A header-echo page names PUT in the body but never changes the
        # status: the override was not routed as PUT.
        def handler(url, override):
            if override is None:
                return Resp("ok", status_code=200, url=url)
            return Resp(
                "You sent X-HTTP-Method-Override: PUT", status_code=200, url=url
            )

        scanner = FakeScanner(post_handler=handler)
        assert _run_override(scanner) == []

    def test_input_word_does_not_fake_method_mention(self):
        # "INPUT" contains "PUT" but has no word boundary before it.
        def handler(url, override):
            if override is None:
                return Resp("ok", status_code=200, url=url)
            return Resp("invalid INPUT received", status_code=405, url=url)

        scanner = FakeScanner(post_handler=handler)
        assert _run_override(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(post_handler=lambda url, override: None)
        assert _run_override(scanner) == []

    def test_override_failure_does_not_flag(self):
        def handler(url, override):
            if override is None:
                return Resp("ok", status_code=200, url=url)
            return None

        scanner = FakeScanner(post_handler=handler)
        assert _run_override(scanner) == []

    def test_override_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(post_handler=_honoring_server)
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.post_calls == []
        assert [f for f in scanner.findings if f.id == "MTHD-001"] == []

    def test_override_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(post_handler=_honoring_server)
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.post_calls) == 3
        assert [f for f in scanner.findings if f.id == "MTHD-001"]
