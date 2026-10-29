"""Stage 3 tests: judge findings in context.

Covers:
  1. CORS collapse: multiple permissive pages -> one CORS-001 per (host, severity).
  2. Mixed CORS: HIGH page + LOW pages -> exactly 2 findings.
  3. unique_issue_count in ScanResult.to_dict().
  4. Injection skip (advanced_injection, injection_advanced): inert hint -> zero sends.
  5. External-action form guard for both injection modules.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from xploit.modules.advanced_injection import MultiVectorInjectionModule
from xploit.modules.general import GeneralModule
from xploit.modules.injection_advanced import CommandTraversalModule
from xploit.scanner import Finding, HIGH, LOW, MEDIUM, ScanResult


# ---------------------------------------------------------------------------
# Minimal stubs reused across tests
# ---------------------------------------------------------------------------

class Resp:
    """Minimal requests.Response stand-in."""
    def __init__(self, text="", status_code=200, headers=None, url="http://x/"):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()

    def get(self, key, default=None):
        return self.headers.get(key, default)


class FakeScanner:
    """Minimal scanner stub matching the pattern from test_stage2_learning.py."""
    def __init__(self, root="http://x/"):
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
        self.mode = "active"
        self.on_finding = None

    def _request(self, method, url, **kwargs):
        self.request_count += 1
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


# ---------------------------------------------------------------------------
# 1. CORS collapse: 3 wildcard pages -> exactly 1 CORS-001 finding
# ---------------------------------------------------------------------------

class TestCorsCollapse:
    def _run_cors(self, scanner):
        """Run _check_cors on the scanner and return the findings list."""
        module = GeneralModule(scanner)
        module._check_cors()
        return scanner.findings

    def _make_wildcard_scanner(self, urls, root="http://x/"):
        """Return a FakeScanner whose _request replies with ACAO: * for the given URLs."""
        scanner = FakeScanner(root=root)
        # All given URLs are in pages (non-binary, distinct shapes).
        scanner.pages = {u: Resp(headers={"Content-Type": "text/html"}) for u in urls}

        def request_stub(method, url, headers=None, **kwargs):
            if url in urls:
                return Resp(
                    headers={"Access-Control-Allow-Origin": "*"},
                    url=url,
                )
            return Resp("")

        scanner._request = request_stub
        return scanner

    def test_three_wildcard_pages_produce_exactly_one_finding(self):
        urls = ["http://x/a", "http://x/b", "http://x/c"]
        scanner = self._make_wildcard_scanner(urls)
        findings = self._run_cors(scanner)
        cors_findings = [f for f in findings if f.id == "CORS-001"]
        assert len(cors_findings) == 1, (
            f"Expected 1 CORS-001 finding, got {len(cors_findings)}: "
            + str([f.evidence for f in cors_findings])
        )

    def test_collapsed_evidence_mentions_endpoint_count(self):
        urls = ["http://x/a", "http://x/b", "http://x/c"]
        scanner = self._make_wildcard_scanner(urls)
        findings = self._run_cors(scanner)
        cors = [f for f in findings if f.id == "CORS-001"][0]
        assert "3 endpoint" in cors.evidence, f"Expected '3 endpoint' in evidence: {cors.evidence!r}"

    def test_single_wildcard_page_has_no_endpoint_suffix(self):
        """When only 1 endpoint fires, evidence should NOT include the n-endpoints suffix."""
        urls = ["http://x/only"]
        scanner = self._make_wildcard_scanner(urls)
        findings = self._run_cors(scanner)
        cors = [f for f in findings if f.id == "CORS-001"][0]
        assert "endpoint" not in cors.evidence, (
            f"Single-hit evidence should not mention endpoints: {cors.evidence!r}"
        )

    def test_finding_severity_is_low_for_wildcard(self):
        scanner = self._make_wildcard_scanner(["http://x/api"])
        findings = self._run_cors(scanner)
        cors = [f for f in findings if f.id == "CORS-001"][0]
        assert cors.severity == LOW

    # ----- Mixed: 1 HIGH (reflected+credentials) + 2 LOW (wildcard) -> 2 findings -----

    def test_mixed_cors_produces_two_findings_high_and_low(self):
        origin = "https://evil.example"

        high_url = "http://x/admin"
        low_urls = ["http://x/public/a", "http://x/public/b"]

        scanner = FakeScanner(root="http://x/")
        all_urls = [high_url] + low_urls
        scanner.pages = {u: Resp(headers={"Content-Type": "text/html"}) for u in all_urls}

        def request_stub(method, url, headers=None, **kwargs):
            req_origin = (headers or {}).get("Origin", "")
            if url == high_url:
                return Resp(
                    headers={
                        "Access-Control-Allow-Origin": req_origin,
                        "Access-Control-Allow-Credentials": "true",
                    },
                    url=url,
                )
            elif url in low_urls:
                return Resp(
                    headers={"Access-Control-Allow-Origin": "*"},
                    url=url,
                )
            return Resp("")

        scanner._request = request_stub
        module = GeneralModule(scanner)
        module._check_cors()

        cors_findings = [f for f in scanner.findings if f.id == "CORS-001"]
        severities = {f.severity for f in cors_findings}

        assert len(cors_findings) == 2, (
            f"Expected exactly 2 CORS-001 findings (HIGH + LOW), got {len(cors_findings)}: "
            + str([(f.severity, f.evidence) for f in cors_findings])
        )
        assert HIGH in severities, "Expected one HIGH finding"
        assert LOW in severities, "Expected one LOW finding"

    def test_mixed_cors_low_group_evidence_mentions_two_endpoints(self):
        """The LOW group with 2 pages should collapse evidence to mention 2 endpoints."""
        origin = "https://evil.example"
        high_url = "http://x/admin"
        low_urls = ["http://x/public/a", "http://x/public/b"]

        scanner = FakeScanner(root="http://x/")
        all_urls = [high_url] + low_urls
        scanner.pages = {u: Resp(headers={"Content-Type": "text/html"}) for u in all_urls}

        def request_stub(method, url, headers=None, **kwargs):
            req_origin = (headers or {}).get("Origin", "")
            if url == high_url:
                return Resp(headers={"Access-Control-Allow-Origin": req_origin,
                                     "Access-Control-Allow-Credentials": "true"}, url=url)
            elif url in low_urls:
                return Resp(headers={"Access-Control-Allow-Origin": "*"}, url=url)
            return Resp("")

        scanner._request = request_stub
        module = GeneralModule(scanner)
        module._check_cors()

        low_finding = next(
            (f for f in scanner.findings if f.id == "CORS-001" and f.severity == LOW), None
        )
        assert low_finding is not None
        assert "2 endpoint" in low_finding.evidence, (
            f"LOW group should mention 2 endpoints: {low_finding.evidence!r}"
        )


# ---------------------------------------------------------------------------
# 2. unique_issue_count in ScanResult.to_dict()
# ---------------------------------------------------------------------------

def _make_finding(fid: str) -> Finding:
    return Finding(
        id=fid, name=f"Finding {fid}", category="Test",
        severity=LOW, confidence="High", url="http://x/",
        evidence="e", impact="i", remediation="r",
    )


class TestUniqueIssueCount:
    def test_two_distinct_ids_gives_unique_count_two(self):
        result = ScanResult(
            target="http://x/", normalized_target="http://x/",
            started_at="2026-01-01T00:00:00", duration_seconds=1.0,
            status="completed", scan_mode="full", scope_prefix="",
            completion_percent=100, checks_run=[], pages_seen=[],
            forms_seen=0,
            findings=[_make_finding("A"), _make_finding("A"), _make_finding("B")],
            errors=[],
        )
        d = result.to_dict()
        assert d["unique_issue_count"] == 2

    def test_three_same_ids_gives_unique_count_one(self):
        result = ScanResult(
            target="http://x/", normalized_target="http://x/",
            started_at="2026-01-01T00:00:00", duration_seconds=1.0,
            status="completed", scan_mode="full", scope_prefix="",
            completion_percent=100, checks_run=[], pages_seen=[],
            forms_seen=0,
            findings=[_make_finding("X"), _make_finding("X"), _make_finding("X")],
            errors=[],
        )
        d = result.to_dict()
        assert d["unique_issue_count"] == 1

    def test_empty_findings_gives_unique_count_zero(self):
        result = ScanResult(
            target="http://x/", normalized_target="http://x/",
            started_at="2026-01-01T00:00:00", duration_seconds=1.0,
            status="completed", scan_mode="full", scope_prefix="",
            completion_percent=100, checks_run=[], pages_seen=[],
            forms_seen=0,
            findings=[],
            errors=[],
        )
        d = result.to_dict()
        assert d["unique_issue_count"] == 0

    def test_three_distinct_ids_gives_unique_count_three(self):
        result = ScanResult(
            target="http://x/", normalized_target="http://x/",
            started_at="2026-01-01T00:00:00", duration_seconds=1.0,
            status="completed", scan_mode="full", scope_prefix="",
            completion_percent=100, checks_run=[], pages_seen=[],
            forms_seen=0,
            findings=[_make_finding("A"), _make_finding("B"), _make_finding("C")],
            errors=[],
        )
        d = result.to_dict()
        assert d["unique_issue_count"] == 3


# ---------------------------------------------------------------------------
# 3. Injection skip helpers
# ---------------------------------------------------------------------------

class _CountingScanner(FakeScanner):
    """FakeScanner that counts _request calls and never returns a finding trigger."""
    def _request(self, method, url, **kwargs):
        self.request_count += 1
        return Resp(text="")


# ---------------------------------------------------------------------------
# 4a. advanced_injection — inert-param hint -> zero sends
# ---------------------------------------------------------------------------

class TestAdvancedInjectionHintSkip:
    def _make_scanner_with_inert_form(self, root="http://x/"):
        scanner = _CountingScanner(root=root)
        scanner.param_hints = {
            ("http://x/search", "POST", "q"): {"changes": False, "reflects": False},
        }
        scanner.forms = []
        scanner.pages = {}
        return scanner

    def test_inert_form_param_sends_zero_requests(self):
        scanner = self._make_scanner_with_inert_form()
        mod = MultiVectorInjectionModule(scanner)
        form = SimpleNamespace(
            action="http://x/search", method="POST",
            inputs={"q": "hello"},
        )
        mod._check_form(form)
        assert scanner.request_count == 0, (
            f"Inert param should be skipped entirely, got {scanner.request_count} requests"
        )

    def test_no_hint_form_param_sends_requests(self):
        scanner = _CountingScanner()
        scanner.param_hints = {}
        mod = MultiVectorInjectionModule(scanner)
        form = SimpleNamespace(
            action="http://x/search", method="POST",
            inputs={"q": "hello"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Without hint, probes should be sent"

    def test_inert_url_param_sends_zero_requests(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/search?q=test", "GET", "q"): {"changes": False, "reflects": False},
        }
        mod = MultiVectorInjectionModule(scanner)
        mod._check_url("http://x/search?q=test")
        assert scanner.request_count == 0, (
            f"Inert URL param should be skipped entirely, got {scanner.request_count} requests"
        )

    def test_param_with_changes_signal_is_probed(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/search", "POST", "q"): {"changes": True, "reflects": False},
        }
        mod = MultiVectorInjectionModule(scanner)
        form = SimpleNamespace(
            action="http://x/search", method="POST",
            inputs={"q": "hello"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Param with changes=True should be probed"

    def test_param_with_reflects_signal_is_probed(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/search", "POST", "q"): {"changes": False, "reflects": True},
        }
        mod = MultiVectorInjectionModule(scanner)
        form = SimpleNamespace(
            action="http://x/search", method="POST",
            inputs={"q": "hello"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Param with reflects=True should be probed"

    def test_external_action_form_sends_zero_requests(self):
        scanner = _CountingScanner(root="http://x/")
        scanner.param_hints = {}
        mod = MultiVectorInjectionModule(scanner)
        form = SimpleNamespace(
            action="https://other.example/submit", method="POST",
            inputs={"q": "hello"},
        )
        mod._check_form(form)
        assert scanner.request_count == 0, (
            f"External form should be skipped entirely, got {scanner.request_count} requests"
        )


# ---------------------------------------------------------------------------
# 4b. injection_advanced — inert-param hint -> zero sends
# ---------------------------------------------------------------------------

class TestCommandTraversalHintSkip:
    def test_inert_form_param_sends_zero_requests(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/cmd", "POST", "input"): {"changes": False, "reflects": False},
        }
        mod = CommandTraversalModule(scanner)
        form = SimpleNamespace(
            action="http://x/cmd", method="POST",
            inputs={"input": "test"},
        )
        mod._check_form(form)
        assert scanner.request_count == 0, (
            f"Inert param should be skipped, got {scanner.request_count} requests"
        )

    def test_no_hint_form_param_sends_requests(self):
        scanner = _CountingScanner()
        scanner.param_hints = {}
        mod = CommandTraversalModule(scanner)
        form = SimpleNamespace(
            action="http://x/cmd", method="POST",
            inputs={"input": "test"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Without hint, probes should be sent"

    def test_inert_url_param_sends_zero_requests(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/run?cmd=ls", "GET", "cmd"): {"changes": False, "reflects": False},
        }
        mod = CommandTraversalModule(scanner)
        mod._check_url("http://x/run?cmd=ls")
        assert scanner.request_count == 0, (
            f"Inert URL param should be skipped, got {scanner.request_count} requests"
        )

    def test_param_with_changes_signal_is_probed(self):
        scanner = _CountingScanner()
        scanner.param_hints = {
            ("http://x/cmd", "POST", "input"): {"changes": True, "reflects": False},
        }
        mod = CommandTraversalModule(scanner)
        form = SimpleNamespace(
            action="http://x/cmd", method="POST",
            inputs={"input": "test"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Param with changes=True should be probed"

    def test_external_action_form_sends_zero_requests(self):
        scanner = _CountingScanner(root="http://x/")
        scanner.param_hints = {}
        mod = CommandTraversalModule(scanner)
        form = SimpleNamespace(
            action="https://other.example/run", method="POST",
            inputs={"cmd": "ls"},
        )
        mod._check_form(form)
        assert scanner.request_count == 0, (
            f"External form should be skipped, got {scanner.request_count} requests"
        )

    def test_same_host_form_is_probed(self):
        scanner = _CountingScanner(root="http://x/")
        scanner.param_hints = {}
        mod = CommandTraversalModule(scanner)
        form = SimpleNamespace(
            action="http://x/run", method="POST",
            inputs={"cmd": "ls"},
        )
        mod._check_form(form)
        assert scanner.request_count > 0, "Same-host form should be probed"
