"""CSP nonce enforcement: a page whose Content-Security-Policy still lets
inline scripts run without a nonce (script-src/default-src missing, or
'unsafe-inline' with no nonce/hash token) is flagged as CSP-001, one
finding per host. Policies that block inline scripts, gate them behind a
nonce/hash, or pages with no inline scripts are not flagged.
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
    """Minimal scanner stub matching the pattern from test_stage3_context.py."""
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


def _page(url: str, csp: str | None, body: str = "<script>var a = 1;</script>"):
    headers = {"Content-Type": "text/html"}
    if csp is not None:
        headers["Content-Security-Policy"] = csp
    return url, Resp(
        text=f"<html><head>{body}</head><body></body></html>",
        headers=headers,
        url=url,
    )


def _run_nonce(pages: dict[str, Resp]):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_csp_nonce()
    return [f for f in scanner.findings if f.id == "CSP-001"]


class TestCspNonceFindings:
    def test_unsafe_inline_with_inline_script_flags(self):
        url, page = _page(
            "https://x/", "default-src 'self'; script-src 'self' 'unsafe-inline'"
        )
        findings = _run_nonce({url: page})
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert "unsafe-inline" in findings[0].evidence
        assert findings[0].cwe == "CWE-693"

    def test_no_script_src_or_default_src_flags(self):
        url, page = _page("https://x/", "img-src 'self'; style-src 'self'")
        findings = _run_nonce({url: page})
        assert len(findings) == 1
        assert "no script-src" in findings[0].evidence

    def test_strict_script_src_does_not_flag(self):
        url, page = _page("https://x/", "script-src 'self'")
        assert _run_nonce({url: page}) == []

    def test_nonce_gated_policy_does_not_flag(self):
        url, page = _page(
            "https://x/",
            "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'",
        )
        assert _run_nonce({url: page}) == []

    def test_hash_gated_policy_does_not_flag(self):
        url, page = _page(
            "https://x/",
            "script-src 'self' 'unsafe-inline' 'sha256-abc123'",
        )
        assert _run_nonce({url: page}) == []

    def test_default_src_fallback_is_evaluated(self):
        # No script-src: default-src 'self' blocks inline scripts.
        url, page = _page("https://x/", "default-src 'self'")
        assert _run_nonce({url: page}) == []
        # ... but default-src 'unsafe-inline' allows them.
        url, page = _page("https://x/", "default-src 'self' 'unsafe-inline'")
        assert len(_run_nonce({url: page})) == 1

    def test_no_csp_header_does_not_flag(self):
        # Missing CSP is the HDR-CSP finding's job, not this check's.
        url, page = _page("https://x/", None)
        assert _run_nonce({url: page}) == []

    def test_no_inline_scripts_does_not_flag(self):
        url, page = _page(
            "https://x/",
            "script-src 'self' 'unsafe-inline'",
            body='<script src="https://x/app.js"></script>',
        )
        assert _run_nonce({url: page}) == []

    def test_empty_inline_script_does_not_flag(self):
        url, page = _page(
            "https://x/",
            "script-src 'self' 'unsafe-inline'",
            body="<script>   </script>",
        )
        assert _run_nonce({url: page}) == []

    def test_script_src_none_does_not_flag(self):
        url, page = _page("https://x/", "script-src 'none'")
        assert _run_nonce({url: page}) == []

    def test_multiple_pages_same_host_collapse_to_one_finding(self):
        url1, page1 = _page(
            "https://x/one", "script-src 'self' 'unsafe-inline'"
        )
        url2, page2 = _page(
            "https://x/two", "script-src 'self' 'unsafe-inline'"
        )
        findings = _run_nonce({url1: page1, url2: page2})
        assert len(findings) == 1
        assert "2 page(s)" in findings[0].evidence
        assert "/one" in findings[0].evidence
        assert "/two" in findings[0].evidence

    def test_two_hosts_give_two_findings(self):
        url1, page1 = _page(
            "https://x/a", "script-src 'self' 'unsafe-inline'"
        )
        url2, page2 = _page(
            "https://y/b", "script-src 'self' 'unsafe-inline'"
        )
        findings = _run_nonce({url1: page1, url2: page2})
        assert len(findings) == 2

    def test_non_html_page_is_skipped(self):
        url, page = _page(
            "https://x/", "script-src 'self' 'unsafe-inline'"
        )
        page.headers["Content-Type"] = "application/json"
        assert _run_nonce({url: page}) == []

    def test_nonce_check_runs_in_passive_mode_via_run(self):
        scanner = FakeScanner(root="https://x/")
        scanner.mode = "passive"
        url, page = _page(
            "https://x/", "script-src 'self' 'unsafe-inline'"
        )
        scanner.pages = {url: page}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert [f for f in scanner.findings if f.id == "CSP-001"]
