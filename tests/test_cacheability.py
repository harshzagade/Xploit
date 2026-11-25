"""Response cacheability audit: a sensitive page — one that sets a session
cookie, or whose path names account-like surface — served with a cacheable
response is flagged as CACHE-001 (LOW, CWE-524). Cacheable means
Cache-Control: public, or no Cache-Control carrying private / no-store /
no-cache. A shared cache may then serve one user's authenticated page to
the next visitor. Non-sensitive pages and properly private responses flag
nothing.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import LOW


class _RawHeaders:
    """Stand-in for urllib3 response headers: getlist returns every
    Set-Cookie line, the way the cacheability check reads them."""
    def __init__(self, cookies):
        self._cookies = cookies

    def getlist(self, name):
        return list(self._cookies) if name.lower() == "set-cookie" else []


class Resp:
    """Minimal requests.Response stand-in."""
    def __init__(self, text="", status_code=200, headers=None, url="http://x/",
                 set_cookies=None):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()
        self.raw = SimpleNamespace(headers=_RawHeaders(set_cookies or []))


class FakeScanner:
    """Minimal scanner stub matching the pattern from test_stage3_context.py."""
    def __init__(self, root="https://x/"):
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


def _run_cacheability(pages):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_cacheability()
    return [f for f in scanner.findings if f.id == "CACHE-001"]


def _page(url, headers=None, *cookies):
    return url, Resp(text="<html></html>", url=url, headers=headers or {},
                     set_cookies=list(cookies))


class TestCacheabilityFindings:
    def test_session_page_with_public_flags(self):
        findings = _run_cacheability(dict([_page(
            "https://x/login",
            {"Cache-Control": "public, max-age=3600"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert len(findings) == 1
        assert findings[0].severity == LOW
        assert findings[0].cwe == "CWE-524"
        assert "public" in findings[0].evidence

    def test_session_page_with_no_cache_control_flags(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert len(findings) == 1
        assert "no Cache-Control header" in findings[0].evidence

    def test_session_page_with_max_age_only_flags(self):
        # max-age alone is neither private nor no-store/no-cache.
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "max-age=600"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert len(findings) == 1
        assert "no private/no-store/no-cache" in findings[0].evidence

    def test_session_page_with_private_does_not_flag(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "private, max-age=0"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_session_page_with_no_store_does_not_flag(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "no-store"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_session_page_with_no_cache_does_not_flag(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "no-cache"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_public_beats_private_when_both_present(self):
        # Contradictory headers: a `public` directive still makes the
        # response storable by a shared cache.
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "private, public"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert len(findings) == 1

    def test_sensitive_path_with_public_flags_without_cookie(self):
        findings = _run_cacheability(dict([_page(
            "https://x/account/settings",
            {"Cache-Control": "public, max-age=3600"},
        )]))
        assert len(findings) == 1

    def test_non_sensitive_page_with_public_does_not_flag(self):
        findings = _run_cacheability(dict([_page(
            "https://x/about",
            {"Cache-Control": "public, max-age=3600"},
        )]))
        assert findings == []

    def test_non_sensitive_page_without_cache_control_does_not_flag(self):
        findings = _run_cacheability(dict([_page("https://x/about", {})]))
        assert findings == []

    def test_cookie_value_containing_sessionid_does_not_fake_sensitive(self):
        # The word "sessionid" inside a cookie VALUE must not make the
        # page sensitive — only the cookie name counts.
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "public, max-age=3600"},
            "theme=sessionid; Secure",
        )]))
        assert findings == []

    def test_non_session_cookie_does_not_make_page_sensitive(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "public, max-age=3600"},
            "theme=dark; Secure",
        )]))
        assert findings == []

    def test_header_name_case_insensitive(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"CACHE-CONTROL": "private"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_directive_case_insensitive(self):
        findings = _run_cacheability(dict([_page(
            "https://x/",
            {"Cache-Control": "PRIVATE"},
            "sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_each_sensitive_page_flagged_once(self):
        findings = _run_cacheability(dict([
            _page("https://x/account", {"Cache-Control": "public"}),
            _page("https://x/checkout", {"Cache-Control": "public"}),
        ]))
        assert len(findings) == 2
        assert {f.url for f in findings} == {
            "https://x/account", "https://x/checkout",
        }

    def test_path_segment_match_is_exact(self):
        # "/configure" must not count as the "config"-style sensitive
        # segment — segments are matched whole.
        findings = _run_cacheability(dict([_page(
            "https://x/configure",
            {"Cache-Control": "public, max-age=3600"},
        )]))
        assert findings == []
