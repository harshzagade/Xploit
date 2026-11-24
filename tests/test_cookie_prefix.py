"""Cookie __Host- / __Secure- prefix audit: a session cookie set over HTTPS
without the __Host- or __Secure- prefix is flagged as COOK-004 (LOW,
CWE-1004) — without a prefix, a cookie set from a compromised subdomain or
over an insecure channel can overwrite the session cookie. A prefixed
cookie that breaks the prefix rules (__Secure- without Secure; __Host-
without Secure, with a Domain attribute, or with Path other than '/') is
flagged too, since browsers silently reject such cookies. Correctly
prefixed cookies, non-session cookies, and HTTP pages flag nothing.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import LOW


class _RawHeaders:
    """Stand-in for urllib3 response headers: getlist returns every
    Set-Cookie line, the way _check_session_cookies reads them."""
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


def _run_prefix(pages):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_session_cookies()
    return [f for f in scanner.findings if f.id == "COOK-004"]


def _page(url, *cookies):
    return url, Resp(text="<html></html>", url=url, set_cookies=list(cookies))


class TestCookiePrefixFindings:
    def test_session_cookie_without_prefix_flags(self):
        findings = _run_prefix(dict([_page(
            "https://x/login",
            "sessionid=abc123; Secure; HttpOnly; SameSite=Lax",
        )]))
        assert len(findings) == 1
        assert findings[0].severity == LOW
        assert findings[0].cwe == "CWE-1004"
        assert "sessionid" in findings[0].evidence
        assert "__Host-" in findings[0].evidence
        assert findings[0].parameter == "sessionid"

    def test_non_session_cookie_without_prefix_does_not_flag(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "theme=dark; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_http_session_cookie_does_not_flag(self):
        # Prefixes are meaningless over plain HTTP.
        findings = _run_prefix(dict([_page(
            "http://x/login",
            "sessionid=abc123; HttpOnly",
        )]))
        assert findings == []

    def test_secure_prefixed_cookie_with_secure_does_not_flag(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Secure-sessionid=abc123; Secure; HttpOnly",
        )]))
        assert findings == []

    def test_secure_prefixed_cookie_without_secure_flags(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Secure-sessionid=abc123; HttpOnly",
        )]))
        assert len(findings) == 1
        assert "without the Secure attribute" in findings[0].evidence

    def test_host_prefixed_cookie_correct_does_not_flag(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Host-sessionid=abc123; Secure; HttpOnly; Path=/",
        )]))
        assert findings == []

    def test_host_prefixed_cookie_with_domain_flags(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Host-sessionid=abc123; Secure; HttpOnly; Path=/; Domain=x",
        )]))
        assert len(findings) == 1
        assert "Domain attribute" in findings[0].evidence

    def test_host_prefixed_cookie_with_wrong_path_flags(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Host-sessionid=abc123; Secure; HttpOnly; Path=/app",
        )]))
        assert len(findings) == 1
        assert "Path" in findings[0].evidence

    def test_host_prefixed_cookie_without_secure_flags(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__Host-sessionid=abc123; HttpOnly; Path=/",
        )]))
        assert len(findings) == 1
        assert "without the Secure attribute" in findings[0].evidence

    def test_prefix_match_is_case_insensitive(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "__HOST-SESSIONID=abc123; Secure; HttpOnly; Path=/",
        )]))
        assert findings == []

    def test_cookie_value_containing_secure_does_not_fake_flag(self):
        # The word "secure" inside the cookie VALUE must not count as the
        # Secure attribute — this cookie still lacks the prefix.
        findings = _run_prefix(dict([_page(
            "https://x/",
            "sessionid=secure_mode; HttpOnly; SameSite=Lax",
        )]))
        assert len(findings) == 1
        assert "without the __Host- or __Secure- prefix" in findings[0].evidence

    def test_same_cookie_on_two_pages_flags_once(self):
        findings = _run_prefix(dict([
            _page("https://x/a", "sessionid=abc; Secure; HttpOnly"),
            _page("https://x/b", "sessionid=def; Secure; HttpOnly"),
        ]))
        assert len(findings) == 1

    def test_multiple_session_cookies_each_flagged(self):
        findings = _run_prefix(dict([_page(
            "https://x/",
            "sessionid=abc; Secure; HttpOnly",
            "auth_token=xyz; Secure; HttpOnly",
        )]))
        assert len(findings) == 2
        assert {f.parameter for f in findings} == {"sessionid", "auth_token"}
