"""JWT in URL: a JWT carried in a query string or a Location header leaks
into server logs, browser history, Referer headers and shared links, so
it is flagged as JWT-001 (MEDIUM, CWE-598). A candidate must be
JWT-shaped (three base64url segments of 4+ chars, so "1.2.3" never
matches) AND its first segment must decode to a JSON object carrying
"alg" — a real JWT header, not a random three-part token. Hits group
per (host, parameter, alg), and the evidence names the algorithm, never
the token itself. Passive: inspects crawled pages only, no new requests.
"""
from __future__ import annotations

import base64
import json
import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import MEDIUM


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _make_jwt(alg="RS256", payload=None):
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload or {"sub": "123"}).encode())
    return f"{header}.{body}.{_b64url(b'signature')}"


JWT = _make_jwt()
JWT_HS256 = _make_jwt(alg="HS256", payload={"user": "alice"})


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


def _run_jwt(pages):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_jwt_in_url()
    return [f for f in scanner.findings if f.id == "JWT-001"]


class TestJwtInUrlFindings:
    def test_jwt_in_query_param_flags(self):
        findings = _run_jwt({
            f"https://x/profile?token={JWT}": Resp(url="https://x/profile"),
        })
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].cwe == "CWE-598"
        assert findings[0].category == "Information Disclosure"
        assert findings[0].parameter == "token"
        assert "RS256" in findings[0].evidence
        # The token itself must never appear in the report.
        assert JWT not in findings[0].evidence
        assert "eyJ" not in findings[0].evidence

    def test_jwt_in_location_header_flags(self):
        findings = _run_jwt({
            "https://x/login": Resp(
                status_code=302,
                headers={"Location": f"https://x/home?auth={JWT_HS256}"},
                url="https://x/login",
            ),
        })
        assert len(findings) == 1
        assert findings[0].parameter == "Location"
        assert "HS256" in findings[0].evidence

    def test_same_param_across_pages_groups_into_one(self):
        findings = _run_jwt({
            f"https://x/a?token={JWT}": Resp(url="https://x/a"),
            f"https://x/b?token={JWT}": Resp(url="https://x/b"),
            f"https://x/c?token={JWT}": Resp(url="https://x/c"),
        })
        assert len(findings) == 1
        assert "+2 more URL(s)" in findings[0].evidence

    def test_two_params_are_two_findings(self):
        findings = _run_jwt({
            f"https://x/a?token={JWT}&auth={JWT_HS256}": Resp(url="https://x/a"),
        })
        assert len(findings) == 2
        assert {f.parameter for f in findings} == {"token", "auth"}

    def test_three_part_non_jwt_does_not_flag(self):
        # First segment decodes to JSON without "alg".
        header = _b64url(json.dumps({"typ": "JWT"}).encode())
        body = _b64url(json.dumps({"sub": "123"}).encode())
        fake = f"{header}.{body}.{_b64url(b'sig')}"
        findings = _run_jwt({
            f"https://x/a?token={fake}": Resp(url="https://x/a"),
        })
        assert findings == []

    def test_non_json_first_segment_does_not_flag(self):
        fake = f"{_b64url(b'not json at all')}.{_b64url(b'aaa')}.{_b64url(b'bbb')}"
        findings = _run_jwt({
            f"https://x/a?token={fake}": Resp(url="https://x/a"),
        })
        assert findings == []

    def test_version_string_does_not_flag(self):
        findings = _run_jwt({
            "https://x/a?v=1.2.3": Resp(url="https://x/a"),
        })
        assert findings == []

    def test_no_jwt_does_not_flag(self):
        findings = _run_jwt({
            "https://x/a?token=abc123": Resp(url="https://x/a"),
            "https://x/b": Resp(status_code=302, headers={"Location": "https://x/c"}),
        })
        assert findings == []

    def test_jwt_embedded_in_longer_value_flags(self):
        findings = _run_jwt({
            f"https://x/a?next=/home&token=Bearer%20{JWT}": Resp(url="https://x/a"),
        })
        assert len(findings) == 1

    def test_jwt_check_runs_in_passive_mode_via_run(self):
        scanner = FakeScanner(root="https://x/")
        scanner.mode = "passive"
        scanner.pages = {
            f"https://x/profile?token={JWT}": Resp(url="https://x/profile"),
        }
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len([f for f in scanner.findings if f.id == "JWT-001"]) == 1
        assert scanner.request_count == 0
