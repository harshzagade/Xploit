"""Error-page header leak audit: a 4xx/5xx response that discloses a
Server/X-Powered-By/X-AspNet-Version banner the site's normal (2xx) pages
suppress — or disclose with a different value — is flagged as ERRHDR-001.
A banner identical to the normal pages' is the INFO-SVR/INFO-XPB finding's
job, not this one; a 2xx answer to the probe (catch-all page) or a failed
probe is not an error page at all.
"""
from __future__ import annotations

import threading
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

    ``error_handler`` decides the 404-probe response from the probed URL;
    every other method returns an empty 200 so the sibling checks stay quiet.
    """
    def __init__(self, root="http://x/", error_handler=None):
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
        self.error_handler = error_handler or (lambda url: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if "xploit-404-probe-" in url:
            self.probe_calls.append(url)
            return self.error_handler(url)
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


def _page(url: str, status: int = 200, headers: dict | None = None):
    return url, Resp(text="ok", status_code=status, headers=headers or {}, url=url)


def _error(status: int = 404, headers: dict | None = None):
    return lambda url: Resp(
        text="Not Found", status_code=status, headers=headers or {}, url=url
    )


def _run_errhdr(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_error_page_headers()
    return [f for f in scanner.findings if f.id == "ERRHDR-001"]


class TestErrorPageHeaderLeak:
    def test_leak_suppressed_on_normal_pages_flags(self):
        scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx/1.18.0"}))
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        findings = _run_errhdr(scanner)
        assert len(findings) == 1
        assert findings[0].severity == LOW
        assert findings[0].cwe == "CWE-200"
        assert findings[0].category == "Information Disclosure"
        assert "server: nginx/1.18.0" in findings[0].evidence
        assert "suppressed on normal pages" in findings[0].evidence

    def test_leak_with_different_value_than_normal_pages_flags(self):
        scanner = FakeScanner(error_handler=_error(404, {"Server": "Apache/2.4.52"}))
        url, page = _page("http://x/", headers={"Server": "nginx"})
        scanner.pages = {url: page}
        findings = _run_errhdr(scanner)
        assert len(findings) == 1
        assert "server: Apache/2.4.52" in findings[0].evidence
        assert "normal pages show: nginx" in findings[0].evidence

    def test_same_banner_as_normal_pages_does_not_flag(self):
        scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx"}))
        url, page = _page("http://x/", headers={"Server": "nginx"})
        scanner.pages = {url: page}
        assert _run_errhdr(scanner) == []

    def test_x_powered_by_leak_flags(self):
        scanner = FakeScanner(
            error_handler=_error(404, {"X-Powered-By": "PHP/8.1.0"})
        )
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        findings = _run_errhdr(scanner)
        assert len(findings) == 1
        assert "x-powered-by: PHP/8.1.0" in findings[0].evidence

    def test_no_tech_headers_on_error_page_does_not_flag(self):
        scanner = FakeScanner(error_handler=_error(404, {"Content-Type": "text/html"}))
        url, page = _page("http://x/", headers={"Server": "nginx"})
        scanner.pages = {url: page}
        assert _run_errhdr(scanner) == []

    def test_multiple_leaks_collapse_to_one_finding(self):
        scanner = FakeScanner(error_handler=_error(
            404, {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.0"}
        ))
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        findings = _run_errhdr(scanner)
        assert len(findings) == 1
        assert "server: nginx/1.18.0" in findings[0].evidence
        assert "x-powered-by: PHP/8.1.0" in findings[0].evidence

    def test_500_error_page_with_leak_flags(self):
        scanner = FakeScanner(error_handler=_error(500, {"Server": "nginx/1.18.0"}))
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        assert len(_run_errhdr(scanner)) == 1

    def test_2xx_probe_answer_is_not_an_error_page(self):
        # Catch-all site serving 200 for the probe path: nothing to compare.
        scanner = FakeScanner(error_handler=_error(200, {"Server": "nginx/1.18.0"}))
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        assert _run_errhdr(scanner) == []

    def test_failed_probe_does_not_flag(self):
        scanner = FakeScanner(error_handler=lambda url: None)
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        assert _run_errhdr(scanner) == []

    def test_baseline_uses_same_host_only(self):
        # A banner seen only on another host's pages does not seed the
        # baseline for the probed host.
        scanner = FakeScanner(error_handler=_error(404, {"Server": "Apache/2.4.52"}))
        url, page = _page("http://other-host/", headers={"Server": "Apache/2.4.52"})
        scanner.pages = {url: page}
        findings = _run_errhdr(scanner)
        assert len(findings) == 1
        assert "suppressed on normal pages" in findings[0].evidence

    def test_error_page_in_crawl_does_not_seed_baseline(self):
        # A 404 already stored in pages (linked dead page) is not a normal
        # page, so its banner must not whitewash the probe's leak.
        scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx/1.18.0"}))
        url1, normal = _page("http://x/", headers={})
        url2, dead = _page("http://x/gone", status=404, headers={"Server": "nginx/1.18.0"})
        scanner.pages = {url1: normal, url2: dead}
        assert len(_run_errhdr(scanner)) == 1

    def test_probe_url_is_unique_per_run(self):
        seen = set()
        for _ in range(5):
            scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx"}))
            url, page = _page("http://x/", headers={})
            scanner.pages = {url: page}
            _run_errhdr(scanner)
            assert len(scanner.probe_calls) == 1
            seen.add(scanner.probe_calls[0])
        assert len(seen) == 5

    def test_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx/1.18.0"}))
        scanner.mode = "passive"
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.probe_calls == []
        assert [f for f in scanner.findings if f.id == "ERRHDR-001"] == []

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(error_handler=_error(404, {"Server": "nginx/1.18.0"}))
        url, page = _page("http://x/", headers={})
        scanner.pages = {url: page}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.probe_calls) == 1
        assert [f for f in scanner.findings if f.id == "ERRHDR-001"]
