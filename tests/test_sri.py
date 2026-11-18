"""SRI verification: external <script src> tags without an integrity
attribute are flagged as SRI-001 (one finding per page-host/script-host
pair), while same-site scripts, scripts with integrity, and HTTP scripts
are not.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule, _parse_script_tags
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


def _html_page(body: str, url: str = "https://x/") -> tuple[str, Resp]:
    return url, Resp(
        text=f"<html><head>{body}</head><body></body></html>",
        headers={"Content-Type": "text/html"},
        url=url,
    )


def _run_sri(pages: dict[str, Resp]):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_sri()
    return [f for f in scanner.findings if f.id == "SRI-001"]


class TestParseScriptTags:
    def test_double_quoted_src_and_integrity(self):
        tags = _parse_script_tags(
            '<script src="https://cdn.example/a.js" integrity="sha384-abc"></script>'
        )
        assert len(tags) == 1
        assert tags[0]["src"] == "https://cdn.example/a.js"
        assert tags[0]["integrity"] == "sha384-abc"
        assert tags[0]["body"] == ""

    def test_single_quoted_and_unquoted_attrs_in_any_order(self):
        tags = _parse_script_tags(
            "<script integrity='sha384-x' src=https://cdn.example/b.js></script>"
        )
        assert tags[0]["src"] == "https://cdn.example/b.js"
        assert tags[0]["integrity"] == "sha384-x"

    def test_inline_script_has_no_src_and_keeps_body(self):
        tags = _parse_script_tags("<script>var a = 1;</script>")
        assert tags[0]["src"] is None
        assert tags[0]["integrity"] is None
        assert tags[0]["body"] == "var a = 1;"

    def test_empty_integrity_stays_empty_string(self):
        tags = _parse_script_tags(
            '<script src="https://cdn.example/c.js" integrity=""></script>'
        )
        assert tags[0]["integrity"] == ""

    def test_no_script_tags_gives_empty_list(self):
        assert _parse_script_tags("<p>hello</p>") == []


class TestSriFindings:
    def test_external_https_script_without_integrity_flags(self):
        url, page = _html_page(
            '<script src="https://cdn.example.com/lib.js"></script>'
        )
        findings = _run_sri({url: page})
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert "cdn.example.com" in findings[0].evidence
        assert "https://cdn.example.com/lib.js" in findings[0].evidence
        assert findings[0].cwe == "CWE-829"

    def test_script_with_integrity_does_not_flag(self):
        url, page = _html_page(
            '<script src="https://cdn.example.com/lib.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
        )
        assert _run_sri({url: page}) == []

    def test_empty_integrity_counts_as_missing(self):
        url, page = _html_page(
            '<script src="https://cdn.example.com/lib.js" integrity=""></script>'
        )
        assert len(_run_sri({url: page})) == 1

    def test_same_host_script_does_not_flag(self):
        url, page = _html_page('<script src="https://x/app.js"></script>')
        assert _run_sri({url: page}) == []

    def test_subdomain_script_does_not_flag(self):
        url, page = _html_page(
            '<script src="https://cdn.x/static.js"></script>'
        )
        assert _run_sri({url: page}) == []

    def test_relative_script_does_not_flag(self):
        url, page = _html_page('<script src="/static/app.js"></script>')
        assert _run_sri({url: page}) == []

    def test_http_script_does_not_flag(self):
        url, page = _html_page(
            '<script src="http://cdn.example.com/lib.js"></script>'
        )
        assert _run_sri({url: page}) == []

    def test_protocol_relative_resolves_against_https_page(self):
        url, page = _html_page(
            '<script src="//cdn.example.com/lib.js"></script>'
        )
        findings = _run_sri({url: page})
        assert len(findings) == 1
        assert "cdn.example.com" in findings[0].evidence

    def test_inline_script_does_not_flag(self):
        url, page = _html_page("<script>var a = 1;</script>")
        assert _run_sri({url: page}) == []

    def test_non_html_page_is_skipped(self):
        url, page = _html_page(
            '<script src="https://cdn.example.com/lib.js"></script>'
        )
        page.headers = {"Content-Type": "application/json"}
        assert _run_sri({url: page}) == []

    def test_multiple_scripts_same_host_collapse_to_one_finding(self):
        url, page = _html_page(
            '<script src="https://cdn.example.com/a.js"></script>'
            '<script src="https://cdn.example.com/b.js"></script>'
            '<script src="https://cdn.example.com/c.js"></script>'
        )
        findings = _run_sri({url: page})
        assert len(findings) == 1
        assert "3 external script" in findings[0].evidence
        assert "a.js" in findings[0].evidence
        assert "c.js" in findings[0].evidence

    def test_two_script_hosts_give_two_findings(self):
        url, page = _html_page(
            '<script src="https://cdn-a.example.com/a.js"></script>'
            '<script src="https://cdn-b.example.com/b.js"></script>'
        )
        findings = _run_sri({url: page})
        assert len(findings) == 2
        hosts = {f.evidence.split("from ")[1].split(" ")[0] for f in findings}
        assert hosts == {"cdn-a.example.com", "cdn-b.example.com"}

    def test_same_script_host_across_two_pages_collapses(self):
        url1, page1 = _html_page(
            '<script src="https://cdn.example.com/a.js"></script>',
            url="https://x/one",
        )
        url2, page2 = _html_page(
            '<script src="https://cdn.example.com/b.js"></script>',
            url="https://x/two",
        )
        findings = _run_sri({url1: page1, url2: page2})
        assert len(findings) == 1
        assert "2 external script" in findings[0].evidence

    def test_sri_runs_in_passive_mode_via_run(self):
        scanner = FakeScanner(root="https://x/")
        scanner.mode = "passive"
        url, page = _html_page(
            '<script src="https://cdn.example.com/lib.js"></script>'
        )
        scanner.pages = {url: page}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert [f for f in scanner.findings if f.id == "SRI-001"]
