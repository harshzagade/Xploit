"""Directory listing detection: a crawled page whose body is an autoindex
listing — Apache mod_autoindex or nginx autoindex, both of which emit
"<title>Index of /path</title>" and "<h1>Index of /path</h1>" — is
flagged once per host as DIRLIST-001 (LOW, CWE-548). Both markers are
required, so a page merely discussing listings in prose flags nothing.
Passive: only pages already crawled are inspected.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import LOW


class _RawHeaders:
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


APACHE_LISTING = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /files</title></head>
<body><h1>Index of /files</h1>
<table><tr><td><a href="backup.zip">backup.zip</a></td></tr></table>
</body></html>"""

NGINX_LISTING = """<html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>
<a href="report.pdf">report.pdf</a></pre><hr></body></html>"""


def _run_dirlist(pages):
    scanner = FakeScanner(root="https://x/")
    scanner.pages = pages
    module = GeneralModule(scanner)
    module._check_directory_listing()
    return [f for f in scanner.findings if f.id == "DIRLIST-001"]


class TestDirectoryListing:
    def test_apache_listing_flags(self):
        findings = _run_dirlist({"https://x/files/": Resp(APACHE_LISTING)})
        assert len(findings) == 1
        assert findings[0].severity == LOW
        assert findings[0].cwe == "CWE-548"
        assert findings[0].category == "Information Disclosure"
        assert "https://x/files/" in findings[0].evidence

    def test_nginx_listing_flags(self):
        findings = _run_dirlist({"https://x/uploads/": Resp(NGINX_LISTING)})
        assert len(findings) == 1
        assert "x" in findings[0].evidence

    def test_normal_page_does_not_flag(self):
        page = ("<html><head><title>Welcome</title></head>"
                "<body><h1>Welcome</h1><p>Home page.</p></body></html>")
        assert _run_dirlist({"https://x/": Resp(page)}) == []

    def test_title_only_does_not_flag(self):
        # A page discussing listings in its title but with no listing
        # heading is prose, not an autoindex page.
        page = ("<html><head><title>Index of /files — our docs</title></head>"
                "<body><h1>File downloads</h1></body></html>")
        assert _run_dirlist({"https://x/files/": Resp(page)}) == []

    def test_h1_only_does_not_flag(self):
        page = ("<html><head><title>Downloads</title></head>"
                "<body><h1>Index of /files</h1><p>See below.</p></body></html>")
        assert _run_dirlist({"https://x/files/": Resp(page)}) == []

    def test_prose_mention_does_not_flag(self):
        page = ("<html><head><title>Hardening guide</title></head><body>"
                "<h1>Server hardening</h1><p>Disable the Index of / "
                "directory listing; an Index of / page leaks files.</p>"
                "</body></html>")
        assert _run_dirlist({"https://x/guide": Resp(page)}) == []

    def test_markers_are_case_insensitive(self):
        page = ("<HTML><HEAD><TITLE>INDEX OF /data</TITLE></HEAD>"
                "<BODY><H1>INDEX OF /data</H1></BODY></HTML>")
        assert len(_run_dirlist({"https://x/data/": Resp(page)})) == 1

    def test_multiple_listings_same_host_collapse_to_one_finding(self):
        pages = {
            "https://x/a/": Resp(APACHE_LISTING),
            "https://x/b/": Resp(NGINX_LISTING),
            "https://x/": Resp("<html><body>home</body></html>"),
        }
        findings = _run_dirlist(pages)
        assert len(findings) == 1
        assert "2 page(s)" in findings[0].evidence
        assert "https://x/a/" in findings[0].evidence
        assert "https://x/b/" in findings[0].evidence

    def test_listings_on_two_hosts_are_two_findings(self):
        pages = {
            "https://x/a/": Resp(APACHE_LISTING),
            "https://y/a/": Resp(APACHE_LISTING),
        }
        findings = _run_dirlist(pages)
        assert len(findings) == 2

    def test_more_than_five_urls_truncates_evidence(self):
        pages = {
            f"https://x/dir{i}/": Resp(APACHE_LISTING) for i in range(7)
        }
        findings = _run_dirlist(pages)
        assert len(findings) == 1
        assert "7 page(s)" in findings[0].evidence
        assert "(+2 more)" in findings[0].evidence

    def test_none_response_does_not_flag(self):
        assert _run_dirlist({"https://x/a/": None}) == []

    def test_check_runs_in_passive_mode_via_run(self):
        scanner = FakeScanner(root="https://x/")
        scanner.pages = {"https://x/files/": Resp(APACHE_LISTING)}
        scanner.forms = []
        scanner.mode = "passive"
        GeneralModule(scanner).run()
        assert len([f for f in scanner.findings if f.id == "DIRLIST-001"]) == 1

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(root="https://x/")
        scanner.pages = {"https://x/files/": Resp(APACHE_LISTING)}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len([f for f in scanner.findings if f.id == "DIRLIST-001"]) == 1
