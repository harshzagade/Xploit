"""security.txt presence: a site publishing /.well-known/security.txt with
a Contact: field has a documented vulnerability-disclosure channel, and
the report notes it as an INFO finding (SECTXT-001). A missing file, a
non-200 answer, or a file with no Contact: field flags nothing — without
a contact there is no channel to note.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

from xploit.modules.general import GeneralModule
from xploit.scanner import INFO


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

    ``security_txt_handler`` decides the security.txt response from the
    probed URL; every other method returns an empty 200 so the sibling
    checks stay quiet.
    """
    def __init__(self, root="http://x/", security_txt_handler=None):
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
        self.security_txt_handler = security_txt_handler or (lambda url: Resp(""))

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        if "/.well-known/security.txt" in url:
            self.probe_calls.append(url)
            return self.security_txt_handler(url)
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


def _run_sectxt(scanner: FakeScanner):
    module = GeneralModule(scanner)
    module._check_security_txt()
    return [f for f in scanner.findings if f.id == "SECTXT-001"]


class TestSecurityTxt:
    def test_present_with_contact_flags_info(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
            status_code=200, url=url,
        ))
        findings = _run_sectxt(scanner)
        assert len(findings) == 1
        assert findings[0].severity == INFO
        assert findings[0].category == "Security Policy"
        assert "mailto:security@example.com" in findings[0].evidence
        assert findings[0].url.endswith("/.well-known/security.txt")

    def test_contact_field_name_is_case_insensitive(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "contact: https://example.com/security\n",
            status_code=200, url=url,
        ))
        findings = _run_sectxt(scanner)
        assert len(findings) == 1
        assert "https://example.com/security" in findings[0].evidence

    def test_multiple_contacts_are_listed(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Contact: mailto:a@example.com\nContact: mailto:b@example.com\n",
            status_code=200, url=url,
        ))
        findings = _run_sectxt(scanner)
        assert len(findings) == 1
        assert "mailto:a@example.com" in findings[0].evidence
        assert "mailto:b@example.com" in findings[0].evidence

    def test_present_without_contact_does_not_flag(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Expires: 2027-01-01T00:00:00Z\nAcknowledgments: https://example.com/hall-of-fame\n",
            status_code=200, url=url,
        ))
        assert _run_sectxt(scanner) == []

    def test_missing_file_does_not_flag(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Not Found", status_code=404, url=url,
        ))
        assert _run_sectxt(scanner) == []

    def test_request_failure_does_not_flag(self):
        scanner = FakeScanner(security_txt_handler=lambda url: None)
        assert _run_sectxt(scanner) == []

    def test_contact_mentioned_in_prose_does_not_flag(self):
        # "Contact" must be a field line, not a word inside another line.
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Please contact the security team at security@example.com.\n",
            status_code=200, url=url,
        ))
        assert _run_sectxt(scanner) == []

    def test_probe_targets_well_known_path(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Contact: mailto:security@example.com\n",
            status_code=200, url=url,
        ))
        _run_sectxt(scanner)
        assert len(scanner.probe_calls) == 1
        assert scanner.probe_calls[0] == "http://x/.well-known/security.txt"

    def test_check_does_not_run_in_passive_mode(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Contact: mailto:security@example.com\n",
            status_code=200, url=url,
        ))
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert scanner.probe_calls == []
        assert [f for f in scanner.findings if f.id == "SECTXT-001"] == []

    def test_check_runs_in_active_mode_via_run(self):
        scanner = FakeScanner(security_txt_handler=lambda url: Resp(
            "Contact: mailto:security@example.com\n",
            status_code=200, url=url,
        ))
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len(scanner.probe_calls) == 1
        assert [f for f in scanner.findings if f.id == "SECTXT-001"]
