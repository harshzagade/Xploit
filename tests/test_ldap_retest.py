"""Retest coverage for LDAP-001 findings.

The LDAP module already attaches replayable proof (the exact mutated
request + the LDAP error marker), so the generic `--retest` pass *should*
replay LDAP-001 like it does SQLi/XSS — but no test ever proved it.
These tests drive a real LDAP finding through `retest_findings` and
assert the confirmed / fixed / blocked / POST round-trips.
"""
from xploit.modules.advanced_injection import (
    LDAP_CONFIRM_PAYLOADS,
    MultiVectorInjectionModule,
)
from xploit.retest import (
    RETEST_CONFIRMED,
    RETEST_FIXED,
    RETEST_UNVERIFIABLE,
    retest_findings,
)
from xploit.scanner import FULL, PASSIVE, WebScanner


class Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


ERROR_PAGE = Resp("com.novell.ldap.LDAPException: Invalid DN Syntax (34)")
CLEAN_PAGE = Resp("search the company directory")
BASELINE = Resp("search the company directory")


def ldap_finding(method="GET", base_data=None):
    """Produce a real LDAP-001 finding via the module's own code path."""
    module = MultiVectorInjectionModule(WebScanner("http://x/", mode="passive"))

    def responder(url, param, method_, payload, base_data_=None):
        if payload == "ldap_baseline_xploit":
            return BASELINE
        if payload == "*" or payload == LDAP_CONFIRM_PAYLOADS[0]:
            return ERROR_PAGE
        return CLEAN_PAGE

    module._send = responder
    module._test_ldap_injection("http://x/search", "q", method, base_data)
    assert len(module.scanner.findings) == 1
    return module.scanner.findings[0]


class FakeScanner:
    """Stands in for WebScanner._request in the retest pass."""

    def __init__(self, mode, response):
        self.mode = mode
        self.response = response
        self.calls = []

    def _request(self, method, url, quiet=False, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


def test_ldap_finding_carries_replayable_proof():
    finding = ldap_finding()
    assert finding.id == "LDAP-001"
    assert finding.verified is True
    assert finding.has_replayable_proof() is True
    assert finding.proof_method == "GET"
    assert "search" in finding.proof_url
    assert finding.proof_marker == "com.novell.ldap"


def test_retest_confirms_ldap_when_error_reproduces():
    finding = ldap_finding()
    scanner = FakeScanner(FULL, ERROR_PAGE)
    stats = retest_findings(scanner, [finding])
    assert stats[RETEST_CONFIRMED] == 1
    assert finding.retest_status == RETEST_CONFIRMED


def test_retest_marks_ldap_fixed_when_error_gone():
    finding = ldap_finding()
    scanner = FakeScanner(FULL, CLEAN_PAGE)
    stats = retest_findings(scanner, [finding])
    assert stats[RETEST_FIXED] == 1
    assert finding.retest_status == RETEST_FIXED


def test_retest_marks_blocked_ldap_replay_unverifiable():
    finding = ldap_finding()
    scanner = FakeScanner(FULL, Resp("access denied", status_code=403))
    stats = retest_findings(scanner, [finding])
    assert stats[RETEST_UNVERIFIABLE] == 1
    assert finding.retest_status == RETEST_UNVERIFIABLE


def test_retest_replays_post_ldap_proof_with_form_data():
    finding = ldap_finding(method="POST", base_data={"q": "x", "other": "y"})
    assert finding.proof_method == "POST"
    scanner = FakeScanner(FULL, ERROR_PAGE)
    stats = retest_findings(scanner, [finding])
    assert stats[RETEST_CONFIRMED] == 1
    method, url, kwargs = scanner.calls[0]
    assert method == "POST"
    assert kwargs["data"]["q"] == "*"
    assert kwargs["data"]["other"] == "y"


def test_retest_skips_ldap_in_passive_mode():
    finding = ldap_finding()
    scanner = FakeScanner(PASSIVE, ERROR_PAGE)
    stats = retest_findings(scanner, [finding])
    assert stats["skipped"] == 1
    assert finding.retest_status == "skipped"
    assert scanner.calls == []
