"""Retest summary in JSON reports.

`_retest_if_requested` used to only print the tally; JSON consumers lost
it. The tally is now stored on `ScanResult.retest_summary` (None when no
retest ran) and serialized by `to_dict()`.
"""
import argparse

from xploit.cli import _retest_if_requested
from xploit.retest import RETEST_CONFIRMED, RETEST_SKIPPED
from xploit.scanner import ACTIVE, PASSIVE, Finding, ScanResult


def _finding(**over):
    base = dict(
        id="LDAP-001", name="LDAP injection", category="advanced",
        severity="HIGH", confidence="high",
        url="http://x/search", evidence="ldap error",
        impact="filter bypass", remediation="escape input",
        proof_method="GET", proof_url="http://x/search?q=*",
        proof_marker="com.novell.ldap",
    )
    base.update(over)
    return Finding(**base)


def _result(findings):
    return ScanResult(
        target="http://x/", normalized_target="x",
        started_at="2026-10-31T00:00:00", duration_seconds=1.0,
        status="ok", scan_mode="full", scope_prefix="/",
        completion_percent=100, checks_run=[], pages_seen=[],
        forms_seen=0, findings=findings, errors=[],
    )


class Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class FakeScanner:
    def __init__(self, mode, response):
        self.mode = mode
        self.response = response
        self.on_request = lambda *a: None

    def _request(self, method, url, quiet=True, **kwargs):
        return self.response


def test_to_dict_defaults_retest_summary_to_none():
    result = _result([])
    assert result.to_dict()["retest_summary"] is None


def test_to_dict_carries_set_retest_summary():
    result = _result([])
    result.retest_summary = {"confirmed": 1, "fixed": 0,
                             "unverifiable": 0, "skipped": 0}
    assert result.to_dict()["retest_summary"]["confirmed"] == 1


def test_retest_if_requested_stores_confirmed_tally():
    finding = _finding()
    result = _result([finding])
    args = argparse.Namespace(retest=True)
    scanner = FakeScanner(ACTIVE, Resp("com.novell.ldap.LDAPException"))
    _retest_if_requested(args, scanner, result, colors=False, show_ui=False)
    assert finding.retest_status == RETEST_CONFIRMED
    assert result.retest_summary == {"confirmed": 1, "fixed": 0,
                                     "unverifiable": 0, "skipped": 0}
    assert result.to_dict()["retest_summary"]["confirmed"] == 1


def test_retest_if_requested_skips_when_flag_off():
    result = _result([_finding()])
    args = argparse.Namespace(retest=False)
    _retest_if_requested(args, FakeScanner(ACTIVE, Resp("x")),
                         result, colors=False, show_ui=False)
    assert result.retest_summary is None


def test_retest_if_requested_stores_skipped_tally_in_passive_mode():
    finding = _finding()
    result = _result([finding])
    args = argparse.Namespace(retest=True)
    _retest_if_requested(args, FakeScanner(PASSIVE, Resp("x")),
                         result, colors=False, show_ui=False)
    assert finding.retest_status == RETEST_SKIPPED
    assert result.retest_summary["skipped"] == 1
