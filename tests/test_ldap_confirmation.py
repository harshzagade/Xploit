"""Two-round-trip confirmation for LDAP findings in MultiVectorInjectionModule.

A finding now requires TWO structurally distinct malformed filters to both
produce LDAP error output; a single error page tripped by any changed input
must not flag.
"""
import sys
import types

# bs4 (beautifulsoup4) is a runtime requirement of xploit.scanner but is not
# installed in this environment (no installs without his word). These tests
# never crawl HTML, so a minimal import-time stub is enough; real crawls would
# still need the real package.
_bs4_stub = types.ModuleType("bs4")


class _SoupStub:  # noqa: D101
    def __init__(self, *args, **kwargs):
        raise RuntimeError("bs4 stub: no real HTML parsing in this environment")


_bs4_stub.BeautifulSoup = _SoupStub
sys.modules.setdefault("bs4", _bs4_stub)

from xploit.modules.advanced_injection import (
    LDAP_CONFIRM_PAYLOADS,
    MultiVectorInjectionModule,
)
from xploit.scanner import WebScanner


class Resp:
    def __init__(self, text=""):
        self.text = text


def module():
    return MultiVectorInjectionModule(WebScanner("http://x/", mode="passive"))


BASELINE = Resp("search the company directory")
ERROR_PAGE = Resp("com.novell.ldap.LDAPException: Invalid DN Syntax (34)")


def run_with(responder):
    m = module()
    m._send = lambda url, param, method, payload, base_data=None: responder(payload)
    m._test_ldap_injection("http://x/search", "q", "GET")
    return m


# --- the confirmation payloads ------------------------------------------------

def test_confirm_payloads_are_distinct_and_malformed():
    assert len(set(LDAP_CONFIRM_PAYLOADS)) >= 3
    for payload in LDAP_CONFIRM_PAYLOADS:
        # every confirmation payload is a structurally odd filter, not a plain
        # probe like "*" — unbalanced parens, a null-byte terminator, or a
        # dangling boolean operator like "(|".
        odd = (
            payload.count("(") != payload.count(")")
            or "%00" in payload
            or "(|" in payload
            or "|)" in payload
            or payload.startswith("*)")
        )
        assert odd, payload


# --- confirmation logic --------------------------------------------------------

def test_no_finding_when_confirmation_payloads_stay_clean():
    # First payload trips an LDAP error page, but the confirmation round-trip
    # (a generic changed-input error template) does not -> no finding.
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASELINE
        if payload == "*":  # first discovery payload
            return ERROR_PAGE
        return Resp("search the company directory")  # confirm probes clean
    m = run_with(responder)
    assert m.scanner.findings == []


def test_finding_when_second_malformed_filter_also_errors():
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASELINE
        if payload in ("*", "*))(|(uid=*"):
            return ERROR_PAGE
        return Resp("search the company directory")
    m = run_with(responder)
    assert len(m.scanner.findings) == 1
    f = m.scanner.findings[0]
    assert f.id == "LDAP-001"
    assert f.trigger == "*"
    assert "*))(|(uid=*" in f.evidence  # both filters named in the evidence
    assert f.verified is True


def test_confirmation_skips_null_responses():
    # A dropped/None confirmation response does not kill the round-trip: the
    # next confirmation payload can still confirm.
    calls = []

    def responder(payload):
        calls.append(payload)
        if payload == "ldap_baseline_xploit":
            return BASELINE
        if payload == "*":
            return ERROR_PAGE
        if payload == LDAP_CONFIRM_PAYLOADS[0]:
            return None
        if payload == LDAP_CONFIRM_PAYLOADS[1]:
            return ERROR_PAGE
        return Resp("search the company directory")
    m = run_with(responder)
    assert len(m.scanner.findings) == 1
    assert LDAP_CONFIRM_PAYLOADS[1] in m.scanner.findings[0].evidence


def test_no_confirm_requests_when_nothing_matches():
    # When no discovery payload produces an LDAP error, the confirmation
    # payloads are never sent at all (no wasted requests).
    sent = []

    def responder(payload):
        sent.append(payload)
        return Resp("search the company directory")
    run_with(responder)
    assert not any(p in LDAP_CONFIRM_PAYLOADS for p in sent)
    assert "ldap_baseline_xploit" in sent


def test_findings_still_dedupe_to_one_per_param():
    # Both discovery AND confirmation error for the first payload: only one
    # finding is recorded even though the module would otherwise keep probing.
    def responder(payload):
        return BASELINE if payload == "ldap_baseline_xploit" else ERROR_PAGE
    m = run_with(responder)
    assert len(m.scanner.findings) == 1
    assert m.scanner.findings[0].id == "LDAP-001"
