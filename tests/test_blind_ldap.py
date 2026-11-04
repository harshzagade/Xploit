"""Boolean-based blind LDAP detection (LDAP-002) in MultiVectorInjectionModule.

Backends that swallow error text never produce LDAP-001, so the blind
check compares response lengths differentially: a plain impossible value
must sit near the baseline, and TWO structurally different wildcard
probes must both come back substantially longer (more directory entries
returned). One differing wildcard, an unstable no-match page, or an
error marker in any blind probe must not flag.
"""
import sys
import types

# bs4 is a runtime requirement of xploit.scanner but is not installed in
# this environment (no installs without his word). These tests never crawl
# HTML, so a minimal import-time stub is enough.
_bs4_stub = types.ModuleType("bs4")


class _SoupStub:  # noqa: D101
    def __init__(self, *args, **kwargs):
        raise RuntimeError("bs4 stub: no real HTML parsing in this environment")


_bs4_stub.BeautifulSoup = _SoupStub
sys.modules.setdefault("bs4", _bs4_stub)

from xploit.modules.advanced_injection import (
    BLIND_LDAP_DELTA_BYTES,
    BLIND_LDAP_FALSE_PAYLOAD,
    BLIND_LDAP_NEAR_BYTES,
    BLIND_LDAP_TRUE_PAYLOADS,
    MultiVectorInjectionModule,
)
from xploit.scanner import WebScanner


class Resp:
    def __init__(self, text=""):
        self.text = text


def module():
    return MultiVectorInjectionModule(WebScanner("http://x/", mode="passive"))


BASE = Resp("search the company directory: no results")
LONG = Resp("search results: " + "user entry " * 60)  # ~660B, >> 200B over BASE
ERROR_PAGE = Resp("com.novell.ldap.LDAPException: Invalid DN Syntax (34)")


def run_with(responder):
    m = module()
    m._send = lambda url, param, method, payload, base_data=None: responder(payload)
    m._test_ldap_injection("http://x/search", "q", "GET")
    return m


def blind_responder(true_map):
    """Clean (error-free) responder: baseline/false -> BASE, wildcards per map."""
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASE
        if payload == BLIND_LDAP_FALSE_PAYLOAD:
            return BASE
        return true_map.get(payload, BASE)
    return responder


def test_constants_are_sane():
    assert len(BLIND_LDAP_TRUE_PAYLOADS) == 2
    assert len(set(BLIND_LDAP_TRUE_PAYLOADS)) == 2
    # The false probe is a plain impossible value: no wildcard, no parens,
    # so it matches nothing whether interpolated or treated literally.
    assert "*" not in BLIND_LDAP_FALSE_PAYLOAD
    assert "(" not in BLIND_LDAP_FALSE_PAYLOAD
    assert BLIND_LDAP_NEAR_BYTES == 150
    assert BLIND_LDAP_DELTA_BYTES == 200


def test_finding_when_both_wildcards_expand():
    m = run_with(blind_responder({p: LONG for p in BLIND_LDAP_TRUE_PAYLOADS}))
    assert len(m.scanner.findings) == 1
    f = m.scanner.findings[0]
    assert f.id == "LDAP-002"
    assert f.confidence == "Medium"
    assert f.cwe == "CWE-90"
    assert str(len(LONG.text)) in f.evidence
    # Behavioral confirmation: no substring marker, so the provenance gate
    # honestly leaves it unverified until an analyst confirms it.
    assert f.verified is False
    assert f.proof_url  # the wildcard request is still replayable by hand


def test_no_finding_when_only_one_wildcard_expands():
    m = run_with(blind_responder({BLIND_LDAP_TRUE_PAYLOADS[0]: LONG}))
    assert m.scanner.findings == []


def test_no_finding_when_all_responses_identical():
    m = run_with(blind_responder({}))
    assert m.scanner.findings == []


def test_no_finding_when_no_match_page_is_unstable():
    # The false probe diverges from the baseline by more than the near
    # tolerance (echo/timestamps): the page is too unstable for a
    # differential verdict, even though both wildcards expand.
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASE
        if payload == BLIND_LDAP_FALSE_PAYLOAD:
            return Resp("unstable page " + "x" * 400)
        if payload in BLIND_LDAP_TRUE_PAYLOADS:
            return LONG
        return BASE
    m = run_with(responder)
    assert m.scanner.findings == []


def test_no_finding_when_blind_probe_carries_error_marker():
    # An error marker in a blind probe belongs to LDAP-001's path; the
    # blind check must not upgrade it (here the confirmation round-trip
    # fails, so LDAP-001 does not fire either).
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASE
        if payload in BLIND_LDAP_TRUE_PAYLOADS:
            return ERROR_PAGE
        return BASE
    m = run_with(responder)
    assert m.scanner.findings == []


def test_error_path_still_wins_over_blind():
    # When the error path fires, only LDAP-001 is recorded — never both.
    def responder(payload):
        if payload == "ldap_baseline_xploit":
            return BASE
        if payload in ("*", "*))(|(uid=*"):
            return ERROR_PAGE
        return BASE
    m = run_with(responder)
    assert [f.id for f in m.scanner.findings] == ["LDAP-001"]
