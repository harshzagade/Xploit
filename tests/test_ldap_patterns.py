"""LDAP injection error-pattern coverage (expanded 2026-10-14).

Each vendor/stack-specific LDAP error string must trigger LDAP-001 when it
appears in a payload response but NOT in the baseline, and must not fire when
it is already present in the baseline (static content).
"""
from types import SimpleNamespace

import pytest

from xploit.modules.advanced_injection import MultiVectorInjectionModule

# (rendered response text, canonical pattern the evidence must report)
NEW_CASES = [
    ("com.novell.ldap.sdk pool exhausted", "com.novell.ldap"),
    ("LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error", "LdapErr: DSID"),
    ("LDAP: error code 49 - 80090308", "80090308"),
    ("org.springframework.ldap.InvalidSearchFilterException", "org.springframework.ldap"),
    ("Invalid search filter in request", "Invalid search filter"),
    ("Bad search filter (18)", "Bad search filter"),
    ("Net::LDAP connection object died", "Net::LDAP"),
    ("ldap.LDAPFilterSyntaxError: invalid filter", "LDAPFilterSyntaxError"),
    ("System.DirectoryServices.DirectoryServicesCOMException", "DirectoryServicesCOMException"),
    ("Invalid attribute syntax (21)", "Invalid attribute syntax"),
    ("Server is unwilling to perform (53)", "Server is unwilling to perform"),
]

OLD_PATTERNS = [
    "javax.naming.directory",
    "LDAPException",
    "com.sun.jndi.ldap",
    "ldap_search",
    "Invalid DN syntax",
    "Protocol error occurred",
]


class Resp:
    def __init__(self, text=""):
        self.text = text


def make_mod(monkeypatch, payload_text, baseline_text="login page, enter credentials"):
    mod = MultiVectorInjectionModule(
        SimpleNamespace(findings=[], on_finding=None, _finding_keys=set())
    )

    def fake_send(url, param, method, payload, base_data=None):
        if payload == "ldap_baseline_xploit":
            return Resp(baseline_text)
        return Resp(payload_text)

    monkeypatch.setattr(mod, "_send", fake_send)
    return mod


def findings_of(mod):
    return [f for f in mod.scanner.findings if f.id == "LDAP-001"]


@pytest.mark.parametrize("response_text, expected", NEW_CASES)
def test_new_error_patterns_trigger_ldap_finding(monkeypatch, response_text, expected):
    mod = make_mod(monkeypatch, f"<html>error: {response_text}</html>")
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    found = findings_of(mod)
    assert len(found) == 1, f"pattern {expected!r} did not trigger LDAP-001"
    assert expected in found[0].evidence
    assert found[0].verified  # proof attached via _attach_proof


@pytest.mark.parametrize("pattern", OLD_PATTERNS)
def test_old_error_patterns_still_trigger(monkeypatch, pattern):
    mod = make_mod(monkeypatch, f"stack trace {pattern} at ldap")
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    assert findings_of(mod), f"regression: pattern {pattern!r} no longer triggers"


def test_pattern_matching_is_case_insensitive(monkeypatch):
    mod = make_mod(monkeypatch, "error: LDAPEXCEPTION thrown by jndi")
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    assert findings_of(mod)


@pytest.mark.parametrize("response_text, expected", NEW_CASES)
def test_baseline_exclusion_avoids_false_positive_new(monkeypatch, response_text, expected):
    # Same error string on the baseline page (static content) -> no finding.
    mod = make_mod(
        monkeypatch,
        f"error: {response_text}",
        baseline_text=f"docs page mentions {response_text}",
    )
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    assert not findings_of(mod), f"pattern {expected!r} fired from static baseline content"


@pytest.mark.parametrize("pattern", OLD_PATTERNS)
def test_baseline_exclusion_avoids_false_positive_old(monkeypatch, pattern):
    mod = make_mod(
        monkeypatch,
        f"error: {pattern}",
        baseline_text=f"docs page mentions {pattern}",
    )
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    assert not findings_of(mod), f"pattern {pattern!r} fired from static baseline content"


def test_clean_response_no_finding(monkeypatch):
    mod = make_mod(monkeypatch, "login failed, try again")
    mod._test_ldap_injection("http://t/login?user=", "user", "GET")
    assert not findings_of(mod)


def test_post_forms_also_checked(monkeypatch):
    mod = make_mod(monkeypatch, "LdapErr: DSID-0C0903A9, comment: bad search filter")
    mod._test_ldap_injection("http://t/login", "user", "POST", {"user": ""})
    assert findings_of(mod)
