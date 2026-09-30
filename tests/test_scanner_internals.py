"""Internals of scanner.py: envelopes, URL helpers, scope, init (round 2)."""
import time

import pytest

from xploit.scanner import (
    HIGH,
    LOW,
    Finding,
    WebScanner,
    gate_finding,
    mutate_query,
    normalize_url,
    same_origin,
)


def make_finding(**kw):
    base = dict(
        id="T-1", name="t", category="c", severity=LOW, confidence="low",
        url="http://x/", evidence="e", impact="i", remediation="r",
    )
    base.update(kw)
    return Finding(**base)


# --- Finding envelope ----------------------------------------------------

def test_finding_defaults_to_unverified():
    assert make_finding().verified is False


def test_finding_has_replayable_proof_true():
    f = make_finding(proof_method="GET", proof_url="http://x/?a=1", proof_marker="root:")
    assert f.has_replayable_proof() is True


def test_finding_proof_without_marker_is_not_replayable():
    f = make_finding(proof_method="GET", proof_url="http://x/?a=1")
    assert f.has_replayable_proof() is False


def test_finding_empty_proof_is_not_replayable():
    assert make_finding().has_replayable_proof() is False


def test_finding_to_dict_carries_envelope_keys():
    d = make_finding().to_dict()
    for key in ("proof_method", "proof_url", "proof_data", "proof_marker",
                "verified", "verification_note", "retest_status"):
        assert key in d


# --- gate_finding ---------------------------------------------------------

def test_gate_marks_verified_when_proof_attached():
    f = make_finding(proof_method="GET", proof_url="http://x/", proof_marker="m")
    gate_finding(f)
    assert f.verified is True
    assert "Replayable proof" in f.verification_note


def test_gate_behavioral_request_only_is_unverified():
    f = make_finding(proof_method="POST", proof_url="http://x/")
    gate_finding(f)
    assert f.verified is False
    assert "behavioral" in f.verification_note


def test_gate_high_without_proof_is_flagged():
    f = make_finding(severity=HIGH)
    gate_finding(f)
    assert f.verified is False
    assert "HIGH" in f.verification_note


def test_gate_low_without_proof_uses_standard_note():
    f = make_finding(severity=LOW)
    gate_finding(f)
    assert f.verification_note == "Analyst-readable evidence only; no replayable proof attached."


# --- normalize_url ---------------------------------------------------------

def test_normalize_adds_scheme_when_missing():
    assert normalize_url("example.com") == "http://example.com/"


def test_normalize_strips_userinfo():
    assert normalize_url("http://user:pass@example.com/") == "http://example.com/"


def test_normalize_drops_fragment():
    assert normalize_url("http://example.com/page#frag") == "http://example.com/page"


def test_normalize_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com/")


def test_normalize_rejects_blank():
    with pytest.raises(ValueError):
        normalize_url("   ")


def test_normalize_preserves_query():
    assert normalize_url("http://example.com/?a=1") == "http://example.com/?a=1"


# --- same_origin -------------------------------------------------------------

def test_same_origin_ignores_default_port():
    assert same_origin("http://x:80/a", "http://x/b") is True


def test_same_origin_rejects_different_port():
    assert same_origin("http://x:8080/", "http://x/") is False


def test_same_origin_host_case_insensitive():
    assert same_origin("http://X.COM/", "http://x.com/") is True


def test_same_origin_malformed_port_is_out_of_scope():
    assert same_origin("http://x:badport/", "http://x/") is False


# --- mutate_query --------------------------------------------------------------

def test_mutate_query_replaces_existing_param():
    assert mutate_query("http://x/?a=1&b=2", "a", "P") == "http://x/?a=P&b=2"


def test_mutate_query_appends_missing_param():
    assert mutate_query("http://x/", "q", "P") == "http://x/?q=P"


def test_mutate_query_appends_extra_params():
    out = mutate_query("http://x/", "q", "P", extra_params={"z": "9"})
    assert "q=P" in out and "z=9" in out


# --- init / scope -------------------------------------------------------------

def test_scope_prefix_normalized_with_leading_slash():
    sc = WebScanner("http://x/", mode="passive", scope_prefix="api/")
    assert sc.scope_prefix == "/api"


def test_scanner_init_clamps_page_and_depth():
    sc = WebScanner("http://x/", mode="passive", max_pages=0, depth=-3)
    assert sc.max_pages >= 1
    assert sc.depth >= 0


def test_rate_limit_zero_does_not_sleep():
    sc = WebScanner("http://x/", mode="passive", rate_limit=0.0)
    start = time.monotonic()
    sc._respect_rate_limit()
    assert time.monotonic() - start < 1.0
