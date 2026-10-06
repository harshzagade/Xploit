"""Reporting, sanitizers, retest edge cases (round 2)."""
import json

from xploit.cli import prompt_required_text
from xploit.reporting import (
    _finding_sort_key,
    render_json_report,
    render_text_report,
    sanitize_terminal,
    strip_ansi,
    write_report,
)
from xploit.retest import RETEST_SKIPPED, _replay_blocked, retest_findings
from xploit.scanner import (
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    Finding,
    ScanResult,
    WebScanner,
)


class Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def make_finding(**kw):
    base = dict(
        id="T-1", name="t", category="c", severity=LOW, confidence="low",
        url="http://x/", evidence="e", impact="i", remediation="r",
    )
    base.update(kw)
    return Finding(**base)


def empty_result():
    return ScanResult(
        target="http://x/", normalized_target="http://x/", started_at="",
        duration_seconds=0.0, status="complete", scan_mode="passive",
        scope_prefix="/", completion_percent=100, checks_run=[],
        pages_seen=[], forms_seen=0, findings=[], errors=[],
    )


# --- strip_ansi ----------------------------------------------------------------

def test_strip_ansi_removes_sgr_codes():
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_strip_ansi_leaves_plain_text():
    assert strip_ansi("plain text") == "plain text"


def test_strip_ansi_removes_multiple_codes():
    assert strip_ansi("\x1b[1m\x1b[32mbold green\x1b[0m") == "bold green"


# --- sanitize_terminal ----------------------------------------------------------

def test_sanitize_keeps_newline_and_tab():
    assert sanitize_terminal("a\nb\tc") == "a\nb\tc"


def test_sanitize_strips_osc_hyperlink():
    evil = "\x1b]8;;http://evil\x07click\x1b]8;;\x07"
    out = sanitize_terminal(evil)
    assert "\x1b" not in out and "click" in out


def test_sanitize_strips_c0_controls():
    assert sanitize_terminal("a\x00b\x07c") == "abc"


def test_sanitize_empty_string():
    assert sanitize_terminal("") == ""


# --- finding sort order ------------------------------------------------------------

def test_sort_key_orders_high_before_low():
    order = [_finding_sort_key(make_finding(severity=s))[0] for s in (HIGH, MEDIUM, LOW, INFO)]
    assert order == sorted(order) == [0, 1, 2, 3]


def test_sort_key_pushes_unknown_severity_last():
    assert _finding_sort_key(make_finding(severity="WEIRD"))[0] == 9


def test_text_report_groups_high_before_low():
    res = empty_result()
    res.findings = [make_finding(id="L", severity=LOW), make_finding(id="H", severity=HIGH)]
    text = strip_ansi(render_text_report(res))
    assert text.index("HIGH") < text.index("LOW")


def test_json_report_is_valid_json_with_expected_keys():
    data = json.loads(render_json_report(empty_result()))
    assert data["target"] == "http://x/"
    assert data["findings"] == []


def test_json_report_includes_duration_and_finding_counts():
    res = empty_result()
    res.duration_seconds = 12.5
    res.findings = [
        make_finding(id="H1", severity=HIGH, verified=True),
        make_finding(id="H2", severity=HIGH),
        make_finding(id="L1", severity=LOW),
    ]
    data = json.loads(render_json_report(res))
    assert data["duration_seconds"] == 12.5
    assert data["summary"][HIGH] == 2
    assert data["summary"][LOW] == 1
    assert data["total_findings"] == 3
    assert data["verified_findings"] == 1


# --- write_report ---------------------------------------------------------------------

def test_write_report_creates_parent_dirs(tmp_path):
    target = tmp_path / "a" / "b" / "report.txt"
    write_report("hello", str(target))
    assert target.read_text().strip() == "hello"


def test_write_report_ends_with_single_newline():
    write_report("x", "/tmp/xploit-wr-test.txt")
    with open("/tmp/xploit-wr-test.txt", "rb") as fh:
        assert fh.read().endswith(b"\n")


# --- prompt_required_text ---------------------------------------------------------------

def test_prompt_retries_on_empty_input():
    answers = iter(["", "  ", "ok"])
    assert prompt_required_text("Label", input_fn=lambda p: next(answers)) == "ok"


def test_prompt_strips_whitespace():
    assert prompt_required_text("", input_fn=lambda p: "  done  ") == "done"


# --- _replay_blocked -----------------------------------------------------------------------

def test_replay_blocked_none_on_clean_200():
    assert _replay_blocked(Resp("all good", 200)) is None


def test_replay_blocked_on_403():
    assert _replay_blocked(Resp("denied", 403)) == "HTTP 403"


def test_replay_blocked_on_500():
    assert _replay_blocked(Resp("boom", 500)) == "HTTP 500"


def test_replay_blocked_on_login_redirect():
    res = Resp("x", 302, {"Location": "/login?next=/admin"})
    reason = _replay_blocked(res)
    assert reason is not None and "login" in reason


def test_replay_blocked_on_waf_body():
    res = Resp("Request blocked by WAF policy", 200)
    assert "block page" in _replay_blocked(res)


def test_replay_blocked_on_rate_limit_body():
    res = Resp("too many requests, slow down", 200)
    assert "block page" in _replay_blocked(res)


def test_replay_blocked_ignores_non_login_redirect():
    res = Resp("x", 302, {"Location": "/dashboard"})
    assert _replay_blocked(res) is None


# --- retest_findings edge cases ---------------------------------------------------------------

def test_retest_skips_all_in_passive_mode():
    sc = WebScanner("http://x/", mode="passive")
    findings = [make_finding(proof_method="GET", proof_url="http://x/", proof_marker="m")]
    stats = retest_findings(sc, findings)
    assert stats[RETEST_SKIPPED] == 1
    assert findings[0].retest_status == RETEST_SKIPPED


def test_retest_empty_findings_returns_zero_stats():
    sc = WebScanner("http://x/", mode="passive")
    assert sum(retest_findings(sc, []).values()) == 0


def test_retest_marks_proofless_finding_unverifiable_without_network():
    from xploit.retest import RETEST_UNVERIFIABLE
    sc = WebScanner("http://127.0.0.1:9/", mode="active")
    findings = [make_finding()]  # no proof envelope at all
    stats = retest_findings(sc, findings)
    assert stats[RETEST_UNVERIFIABLE] == 1
    assert findings[0].retest_status == RETEST_UNVERIFIABLE
