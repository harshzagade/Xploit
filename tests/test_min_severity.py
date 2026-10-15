"""--min-severity display filtering: only what matters hits the terminal."""
import pytest

from xploit.cli import build_parser, finding_visible
from xploit.reporting import meets_severity, render_text_report, strip_ansi
from xploit.scanner import HIGH, INFO, LOW, MEDIUM, Finding, ScanResult


def make_finding(**kw):
    base = dict(
        id="T-1", name="Test Finding", category="c", severity=MEDIUM,
        confidence="high", url="http://x/page", evidence="some evidence",
        impact="some impact", remediation="some fix",
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


# --- meets_severity ---------------------------------------------------------

def test_meets_severity_ordering():
    assert meets_severity(HIGH, HIGH)
    assert meets_severity(HIGH, MEDIUM)
    assert meets_severity(MEDIUM, MEDIUM)
    assert not meets_severity(MEDIUM, HIGH)
    assert meets_severity(LOW, INFO)
    assert not meets_severity(LOW, MEDIUM)
    assert not meets_severity(INFO, MEDIUM)
    assert meets_severity(INFO, INFO)


def test_meets_severity_unknown_severity_never_passes():
    # Unknown severities sort below every threshold — never silently promoted.
    assert not meets_severity("WEIRD", INFO)
    assert not meets_severity("WEIRD", HIGH)


def test_meets_severity_unknown_minimum_is_permissive():
    # Defensive: an unrecognized threshold never hides real findings.
    assert meets_severity(LOW, "BOGUS")


# --- render_text_report filtering -------------------------------------------

def _report(severities, **kwargs):
    res = empty_result()
    res.findings = [make_finding(id=str(i), severity=s, name=f"Finding {s} {i}",
                                 impact=f"impact-{s}-{i}")
                    for i, s in enumerate(severities)]
    return strip_ansi(render_text_report(res, colors=False, **kwargs))


def test_default_threshold_shows_high_medium_full_detail():
    text = _report([HIGH, MEDIUM, LOW, INFO])
    # Full detail blocks carry the impact field label for shown findings.
    assert "impact-HIGH-0" in text
    assert "impact-MEDIUM-1" in text
    # Below-threshold findings collapse: name appears in the one-line list,
    # but their detail blocks (impact text) do not.
    assert "Finding LOW 2" in text
    assert "impact-LOW-2" not in text
    assert "impact-INFO-3" not in text
    assert "LOWER SEVERITY" in text
    assert "--min-severity MEDIUM" in text


def test_threshold_info_shows_everything_in_full():
    text = _report([HIGH, MEDIUM, LOW, INFO], min_severity="INFO")
    assert "impact-HIGH-0" in text
    assert "impact-LOW-2" in text
    assert "impact-INFO-3" in text
    assert "LOWER SEVERITY" not in text


def test_threshold_high_hides_medium_too():
    text = _report([HIGH, MEDIUM, LOW], min_severity="HIGH")
    assert "impact-HIGH-0" in text
    assert "impact-MEDIUM-1" not in text
    assert "impact-LOW-2" not in text
    assert "LOWER SEVERITY" in text


def test_collapsed_section_counts_findings():
    text = _report([LOW, INFO, INFO])
    assert "3 findings below --min-severity MEDIUM" in text


def test_collapsed_line_shows_url_and_param():
    res = empty_result()
    res.findings = [make_finding(severity=LOW, parameter="q",
                                 url="https://example.com/search")]
    text = strip_ansi(render_text_report(res, colors=False))
    assert "example.com/search" in text
    assert "param: q" in text


def test_no_hidden_section_when_nothing_hidden():
    text = _report([HIGH])
    assert "LOWER SEVERITY" not in text


# --- CLI wiring -------------------------------------------------------------

def test_parser_min_severity_defaults_to_medium():
    args = build_parser().parse_args(["http://x/"])
    assert args.min_severity == "MEDIUM"


def test_parser_min_severity_accepts_all_levels():
    for level in ("HIGH", "MEDIUM", "LOW", "INFO"):
        args = build_parser().parse_args(["http://x/", "--min-severity", level])
        assert args.min_severity == level


def test_parser_min_severity_rejects_invalid():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["http://x/", "--min-severity", "CRITICAL"])


def test_finding_visible_gate():
    assert finding_visible(make_finding(severity=HIGH), "MEDIUM")
    assert finding_visible(make_finding(severity=MEDIUM), "MEDIUM")
    assert not finding_visible(make_finding(severity=LOW), "MEDIUM")
    assert not finding_visible(make_finding(severity=INFO), "MEDIUM")
    assert finding_visible(make_finding(severity=LOW), "LOW")
    assert finding_visible(make_finding(severity=INFO), "INFO")


# --- --threads ---------------------------------------------------------------

def test_parser_threads_defaults_to_5():
    assert build_parser().parse_args(["http://x/"]).threads == 5


def test_parser_threads_accepts_custom_value():
    assert build_parser().parse_args(["http://x/", "--threads", "20"]).threads == 20


def test_scanner_threads_clamped_to_at_least_one():
    from xploit.scanner import WebScanner
    assert WebScanner("http://example.com/", threads=0).threads == 1
    assert WebScanner("http://example.com/", threads=20).threads == 20


# --- map_probes concurrency ---------------------------------------------------

def _make_scanner(threads=4):
    from xploit.scanner import WebScanner
    return WebScanner("http://example.com/", threads=threads)


def test_map_probes_runs_all_items():
    s = _make_scanner()
    seen = []
    s.map_probes(seen.append, [1, 2, 3, 4, 5])
    assert sorted(seen) == [1, 2, 3, 4, 5]


def test_map_probes_empty_is_noop():
    s = _make_scanner()
    s.map_probes(lambda x: 1 / 0, [])


def test_map_probes_records_item_errors_not_raise():
    s = _make_scanner()

    def boom(x):
        raise ValueError("bad item")

    s.map_probes(boom, ["a", "b"])
    assert len(s.errors) == 2
    assert all("bad item" in e for e in s.errors)


def test_map_probes_inline_when_threads_is_1():
    s = _make_scanner(threads=1)
    order = []
    s.map_probes(order.append, [1, 2, 3])
    assert order == [1, 2, 3]


def test_map_probes_respects_thread_limit():
    import threading
    s = _make_scanner(threads=2)
    live = 0
    peak = 0
    lock = threading.Lock()

    def work(x):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        import time
        time.sleep(0.05)
        with lock:
            live -= 1

    s.map_probes(work, range(8))
    assert peak <= 2
    assert peak > 1  # actually ran concurrently


def test_add_finding_dedupes_concurrent_duplicates():
    import threading
    from xploit.modules.base import BaseModule
    from xploit.scanner import Finding

    s = _make_scanner(threads=8)
    mod = BaseModule(s)

    def mk():
        return Finding(id="X-1", name="Dup", category="C", severity="HIGH",
                       confidence="High", url="http://x/", evidence="e",
                       impact="i", remediation="r", parameter="p")

    threads = [threading.Thread(target=lambda: mod.add_finding(mk()))
               for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(s.findings) == 1
