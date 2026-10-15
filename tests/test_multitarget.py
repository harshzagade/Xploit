"""Concurrent multi-target scanning: xploit <url> [url ...]."""
from argparse import Namespace
from unittest.mock import patch

from xploit.cli import (
    _error_result,
    _run_multi_target,
    build_parser,
    run_scan,
    target_list,
)
from xploit.scanner import HIGH, MEDIUM, Finding, ScanResult


def _args(*urls, **kw):
    base = dict(
        url=urls[0], extra_urls=list(urls[1:]),
        depth=4, max_pages=500, timeout=6.0, mode="full",
        rate_limit=0.0, jitter=0.0, scope_prefix="/", exclude=[],
        format="text", output=None, retest=False, header=[], cookie=[],
        insecure=False, no_color=True, quiet=True,
        min_severity="MEDIUM", threads=5,
    )
    base.update(kw)
    return Namespace(**base)


def _result(target, severities=()):
    findings = [
        Finding(id=f"F-{i}", name=f"Finding {i}", category="C",
                severity=s, confidence="High", url=target,
                evidence="e", impact="i", remediation="r")
        for i, s in enumerate(severities)
    ]
    return ScanResult(
        target=target, normalized_target=target, started_at="",
        duration_seconds=1.0, status="completed", scan_mode="full",
        scope_prefix="/", completion_percent=100, checks_run=[],
        pages_seen=[], forms_seen=0, findings=findings, errors=[],
    )


# --- target list ------------------------------------------------------------

def test_target_list_single():
    assert target_list(_args("http://a/")) == ["http://a/"]


def test_target_list_multiple():
    assert target_list(_args("http://a/", "http://b/", "http://c/")) == [
        "http://a/", "http://b/", "http://c/"]


def test_parser_captures_extra_urls():
    args = build_parser().parse_args(["http://a/", "http://b/", "http://c/"])
    assert args.url == "http://a/"
    assert args.extra_urls == ["http://b/", "http://c/"]


def test_parser_extra_urls_default_empty():
    assert build_parser().parse_args(["http://a/"]).extra_urls == []


# --- _error_result ----------------------------------------------------------

def test_error_result_carries_status():
    r = _error_result("http://a/", "invalid")
    assert r.status == "invalid"
    assert r.findings == []
    assert r.target == "http://a/"


# --- run_scan dispatch ------------------------------------------------------

class _FakeScanner:
    def __init__(self, result):
        self._result = result
        self.on_finding = None
        self.on_progress = None
        self.on_request = None

    def scan(self):
        return self._result


def _run_multi(capsys, *targets, results):
    args = _args(*targets)
    fakes = {t: _FakeScanner(results[t]) for t in targets}
    with patch("xploit.cli._build_scanner",
               side_effect=lambda a, t: fakes[t]):
        code = _run_multi_target(args, list(targets))
    return code, capsys.readouterr().out


def test_multi_returns_zero_when_no_high(capsys):
    code, _ = _run_multi(
        capsys, "http://a/", "http://b/",
        results={"http://a/": _result("http://a/", [MEDIUM]),
                 "http://b/": _result("http://b/", [])})
    assert code == 0


def test_multi_returns_one_when_any_high(capsys):
    code, _ = _run_multi(
        capsys, "http://a/", "http://b/",
        results={"http://a/": _result("http://a/", []),
                 "http://b/": _result("http://b/", [HIGH])})
    assert code == 1


def test_multi_returns_two_when_any_unreachable(capsys):
    code, _ = _run_multi(
        capsys, "http://a/", "http://b/",
        results={"http://a/": _result("http://a/", [HIGH]),
                 "http://b/": _error_result("http://b/", "unreachable")})
    assert code == 2


def test_multi_renders_each_target_report(capsys):
    _, out = _run_multi(
        capsys, "http://a/", "http://b/",
        results={"http://a/": _result("http://a/", [HIGH]),
                 "http://b/": _result("http://b/", [MEDIUM])})
    assert "http://a/" in out
    assert "http://b/" in out
    assert "Finding 0" in out


def test_multi_json_is_array(capsys):
    import json
    args = _args("http://a/", "http://b/", format="json")
    results = {"http://a/": _result("http://a/", []),
               "http://b/": _result("http://b/", [])}
    fakes = {t: _FakeScanner(results[t]) for t in ("http://a/", "http://b/")}
    with patch("xploit.cli._build_scanner",
               side_effect=lambda a, t: fakes[t]):
        _run_multi_target(args, ["http://a/", "http://b/"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list) and len(data) == 2
    assert data[0]["target"] == "http://a/"


def test_multi_failed_target_does_not_kill_others(capsys):
    args = _args("http://a/", "http://bad/", "http://c/")
    results = {"http://a/": _result("http://a/", []),
               "http://c/": _result("http://c/", [])}

    def fake_build(a, t):
        if t == "http://bad/":
            raise ValueError("bad url")
        return _FakeScanner(results[t])

    with patch("xploit.cli._build_scanner", side_effect=fake_build):
        code = _run_multi_target(args, ["http://a/", "http://bad/", "http://c/"])
    out = capsys.readouterr().out
    assert code == 2  # invalid target -> exit 2, but others still scanned
    assert "http://a/" in out and "http://c/" in out


def test_run_scan_dispatches_single_target(capsys):
    args = _args("http://only/")
    with patch("xploit.cli._run_single_target", return_value=7) as m:
        assert run_scan(args) == 7
        m.assert_called_once_with(args, "http://only/")


def test_run_scan_dispatches_multi_target(capsys):
    args = _args("http://a/", "http://b/")
    with patch("xploit.cli._run_multi_target", return_value=8) as m:
        assert run_scan(args) == 8
        m.assert_called_once_with(args, ["http://a/", "http://b/"])
