"""CSV report format: `--format csv` alongside text/json.

One row per finding (id, severity, url, parameter, evidence) for
spreadsheet pipelines. The csv module's quoting must round-trip
evidence containing commas, quotes and newlines.
"""
import csv
import io

from xploit.cli import build_parser
from xploit.reporting import render_csv_report, render_csv_reports
from xploit.scanner import Finding, ScanResult


def _finding(**over):
    base = dict(
        id="XSS-001", name="Reflected XSS", category="xss",
        severity="HIGH", confidence="high",
        url="http://example.com/search?q=x", evidence="payload reflected",
        impact="script execution", remediation="encode output",
        parameter="q",
    )
    base.update(over)
    return Finding(**base)


def _result(findings):
    return ScanResult(
        target="http://example.com/", normalized_target="example.com",
        started_at="2026-10-31T00:00:00", duration_seconds=1.5,
        status="ok", scan_mode="full", scope_prefix="/",
        completion_percent=100, checks_run=["xss"], pages_seen=[],
        forms_seen=0, findings=findings, errors=[],
    )


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


def test_csv_header_and_rows():
    out = render_csv_report(_result([_finding(), _finding(
        id="SQLI-001", name="SQL injection", category="sqli",
        severity="MEDIUM", url="http://example.com/item?id=1",
        evidence="error-based", parameter="id")]))
    rows = _rows(out)
    assert rows[0] == ["id", "severity", "url", "parameter", "evidence"]
    assert rows[1] == ["XSS-001", "HIGH",
                       "http://example.com/search?q=x", "q",
                       "payload reflected"]
    assert rows[2][0] == "SQLI-001" and rows[2][1] == "MEDIUM"


def test_csv_quoting_round_trips_commas_quotes_newlines():
    out = render_csv_report(_result([_finding(
        evidence='says "hi", then\nbroke')]))
    rows = _rows(out)
    assert len(rows) == 2
    assert rows[1][4] == 'says "hi", then\nbroke'


def test_csv_empty_findings_is_header_only():
    rows = _rows(render_csv_report(_result([])))
    assert rows == [["id", "severity", "url", "parameter", "evidence"]]


def test_csv_reports_writes_header_once_for_many_targets():
    out = render_csv_reports([_result([_finding()]),
                              _result([_finding(id="SQLI-001")])])
    rows = _rows(out)
    assert rows[0] == ["id", "severity", "url", "parameter", "evidence"]
    assert [r[0] for r in rows[1:]] == ["XSS-001", "SQLI-001"]


def test_parser_accepts_csv_format():
    args = build_parser().parse_args(
        ["http://x/", "--format", "csv"])
    assert args.format == "csv"
