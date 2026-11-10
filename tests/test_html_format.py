"""HTML output format: `--format html` alongside text/json/csv/sarif.

A single self-contained HTML document (inline CSS, no external
resources) for sharing with clients who will not read terminal output:
severity-coloured findings with evidence, impact and remediation, and
all finding text HTML-escaped so reflected payloads render as text.
"""
import re

from xploit.cli import build_parser
from xploit.reporting import render_html_report, render_html_reports
from xploit.scanner import Finding, ScanResult


def _finding(**over):
    base = dict(
        id="XSS-001", name="Reflected XSS", category="Cross-Site Scripting",
        severity="HIGH", confidence="High",
        url="http://example.com/search?q=x", evidence="payload reflected",
        impact="script execution", remediation="encode output",
        trigger="payload=<svg>", cwe="CWE-79", parameter="q", method="GET",
        verified=True,
    )
    base.update(over)
    return Finding(**base)


def _result(findings, target="http://example.com/"):
    return ScanResult(
        target=target, normalized_target="example.com",
        started_at="2026-11-07T00:00:00", duration_seconds=1.5,
        status="ok", scan_mode="full", scope_prefix="/",
        completion_percent=100, checks_run=["xss"], pages_seen=["/"],
        forms_seen=1, findings=findings, errors=[],
    )


def test_html_document_shape():
    text = render_html_report(_result([_finding()]))
    assert text.startswith("<!DOCTYPE html>")
    assert "<title>Xploit Scan Report</title>" in text
    assert "<style>" in text and "</style>" in text
    # self-contained: no external resources
    assert "<link" not in text and "<script" not in text
    assert "example.com" in text
    assert "Xploit Scan Report" in text


def test_html_summary_badges_and_counts():
    text = render_html_report(_result([
        _finding(),
        _finding(id="SQLI-001", name="SQL Injection",
                 category="SQL Injection", severity="MEDIUM",
                 url="http://example.com/item?id=1", evidence="error-based",
                 parameter="id", cwe="CWE-89", verified=False),
    ]))
    assert "HIGH 1" in text
    assert "MEDIUM 1" in text
    assert "1/2 verified" in text


def test_html_finding_fields_present():
    text = render_html_report(_result([_finding()]))
    for needle in ("Reflected XSS", "CWE-79", "http://example.com/search?q=x",
                   "payload reflected", "script execution", "encode output",
                   "verified"):
        assert needle in text


def test_html_escapes_reflected_payloads():
    text = render_html_report(_result([_finding(
        evidence="<svg onload=alert(1)>", impact="<b>bold</b>",
        url="http://example.com/?q=<script>alert(1)</script>")]))
    assert "<svg onload=alert(1)>" not in text
    assert "&lt;svg onload=alert(1)&gt;" in text
    assert "&lt;b&gt;bold&lt;/b&gt;" in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_html_severity_classes():
    text = render_html_report(_result([
        _finding(),
        _finding(id="INFO-001", name="Info note", category="Info",
                 severity="INFO", url="http://example.com/",
                 evidence="note", verified=False, cwe=""),
    ]))
    assert 'class="finding sev-high"' in text
    assert 'class="finding sev-info"' in text
    assert "HIGH (1)" in text and "INFO (1)" in text


def test_html_empty_findings():
    text = render_html_report(_result([]))
    assert "No findings detected." in text
    assert "0 findings" in text


def test_html_unreachable_target():
    result = _result([])
    result.status = "unreachable"
    assert "Target was unreachable." in render_html_report(result)


def test_html_multi_target_sections():
    other = _result([_finding()], target="http://other.example/")
    other.normalized_target = "other.example"
    text = render_html_reports([_result([_finding()]), other])
    assert text.count("<h2>") == 2
    assert "example.com" in text and "other.example" in text
    # still a single document
    assert text.count("<!DOCTYPE html>") == 1
    assert text.count("</html>") == 1


def test_html_format_accepted_by_cli():
    args = build_parser().parse_args(
        ["http://example.com/", "--format", "html"])
    assert args.format == "html"


def test_html_has_no_external_urls():
    text = render_html_report(_result([_finding()]))
    hrefs = re.findall(r"(?:src|href)\s*=\s*\"([^\"]+)\"", text)
    assert hrefs == []
