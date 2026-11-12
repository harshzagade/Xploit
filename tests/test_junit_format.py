"""JUnit XML output format: `--format junit` alongside text/json/csv/sarif/html.

CI pipelines ingest findings as native test results: one testsuite per
scan result, one testcase per finding, HIGH findings as `<failure>`
elements so a build fails on HIGH findings with no extra tooling.
"""
import xml.etree.ElementTree as ET

from xploit.cli import build_parser
from xploit.reporting import render_junit_report, render_junit_reports
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


def _result(findings, target="http://example.com/", status="completed",
            normalized_target="example.com"):
    return ScanResult(
        target=target, normalized_target=normalized_target,
        started_at="2026-11-07T00:00:00", duration_seconds=1.5,
        status=status, scan_mode="full", scope_prefix="/",
        completion_percent=100, checks_run=["xss"], pages_seen=[],
        forms_seen=0, findings=findings, errors=[],
    )


def _root(text):
    return ET.fromstring(text)


def test_junit_document_shape():
    root = _root(render_junit_report(_result([_finding()])))
    assert root.tag == "testsuites"
    suites = list(root)
    assert len(suites) == 1
    suite = suites[0]
    assert suite.tag == "testsuite"
    assert suite.get("name") == "xploit:example.com"
    assert suite.get("tests") == "1"
    assert suite.get("failures") == "1"
    assert suite.get("errors") == "0"
    assert suite.get("time") == "1.5"
    props = {p.get("name"): p.get("value")
             for p in suite.find("properties")}
    assert props["target"] == "example.com"
    assert props["scanMode"] == "full"


def test_junit_high_becomes_failure_with_detail():
    root = _root(render_junit_report(_result([_finding()])))
    case = root.find("./testsuite/testcase")
    assert case.get("classname") == "xploit.XSS-001"
    assert case.get("name") == "XSS-001 Reflected XSS"
    failure = case.find("failure")
    assert failure is not None
    assert failure.get("type") == "HIGH"
    assert "http://example.com/search?q=x" in failure.get("message")
    assert "Evidence: payload reflected" in failure.text
    assert "Parameter: q" in failure.text
    assert "CWE: CWE-79" in failure.text
    assert "Remediation: encode output" in failure.text


def test_junit_lower_severities_listed_without_failure():
    root = _root(render_junit_report(_result([
        _finding(severity="HIGH"),
        _finding(id="A", severity="MEDIUM"),
        _finding(id="B", severity="LOW"),
        _finding(id="C", severity="INFO"),
    ])))
    suite = root.find("testsuite")
    assert suite.get("tests") == "4"
    assert suite.get("failures") == "1"
    cases = suite.findall("testcase")
    assert [c.get("classname") for c in cases] == [
        "xploit.XSS-001", "xploit.A", "xploit.B", "xploit.C"]
    assert cases[0].find("failure") is not None
    assert all(c.find("failure") is None for c in cases[1:])


def test_junit_empty_findings_is_zero_test_pass():
    root = _root(render_junit_report(_result([])))
    suite = root.find("testsuite")
    assert suite.get("tests") == "0"
    assert suite.get("failures") == "0"
    assert suite.get("errors") == "0"
    assert suite.findall("testcase") == []


def test_junit_unreachable_is_error_not_silent_pass():
    result = _result([], status="unreachable")
    result.errors = ["GET http://example.com/: connection refused"]
    root = _root(render_junit_report(result))
    suite = root.find("testsuite")
    assert suite.get("tests") == "1"
    assert suite.get("failures") == "0"
    assert suite.get("errors") == "1"
    case = suite.find("testcase")
    assert case.get("name") == "target-unreachable"
    error = case.find("error")
    assert error is not None
    assert error.get("type") == "unreachable"
    assert "connection refused" in error.text


def test_junit_payload_text_escaped_not_markup():
    root = _root(render_junit_report(_result([
        _finding(evidence="reflected <svg onload=alert(1)> & \"quotes\""),
    ])))
    failure = root.find("./testsuite/testcase/failure")
    # Parses back to the original text: the payload was escaped, never markup.
    assert "<svg onload=alert(1)>" in failure.text
    assert '& "quotes"' in failure.text


def test_junit_reports_one_suite_per_target():
    root = _root(render_junit_reports([
        _result([_finding()]),
        _result([_finding(id="SQLI-001")], target="http://other.example/",
                normalized_target="other.example"),
    ]))
    suites = list(root)
    assert len(suites) == 2
    assert suites[0].find("testcase").get("classname") == "xploit.XSS-001"
    assert suites[1].find("testcase").get("classname") == "xploit.SQLI-001"
    assert suites[1].get("name") == "xploit:other.example"


def test_cli_accepts_junit_format():
    parser = build_parser()
    args = parser.parse_args(["http://x/", "--format", "junit"])
    assert args.format == "junit"


def test_cli_junit_end_to_end(capsys):
    """Full path: live fixture server -> scan -> JUnit XML on stdout."""
    from xploit.cli import run_scan
    from tests.test_json_body import _run_server

    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        parser = build_parser()
        args = parser.parse_args([base, "--format", "junit",
                                  "--modules", "sqli", "--quiet"])
        assert run_scan(args) == 1  # HIGH finding present
        root = ET.fromstring(capsys.readouterr().out)
        suite = root.find("testsuite")
        assert suite.get("failures") == "1"
        case = suite.find("testcase[@classname='xploit.SQLI-001']")
        assert case is not None
        assert case.find("failure") is not None
    finally:
        server.shutdown()
        server.server_close()
