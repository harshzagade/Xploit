"""SARIF output format: `--format sarif` alongside text/json/csv.

A SARIF 2.1.0 document GitHub code scanning can ingest: one run per
scan result, one rule per distinct finding id, one result per finding,
severity mapped onto the SARIF level vocabulary.
"""
import json

from xploit import __version__
from xploit.cli import build_parser
from xploit.reporting import render_sarif_report, render_sarif_reports
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
        completion_percent=100, checks_run=["xss"], pages_seen=[],
        forms_seen=0, findings=findings, errors=[],
    )


def _doc(text):
    return json.loads(text)


def test_sarif_document_shape():
    doc = _doc(render_sarif_report(_result([_finding()])))
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Xploit"
    assert run["tool"]["driver"]["version"] == __version__
    assert run["properties"]["target"] == "example.com"
    assert len(run["results"]) == 1


def test_sarif_rules_deduped_first_seen_order():
    doc = _doc(render_sarif_report(_result([
        _finding(),
        _finding(id="SQLI-001", name="SQL Injection",
                 category="SQL Injection", severity="MEDIUM",
                 url="http://example.com/item?id=1", evidence="error-based",
                 parameter="id", cwe="CWE-89"),
        _finding(url="http://example.com/other?q=x"),
    ])))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["XSS-001", "SQLI-001"]
    assert rules[0]["shortDescription"]["text"] == "Reflected XSS"
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    assert rules[0]["properties"]["cwe"] == "CWE-79"
    assert "CWE-79" in rules[0]["properties"]["tags"]
    assert rules[1]["defaultConfiguration"]["level"] == "warning"


def test_sarif_severity_levels():
    doc = _doc(render_sarif_report(_result([
        _finding(severity="HIGH"),
        _finding(id="A", severity="MEDIUM"),
        _finding(id="B", severity="LOW"),
        _finding(id="C", severity="INFO"),
        _finding(id="D", severity="UNKNOWN"),
    ])))
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "warning", "note", "note", "warning"]


def test_sarif_result_fields():
    doc = _doc(render_sarif_report(_result([_finding()])))
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "XSS-001"
    assert res["level"] == "error"
    assert res["message"]["text"] == "payload reflected"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == "http://example.com/search?q=x"
    props = res["properties"]
    assert props["parameter"] == "q"
    assert props["method"] == "GET"
    assert props["confidence"] == "High"
    assert props["verified"] is True
    assert props["cwe"] == "CWE-79"
    assert props["remediation"] == "encode output"


def test_sarif_empty_findings():
    doc = _doc(render_sarif_report(_result([])))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_sarif_reports_one_run_per_target():
    doc = _doc(render_sarif_reports([
        _result([_finding()]),
        _result([_finding(id="SQLI-001")], target="http://other.example/"),
    ]))
    assert len(doc["runs"]) == 2
    assert doc["runs"][0]["results"][0]["ruleId"] == "XSS-001"
    assert doc["runs"][1]["results"][0]["ruleId"] == "SQLI-001"


def test_cli_accepts_sarif_format():
    parser = build_parser()
    args = parser.parse_args(["http://x/", "--format", "sarif"])
    assert args.format == "sarif"


def test_cli_sarif_end_to_end(capsys):
    """Full path: live fixture server -> scan -> SARIF on stdout."""
    from xploit.cli import run_scan
    from tests.test_json_body import _run_server

    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        parser = build_parser()
        args = parser.parse_args([base, "--format", "sarif",
                                  "--modules", "sqli", "--quiet"])
        assert run_scan(args) == 1  # HIGH finding present
        doc = json.loads(capsys.readouterr().out)
        assert doc["version"] == "2.1.0"
        results = doc["runs"][0]["results"]
        assert any(r["ruleId"] == "SQLI-001" and r["level"] == "error"
                   for r in results)
    finally:
        server.shutdown()
        server.server_close()
