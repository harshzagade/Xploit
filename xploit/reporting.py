from __future__ import annotations

import json
from pathlib import Path

from .scanner import Finding, ScanResult, summarize_findings


def render_text_report(result: ScanResult) -> str:
    bold = "\033[1m"
    reset = "\033[0m"
    lines: list[str] = []
    lines.append(f"{bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    lines.append(f"{bold}                            XPLOIT ASSESSMENT REPORT                            {reset}")
    lines.append(f"{bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    lines.append("")
    lines.append(f"{bold}[1] ASSESSMENT OVERVIEW{reset}")
    lines.append(f"    Target URL        : {result.normalized_target}")
    lines.append(f"    Scan Status       : {result.status.upper()}")
    lines.append(f"    Scan Mode         : {result.scan_mode.upper()}")
    lines.append(f"    Scope Prefix      : {result.scope_prefix or '/'}")
    lines.append(f"    Started At        : {result.started_at}")
    lines.append(f"    Duration          : {result.duration_seconds}s")
    lines.append(f"    Pages Crawled     : {len(result.pages_seen)}")
    lines.append(f"    Forms Discovered  : {result.forms_seen}")
    lines.append(f"    Checks Executed   : {len(result.checks_run)}")
    lines.append("")
    
    if result.errors:
        lines.append(f"{bold}[!] SCAN ERRORS{reset}")
        for error in result.errors[:10]: # Limit to first 10 errors
            lines.append(f"    - {error}")
        if len(result.errors) > 10:
            lines.append(f"    - ... and {len(result.errors) - 10} more errors")
        lines.append("")

    summary = summarize_findings(result.findings)
    lines.append(f"{bold}[2] FINDINGS SUMMARY{reset}")
    lines.append(f"    CRITICAL/HIGH     : {summary['HIGH']}")
    lines.append(f"    MEDIUM            : {summary['MEDIUM']}")
    lines.append(f"    LOW               : {summary['LOW']}")
    lines.append(f"    INFORMATIONAL     : {summary['INFO']}")
    lines.append("")

    if not result.findings:
        if result.status == "unreachable":
            lines.append(f"{bold}The assessment could not be completed because the target was unreachable.{reset}")
        else:
            lines.append(f"{bold}No findings were detected during this assessment.{reset}")
        return "\n".join(lines)

    lines.append(f"{bold}[3] DETAILED VULNERABILITY ANALYSIS{reset}")
    lines.append("    " + "━" * 68)
    for index, finding in enumerate(sorted(result.findings, key=_finding_sort_key), start=1):
        lines.append(f"    {bold}ID: {finding.id} | {finding.name}{reset}")
        lines.append(f"    " + "─" * 68)
        lines.append(f"    Severity    : {finding.severity}")
        lines.append(f"    Category    : {finding.category}")
        lines.append(f"    CWE         : {finding.cwe or 'N/A'}")
        lines.append(f"    Target      : {finding.method} {finding.url}")
        if finding.parameter:
            lines.append(f"    Parameter   : {finding.parameter}")
        lines.append(f"    Evidence    : {finding.evidence}")
        lines.append(f"    Description : {finding.impact}")
        lines.append(f"    Remediation : {finding.remediation}")
        if finding.trigger:
            lines.append(f"    Reproducer  : {finding.trigger}")
        lines.append("")
    
    lines.append(f"{bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{reset}")
    return "\n".join(lines).rstrip()


def render_json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def write_report(content: str, output_path: str) -> None:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")


def _finding_sort_key(finding: Finding) -> tuple[int, str]:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return order.get(finding.severity, 9), finding.category


def _render_finding_lines(index: int, finding: Finding) -> list[str]:
    lines = [
        f"[{index:02d}] {finding.severity} {finding.name}",
        f"     Finding ID     : {finding.id}",
        f"     Category       : {finding.category}",
        f"     Severity       : {finding.severity}",
        f"     Confidence     : {finding.confidence}",
        f"     Affected URL   : {finding.url}",
        f"     HTTP Method    : {finding.method}",
    ]
    if finding.parameter:
        lines.append(f"     Parameter      : {finding.parameter}")
    if finding.trigger:
        lines.append(f"     Detected By    : {finding.trigger}")
    if finding.cwe:
        lines.append(f"     CWE            : {finding.cwe}")
    lines.extend(
        [
            f"     Evidence       : {finding.evidence}",
            f"     Security Impact: {finding.impact}",
            f"     Remediation    : {finding.remediation}",
        ]
    )
    return lines
