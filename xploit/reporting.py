from __future__ import annotations

import json
from pathlib import Path

from .scanner import Finding, ScanResult, summarize_findings


def render_text_report(result: ScanResult) -> str:
    bold   = "\033[1m"
    reset  = "\033[0m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"
    SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": DIM}

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{bold}Assessment Summary{reset}")
    lines.append("─" * 50)
    lines.append(f"Target   : {result.normalized_target}")
    lines.append(f"Mode     : {result.scan_mode.upper()}  |  Duration : {result.duration_seconds}s")
    lines.append(f"Crawled  : {len(result.pages_seen)} pages  |  Forms : {result.forms_seen}")
    lines.append("")

    # ── Summary counts ──────────────────────────────────────────────────
    summary = summarize_findings(result.findings)
    lines.append(f"{bold}Findings{reset}")
    lines.append("─" * 50)
    lines.append(f"  {RED}HIGH{reset}   : {summary['HIGH']}")
    lines.append(f"  {YELLOW}MEDIUM{reset} : {summary['MEDIUM']}")
    lines.append(f"  {CYAN}LOW{reset}    : {summary['LOW']}")
    lines.append(f"  {DIM}INFO{reset}   : {summary['INFO']}")
    lines.append("")

    if not result.findings:
        if result.status == "unreachable":
            lines.append("Target was unreachable.")
        else:
            lines.append("No findings detected.")
        return "\n".join(lines)

    # ── Individual findings ─────────────────────────────────────────────
    for i, f in enumerate(sorted(result.findings, key=_finding_sort_key), 1):
        col = SEV_COLOR.get(f.severity, "")
        lines.append(f"[{i:02d}] {col}{f.severity}{reset}  {bold}{f.name}{reset}")
        lines.append(f"      URL        : {f.url}")
        if f.parameter:
            lines.append(f"      Parameter  : {f.parameter}")
        lines.append(f"      Evidence   : {f.evidence}")
        lines.append(f"      Fix        : {f.remediation}")
        if f.cwe:
            lines.append(f"      CWE        : {f.cwe}")
        lines.append("")

    lines.append("─" * 50)
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
