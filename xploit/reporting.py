from __future__ import annotations

import json
import textwrap
from pathlib import Path

from .scanner import Finding, ScanResult, summarize_findings


def render_text_report(result: ScanResult) -> str:
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": DIM}

    LABEL_W  = 8   # width of field label column ("found   ", "impact  ", etc.)
    VAL_W    = 58  # wrap width for field values
    INDENT   = 6 + LABEL_W + 2  # indent for continuation lines

    def _wrap(text: str) -> str:
        """Wrap at VAL_W, indent continuation lines to align under first word."""
        if not text:
            return ""
        paras = textwrap.wrap(text, VAL_W)
        cont  = " " * INDENT
        return ("\n" + cont).join(paras)

    def _field(label: str, value: str) -> str | None:
        if not value:
            return None
        return f"      {DIM}{label:<{LABEL_W}}{RESET}  {_wrap(value)}"

    lines: list[str] = []
    summary = summarize_findings(result.findings)

    # ── Header box ──────────────────────────────────────────────────────
    target   = result.normalized_target
    meta     = f"{result.scan_mode.upper()}  ·  {result.duration_seconds}s  ·  {result.started_at}"
    coverage = f"{len(result.pages_seen)} pages  ·  {result.forms_seen} forms discovered"

    box_w = max(len(target), len(meta), len(coverage)) + 4
    box_w = max(box_w, 54)

    lines.append("")
    lines.append(f"┌{'─' * box_w}┐")
    lines.append(f"│  {BOLD}{target:<{box_w - 3}}{RESET}│")
    lines.append(f"│  {DIM}{meta:<{box_w - 3}}{RESET}│")
    lines.append(f"│  {DIM}{coverage:<{box_w - 3}}{RESET}│")
    lines.append(f"└{'─' * box_w}┘")
    lines.append("")

    # ── Risk breakdown ───────────────────────────────────────────────────
    total   = sum(summary.values()) or 1
    bar_w   = 22
    sev_order = [("HIGH", RED), ("MEDIUM", YELLOW), ("LOW", CYAN), ("INFO", DIM)]

    for sev, col in sev_order:
        count  = summary[sev]
        filled = round((count / total) * bar_w)
        bar    = f"{col}{'█' * filled}{RESET}{DIM}{'░' * (bar_w - filled)}{RESET}"
        lines.append(f"  {col}{BOLD}{sev:<8}{RESET}  {bar}  {count}")

    lines.append("")

    if not result.findings:
        if result.status == "unreachable":
            lines.append(f"  {RED}Target was unreachable.{RESET}")
        else:
            lines.append(f"  {GREEN}No findings detected.{RESET}")
        return "\n".join(lines)

    # ── Findings grouped by severity ─────────────────────────────────────
    sorted_findings = sorted(result.findings, key=_finding_sort_key)
    current_sev     = None
    idx             = 0

    for finding in sorted_findings:
        idx += 1
        if finding.severity != current_sev:
            current_sev = finding.severity
            col         = SEV_COLOR.get(current_sev, "")
            cnt         = summary[current_sev]
            label       = f" {col}{BOLD}{current_sev}{RESET} ({cnt}) "
            # strip ANSI for length calc
            label_plain = f" {current_sev} ({cnt}) "
            pad         = "─" * max(0, box_w + 2 - len(label_plain) - 4)
            lines.append(f"───{label}{pad}───")
            lines.append("")

        col     = SEV_COLOR.get(finding.severity, "")
        cwe_str = f"  {DIM}{finding.cwe}{RESET}" if finding.cwe else ""
        lines.append(f"  {BOLD}{idx:>2}{RESET}  {BOLD}{finding.name}{RESET}{cwe_str}")

        for line in filter(None, [
            _field("url",    finding.url),
            _field("param",  finding.parameter),
            _field("method", finding.method if finding.method != "GET" else ""),
            _field("found",  finding.evidence),
            _field("impact", finding.impact),
            _field("fix",    finding.remediation),
        ]):
            lines.append(line)

        lines.append("")

    lines.append("─" * (box_w + 2))
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
