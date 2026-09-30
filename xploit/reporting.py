from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

from .scanner import Finding, ScanResult, summarize_findings

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes — file output must be plain text."""
    return _ANSI_RE.sub("", text)


# Any ANSI/VT100 escape sequence (broader than the SGR-only _ANSI_RE above):
# OSC ... BEL/ST, CSI ... final byte, charset designations, other Fe escapes.
_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[()#][0-9A-Z]"
    r"|\x1b[@-Z\\-_]"
)
# C0 control characters and DEL — ESC (\x1b) is in this range, so any escape
# the sequence regex above misses is still neutralized (possibly leaving a
# harmless printable remnant like "[31m", never an active escape).
_C0_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_terminal(text: str) -> str:
    """Strip ANSI escape sequences and C0 control characters from
    server-controlled text before it is interpolated into terminal output —
    a malicious target could otherwise inject terminal escapes via reflected
    payloads in finding fields. Keeps \\n and \\t so multi-line evidence
    still renders readably."""
    if not text:
        return ""
    return _C0_RE.sub("", _ESCAPE_RE.sub("", text))


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
    lines.append(f"│  {BOLD}{target:<{box_w - 2}}{RESET}│")
    lines.append(f"│  {DIM}{meta:<{box_w - 2}}{RESET}│")
    lines.append(f"│  {DIM}{coverage:<{box_w - 2}}{RESET}│")
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
        cwe_str = f"  {DIM}{sanitize_terminal(finding.cwe)}{RESET}" if finding.cwe else ""
        lines.append(f"  {BOLD}{idx:>2}{RESET}  {BOLD}{sanitize_terminal(finding.name)}{RESET}{cwe_str}")

        note = sanitize_terminal(finding.verification_note)
        verified_str = (
            "yes — replayable proof attached"
            if finding.verified
            else (f"no — {note}" if note else "no")
        )
        retest_str = sanitize_terminal(finding.retest_status) if finding.retest_status != "not_run" else ""

        for line in filter(None, [
            _field("url",    sanitize_terminal(finding.url)),
            _field("param",  sanitize_terminal(finding.parameter)),
            _field("method", sanitize_terminal(finding.method) if finding.method != "GET" else ""),
            _field("found",  sanitize_terminal(finding.evidence)),
            _field("verify", verified_str),
            _field("retest", retest_str),
            _field("impact", sanitize_terminal(finding.impact)),
            _field("fix",    sanitize_terminal(finding.remediation)),
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
