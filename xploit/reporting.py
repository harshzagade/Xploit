from __future__ import annotations

import csv
import html
import io
import json
import re
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .scanner import Finding, ScanResult, summarize_findings

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes — file output must be plain text."""
    return _ANSI_RE.sub("", text)


# Severity ordering for display filtering (--min-severity). Lower rank =
# more severe. Unknown severities sort last so they are never silently
# promoted above the threshold.
_SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def meets_severity(severity: str, minimum: str) -> bool:
    """True when `severity` is at or above the `minimum` severity threshold."""
    return _SEV_RANK.get(severity, 9) <= _SEV_RANK.get(minimum, 9)


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


def render_text_report(result: ScanResult, colors: bool = True,
                       min_severity: str = "MEDIUM") -> str:
    """Render the human-readable report.

    Findings at or above `min_severity` get full detail blocks; anything
    below is collapsed to a compact one-line list at the end so the report
    stays focused on what matters. The JSON report always carries every
    finding — nothing is lost, only the terminal noise is reduced.
    """
    BOLD   = "\033[1m"  if colors else ""
    RESET  = "\033[0m"  if colors else ""
    DIM    = "\033[2m"  if colors else ""
    RED    = "\033[91m" if colors else ""
    YELLOW = "\033[93m" if colors else ""
    CYAN   = "\033[96m" if colors else ""
    GREEN  = "\033[92m" if colors else ""
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
    if getattr(result, "robots_skipped", 0):
        coverage += f"  ·  {result.robots_skipped} robots.txt-skipped"
    verified = sum(1 for f in result.findings if f.verified)
    total_f  = len(result.findings)
    proof_line = f"✓ {verified}/{total_f} findings verified with replayable proof" if total_f else None

    box_w = max(len(target), len(meta), len(coverage),
                len(proof_line) if proof_line else 0) + 4
    box_w = max(box_w, 54)

    lines.append("")
    lines.append(f"┌{'─' * box_w}┐")
    title_vis = f"SCAN REPORT  ·  xploit v{__version__}"
    title_pad = box_w - 4 - len(title_vis)
    lines.append(f"│  {BOLD}{RED}SCAN REPORT{RESET}  {DIM}·  xploit v{__version__}{RESET}"
                 f"{' ' * title_pad}│")
    lines.append(f"│  {BOLD}{target:<{box_w - 2}}{RESET}│")
    lines.append(f"│  {DIM}{meta:<{box_w - 2}}{RESET}│")
    lines.append(f"│  {DIM}{coverage:<{box_w - 2}}{RESET}│")
    if proof_line:
        lines.append(f"│  {GREEN}{proof_line:<{box_w - 2}}{RESET}│")
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

    if result.status == "dry-run":
        # A dry-run has no findings by design — its output IS the
        # entry-point listing, so it replaces the findings section
        # instead of falling through to "No findings detected."
        lines.append(f"  {DIM}DRY RUN — no probe traffic sent; "
                     f"entry points discovered by the crawl:{RESET}")
        lines.append("")
        entries = getattr(result, "entry_points", []) or []
        if not entries:
            lines.append(f"  {DIM}No pages or forms discovered.{RESET}")
        for entry in entries:
            params = ", ".join(entry.get("parameters") or [])
            param_str = f"  {DIM}params: {params}{RESET}" if params else ""
            if entry.get("kind") == "form":
                lines.append(f"  {BOLD}{entry.get('method', '')} "
                             f"{sanitize_terminal(entry.get('url', ''))}{RESET}"
                             f"  {DIM}(form on "
                             f"{sanitize_terminal(entry.get('page_url', ''))}){RESET}")
            else:
                lines.append(f"  {BOLD}{entry.get('method', 'GET')} "
                             f"{sanitize_terminal(entry.get('url', ''))}{RESET}")
            if param_str:
                lines.append(f"    {param_str}")
        lines.append("")
        lines.append("─" * (box_w + 2))
        return "\n".join(lines).rstrip()

    if not result.findings:
        if result.status == "unreachable":
            lines.append(f"  {RED}Target was unreachable.{RESET}")
        else:
            lines.append(f"  {GREEN}No findings detected.{RESET}")
        return "\n".join(lines)

    # ── Findings grouped by severity ─────────────────────────────────────
    # Below-threshold findings are collapsed to one-liners at the end —
    # the terminal shows what matters, the JSON report keeps everything.
    main_findings   = [f for f in result.findings if meets_severity(f.severity, min_severity)]
    hidden_findings = [f for f in result.findings if not meets_severity(f.severity, min_severity)]
    sorted_findings = sorted(main_findings, key=_finding_sort_key)
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
        if finding.verified and finding.proof_kind == "timing":
            verified_str = (f"yes — timing proof attached "
                            f"(delay >= {finding.proof_delay_s:g}s reproduced)")
        else:
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

    if hidden_findings:
        lines.append("")
        cnt = len(hidden_findings)
        what = "finding" if cnt == 1 else "findings"
        label = f" {DIM}LOWER SEVERITY ({cnt} {what} below --min-severity {min_severity}){RESET} "
        label_plain = f" LOWER SEVERITY ({cnt} {what} below --min-severity {min_severity}) "
        pad = "─" * max(0, box_w + 2 - len(label_plain) - 4)
        lines.append(f"───{label}{pad}───")
        lines.append("")
        for finding in sorted(hidden_findings, key=_finding_sort_key):
            col = SEV_COLOR.get(finding.severity, "")
            short_url = sanitize_terminal(finding.url).replace("https://", "").replace("http://", "")
            param = f"  {DIM}· param: {sanitize_terminal(finding.parameter)}{RESET}" if finding.parameter else ""
            lines.append(f"  {col}{finding.severity:<6}{RESET}  {sanitize_terminal(finding.name)}"
                         f"  {DIM}— {short_url}{RESET}{param}")
        lines.append("")

    lines.append("─" * (box_w + 2))
    return "\n".join(lines).rstrip()


def render_json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


# CSV columns for `--format csv`: one row per finding, for spreadsheet
# pipelines. Every finding is included (like JSON, unlike the text report's
# --min-severity collapsing), and the csv module's quoting round-trips
# evidence containing commas, quotes or newlines.
_CSV_HEADER = ["id", "severity", "url", "parameter", "evidence"]


def render_csv_reports(results: list[ScanResult]) -> str:
    """Render findings from one or more scan results as CSV text.

    A single header row covers all results, so multi-target runs produce
    one concatenated table (each finding's full URL identifies its target).
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_CSV_HEADER)
    for result in results:
        for finding in result.findings:
            writer.writerow([finding.id, finding.severity, finding.url,
                             finding.parameter, finding.evidence])
    return buf.getvalue().rstrip("\n")


def render_csv_report(result: ScanResult) -> str:
    return render_csv_reports([result])


# SARIF 2.1.0 output for `--format sarif`: GitHub code scanning and other
# SARIF consumers ingest findings with rule IDs, severity levels and the
# URL where each finding was observed. One run per scan result; one rule
# per distinct finding id (first-seen order); one result per finding.
# Severity mapping follows the SARIF level vocabulary: HIGH findings are
# errors, MEDIUM are warnings, LOW/INFO are notes.
_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note",
                "INFO": "note"}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_rule(finding: Finding) -> dict:
    rule: dict = {
        "id": finding.id,
        "name": finding.id.replace("-", ""),
        "shortDescription": {"text": finding.name},
        "fullDescription": {"text": finding.impact or finding.name},
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        },
        "help": {"text": finding.remediation or finding.name},
    }
    properties: dict = {"category": finding.category}
    if finding.cwe:
        properties["cwe"] = finding.cwe
        properties["tags"] = ["security", finding.cwe]
    else:
        properties["tags"] = ["security"]
    rule["properties"] = properties
    return rule


def _sarif_result(finding: Finding) -> dict:
    result: dict = {
        "ruleId": finding.id,
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": finding.evidence},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.url},
            },
        }],
    }
    properties: dict = {
        "confidence": finding.confidence,
        "verified": finding.verified,
    }
    if finding.parameter:
        properties["parameter"] = finding.parameter
    if finding.method:
        properties["method"] = finding.method
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.impact:
        properties["impact"] = finding.impact
    if finding.remediation:
        properties["remediation"] = finding.remediation
    result["properties"] = properties
    return result


def _sarif_run(result: ScanResult) -> dict:
    rules: list[dict] = []
    seen_ids: set[str] = set()
    for finding in result.findings:
        if finding.id not in seen_ids:
            seen_ids.add(finding.id)
            rules.append(_sarif_rule(finding))
    return {
        "tool": {
            "driver": {
                "name": "Xploit",
                "version": __version__,
                "informationUri": "https://github.com/harshzagade/Xploit",
                "rules": rules,
            },
        },
        "results": [_sarif_result(f) for f in result.findings],
        "properties": {
            "target": result.normalized_target,
            "scanMode": result.scan_mode,
            "startedAt": result.started_at,
            "durationSeconds": result.duration_seconds,
        },
    }


def render_sarif_reports(results: list[ScanResult]) -> str:
    """Render one or more scan results as a SARIF 2.1.0 document.

    Multi-target runs produce one run per target, so a single SARIF file
    can carry the whole run (like the CSV format's single header row).
    """
    document = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [_sarif_run(r) for r in results],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def render_sarif_report(result: ScanResult) -> str:
    return render_sarif_reports([result])


# HTML output for `--format html`: a single self-contained report (inline
# CSS, no external resources) for sharing with clients who will not read
# terminal output. Every finding is included (like JSON/CSV, unlike the
# text report's --min-severity collapsing), grouped by severity, with
# severity-coloured badges and the evidence/impact/remediation fields.
# All finding text is HTML-escaped: evidence can carry reflected payloads
# (`<script>`, `<svg onload=...>`) that must render as text, never markup.
_SEV_CLASS = {"HIGH": "sev-high", "MEDIUM": "sev-medium",
              "LOW": "sev-low", "INFO": "sev-info"}
_SEV_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")

_HTML_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
margin:2em auto;max-width:960px;padding:0 1em;color:#1f2328;
background:#fff;line-height:1.5}
h1{font-size:1.6em;margin-bottom:.1em}
h2{font-size:1.2em;border-bottom:1px solid #d0d7de;padding-bottom:.3em;
margin-top:2em}
.meta{color:#656d76;font-size:.9em}
.summary{margin:1em 0}
.badge{display:inline-block;padding:.1em .6em;border-radius:999px;
color:#fff;font-weight:600;font-size:.85em;margin-right:.4em}
.sev-high{background:#d1242f}.sev-medium{background:#9a6700}
.sev-low{background:#0969da}.sev-info{background:#656d76}
.finding{border:1px solid #d0d7de;border-left-width:6px;border-radius:6px;
padding:.8em 1em;margin:1em 0}
.finding.sev-high{border-left-color:#d1242f}
.finding.sev-medium{border-left-color:#9a6700}
.finding.sev-low{border-left-color:#0969da}
.finding.sev-info{border-left-color:#656d76}
.finding h3{margin:.1em 0 .4em;font-size:1.05em}
.finding dl{display:grid;grid-template-columns:8em 1fr;gap:.2em .8em;
margin:.4em 0 0}
.finding dt{font-weight:600;color:#656d76}
.finding dd{margin:0;overflow-wrap:anywhere}
.finding code{background:#f6f8fa;padding:.1em .3em;border-radius:4px;
overflow-wrap:anywhere}
.verified{color:#1a7f37;font-weight:600}
.unverified{color:#9a6700;font-weight:600}
footer{color:#656d76;font-size:.85em;margin-top:2em}
""".strip()


def _html_finding(finding: Finding) -> str:
    """One finding as an HTML card, all values escaped."""
    sev = finding.severity
    cls = _SEV_CLASS.get(sev, "sev-info")
    cwe = f" &middot; {html.escape(finding.cwe)}" if finding.cwe else ""
    verified = ("<span class=\"verified\">verified &mdash; replayable proof "
                "attached</span>" if finding.verified
                else "<span class=\"unverified\">unverified</span>")
    rows = [
        ("URL", html.escape(finding.url)),
        ("Parameter", html.escape(finding.parameter)),
        ("Method", html.escape(finding.method) if finding.method != "GET" else ""),
        ("Evidence", f"<code>{html.escape(finding.evidence)}</code>"),
        ("Verified", verified),
        ("Impact", html.escape(finding.impact)),
        ("Remediation", html.escape(finding.remediation)),
    ]
    body = "".join(
        f"<dt>{label}</dt><dd>{value}</dd>"
        for label, value in rows if value
    )
    return (
        f"<article class=\"finding {cls}\">"
        f"<h3><span class=\"badge {cls}\">{html.escape(sev)}</span> "
        f"{html.escape(finding.name)}{cwe}</h3>"
        f"<dl>{body}</dl></article>"
    )


def _html_section(result: ScanResult) -> str:
    """One scan result as the body section of an HTML report."""
    summary = summarize_findings(result.findings)
    total = len(result.findings)
    verified = sum(1 for f in result.findings if f.verified)
    badges = "".join(
        f"<span class=\"badge {_SEV_CLASS[sev]}\">{sev} {summary[sev]}</span>"
        for sev in _SEV_ORDER if summary[sev]
    ) or "<span class=\"badge sev-info\">0 findings</span>"
    meta = (f"{html.escape(result.scan_mode.upper())} &middot; "
            f"{result.duration_seconds:g}s &middot; "
            f"{html.escape(result.started_at)} &middot; "
            f"{len(result.pages_seen)} pages &middot; "
            f"{result.forms_seen} forms")
    parts = [
        f"<h2>{html.escape(result.normalized_target)}</h2>",
        f"<p class=\"meta\">{meta}</p>",
        f"<p class=\"summary\">{badges} &nbsp; "
        f"{verified}/{total} verified</p>",
    ]
    if result.status == "unreachable":
        parts.append("<p><strong>Target was unreachable.</strong></p>")
    elif not result.findings:
        parts.append("<p><strong>No findings detected.</strong></p>")
    else:
        for sev in _SEV_ORDER:
            group = [f for f in result.findings if f.severity == sev]
            if not group:
                continue
            parts.append(f"<h3>{sev} ({len(group)})</h3>")
            parts.extend(_html_finding(f)
                         for f in sorted(group, key=_finding_sort_key))
    return "\n".join(parts)


def render_html_reports(results: list[ScanResult]) -> str:
    """Render one or more scan results as a single self-contained HTML
    document. Multi-target runs get one section per target, like the CSV
    format's single table and the SARIF format's one run per target."""
    title = "Xploit Scan Report"
    sections = "\n".join(_html_section(r) for r in results)
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{title}</title>\n"
        f"<style>\n{_HTML_CSS}\n</style>\n</head>\n<body>\n"
        f"<h1>{title}</h1>\n"
        f"<p class=\"meta\">xploit v{__version__}</p>\n"
        f"{sections}\n"
        f"<footer>Generated by Xploit v{__version__}</footer>\n"
        "</body>\n</html>"
    )


def render_html_report(result: ScanResult) -> str:
    return render_html_reports([result])


# JUnit XML output for `--format junit`: CI pipelines ingest findings as
# native test results, so a build fails on HIGH findings with no extra
# tooling. One testsuite per scan result; one testcase per finding
# (classname `xploit.<finding-id>`, name `<id> <name>`). Only HIGH
# findings become `<failure>` elements — MEDIUM/LOW/INFO findings are
# listed as passing testcases so the run stays visible without breaking
# the build; teams wanting stricter gating can post-process the XML.
# An unreachable target is a single `<error>` testcase instead of a
# silent zero-test pass, so a dead target fails the build too. ElementTree
# escapes all finding text, so reflected payloads in evidence can never
# break the document.
def _junit_testcase(finding: Finding) -> ET.Element:
    case = ET.Element("testcase", {
        "classname": f"xploit.{finding.id}",
        "name": f"{finding.id} {finding.name}",
    })
    if finding.severity != "HIGH":
        return case
    detail = "\n".join(filter(None, [
        f"URL: {finding.url}",
        f"Parameter: {finding.parameter}" if finding.parameter else "",
        f"Method: {finding.method}" if finding.method != "GET" else "",
        f"Evidence: {finding.evidence}",
        f"CWE: {finding.cwe}" if finding.cwe else "",
        f"Impact: {finding.impact}" if finding.impact else "",
        f"Remediation: {finding.remediation}" if finding.remediation else "",
    ]))
    failure = ET.SubElement(case, "failure", {
        "message": f"{finding.id} ({finding.severity}) at {finding.url}",
        "type": finding.severity,
    })
    failure.text = detail
    return case


def _junit_suite(result: ScanResult) -> ET.Element:
    failures = sum(1 for f in result.findings if f.severity == "HIGH")
    unreachable = result.status == "unreachable"
    suite = ET.Element("testsuite", {
        "name": f"xploit:{result.normalized_target}",
        "tests": str(1 if unreachable else len(result.findings)),
        "failures": str(0 if unreachable else failures),
        "errors": "1" if unreachable else "0",
        "skipped": "0",
        "time": f"{result.duration_seconds:g}",
    })
    props = ET.SubElement(suite, "properties")
    for key, value in (("target", result.normalized_target),
                       ("scanMode", result.scan_mode),
                       ("startedAt", result.started_at)):
        ET.SubElement(props, "property", {"name": key, "value": value})
    if unreachable:
        case = ET.SubElement(suite, "testcase", {
            "classname": "xploit.target",
            "name": "target-unreachable",
        })
        error = ET.SubElement(case, "error", {
            "message": f"target unreachable: {result.normalized_target}",
            "type": "unreachable",
        })
        error.text = "; ".join(result.errors) or "target unreachable"
    else:
        for finding in result.findings:
            suite.append(_junit_testcase(finding))
    return suite


def render_junit_reports(results: list[ScanResult]) -> str:
    """Render one or more scan results as a JUnit XML document.

    Multi-target runs produce one testsuite per target inside a single
    `<testsuites>` root, like the SARIF format's one run per target.
    """
    root = ET.Element("testsuites")
    for result in results:
        root.append(_junit_suite(result))
    ET.indent(root, space="  ")
    # xml_declaration needs a byte encoding; decode back to str.
    return ET.tostring(root, encoding="utf-8",
                       xml_declaration=True).decode("utf-8")


def render_junit_report(result: ScanResult) -> str:
    return render_junit_reports([result])


def write_report(content: str, output_path: str) -> None:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")


def _finding_sort_key(finding: Finding) -> tuple[int, str]:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return order.get(finding.severity, 9), finding.category
