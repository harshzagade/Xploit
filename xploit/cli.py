from __future__ import annotations

import argparse
import sys

from . import __version__
from .scanner import HIGH, INFO, LOW, MEDIUM, Finding, ScanResult, WebScanner, summarize_findings


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    HIGH: "\033[91m",
    MEDIUM: "\033[93m",
    LOW: "\033[96m",
    INFO: "\033[90m",
    "OK": "\033[92m",
}

COVERAGE = (
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
    "Command Injection",
    "Directory Traversal",
    "Insecure HTTP Headers",
    "Broken Authentication",
    "Sensitive Data Exposure",
    "Open Redirect",
    "Security Misconfiguration",
)


def color(text: str, name: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(name, '')}{text}{RESET}"


def banner(enabled: bool = True) -> str:
    logo = r"""
██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║
 ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║
██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
"""
    return color(logo.rstrip(), "OK", enabled)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xploit",
        usage="xploit <url> [options]",
        description="Xploit CLI web vulnerability scanner for authorized assessments.",
        epilog=(
            "Simple usage: xploit https://target.example\n"
            "Tuned scan:   xploit https://target.example --depth 2 --max-pages 40"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"Xploit {__version__}")
    parser.add_argument("url", help="target URL, for example https://example.com")
    parser.add_argument("--depth", type=int, default=1, help="crawl depth inside the same origin (default: 1)")
    parser.add_argument("--max-pages", type=int, default=16, help="maximum pages to crawl (default: 16)")
    parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout in seconds (default: 6)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="print compact terminal output")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        target = input("Target URL: ").strip()
        if not target:
            print("error: target URL is required", file=sys.stderr)
            return 2
        argv = [target]
    elif argv[0] == "scan":
        argv = argv[1:]

    args = build_parser().parse_args(argv)
    return run_scan(args)


def run_scan(args: argparse.Namespace) -> int:
    colors = not args.no_color
    if not args.quiet:
        print(banner(colors))
        print(f"{BOLD if colors else ''}Xploit {__version__}{RESET if colors else ''} | Web Vulnerability Scanner\n")

    scanner = WebScanner(
        args.url,
        depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
    )
    try:
        result = scanner.scan()
    except ValueError as exc:
        print(color(f"error: {exc}", HIGH, colors), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(color("\nscan interrupted", MEDIUM, colors), file=sys.stderr)
        return 130

    print_result(result, colors=colors, quiet=args.quiet)

    if result.status == "unreachable":
        return 2
    return 1 if summarize_findings(result.findings).get(HIGH, 0) else 0


def print_result(result: ScanResult, *, colors: bool, quiet: bool) -> None:
    if result.status == "unreachable":
        if not quiet:
            print(f"Target      : {result.normalized_target}")
            print(f"Status      : {color('UNREACHABLE', MEDIUM, colors)}")
            print(f"Duration    : {result.duration_seconds}s")
            print()
        print(color("Target could not be reached. Check the URL, network, VPN/proxy, or firewall and try again.", MEDIUM, colors))
        return

    summary = summarize_findings(result.findings)
    if not quiet:
        print_scan_overview(result, summary, colors)
        print_coverage()
        print_crawled_urls(result.pages_seen)

    if not result.findings:
        print(color("No findings detected by the configured checks.", "OK", colors))
        return

    print(f"{BOLD if colors else ''}Detailed Findings{RESET if colors else ''}")
    print("-" * 72)
    for idx, finding in enumerate(sorted(result.findings, key=finding_sort_key), start=1):
        print_finding(idx, finding, colors)


def print_scan_overview(result: ScanResult, summary: dict[str, int], colors: bool) -> None:
    print(f"{BOLD if colors else ''}Scan Overview{RESET if colors else ''}")
    print("-" * 72)
    print(f"Target URL        : {result.normalized_target}")
    print(f"Scan status       : {result.status.upper()}")
    print(f"Started at        : {result.started_at}")
    print(f"Duration          : {result.duration_seconds}s")
    print(f"Pages crawled     : {len(result.pages_seen)}")
    print(f"Forms discovered  : {result.forms_seen}")
    print(f"Total findings    : {len(result.findings)}")
    print(f"High severity     : {color(str(summary[HIGH]), HIGH, colors)}")
    print(f"Medium severity   : {color(str(summary[MEDIUM]), MEDIUM, colors)}")
    print(f"Low severity      : {color(str(summary[LOW]), LOW, colors)}")
    print(f"Informational     : {summary[INFO]}")
    print()


def print_coverage() -> None:
    print("Coverage Executed")
    print("-" * 72)
    for item in COVERAGE:
        print(f"  [x] {item}")
    print()


def print_crawled_urls(pages: list[str]) -> None:
    print("Crawled URLs")
    print("-" * 72)
    if not pages:
        print("  none")
        print()
        return
    for index, url in enumerate(pages[:20], start=1):
        print(f"  {index:02d}. {url}")
    if len(pages) > 20:
        print(f"  ... {len(pages) - 20} more")
    print()


def finding_sort_key(finding: Finding) -> tuple[int, str]:
    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    return order.get(finding.severity, 9), finding.category


def print_finding(index: int, finding: Finding, colors: bool) -> None:
    sev = color(finding.severity, finding.severity, colors)
    heading = f"[{index:02d}] {sev} {finding.name}"
    print(f"{BOLD if colors else ''}{heading}{RESET if colors else ''}")
    print(f"     Finding ID     : {finding.id}")
    print(f"     Category       : {finding.category}")
    print(f"     Severity       : {finding.severity}")
    print(f"     Confidence     : {finding.confidence}")
    print(f"     Affected URL   : {finding.url}")
    print(f"     HTTP Method    : {finding.method}")
    if finding.parameter:
        print(f"     Parameter      : {finding.parameter}")
    if finding.trigger:
        print(f"     Detected By    : {finding.trigger}")
    if finding.cwe:
        print(f"     CWE            : {finding.cwe}")
    print(f"     Evidence       : {finding.evidence}")
    print(f"     Security Impact: {finding.impact}")
    print(f"     Remediation    : {finding.remediation}")
    print(f"     Validation     : {validation_note(finding)}")
    print()


def validation_note(finding: Finding) -> str:
    if finding.confidence.lower() == "high":
        return "High-confidence automated finding. Confirm configuration and deploy fix."
    if finding.parameter:
        return "Manual validation recommended for the affected parameter before reporting as confirmed."
    return "Review application context to confirm exploitability and business impact."
