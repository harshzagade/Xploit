from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from . import __version__
from .reporting import render_json_report
from .scanner import ACTIVE, FULL, PASSIVE, HIGH, Finding, ScanResult, WebScanner, summarize_findings


RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
COLORS = {
    HIGH:     "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[96m",
    "INFO":   "\033[2m",
    "OK":     "\033[92m",
}

def color(text: str, name: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(name, '')}{text}{RESET}"

def banner(colors: bool = True) -> str:
    logo = r"""
██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║
 ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║
██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
"""
    return color(logo.rstrip(), "OK", colors)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xploit",
        usage="xploit <url> [options]",
        description="Xploit CLI web vulnerability scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"Xploit {__version__}")
    parser.add_argument("url", help="target URL (e.g., https://example.com)")
    parser.add_argument("--depth", type=int, default=4, help="crawl depth (default: 4)")
    parser.add_argument("--max-pages", type=int, default=500, help="maximum pages to crawl (default: 500)")
    parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout per request in seconds (default: 6)")
    parser.add_argument("--mode", choices=(PASSIVE, ACTIVE, FULL), default=FULL, help="scan mode: passive, active, or full")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="minimum delay between HTTP requests in seconds")
    parser.add_argument("--scope-prefix", default="/", help="restrict crawling/checks to a path prefix")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE", help="add a custom HTTP header; may be repeated")
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE", help="add a cookie; may be repeated")
    parser.add_argument("--insecure", action="store_true", help="disable SSL certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="suppress banner and progress output")
    return parser

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        args = build_interactive_args()
        return run_scan(args)
    
    args = build_parser().parse_args(argv)
    return run_scan(args)

def run_scan(args: argparse.Namespace) -> int:
    colors = not args.no_color
    if not args.quiet and args.format == "text":
        print(banner(colors))
        print("")

    scanner = WebScanner(
        args.url,
        depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        mode=args.mode,
        rate_limit=args.rate_limit,
        scope_prefix=args.scope_prefix,
        verify=not args.insecure,
    )
    try:
        apply_request_overrides(scanner, args.header, args.cookie)
    except ValueError as exc:
        print(color(f"error: {exc}", HIGH, colors), file=sys.stderr)
        return 2

    def progress_callback(current: int, total: int, phase: str):
        _SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin    = color(_SPIN[current % len(_SPIN)], "OK", colors)
        percent = max(0, min(100, int((current / total) * 100))) if total > 0 else 0
        W       = 28
        filled  = int((percent / 100) * W)
        bar     = (
            color("▓" * filled,       "OK",   colors) +
            color("░" * (W - filled), "INFO", colors)
        )
        _b = BOLD  if colors else ""
        _r = RESET if colors else ""
        _d = DIM   if colors else ""
        _k = "\033[K" if colors else ""
        label = phase[:22]
        sys.stdout.write(
            f"\r  {spin}  {_d}{label:<22}{_r}  {bar}  {_b}{percent:>3}%{_r}{_k}"
        )
        sys.stdout.flush()
        if percent == 100 and "complete" in phase.lower():
            sys.stdout.write("\n")

    def finding_callback(finding: Finding):
        if colors:
            sys.stdout.write("\r\033[K")
        else:
            sys.stdout.write("\r" + " " * 80 + "\r")

        _col  = COLORS.get(finding.severity, "") if colors else ""
        _rst  = RESET if colors else ""
        _bold = BOLD  if colors else ""
        _dim  = DIM   if colors else ""
        _sev  = f"{_col}{_bold} {finding.severity:<6}{_rst}"
        _name = f"{_bold}{finding.name}{_rst}"
        print(f"  {_sev}  {_name}")
        # strip scheme for compactness
        short_url = finding.url.replace("https://", "").replace("http://", "")
        print(f"          {_dim}{short_url}{_rst}")
        if finding.parameter:
            print(f"          {_dim}param  {_rst}{finding.parameter}")
        sys.stdout.flush()

    if not args.quiet and args.format == "text":
        scanner.on_progress = progress_callback
        scanner.on_finding = finding_callback

    try:
        result = scanner.scan()
    except ValueError as exc:
        print(color(f"error: {exc}", HIGH, colors), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(color("\nscan interrupted", "MEDIUM", colors), file=sys.stderr)
        return 130

    if args.format == "json":
        print(render_json_report(result))
    else:
        from .reporting import render_text_report
        print(render_text_report(result))
    if result.status == "unreachable":
        return 2
    return 1 if summarize_findings(result.findings).get(HIGH, 0) else 0

def build_interactive_args(input_fn=input) -> argparse.Namespace:
    print(f"{DIM}target  ›{RESET}", end=" ", flush=True)
    url = prompt_required_text("", input_fn=input_fn)
    print(f"{DIM}depth   ›{RESET}", end=" ", flush=True)
    depth = prompt_int("", default=4, input_fn=input_fn)
    print(f"{DIM}pages   ›{RESET}", end=" ", flush=True)
    max_pages = prompt_int("", default=500, input_fn=input_fn)

    return argparse.Namespace(
        url=url,
        depth=depth,
        max_pages=max_pages,
        timeout=6.0,
        mode=FULL,
        rate_limit=0.0,
        scope_prefix="/",
        format="text",
        header=[],
        cookie=[],
        insecure=False,
        no_color=False,
        quiet=False,
    )

def apply_request_overrides(scanner: WebScanner, headers: list[str], cookies: list[str]) -> None:
    for raw_header in headers:
        if ":" not in raw_header:
            raise ValueError(f"invalid header {raw_header!r}; expected 'Name: value'")
        name, value = raw_header.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid header {raw_header!r}; header name is required")
        scanner.session.headers[name] = value.strip()
    for raw_cookie in cookies:
        if "=" not in raw_cookie:
            raise ValueError(f"invalid cookie {raw_cookie!r}; expected 'name=value'")
        name, value = raw_cookie.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid cookie {raw_cookie!r}; cookie name is required")
        scanner.session.cookies.set(name, value)

def prompt_required_text(label: str, *, input_fn: Callable[[str], str]) -> str:
    prompt = f"{label}: " if label else ""
    while True:
        value = input_fn(prompt).strip()
        if value: return value
        if label:
            print(f"{label} is required.")

def prompt_int(label: str, *, default: int, input_fn: Callable[[str], str]) -> int:
    prompt = f"{label} [{default}]: " if label else f"[{default}]: "
    while True:
        raw = input_fn(prompt).strip()
        if not raw: return default
        try:
            val = int(raw)
            if val >= 0: return val
            print("Please enter a non-negative integer.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def render_text_result(result: ScanResult, *, colors: bool = True) -> None:
    if result.status == "unreachable":
        print(color("Target could not be reached.", "MEDIUM", colors))
        return

    summary = summarize_findings(result.findings)
    bold = BOLD if colors else ""
    reset = RESET if colors else ""
    print(f"{bold}Assessment Summary{reset}")
    print("-" * 50)
    print(f"Target URL        : {result.normalized_target}")
    print(f"Scan mode         : {result.scan_mode.upper()}")
    print(f"Scope prefix      : {result.scope_prefix}")
    print(f"Duration          : {result.duration_seconds}s")
    print(f"Pages crawled     : {len(result.pages_seen)}")
    print(f"Forms discovered  : {result.forms_seen}")
    print(f"Checks executed   : {len(result.checks_run)}")
    print(f"Total findings    : {len(result.findings)}")
    print(f"High severity     : {color(str(summary[HIGH]), HIGH, colors)}")
    print(f"Medium severity   : {color(str(summary['MEDIUM']), 'MEDIUM', colors)}")
    print(f"Low severity      : {color(str(summary['LOW']), 'LOW', colors)}")
    print(f"Informational     : {summary['INFO']}")
    print("")

    if not result.findings:
        print(color("No findings detected.", "OK", colors))
        return

    print(f"{bold}Findings{reset}")
    print("-" * 50)
    for idx, finding in enumerate(result.findings, start=1):
        sev = color(finding.severity, finding.severity, colors)
        print(f"[{idx:02d}] {sev} | {finding.name}")
        print(f"     URL: {finding.url}")
        if finding.parameter:
            print(f"     Parameter: {finding.parameter}")
        print(f"     Evidence: {finding.evidence}")
        print(f"     Impact: {finding.impact}")
        print(f"     Remediation: {finding.remediation}")
        print("")

def render_completion_bar(percent: int, colors: bool, width: int = 24) -> str:
    # Kept for test compatibility if needed, but not used in main output
    bounded = max(0, min(100, percent))
    filled = round((bounded / 100) * width)
    bar = f"[{'#' * filled}{'.' * (width - filled)}] {bounded}%"
    return color(bar, "OK", colors) if bounded == 100 else bar

def render_result(result: ScanResult, **kwargs) -> str:
    # Kept for test compatibility
    import io
    from contextlib import redirect_stdout
    f = io.StringIO()
    with redirect_stdout(f):
        render_text_result(result)
    return f.getvalue()
