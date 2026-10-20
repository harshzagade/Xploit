from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import threading
import time
from collections.abc import Callable

from . import __version__
from .reporting import render_json_report, meets_severity
from .scanner import ACTIVE, FULL, PASSIVE, HIGH, Finding, ScanResult, WebScanner, summarize_findings
from .scanner import MODULE_REGISTRY


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
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝""".strip("\n")
    tagline = "web vulnerability scanner"
    if not colors:
        return f"{logo}\n  {tagline}  ·  v{__version__}"
    # red -> amber gradient, one shade per line
    shades = ["\033[91m", "\033[91m", "\033[33m",
              "\033[33m", "\033[93m", "\033[93m"]
    painted = "\n".join(
        f"{shades[i % len(shades)]}{ln}{RESET}"
        for i, ln in enumerate(logo.split("\n"))
    )
    return (
        f"{painted}\n"
        f"  {DIM}{tagline}{RESET}  {DIM}·{RESET}  {BOLD}v{__version__}{RESET}"
    )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xploit",
        usage="xploit <url> [url ...] [options]",
        description="Xploit CLI web vulnerability scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"Xploit {__version__}")
    parser.add_argument("url", help="target URL (e.g., https://example.com)")
    parser.add_argument("extra_urls", nargs="*", metavar="url",
                        help="additional target URLs — all targets are scanned "
                             "concurrently in one run")
    parser.add_argument("--depth", type=int, default=4, help="crawl depth (default: 4)")
    parser.add_argument("--max-pages", type=int, default=500, help="maximum pages to crawl (default: 500)")
    parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout per request in seconds (default: 6)")
    parser.add_argument("--mode", choices=(PASSIVE, ACTIVE, FULL), default=FULL, help="scan mode: passive, active, or full")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="minimum delay between HTTP requests in seconds")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="add up to N extra random seconds between requests "
                             "(smooths request timing; default: 0)")
    parser.add_argument("--scope-prefix", default="/", help="restrict crawling/checks to a path prefix")
    parser.add_argument("--threads", type=int, default=5,
                        help="concurrency for crawling and probe requests "
                             "(default: 5; raise for faster scans on responsive "
                             "targets)")
    parser.add_argument("--parallel-modules", type=int, default=4, metavar="N",
                        help="run up to N scan modules concurrently side by side "
                             "on the same terminal (default: 4; 1 = sequential). "
                             "Each module already fans its own probes over "
                             "--threads, so this multiplies in-flight requests "
                             "— lower it for fragile targets.")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="skip crawling URLs matching PATTERN (Python regex, matched against "
                             "the full URL); may be repeated")
    parser.add_argument("--modules", action="append", default=[], metavar="LIST",
                        help="run only the named scan modules, comma-separated, "
                             "for faster targeted scans (e.g. --modules xss,sqli); "
                             "may be repeated. Valid modules: "
                             + ", ".join(MODULE_REGISTRY))
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    parser.add_argument("--output", metavar="PATH", default=None, help="write the report to a file (ANSI colors stripped)")
    parser.add_argument("--retest", action="store_true", help="re-fire each finding's proof request to confirm it still reproduces (active traffic; skipped in passive mode)")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE", help="add a custom HTTP header; may be repeated")
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE", help="add a cookie; may be repeated")
    parser.add_argument("--insecure", action="store_true", help="disable SSL certificate verification")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="suppress banner and progress output")
    parser.add_argument("--min-severity", choices=("HIGH", "MEDIUM", "LOW", "INFO"), default="MEDIUM",
                        help="only show findings at or above this severity in live output and the "
                             "text report (LOW/INFO collapse to one-liners; default: MEDIUM)")
    return parser

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        args = build_interactive_args()
        return run_scan(args)
    
    args = build_parser().parse_args(argv)
    return run_scan(args)

def finding_visible(finding: Finding, min_severity: str) -> bool:
    """Live-output gate: only findings at/above the threshold print during
    the scan. Below-threshold findings are still counted in the progress
    bar and collapsed to one-liners in the final report."""
    return meets_severity(finding.severity, min_severity)


def target_list(args: argparse.Namespace) -> list[str]:
    """All scan targets: the positional URL plus any extra URLs."""
    return [args.url] + list(getattr(args, "extra_urls", None) or [])


def _build_scanner(args: argparse.Namespace, target_url: str) -> WebScanner:
    """Construct a configured WebScanner. Raises ValueError on bad input."""
    scanner = WebScanner(
        target_url,
        depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        mode=args.mode,
        rate_limit=args.rate_limit,
        jitter=args.jitter,
        scope_prefix=args.scope_prefix,
        exclude=args.exclude,
        threads=args.threads,
        parallel_modules=args.parallel_modules,
        # getattr: Namespaces built by hand (tests, embedders) may predate
        # the --modules flag.
        modules=getattr(args, "modules", None) or None,
        verify=not args.insecure,
    )
    apply_request_overrides(scanner, args.header, args.cookie)
    return scanner


def _retest_if_requested(args: argparse.Namespace, scanner: WebScanner,
                         result: ScanResult, colors: bool, show_ui: bool) -> None:
    if not args.retest:
        return
    from .retest import retest_findings, retest_summary_line
    # Unwire the live progress tick: retest replay requests would otherwise
    # redraw the bar at 100% still labeled "Checks complete".
    scanner.on_request = None
    stats = retest_findings(scanner, result.findings)
    if show_ui:
        print(color(retest_summary_line(stats), "MEDIUM", colors))


def _error_result(target: str, status: str) -> ScanResult:
    """Placeholder result for a target that could not be scanned."""
    return ScanResult(
        target=target, normalized_target=target, started_at="",
        duration_seconds=0.0, status=status, scan_mode="",
        scope_prefix="/", completion_percent=0, checks_run=[],
        pages_seen=[], forms_seen=0, findings=[],
        errors=[f"target {status}: {target}"],
    )


def _write_output(args: argparse.Namespace, content: str, colors: bool) -> None:
    if args.output:
        from .reporting import strip_ansi, write_report
        # ANSI stripping is for human-readable text only — JSON evidence may
        # legitimately contain "\\x1b[<nums>m"-shaped sequences that must not
        # be silently deleted from the saved report.
        write_report(strip_ansi(content) if args.format == "text" else content,
                     args.output)
        if not args.quiet:
            # stderr, not stdout: keeps piped --format json output parseable.
            print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(content)


def run_scan(args: argparse.Namespace) -> int:
    targets = target_list(args)
    if len(targets) == 1:
        return _run_single_target(args, targets[0])
    return _run_multi_target(args, targets)


def _run_multi_target(args: argparse.Namespace, targets: list[str]) -> int:
    """Scan several targets concurrently, one ScanResult per target.

    The animated single-scan progress bar cannot represent N concurrent
    scans, so multi-target mode uses line-based status: one line per
    target start/finish, findings printed live tagged with their target.
    """
    colors = not args.no_color
    show_ui = not args.quiet and args.format == "text"
    _lock = threading.Lock()

    def _short(target: str) -> str:
        return target.replace("https://", "").replace("http://", "").rstrip("/")

    if show_ui:
        print(banner(colors))
        _d = DIM if colors else ""
        _r = RESET if colors else ""
        print(f"  {_d}{len(targets)} targets · {args.mode} · "
              f"{args.threads} threads each{_r}")
        print("")

    def _scan_target(target: str) -> ScanResult:
        if show_ui:
            with _lock:
                print(f"  {color('[+]', 'OK', colors)} {_short(target)} — starting")
        try:
            scanner = _build_scanner(args, target)
        except ValueError as exc:
            with _lock:
                print(color(f"  [!] {_short(target)}: error: {exc}", HIGH, colors))
            return _error_result(target, "invalid")
        if show_ui:
            def on_finding(finding: Finding):
                if not finding_visible(finding, args.min_severity):
                    return
                with _lock:
                    _col = COLORS.get(finding.severity, "") if colors else ""
                    _rst = RESET if colors else ""
                    _b = BOLD if colors else ""
                    print(f"  {_col}▌{_rst} [{_short(target)}] "
                          f"{_col}{_b}{finding.severity:<6}{_rst} {_b}{finding.name}{_rst}")
            scanner.on_finding = on_finding
        try:
            result = scanner.scan()
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # one bad target must not kill the others
            with _lock:
                print(color(f"  [!] {_short(target)}: scan failed: {exc}", HIGH, colors))
            return _error_result(target, "error")
        _retest_if_requested(args, scanner, result, colors, show_ui)
        if show_ui:
            with _lock:
                summary = summarize_findings(result.findings)
                parts = ", ".join(f"{n} {s}" for s, n in summary.items() if n)
                detail = f" ({parts})" if parts else ""
                print(f"  {color('[ok]', 'OK', colors)} {_short(target)} — done: "
                      f"{len(result.findings)} findings{detail} "
                      f"in {result.duration_seconds:g}s")
        return result

    workers = max(1, min(len(targets), args.threads))
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="xploit-target")
    try:
        # executor.map preserves target order for the results list.
        ordered = list(executor.map(_scan_target, targets))
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        print(color("\nscan interrupted", "MEDIUM", colors), file=sys.stderr)
        return 130
    executor.shutdown(wait=True)

    if args.format == "json":
        content = json.dumps([r.to_dict() for r in ordered],
                             indent=2, sort_keys=True)
    else:
        from .reporting import render_text_report
        content = "\n\n".join(
            render_text_report(r, colors=colors,
                               min_severity=args.min_severity)
            for r in ordered)
    _write_output(args, content, colors)

    if any(r.status in ("unreachable", "invalid", "error") for r in ordered):
        return 2
    return 1 if any(summarize_findings(r.findings).get(HIGH, 0)
                     for r in ordered) else 0


def _run_single_target(args: argparse.Namespace, target_url: str) -> int:
    colors = not args.no_color
    if not args.quiet and args.format == "text":
        print(banner(colors))
        _d = DIM if colors else ""
        _r = RESET if colors else ""
        _b = BOLD if colors else ""
        print(f"  {_d}target{_r}  {_b}{target_url}{_r}")
        print(f"  {_d}mode{_r}    {args.mode} · depth {args.depth} · "
              f"{args.max_pages} pages · {args.timeout:g}s timeout")
        print("")

    try:
        scanner = _build_scanner(args, target_url)
    except ValueError as exc:
        print(color(f"error: {exc}", HIGH, colors), file=sys.stderr)
        return 2

    # Progress state shared by the phase callback and the per-request tick.
    # Module runs fire hundreds of sequential requests with no phase change;
    # without the tick the bar looks frozen for minutes on slow targets.
    _ui_lock = threading.Lock()
    _ui_state = {"current": 0, "total": 1, "phase": "", "tick": 0,
                 "requests": 0, "findings": 0, "last_draw": 0.0,
                 "started": time.monotonic()}
    _SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _redraw():
        st = _ui_state
        spin    = color(_SPIN[st["tick"] % len(_SPIN)], "OK", colors)
        percent = max(0, min(100, int((st["current"] / st["total"]) * 100))) if st["total"] > 0 else 0
        W       = 22
        filled  = int((percent / 100) * W)
        bar     = (
            color("━" * filled,       "OK",   colors) +
            color("─" * (W - filled), "INFO", colors)
        )
        _b = BOLD  if colors else ""
        _r = RESET if colors else ""
        _d = DIM   if colors else ""
        _k = "\033[K" if colors else ""
        label = st["phase"][:20]
        elapsed = int(time.monotonic() - st["started"])
        req = f"  {_d}{st['requests']} req{_r}" if st["requests"] else ""
        clock = f"  {_d}{elapsed}s{_r}"
        hits = f"  {_d}▲ {st['findings']}{_r}" if st["findings"] else ""
        sys.stdout.write(
            f"\r  {spin}  {_d}{label:<20}{_r}  {bar}  {_b}{percent:>3}%{_r}{req}{clock}{hits}{_k}"
        )
        sys.stdout.flush()
        st["last_draw"] = time.monotonic()
        if percent == 100 and "complete" in st["phase"].lower():
            sys.stdout.write("\n")

    def progress_callback(current: int, total: int, phase: str):
        with _ui_lock:
            _ui_state.update(current=current, total=total, phase=phase,
                             tick=_ui_state["tick"] + 1)
            _redraw()

    def request_callback(count: int):
        # Throttled heartbeat: redraw at most ~5x/sec so slow sequential
        # module runs visibly advance instead of looking frozen.
        with _ui_lock:
            _ui_state["requests"] = count
            _ui_state["tick"] += 1
            if time.monotonic() - _ui_state["last_draw"] >= 0.2:
                _redraw()

    def request_counter_callback(count: int):
        # Parallel mode has no animated bar to redraw; just record the
        # cumulative count so the module done lines can show it.
        with _ui_lock:
            _ui_state["requests"] = count

    def finding_callback(finding: Finding):
        with _ui_lock:
            _ui_state["findings"] += 1
            if not finding_visible(finding, args.min_severity):
                return  # below threshold: counted, not printed
            if colors:
                sys.stdout.write("\r\033[K")
            else:
                sys.stdout.write("\r" + " " * 80 + "\r")

            _col  = COLORS.get(finding.severity, "") if colors else ""
            _rst  = RESET if colors else ""
            _bold = BOLD  if colors else ""
            _dim  = DIM   if colors else ""
            _ok   = COLORS["OK"] if colors else ""
            n = _ui_state["findings"]
            if finding.verified:
                _proof = f"  {_ok}✓ verified{_rst}"
            else:
                _proof = f"  {_dim}○ unverified{_rst}"
            print(f"  {_col}▌{_rst} {_col}{_bold}{finding.severity:<6}{_rst} "
                  f"{_bold}#{n} {finding.name}{_rst}{_proof}")
            # strip scheme for compactness
            short_url = finding.url.replace("https://", "").replace("http://", "")
            detail = f"  {_dim}└─ {short_url}{_rst}"
            if finding.parameter:
                detail += f"  {_dim}· param: {finding.parameter}{_rst}"
            print(detail)
            sys.stdout.flush()
            _ui_state["last_draw"] = 0.0  # force next tick to redraw

    def _module_status_line(text: str):
        # One animated bar cannot represent N concurrent modules (same
        # rationale as multi-target mode), so parallel-module runs use
        # one status line per module start/finish instead.
        with _ui_lock:
            if colors:
                sys.stdout.write("\r\033[K")
            print(text)
            sys.stdout.flush()

    def module_start_callback(name: str):
        _module_status_line(
            f"  {color('>>', 'INFO', colors)} {name} — starting")

    def module_done_callback(name: str, added: int, secs: float):
        with _ui_lock:
            req_total = _ui_state["requests"]
        req = f" · {req_total} req" if req_total else ""
        _module_status_line(
            f"  {color('<<', 'OK', colors)} {name} — done: "
            f"{added} findings in {secs:.0f}s{req}")

    if not args.quiet and args.format == "text":
        if args.parallel_modules > 1:
            scanner.on_module_start = module_start_callback
            scanner.on_module_done = module_done_callback
            scanner.on_finding = finding_callback
            scanner.on_request = request_counter_callback
        else:
            scanner.on_progress = progress_callback
            scanner.on_finding = finding_callback
            scanner.on_request = request_callback

    try:
        result = scanner.scan()
    except ValueError as exc:
        print(color(f"error: {exc}", HIGH, colors), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(color("\nscan interrupted", "MEDIUM", colors), file=sys.stderr)
        return 130

    _retest_if_requested(args, scanner, result, colors,
                         show_ui=not args.quiet and args.format == "text")

    if args.format == "json":
        content = render_json_report(result)
    else:
        from .reporting import render_text_report
        content = render_text_report(result, colors=colors,
                                     min_severity=args.min_severity)
    _write_output(args, content, colors)

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
        jitter=0.0,
        scope_prefix="/",
        exclude=[],
        modules=[],
        format="text",
        output=None,
        retest=False,
        header=[],
        cookie=[],
        insecure=False,
        no_color=False,
        quiet=False,
        min_severity="MEDIUM",
        threads=5,
        extra_urls=[],
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
    if result.exclude_patterns:
        print(f"Exclude patterns  : {', '.join(result.exclude_patterns)}")
    if result.modules:
        print(f"Modules selected  : {', '.join(result.modules)}")
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
        print(f"     Verified: {'yes (replayable proof)' if finding.verified else 'no'}")
        if finding.retest_status != "not_run":
            print(f"     Retest: {finding.retest_status}")
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
