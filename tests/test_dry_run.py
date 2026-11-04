"""--dry-run entry-point listing (WebScanner dry_run + CLI flag).

A dry-run crawls and lists pages/forms/parameters but runs no scan
module, so it must send no probe traffic: the result carries no
findings, checks_run is ["dry-run"], no checkpoint is written, and the
text report shows the listing instead of "No findings detected."
"""
import argparse
import sys
import types

# bs4 is a runtime requirement of xploit.scanner but is not installed in
# this environment (no installs without his word). These tests stub the
# crawl instead of fetching, so a minimal import-time stub is enough.
_bs4_stub = types.ModuleType("bs4")


class _SoupStub:  # noqa: D101
    def __init__(self, *args, **kwargs):
        raise RuntimeError("bs4 stub: no real HTML parsing in this environment")


_bs4_stub.BeautifulSoup = _SoupStub
sys.modules.setdefault("bs4", _bs4_stub)

from xploit.cli import build_parser, run_scan
from xploit.reporting import render_text_report
from xploit.scanner import FormTarget, ScanResult, WebScanner


class Resp:
    def __init__(self, text=""):
        self.text = text


def dry_scanner():
    scanner = WebScanner("http://x/", mode="passive", dry_run=True)
    scanner.pages = {
        "http://x/search?q=hello&lang=en": Resp("search page"),
        "http://x/about": Resp("about page"),
    }
    scanner.forms = [
        FormTarget("http://x/login", "http://x/login", "POST",
                   {"user": "xploit", "pass": "xploit"}, {}),
        # Exact duplicate form: the listing must collapse it to one entry.
        FormTarget("http://x/login", "http://x/login", "POST",
                   {"user": "xploit", "pass": "xploit"}, {}),
    ]
    # The crawl is the only network phase a dry-run may perform; stub it
    # so the test proves nothing else (no module, no hint pass) runs.
    scanner._crawl = lambda: None
    return scanner


def test_dry_run_lists_pages_forms_and_params_without_findings():
    scanner = dry_scanner()
    result = scanner.scan()
    assert result.status == "dry-run"
    assert result.findings == []
    assert result.checks_run == ["dry-run"]
    assert result.pages_seen == ["http://x/search?q=hello&lang=en",
                                 "http://x/about"]
    assert result.forms_seen == 2  # raw count; the listing dedupes below
    kinds = [(e["kind"], e["url"], e["method"], e["parameters"])
             for e in result.entry_points]
    assert ("page", "http://x/search?q=hello&lang=en", "GET",
            ["q", "lang"]) in kinds
    assert ("page", "http://x/about", "GET", []) in kinds
    assert ("form", "http://x/login", "POST",
            ["pass", "user"]) in kinds
    assert sum(1 for e in result.entry_points
               if e["kind"] == "form") == 1  # duplicate collapsed
    # JSON carries the listing too.
    assert result.to_dict()["entry_points"] == result.entry_points


def test_dry_run_writes_no_checkpoint():
    import tempfile
    import os
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cp.json")
        scanner = dry_scanner()
        scanner.checkpoint_file = path
        scanner._checkpoint_path = path
        scanner.scan()
        assert not os.path.exists(path)


def test_text_report_shows_listing_not_no_findings():
    result = ScanResult(
        target="http://x/", normalized_target="http://x/",
        started_at="", duration_seconds=0.1, status="dry-run",
        scan_mode="passive", scope_prefix="/", completion_percent=100,
        checks_run=["dry-run"],
        pages_seen=["http://x/search?q=hello"],
        forms_seen=1, findings=[], errors=[],
        entry_points=[
            {"kind": "page", "url": "http://x/search?q=hello",
             "method": "GET", "parameters": ["q"]},
            {"kind": "form", "url": "http://x/login", "method": "POST",
             "parameters": ["user"], "page_url": "http://x/login"},
        ],
    )
    text = render_text_report(result, colors=False)
    assert "DRY RUN" in text
    assert "no probe traffic" in text
    assert "http://x/search?q=hello" in text
    assert "http://x/login" in text
    assert "params: q" in text
    assert "No findings detected" not in text


def test_cli_flag_parses_and_guards_meaningless_combos():
    args = build_parser().parse_args(["http://x/", "--dry-run"])
    assert args.dry_run is True

    def base(**over):
        ns = argparse.Namespace(
            url="http://x/", extra_urls=[], dry_run=True,
            checkpoint=None, resume=None, retest=False, no_color=True)
        ns.__dict__.update(over)
        return ns

    assert run_scan(base(checkpoint="cp.json")) == 2
    assert run_scan(base(resume="cp.json")) == 2
    assert run_scan(base(retest=True)) == 2
