"""Tests for the --exclude URL-pattern flag (crawl filtering)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from xploit.cli import build_parser
from xploit.scanner import WebScanner


def parse(*argv):
    return build_parser().parse_args(list(argv))


# --- parser surface ------------------------------------------------------

def test_parser_exclude_defaults_to_empty():
    assert parse("http://x/").exclude == []


def test_parser_collects_multiple_exclude_patterns():
    args = parse("http://x/", "--exclude", "/logout", "--exclude", r"\.pdf$")
    assert args.exclude == ["/logout", r"\.pdf$"]


# --- pattern compilation -------------------------------------------------

def test_invalid_exclude_pattern_raises_value_error():
    with pytest.raises(ValueError, match="invalid --exclude pattern"):
        WebScanner("http://example.com/", exclude=["(["])


def test_excluded_matches_full_url_with_regex():
    scanner = WebScanner("http://example.com/", exclude=[r"/admin", r"\.pdf$"])
    assert scanner._excluded("http://example.com/admin/users") is True
    assert scanner._excluded("http://example.com/report.PDF") is False  # case-sensitive
    assert scanner._excluded("http://example.com/report.pdf") is True
    assert scanner._excluded("http://example.com/about") is False


def test_no_exclude_patterns_excludes_nothing():
    scanner = WebScanner("http://example.com/")
    assert scanner._excluded("http://example.com/logout") is False


# --- end-to-end crawl -----------------------------------------------------

class ExcludeHandler(BaseHTTPRequestHandler):
    def _html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        self.server.requested_paths.append(self.path)
        if self.path == "/":
            self._html(
                '<a href="/keep">keep</a>'
                '<a href="/logout">logout</a>'
                '<a href="/download.pdf">pdf</a>'
            )
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Allow: /robots-only\n")
            return
        if self.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(
                f"<urlset><url><loc>{self.server.base_url}sitemap-page</loc></url></urlset>".encode()
            )
            return
        self._html(f"<p>page {self.path}</p>")

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ExcludeHandler)
    httpd.base_url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.requested_paths = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        thread.join()


def test_crawl_skips_excluded_links(server):
    scanner = WebScanner(
        server.base_url, depth=2, max_pages=16, timeout=3, mode="passive",
        exclude=["logout", r"\.pdf$"],
    )
    scanner._crawl()
    paths = {urlparse(u).path or "/" for u in scanner.pages}
    assert "/" in paths
    assert "/keep" in paths
    assert "/logout" not in paths
    assert "/download.pdf" not in paths
    assert "/logout" not in server.requested_paths
    assert "/download.pdf" not in server.requested_paths


def test_crawl_skips_excluded_entry_points(server):
    scanner = WebScanner(
        server.base_url, depth=2, max_pages=16, timeout=3, mode="passive",
        exclude=["sitemap-page", "robots-only"],
    )
    scanner._crawl()
    crawled = [u for u in scanner.pages]
    assert not any("sitemap-page" in u for u in crawled)
    assert not any("robots-only" in u for u in crawled)
    assert "/sitemap-page" not in server.requested_paths
    assert "/robots-only" not in server.requested_paths


def test_scan_result_carries_exclude_patterns(server):
    scanner = WebScanner(
        server.base_url, depth=0, max_pages=4, timeout=3, mode="passive",
        exclude=["logout"],
    )
    result = scanner.scan()
    assert result.exclude_patterns == ["logout"]
    assert result.to_dict()["exclude_patterns"] == ["logout"]
