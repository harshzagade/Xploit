"""Tests for --respect-robots: honor robots.txt Disallow rules while crawling.

Off by default (a scanner's job is to probe what robots.txt hides), so
the default crawl is unchanged; with the flag on, disallowed paths are
never requested and the skip count is reported on the result.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import pytest

from xploit.cli import build_parser, run_scan
from xploit.scanner import WebScanner


def parse(*argv):
    return build_parser().parse_args(list(argv))


ROBOTS_BODY = "User-agent: *\nDisallow: /admin/\nDisallow: /secret\n"


# --- parser surface ------------------------------------------------------

def test_parser_respect_robots_defaults_off():
    assert parse("http://x/").respect_robots is False


def test_parser_respect_robots_flag():
    assert parse("http://x/", "--respect-robots").respect_robots is True


# --- unit: the disallow check itself --------------------------------------

def _parser_with_rules(body: str) -> RobotFileParser:
    parser = RobotFileParser()
    parser.parse(body.splitlines())
    return parser


def test_robots_disallowed_matches_prefix_rules():
    scanner = WebScanner("http://example.com/", respect_robots=True)
    scanner._robots_parser = _parser_with_rules(ROBOTS_BODY)
    assert scanner._robots_disallowed("http://example.com/admin/users") is True
    assert scanner._robots_disallowed("http://example.com/secret") is True
    assert scanner._robots_disallowed("http://example.com/public") is False
    assert scanner._robots_disallowed("http://example.com/") is False
    assert scanner._robots_skipped == {
        "http://example.com/admin/users", "http://example.com/secret"}


def test_robots_disallowed_off_without_flag_even_with_rules():
    scanner = WebScanner("http://example.com/")
    scanner._robots_parser = _parser_with_rules(ROBOTS_BODY)
    assert scanner._robots_disallowed("http://example.com/admin/") is False
    assert scanner._robots_skipped == set()


def test_robots_disallowed_fail_open_without_robots_txt():
    scanner = WebScanner("http://example.com/", respect_robots=True)
    assert scanner._robots_parser is None
    assert scanner._robots_disallowed("http://example.com/admin/") is False


# --- end-to-end crawl against a fixture server ----------------------------

class RobotsHandler(BaseHTTPRequestHandler):
    def _html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        self.server.requested_paths.append(self.path)
        if self.path == "/":
            self._html(
                '<a href="/public">public</a>'
                '<a href="/admin/">admin</a>'
                '<a href="/secret">secret</a>'
                '<a href="/other">other</a>'
            )
            return
        if self.path == "/robots.txt":
            body = self.server.robots_body
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())
            return
        if self.path in ("/public", "/other", "/admin/", "/secret"):
            self._html(f"<p>page {self.path}</p>")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), RobotsHandler)
    httpd.base_url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.requested_paths = []
    httpd.robots_body = ROBOTS_BODY
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        thread.join()


def _paths(scanner):
    return {urlparse(u).path or "/" for u in scanner.pages}


def test_crawl_skips_disallowed_links_with_flag(server):
    scanner = WebScanner(server.base_url, depth=2, max_pages=16, timeout=3,
                         mode="passive", respect_robots=True)
    scanner._crawl()
    paths = _paths(scanner)
    assert "/" in paths
    assert "/public" in paths
    assert "/other" in paths
    assert "/admin/" not in paths
    assert "/secret" not in paths
    # Disallowed URLs were never requested at all, not just dropped.
    assert "/admin/" not in server.requested_paths
    assert "/secret" not in server.requested_paths


def test_crawl_ignores_robots_txt_without_flag(server):
    scanner = WebScanner(server.base_url, depth=2, max_pages=16, timeout=3,
                         mode="passive")
    scanner._crawl()
    paths = _paths(scanner)
    assert "/admin/" in paths
    assert "/secret" in paths
    assert scanner._robots_skipped == set()


def test_missing_robots_txt_fails_open_with_flag(server):
    server.robots_body = None
    scanner = WebScanner(server.base_url, depth=2, max_pages=16, timeout=3,
                         mode="passive", respect_robots=True)
    scanner._crawl()
    paths = _paths(scanner)
    assert "/admin/" in paths
    assert "/secret" in paths
    assert scanner._robots_skipped == set()


def test_dry_run_result_carries_robots_skipped(server):
    scanner = WebScanner(server.base_url, depth=2, max_pages=16, timeout=3,
                         mode="passive", respect_robots=True, dry_run=True)
    result = scanner.scan()
    assert result.status == "dry-run"
    assert result.robots_skipped == 2
    assert result.to_dict()["robots_skipped"] == 2
    crawled = {urlparse(u).path or "/" for u in result.pages_seen}
    assert "/admin/" not in crawled and "/secret" not in crawled


def test_cli_dry_run_respect_robots_end_to_end(server, capsys):
    args = parse(server.base_url, "--dry-run", "--respect-robots", "--quiet")
    assert run_scan(args) == 0
    out = capsys.readouterr().out
    assert "/public" in out
    assert "/admin/" not in out
    assert "/secret" not in out
    assert "2 robots.txt-skipped" in out
