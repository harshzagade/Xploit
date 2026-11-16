"""Tests for authenticated scanning (--auth-cookie / --auth-header).

Static auth applies credentials the operator already holds (a session
cookie copied from a browser, a Bearer token) to the scanner session,
scoped to the target host for cookies, and records the auth method on
the result so reports show how the scan authenticated.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from xploit.auth import (
    apply_static_auth, parse_auth_cookie, parse_auth_header,
)
from xploit.cli import (
    _build_scanner, build_parser, run_scan, validate_login_args,
)
from xploit.reporting import render_text_report
from xploit.scanner import ScanResult, WebScanner


# --- parsing: unit tests ---------------------------------------------------

def test_parse_auth_cookie_valid_and_value_keeps_equals():
    assert parse_auth_cookie("session=abc123") == ("session", "abc123")
    assert parse_auth_cookie("tok=a=b=c") == ("tok", "a=b=c")


def test_parse_auth_cookie_rejects_bad_shapes():
    with pytest.raises(ValueError, match="expected 'name=value'"):
        parse_auth_cookie("sessionabc")
    with pytest.raises(ValueError, match="cookie name is required"):
        parse_auth_cookie("=abc")


def test_parse_auth_header_valid_and_value_keeps_colons():
    assert parse_auth_header("Authorization: Bearer tok") == (
        "Authorization", "Bearer tok")
    assert parse_auth_header("X-Api-Key: a:b:c") == ("X-Api-Key", "a:b:c")


def test_parse_auth_header_rejects_bad_shapes():
    with pytest.raises(ValueError, match="expected 'Name: value'"):
        parse_auth_header("Authorization Bearer")
    with pytest.raises(ValueError, match="header name is required"):
        parse_auth_header(": Bearer tok")


# --- apply_static_auth: unit tests -----------------------------------------

def test_apply_static_auth_sets_cookie_scoped_and_header():
    session = requests.Session()
    methods = apply_static_auth(
        session, ["session=abc123"], ["Authorization: Bearer tok"],
        domain="example.com")
    assert methods == ["cookie", "header"]
    assert session.headers["Authorization"] == "Bearer tok"
    cookies = {c.name: c for c in session.cookies}
    assert cookies["session"].value == "abc123"
    assert cookies["session"].domain == "example.com"


def test_apply_static_auth_reports_only_what_was_given():
    session = requests.Session()
    assert apply_static_auth(session, ["a=b"], [], domain="example.com") == ["cookie"]
    assert apply_static_auth(session, [], ["X-T: v"]) == ["header"]
    assert apply_static_auth(session, [], []) == []


def test_apply_static_auth_fails_fast_before_applying_anything():
    session = requests.Session()
    with pytest.raises(ValueError):
        apply_static_auth(session, ["not-a-cookie"], ["X-T: v"])
    assert not list(session.cookies)
    assert "X-T" not in session.headers


# --- live propagation: the session really sends the credentials -----------

class _RecordingHandler(BaseHTTPRequestHandler):
    seen: list[dict] = []
    lock = threading.Lock()

    def _record(self):
        body = b"<html><body>hi</body></html>"
        with self.lock:
            self.seen.append({
                "cookie": self.headers.get("Cookie"),
                "auth": self.headers.get("Authorization"),
            })
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record

    def log_message(self, *args):  # silence the test server
        pass


@pytest.fixture()
def recording_server():
    _RecordingHandler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_scanner_sends_auth_cookie_and_header(recording_server):
    args = build_parser().parse_args([
        recording_server + "/", "--auth-cookie", "session=abc123",
        "--auth-header", "Authorization: Bearer tok"])
    scanner = _build_scanner(args, recording_server + "/")
    assert scanner.auth_methods == ["cookie", "header"]
    scanner._request("GET", recording_server + "/page")
    assert _RecordingHandler.seen
    assert _RecordingHandler.seen[0]["cookie"] == "session=abc123"
    assert _RecordingHandler.seen[0]["auth"] == "Bearer tok"


def test_auth_cookie_is_not_sent_to_another_host(recording_server):
    # Cookie scoped to the target host (127.0.0.1): the same machine
    # reached as "localhost" must not receive it.
    args = build_parser().parse_args([
        recording_server + "/", "--auth-cookie", "session=abc123"])
    scanner = _build_scanner(args, recording_server + "/")
    other_host = recording_server.replace("127.0.0.1", "localhost")
    scanner._request("GET", other_host + "/page")
    assert _RecordingHandler.seen
    assert _RecordingHandler.seen[0]["cookie"] is None


# --- result reporting: auth method flows into ScanResult --------------------

def test_unreachable_scan_result_carries_auth_method():
    scanner = WebScanner("http://127.0.0.1:9/", threads=1, timeout=1)
    scanner.auth_methods = ["cookie", "header"]
    result = scanner.scan()
    assert result.status == "unreachable"
    assert result.auth_method == "cookie+header"
    assert result.to_dict()["auth_method"] == "cookie+header"


def test_dry_run_result_carries_auth_method():
    scanner = WebScanner("http://127.0.0.1:9/", threads=1, timeout=1,
                         dry_run=True)
    scanner.auth_methods = ["cookie"]
    result = scanner.scan()
    assert result.status == "dry-run"
    assert result.auth_method == "cookie"


def test_anonymous_result_reports_none_and_no_text_line():
    scanner = WebScanner("http://127.0.0.1:9/", threads=1, timeout=1)
    result = scanner.scan()
    assert result.auth_method == "none"
    assert "auth:" not in render_text_report(result, colors=False)


def test_text_report_shows_auth_method_when_set():
    result = ScanResult(
        target="http://example.com/", normalized_target="http://example.com/",
        started_at="", duration_seconds=0.0, status="completed",
        scan_mode="full", scope_prefix="/", completion_percent=100,
        checks_run=[], pages_seen=[], forms_seen=0, findings=[], errors=[],
        auth_method="login-form")
    assert "auth: login-form" in render_text_report(result, colors=False)


# --- CLI validation ---------------------------------------------------------

def test_auth_flags_parsed_and_wired():
    args = build_parser().parse_args([
        "http://127.0.0.1:9/", "--auth-cookie", "session=abc",
        "--auth-header", "Authorization: Bearer tok"])
    assert args.auth_cookie == ["session=abc"]
    assert args.auth_header == ["Authorization: Bearer tok"]
    scanner = _build_scanner(args, "http://127.0.0.1:9/")
    assert scanner.auth_methods == ["cookie", "header"]


def test_auth_cookie_with_bad_shape_fails_fast_at_build():
    args = build_parser().parse_args(
        ["http://127.0.0.1:9/", "--auth-cookie", "not-a-cookie"])
    with pytest.raises(ValueError, match="invalid --auth-cookie"):
        _build_scanner(args, "http://127.0.0.1:9/")


def test_login_url_conflicts_with_static_auth():
    args = build_parser().parse_args([
        "http://127.0.0.1:9/", "--login-url", "http://127.0.0.1:9/login",
        "--login-user", "u", "--login-pass", "p",
        "--auth-cookie", "session=abc"])
    error = validate_login_args(args)
    assert error is not None and "--login-url cannot be combined" in error
    assert run_scan(args) == 2
