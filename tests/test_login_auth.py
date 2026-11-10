"""Login-form auto-auth: `--login-url` + credentials.

`perform_login` fetches the login page, submits its password form with
the credentials (hidden fields ride along), and leaves the session
cookie on the scanner's `requests.Session` so the whole scan runs
authenticated. A submit that establishes no session is a failure, not
a silent anonymous scan.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import requests

from xploit.auth import LoginResult, parse_login_form, perform_login
from xploit.cli import build_parser, validate_login_args

LOGIN_PAGE = """<html><body>
<form action="/login" method="post">
  <input type="hidden" name="csrf" value="tok123">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Log in">
</form></body></html>"""

EMAIL_PAGE = """<html><body>
<form action="/signin" method="post">
  <input type="email" name="email">
  <input type="password" name="pass">
</form></body></html>"""

NO_FORM_PAGE = "<html><body><p>welcome, no login here</p></body></html>"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/login":
            self._send(200, LOGIN_PAGE)
        elif self.path == "/signin":
            self._send(200, EMAIL_PAGE)
        elif self.path == "/noform":
            self._send(200, NO_FORM_PAGE)
        elif self.path == "/dashboard":
            self._send(200, "<html><body>dashboard</body></html>")
        else:
            self._send(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        fields = parse_qs(self.rfile.read(length).decode())
        user = fields.get("username", fields.get("email", [""]))[0]
        pw = fields.get("password", fields.get("pass", [""]))[0]
        if user == "alice" and pw == "s3cret":
            self._send(302, "", {"Location": "/dashboard",
                                 "Set-Cookie": "session=abc123; Path=/"})
        else:
            # Failed login: same page again, no cookie.
            self._send(200, LOGIN_PAGE)


def _run_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# --- parse_login_form: unit tests --------------------------------------

def test_parse_login_form_finds_password_form():
    form = parse_login_form(LOGIN_PAGE, "http://example.com/login")
    assert form is not None
    assert form.action == "http://example.com/login"
    assert form.method == "post"
    assert form.username_field == "username"
    assert form.password_field == "password"
    assert form.fields["csrf"] == "tok123"  # hidden fields preserved


def test_parse_login_form_email_field_by_hint():
    form = parse_login_form(EMAIL_PAGE, "http://example.com/signin")
    assert form is not None
    assert form.username_field == "email"
    assert form.password_field == "pass"


def test_parse_login_form_none_without_password_field():
    assert parse_login_form(NO_FORM_PAGE, "http://example.com/") is None
    assert parse_login_form("<html><body><form action='/x'>"
                            "<input name='q'></form></body></html>",
                            "http://example.com/") is None


def test_parse_login_form_relative_action_resolved():
    page = ('<form action="auth" method="post">'
            '<input name="u"><input type="password" name="p"></form>')
    form = parse_login_form(page, "http://example.com/app/login")
    assert form is not None
    assert form.action == "http://example.com/app/auth"


# --- perform_login: live fixture-server tests --------------------------

def test_login_success_sets_session_cookie():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        session = requests.Session()
        result = perform_login(session, base + "/login", "alice", "s3cret")
        assert result.success
        assert result.cookies == ["session"]
        assert session.cookies.get("session") == "abc123"
        assert result.final_url == base + "/dashboard"
        # The session stays authenticated for later requests.
        assert session.get(base + "/dashboard").status_code == 200
    finally:
        server.shutdown()
        server.server_close()


def test_login_wrong_credentials_fails_without_session():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        session = requests.Session()
        result = perform_login(session, base + "/login", "alice", "wrong")
        assert not result.success
        assert "no session was established" in result.message
        assert session.cookies.get("session") is None
    finally:
        server.shutdown()
        server.server_close()


def test_login_no_form_fails():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        result = perform_login(requests.Session(), base + "/noform",
                               "alice", "s3cret")
        assert not result.success
        assert "no login form" in result.message
    finally:
        server.shutdown()
        server.server_close()


def test_login_unreachable_page_fails():
    result = perform_login(requests.Session(),
                           "http://127.0.0.1:1/login", "alice", "s3cret",
                           timeout=2.0)
    assert not result.success
    assert isinstance(result, LoginResult)


# --- CLI flags -----------------------------------------------------------

def test_login_flags_parsed():
    args = build_parser().parse_args(
        ["http://example.com/", "--login-url", "http://example.com/login",
         "--login-user", "alice", "--login-pass", "s3cret"])
    assert args.login_url == "http://example.com/login"
    assert args.login_user == "alice"
    assert args.login_pass == "s3cret"
    assert validate_login_args(args) is None


def test_login_flags_all_or_nothing():
    args = build_parser().parse_args(
        ["http://example.com/", "--login-url", "http://example.com/login"])
    assert "must be given together" in validate_login_args(args)
    args = build_parser().parse_args(
        ["http://example.com/", "--login-user", "alice"])
    assert "must be given together" in validate_login_args(args)
    args = build_parser().parse_args(["http://example.com/"])
    assert validate_login_args(args) is None
