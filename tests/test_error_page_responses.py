"""Error-page responses are no longer silently skipped.

`requests.Response.__bool__` is `.ok`, so the modules' old
`if not res: continue` guards discarded every 4xx/5xx page before any
check read its body. A 500 page carrying a SQL error in its body was
never seen by the error-based SQLi check. These tests prove, against a
live fixture server, that a 500 page carrying a SQL error now flags
SQLI-001, and that a 500 page without a SQL error does not.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from xploit.scanner import WebScanner

SQL_ERROR = "You have an error in your SQL syntax near '''"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self._send(200, "text/html",
                       b'<a href="/search?q=test">search</a>'
                       b'<a href="/clean?q=test">clean</a>')
            return
        if parsed.path == "/search":
            value = params.get("q", [""])[0]
            if "'" in value:
                # The regression: this used to be skipped outright because
                # `not res` is True for a 500 response.
                self._send(500, "text/plain", SQL_ERROR.encode())
            else:
                self._send(200, "text/plain", b"no results")
            return
        if parsed.path == "/clean":
            value = params.get("q", [""])[0]
            if "'" in value:
                self._send(500, "text/plain", b"internal error")
            else:
                self._send(200, "text/plain", b"no results")
            return
        self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _run_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _scan():
    server = _run_server()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = WebScanner(base, depth=2, timeout=5, modules=["sqli"])
        return scanner.scan()
    finally:
        server.shutdown()
        server.server_close()


def test_500_page_with_sql_error_flags_sqli_001():
    result = _scan()
    sqli = [f for f in result.findings if f.id == "SQLI-001"]
    assert len(sqli) == 1
    finding = sqli[0]
    assert finding.method == "GET"
    assert finding.parameter == "q"
    assert finding.url.endswith("/search?q=test")
    assert finding.verified


def test_500_page_without_sql_error_flags_nothing():
    result = _scan()
    clean = [f for f in result.findings
             if f.id == "SQLI-001" and "/clean" in f.url]
    assert clean == []
