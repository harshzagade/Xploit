"""Read-deadline tests (round 4).

Regression cover for the full/active scan hang: a server dribbling bytes
slower than --timeout holds the connection open forever because requests'
`timeout` is per socket operation, so `res.text` never returns (process
sleeps in poll()). WebScanner now streams every body through _consume_body
with a hard total deadline derived from --timeout. These tests pin that:
a slow drip returns quickly with partial content, a truncated stream keeps
what arrived, and normal pages are unaffected.
"""
from __future__ import annotations

import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xploit.scanner import WebScanner

DRIP_BYTES = 40
DRIP_INTERVAL = 0.4  # per-recv timeout (1s) never trips on this drip


class DripHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            body = b"<html><body>fine</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/drip":
            # No Content-Length: client reads until we stop sending.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            try:
                for _ in range(DRIP_BYTES):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(DRIP_INTERVAL)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client gave up (deadline) — expected
            return
        if self.path == "/abort":
            # Lie about the length, then close early: incomplete read.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "5000")
            self.end_headers()
            self.wfile.write(b"y" * 100)
            self.wfile.flush()
            return  # HTTP/1.0 default: server closes the connection here
        if self.path == "/big":
            body = b"z" * 2000
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return


class ReadDeadlineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DripHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def test_slow_drip_returns_before_deadline_with_partial_body(self) -> None:
        s = WebScanner(f"{self.base}/", timeout=1.0, read_deadline=2.0,
                       mode="passive")
        start = time.monotonic()
        res = s._request("GET", f"{self.base}/drip", quiet=False)
        elapsed = time.monotonic() - start
        assert res is not None
        # Full drip would take DRIP_BYTES * DRIP_INTERVAL = 16s; the deadline
        # must cut it off far earlier, keeping whatever arrived.
        assert elapsed < 10, f"drip took {elapsed:.1f}s — deadline not enforced"
        assert 0 < len(res.content) < DRIP_BYTES
        assert any("deadline" in e for e in s.errors), s.errors

    def test_normal_page_unaffected(self) -> None:
        s = WebScanner(f"{self.base}/", timeout=1.0, read_deadline=2.0,
                       mode="passive")
        res = s._request("GET", f"{self.base}/ok", quiet=False)
        assert res is not None
        assert res.text == "<html><body>fine</body></html>"
        assert not s.errors, s.errors

    def test_aborted_stream_keeps_partial_body(self) -> None:
        s = WebScanner(f"{self.base}/", timeout=5.0, read_deadline=10.0,
                       mode="passive")
        res = s._request("GET", f"{self.base}/abort", quiet=False)
        # Must not raise: the crawl depends on _request never raising.
        assert res is not None
        assert res.content == b"y" * 100

    def test_body_cap_truncates(self) -> None:
        s = WebScanner(f"{self.base}/", timeout=5.0, read_deadline=10.0,
                       mode="passive")
        s.MAX_BODY_BYTES = 300
        res = s._request("GET", f"{self.base}/big", quiet=False)
        assert res is not None
        assert any("exceeded" in e for e in s.errors), s.errors

    def test_invalid_read_deadline_rejected(self) -> None:
        with pytest.raises(ValueError):
            WebScanner("http://x/", read_deadline=0)

    def test_deadline_derived_from_timeout(self) -> None:
        assert WebScanner("http://x/", timeout=6.0).read_deadline == 30.0
        assert WebScanner("http://x/", timeout=10.0).read_deadline == 50.0
        assert WebScanner("http://x/", timeout=10.0,
                          read_deadline=3.0).read_deadline == 3.0
