"""Progress-heartbeat tests (round 3).

The "freezes mid-scan" fix: WebScanner._request fires an on_request(count)
hook on every request, and cli.run_scan wires it to a throttled live
"N req" counter so sequential module probing visibly advances. These tests
pin the hook contract (thread-safe, exception-proof, always fires) and the
CLI wiring, plus the redirect-hop bound and the oversize-page cap that live
in the same request path.
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xploit.cli import build_parser, run_scan
from xploit.scanner import WebScanner

BIG_BODY = b"<html><body>" + b"x" * (5_000_100) + b"</body></html>"


class HeartbeatHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            self._html(b'<html><body><a href="/page">p</a></body></html>')
            return
        if self.path == "/page":
            self._html(b"<html><body>page</body></html>")
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if self.path.startswith("/r"):
            try:
                n = int(self.path[2:])
            except ValueError:
                self.send_error(404)
                return
            self.send_response(302)
            self.send_header("Location", f"/r{n + 1}")
            self.end_headers()
            return
        if self.path == "/big":
            self._html(BIG_BODY)
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HeartbeatTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HeartbeatHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def make_scanner(self, **kw) -> WebScanner:
        kw.setdefault("mode", "passive")
        kw.setdefault("timeout", 3)
        return WebScanner(f"{self.base}/", **kw)

    # --- hook contract ----------------------------------------------------
    def test_on_request_is_none_by_default(self) -> None:
        self.assertIsNone(self.make_scanner().on_request)

    def test_request_count_starts_at_zero(self) -> None:
        self.assertEqual(self.make_scanner()._request_count, 0)

    def test_on_request_fires_once_per_request(self) -> None:
        seen: list[int] = []
        s = self.make_scanner()
        s.on_request = seen.append
        s._request("GET", f"{self.base}/page", quiet=True)
        s._request("GET", f"{self.base}/page", quiet=True)
        self.assertEqual(seen, [1, 2])

    def test_on_request_receives_int_count(self) -> None:
        seen: list[object] = []
        s = self.make_scanner()
        s.on_request = seen.append
        s._request("GET", f"{self.base}/page", quiet=True)
        self.assertTrue(all(isinstance(c, int) for c in seen))

    def test_on_request_exception_is_swallowed(self) -> None:
        def boom(count: int) -> None:
            raise RuntimeError("ui blew up")

        s = self.make_scanner()
        s.on_request = boom
        res = s._request("GET", f"{self.base}/page", quiet=True)
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)

    def test_on_request_fires_even_when_target_is_dead(self) -> None:
        seen: list[int] = []
        s = WebScanner("http://127.0.0.1:1/", mode="passive", timeout=1)
        s.on_request = seen.append
        self.assertIsNone(s._request("GET", "http://127.0.0.1:1/", quiet=True))
        self.assertEqual(seen, [1])

    def test_on_request_fires_for_quiet_requests(self) -> None:
        seen: list[int] = []
        s = self.make_scanner()
        s.on_request = seen.append
        s._request("GET", f"{self.base}/nope-missing", quiet=True)
        self.assertEqual(len(seen), 1)

    def test_on_request_threadsafe_unique_counts(self) -> None:
        seen: list[int] = []
        lock = threading.Lock()
        s = self.make_scanner()

        def cb(count: int) -> None:
            with lock:
                seen.append(count)

        s.on_request = cb
        threads = [
            threading.Thread(
                target=s._request,
                args=("GET", f"{self.base}/page"),
                kwargs={"quiet": True},
            )
            for _ in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(sorted(seen), list(range(1, 21)))

    def test_on_progress_wirable(self) -> None:
        s = self.make_scanner()
        self.assertIsNone(s.on_progress)
        s.on_progress = lambda c, t, p: None
        self.assertIsNotNone(s.on_progress)

    # --- CLI wiring through run_scan --------------------------------------
    def parse(self, *argv: str):
        return build_parser().parse_args(list(argv))

    def run_quiet_capture(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_scan(self.parse(*argv))
        return code, buf.getvalue()

    def test_run_scan_shows_req_counter(self) -> None:
        code, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("req", out)

    def test_run_scan_quiet_hides_req_counter(self) -> None:
        code, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--quiet")
        self.assertEqual(code, 0)
        self.assertNotIn("req", out)

    def test_run_scan_json_hides_req_counter(self) -> None:
        code, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--format", "json")
        self.assertEqual(code, 0)
        self.assertNotIn("req", out)

    def test_run_scan_prints_banner(self) -> None:
        _, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--no-color")
        # banner() is block-letter ASCII art, not the literal word
        self.assertIn("██╗", out)

    def test_run_scan_no_color_strips_report_ansi(self) -> None:
        _, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--no-color")
        self.assertNotIn("\x1b", out)

    def test_run_scan_color_keeps_report_ansi(self) -> None:
        _, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive")
        self.assertIn("\x1b", out)

    def test_run_scan_invalid_url_returns_2(self) -> None:
        code, _ = self.run_quiet_capture("not-a-url", "--mode", "passive")
        self.assertEqual(code, 2)

    def test_run_scan_passive_completes(self) -> None:
        code, _ = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--no-color")
        self.assertEqual(code, 0)

    def test_run_scan_with_retest_completes(self) -> None:
        code, out = self.run_quiet_capture(
            f"{self.base}/", "--mode", "passive", "--retest", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("retest", out.lower())

    def test_run_scan_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.txt")
            code, _ = self.run_quiet_capture(
                f"{self.base}/", "--mode", "passive", "--no-color",
                "--output", path, "--quiet")
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 0)

    # --- redirect accounting in the same path -------------------------------
    def test_max_redirects_constant_is_10(self) -> None:
        self.assertEqual(WebScanner.MAX_REDIRECTS, 10)

    def test_self_redirect_loop_terminates_on_first_hop(self) -> None:
        s = self.make_scanner()
        # not quiet: the loop-detection note is only logged then
        res = s._request("GET", f"{self.base}/loop")
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(
            any("redirect loop detected" in e for e in s.errors))

    def test_long_chain_stops_at_max_redirects(self) -> None:
        count = {"n": 0}

        import requests as _requests

        real = _requests.Session.request

        def counting(self_, method, url, **kw):
            count["n"] += 1
            return real(self_, method, url, **kw)

        s = self.make_scanner()
        try:
            _requests.Session.request = counting
            # not quiet: the bound-tripped note is only logged then
            res = s._request("GET", f"{self.base}/r0")
        finally:
            _requests.Session.request = real
        # 1 initial + 10 hops, then the bound trips
        self.assertEqual(count["n"], 11)
        self.assertTrue(
            any("exceeded 10 redirects" in e for e in s.errors))
        self.assertEqual(res.status_code, 302)

    def test_redirect_hops_do_not_fire_on_request(self) -> None:
        seen: list[int] = []
        s = self.make_scanner()
        s.on_request = seen.append
        s._request("GET", f"{self.base}/loop", quiet=True)
        # one logical request; hops are internal session calls
        self.assertEqual(seen, [1])

    # --- oversize page cap ---------------------------------------------------
    def test_oversize_page_recorded_but_not_parsed(self) -> None:
        s = WebScanner(f"{self.base}/big", mode="passive", timeout=5,
                       max_pages=4, depth=1)
        s.scan()
        self.assertTrue(any("/big" in u for u in s.pages))
        self.assertFalse(any("/big" in f.page_url for f in s.forms))
        self.assertTrue(any("exceeds 5 MB cap" in e for e in s.errors))

    def test_oversize_page_content_still_recorded(self) -> None:
        s = WebScanner(f"{self.base}/big", mode="passive", timeout=5,
                       max_pages=4, depth=1)
        s.scan()
        big = [r for u, r in s.pages.items() if "/big" in u]
        self.assertEqual(len(big), 1)
        # recorded for evidence, just never fed to BeautifulSoup
        self.assertGreater(len(big[0].content), 5_000_000)


if __name__ == "__main__":
    unittest.main()
