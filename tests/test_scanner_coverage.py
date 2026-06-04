from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from xploit.cli import apply_request_overrides, build_interactive_args, build_parser, render_completion_bar, render_result
from xploit.scanner import FULL, HIGH, MEDIUM, PASSIVE, WebScanner


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            self._html(
                """
                <a href="/search?q=test">search</a>
                <a href="/redirect?next=/">redirect</a>
                <a href="/login">login</a>
                <a href="/frame">frame</a>
                <a href="/cors">cors</a>
                <a href="/upload">upload</a>
                <a href="/account?id=1001">account</a>
                <a href="/files/">files</a>
                <!-- TODO: rotate api_key=demo-key before production -->
                """
            )
            return

        if parsed.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(
                f"Sitemap: {self.server.base_url}sitemap.xml\n".encode()
            )
            return

        if parsed.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(
                f"""
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <url><loc>{self.server.base_url}orphan</loc></url>
                </urlset>
                """.encode()
            )
            return

        if parsed.path == "/search":
            value = params.get("q", [""])[0]
            body = value
            if "; echo $((1330+7))" in value:
                body = "1337"
            elif "' OR '1'='1" in value:
                body = "You have an error in your SQL syntax"
            elif "etc/passwd" in value:
                body = "root:x:0:0:root:/root:/bin/bash"
            self._html(body)
            return

        if parsed.path == "/redirect":
            destination = params.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", destination)
            self.end_headers()
            return

        if parsed.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"""
                <form method="POST" action="/login">
                  <input name="username">
                  <input type="password" name="password">
                </form>
                """
            )
            return

        if parsed.path == "/frame":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>frame test</body></html>")
            return

        if parsed.path == "/cors":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if parsed.path == "/upload":
            self._html(
                """
                <form method="POST" action="/upload">
                  <input name="ip">
                  <input type="file" name="archive">
                </form>
                """
            )
            return

        if parsed.path == "/account":
            self._html("account details")
            return

        if parsed.path == "/files/":
            self._html("<html><title>Index of /files/</title><body>Index of /files/</body></html>")
            return

        if parsed.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=demo\nAPI_KEY=demo\n")
            return

        if parsed.path == "/phpinfo.php":
            self._html("phpinfo() PHP Version 8.3.0")
            return

        if parsed.path == "/search-form":
            self._html(
                """
                <form method="GET" action="/search">
                  <input name="q">
                </form>
                """
            )
            return

        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if "; echo $((1330+7))" in body:
            self._html("1337")
            return
        if "XPLOIT_CMD_TEST" in body:
            self._html("XPLOIT_CMD_TEST")
            return
        if "' OR '1'='1" in body:
            self._html("You have an error in your SQL syntax")
            return
        if "xploit%22%3E%3Csvg" in body or 'xploit"><svg' in body:
            self._html('xploit"><svg/onload=alert(1)>')
            return
        if "etc%2Fpasswd" in body or "etc/passwd" in body:
            self._html("root:x:0:0:root:/root:/bin/bash")
            return
        self._html("ok")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS, PUT, DELETE, TRACE")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class ScannerCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
        cls.server.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = cls.server.base_url

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    def test_all_advertised_vulnerability_categories_are_detectable(self) -> None:
        result = WebScanner(self.base_url, depth=1, max_pages=16, timeout=3).scan()
        categories = {finding.category for finding in result.findings}

        expected = {
            "SQL Injection",
            "Cross-Site Scripting",
            "Cross-Site Request Forgery (CSRF)",
            "Command Injection",
            "Directory Traversal",
            "Insecure HTTP Headers",
            "Clickjacking",
            "CORS Misconfiguration",
            "Broken Authentication",
            "File Upload Surface",
            "Open Redirect",
            "Security Misconfiguration",
            "Sensitive Data Exposure",
            "Information Disclosure",
            "Access Control Heuristic",
        }
        self.assertEqual("completed", result.status)
        self.assertTrue(expected.issubset(categories), f"Missing categories: {expected - categories}")
        self.assertGreaterEqual(sum(f.severity == HIGH for f in result.findings), 1)
        self.assertGreaterEqual(sum(f.severity == MEDIUM for f in result.findings), 1)

    def test_reflected_marker_does_not_trigger_command_injection(self) -> None:
        result = WebScanner(f"{self.base_url}search-form", depth=0, max_pages=4, timeout=3).scan()
        self.assertFalse(
            any(
                finding.category == "Command Injection" and finding.parameter == "q"
                for finding in result.findings
            ),
            result.findings,
        )

    def test_scan_completion_percent_and_bar_are_reported(self) -> None:
        result = WebScanner(self.base_url, depth=0, max_pages=4, timeout=3).scan()
        self.assertGreaterEqual(result.completion_percent, 25)
        # Check that it contains the percent
        self.assertIn(f"{result.completion_percent}%", render_completion_bar(result.completion_percent, colors=False))

    def test_progress_events_complete_and_stay_bounded(self) -> None:
        scanner = WebScanner(self.base_url, depth=0, max_pages=16, timeout=3)
        events = []
        scanner.on_progress = lambda current, total, phase: events.append((current, total, phase))

        scanner.scan()

        self.assertTrue(events)
        self.assertIn((1, 1, "Crawl complete"), events)
        self.assertEqual("Checks complete", events[-1][2])
        for current, total, _phase in events:
            self.assertGreater(total, 0)
            self.assertGreaterEqual(current, 0)
            self.assertLessEqual(current, total)

    def test_json_output_contains_professional_metadata(self) -> None:
        result = WebScanner(self.base_url, depth=0, max_pages=4, timeout=3, mode=FULL, scope_prefix="/").scan()
        payload = render_result(result)
        self.assertIn("Assessment Summary", payload)
        self.assertIn("Target URL", payload)

    def test_text_output_uses_assessment_language(self) -> None:
        result = WebScanner(self.base_url, depth=0, max_pages=4, timeout=3, mode=FULL, scope_prefix="/").scan()
        payload = render_result(result)
        self.assertIn("Assessment Summary", payload)
        self.assertIn("Findings", payload)

    def test_interactive_setup_builds_expected_arguments(self) -> None:
        responses = iter(
            [
                self.base_url,
                "3",
                "100",
            ]
        )
        with patch("builtins.print"):
            args = build_interactive_args(input_fn=lambda _: next(responses))
        self.assertEqual(self.base_url, args.url)
        self.assertEqual(3, args.depth)
        self.assertEqual(100, args.max_pages)

    def test_cli_parser_exposes_documented_scan_controls(self) -> None:
        args = build_parser().parse_args(
            [
                self.base_url,
                "--depth", "2",
                "--max-pages", "10",
                "--timeout", "1.5",
                "--mode", "passive",
                "--rate-limit", "0.25",
                "--scope-prefix", "/app",
                "--format", "json",
                "--header", "Authorization: Bearer token",
                "--cookie", "session=abc123",
                "--no-color",
                "--quiet",
            ]
        )

        self.assertEqual(2, args.depth)
        self.assertEqual(10, args.max_pages)
        self.assertEqual(1.5, args.timeout)
        self.assertEqual(PASSIVE, args.mode)
        self.assertEqual(0.25, args.rate_limit)
        self.assertEqual("/app", args.scope_prefix)
        self.assertEqual("json", args.format)
        self.assertEqual(["Authorization: Bearer token"], args.header)
        self.assertEqual(["session=abc123"], args.cookie)
        self.assertTrue(args.no_color)
        self.assertTrue(args.quiet)

    def test_request_overrides_apply_headers_and_cookies(self) -> None:
        scanner = WebScanner(self.base_url, timeout=3)
        apply_request_overrides(scanner, ["Authorization: Bearer token"], ["session=abc123"])

        self.assertEqual("Bearer token", scanner.session.headers["Authorization"])
        self.assertEqual("abc123", scanner.session.cookies.get("session"))

    def test_passive_mode_skips_active_general_probes(self) -> None:
        result = WebScanner(self.base_url, depth=1, max_pages=16, timeout=3, mode=PASSIVE).scan()
        categories = {finding.category for finding in result.findings}

        self.assertIn("Insecure HTTP Headers", categories)
        self.assertIn("Security Misconfiguration", categories)
        self.assertNotIn("CORS Misconfiguration", categories)
        self.assertNotIn("Sensitive Data Exposure", categories)

    def test_scope_prefix_limits_crawl_surface(self) -> None:
        result = WebScanner(
            f"{self.base_url}search-form",
            depth=1,
            max_pages=8,
            timeout=3,
            mode=FULL,
            scope_prefix="/search",
        ).scan()
        self.assertTrue(result.pages_seen)
        self.assertTrue(all(urlparse(url).path.startswith("/search") for url in result.pages_seen), result.pages_seen)

    def test_security_impact_text_matches_detection_strength(self) -> None:
        result = WebScanner(self.base_url, depth=1, max_pages=16, timeout=3).scan()
        by_name = {finding.name: finding for finding in result.findings}

        self.assertIn("if confirmed", by_name["SQL Injection"].impact.lower())
        self.assertIn("can be observed or modified", by_name["Authentication Form Submitted Over HTTP"].impact.lower())


if __name__ == "__main__":
    unittest.main()
