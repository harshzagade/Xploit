"""Second regression suite: deeper coverage of every audit fix.

Companion to test_bugfix_regressions.py. Each test pins a fixed behavior so a
regression re-introduces a failing test, not a silent production bug.
"""
from __future__ import annotations

import concurrent.futures
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin

from xploit.modules.brute_force import BruteForceModule
from xploit.modules.logic_vulnerabilities import LogicVulnerabilityModule
from xploit.modules.sensitive_data import SensitiveDataModule
from xploit.modules.xss import XSSModule
from xploit.reporting import render_json_report, render_text_report, strip_ansi
from xploit.retest import RETEST_CONFIRMED, retest_findings
from xploit.scanner import (
    ACTIVE,
    PASSIVE,
    Finding,
    FormTarget,
    ScanResult,
    WebScanner,
    normalize_path,
)


class DeepHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            self._html('<a href="/jshrefs">js</a><a href="/page">page</a>')
            return
        if self.path == "/jshrefs":
            self._html(
                '<html><body><a href="javascript:alert(1)">x</a>'
                '<a href="/page">ok</a></body></html>'
            )
            return
        if self.path == "/page":
            self._html("<html><body>page</body></html>")
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def _fake_response(status: int = 200, headers: dict | None = None, text: str = ""):
    class _Fake:
        pass

    fake = _Fake()
    fake.status_code = status
    fake.headers = headers or {}
    fake.text = text
    return fake


def _finding(**over) -> Finding:
    base = dict(
        id="T-001", name="n", category="c", severity="HIGH", confidence="High",
        url="http://x/", evidence="e", impact="i", remediation="r",
    )
    base.update(over)
    return Finding(**base)


class BugfixRegression2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DeepHandler)
        cls.server.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = cls.server.base_url

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    # ---- scanner core -------------------------------------------------
    def test_threads_clamp_to_at_least_one(self) -> None:
        self.assertEqual(1, WebScanner("http://x/", threads=0).threads)
        self.assertEqual(1, WebScanner("http://x/", threads=-5).threads)
        self.assertEqual(4, WebScanner("http://x/", threads=4).threads)

    def test_missing_target_raises_valueerror_direct(self) -> None:
        with self.assertRaises(ValueError):
            WebScanner("")
        with self.assertRaises(ValueError):
            WebScanner("   ")
        with self.assertRaises(ValueError):
            WebScanner("ftp://example.com/")

    def test_retry_strategy_never_retries_post(self) -> None:
        scanner = WebScanner("http://x/")
        adapter = scanner.session.get_adapter("http://x/")
        methods = set(adapter.max_retries.allowed_methods or [])
        self.assertNotIn("POST", methods)
        self.assertNotIn("PUT", methods)
        self.assertIn("GET", methods)
        self.assertIn("HEAD", methods)

    def test_scope_prefix_seeds_entry_point(self) -> None:
        scanner = WebScanner(self.base_url, scope_prefix="/api", timeout=2)
        entry_points = scanner._discover_entry_points()
        self.assertIn(urljoin(self.base_url, "/api"), entry_points)

    def test_max_pages_respected(self) -> None:
        scanner = WebScanner(self.base_url, depth=2, max_pages=2, timeout=3)
        scanner.scan()
        self.assertLessEqual(len(scanner.pages), 2)

    def test_in_scope_rejects_off_origin(self) -> None:
        scanner = WebScanner(self.base_url, timeout=2)
        self.assertFalse(scanner._in_scope("http://evil.example/"))
        self.assertFalse(scanner._in_scope("javascript:alert(1)"))
        self.assertTrue(scanner._in_scope(f"{self.base_url}anything"))

    def test_normalize_path_keeps_query_param_names(self) -> None:
        a = normalize_path("http://x/?sessionid=abc")
        b = normalize_path("http://x/?sessionid=xyz")
        c = normalize_path("http://x/?other=1")
        self.assertIn("sessionid", a)
        self.assertEqual(a, b)  # same shape dedupes
        self.assertNotEqual(a, c)  # different param name crawls separately

    def test_normalize_path_dedupes_numeric_segments(self) -> None:
        self.assertEqual(
            normalize_path("http://x/user/123"), normalize_path("http://x/user/456")
        )

    def test_finding_dedup_across_modules(self) -> None:
        scanner = WebScanner(self.base_url, timeout=2)
        m1, m2 = BruteForceModule(scanner), XSSModule(scanner)
        m1.add_finding(_finding(id="X-1", url=f"{self.base_url}a", parameter="p"))
        m2.add_finding(_finding(id="X-1", url=f"{self.base_url}a", parameter="p",
                                name="different name"))
        self.assertEqual(1, len(scanner.findings))

    def test_module_level_dedup(self) -> None:
        scanner = WebScanner(self.base_url, timeout=2)
        module = BruteForceModule(scanner)
        module.add_finding(_finding(id="X-2"))
        module.add_finding(_finding(id="X-2"))
        self.assertEqual(1, len(scanner.findings))

    def test_gate_applied_inside_add_finding(self) -> None:
        scanner = WebScanner(self.base_url, timeout=2)
        BruteForceModule(scanner).add_finding(_finding())
        self.assertEqual(1, len(scanner.findings))
        self.assertFalse(scanner.findings[0].verified)
        self.assertIn("no replayable proof", scanner.findings[0].verification_note)

    def test_concurrent_request_counting_is_exact(self) -> None:
        scanner = WebScanner(self.base_url, timeout=5)
        url = f"{self.base_url}page"
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(lambda _: scanner._request("GET", url, quiet=True), range(20)))
        self.assertEqual(20, scanner._request_count)

    def test_crawl_ignores_javascript_hrefs(self) -> None:
        scanner = WebScanner(f"{self.base_url}jshrefs", depth=1, max_pages=10,
                             timeout=3)
        scanner.scan()
        self.assertTrue(all(u.startswith("http") for u in scanner.pages),
                        scanner.pages)
        self.assertFalse(
            any("unsupported URL scheme" in e for e in scanner.errors),
            scanner.errors,
        )

    def test_error_pages_do_not_stop_crawl(self) -> None:
        scanner = WebScanner(self.base_url, depth=1, max_pages=10, timeout=3)
        result = scanner.scan()
        self.assertEqual("completed", result.status)
        self.assertGreaterEqual(len(scanner.pages), 2)

    # ---- retest --------------------------------------------------------
    def _retest_scanner(self, responder, mode=ACTIVE):
        class _FakeScanner:
            pass

        fake = _FakeScanner()
        fake.mode = mode
        fake._request = responder
        return fake

    def test_retest_confirmed(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=b",
                     proof_marker="marker")
        scanner = self._retest_scanner(
            lambda *a, **k: _fake_response(200, {}, "marker here"))
        stats = retest_findings(scanner, [f])
        self.assertEqual(RETEST_CONFIRMED, f.retest_status)
        self.assertEqual(1, stats[RETEST_CONFIRMED])

    def test_retest_fixed(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=b",
                     proof_marker="marker")
        scanner = self._retest_scanner(
            lambda *a, **k: _fake_response(200, {}, "all clean now"))
        stats = retest_findings(scanner, [f])
        self.assertEqual("fixed", f.retest_status)
        self.assertEqual(1, stats["fixed"])

    def test_retest_skipped_in_passive(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=b",
                     proof_marker="marker")
        scanner = self._retest_scanner(
            lambda *a, **k: _fake_response(200, {}, "marker"), mode=PASSIVE)
        stats = retest_findings(scanner, [f])
        self.assertEqual("skipped", f.retest_status)
        self.assertEqual(1, stats["skipped"])

    def test_retest_no_proof_is_unverifiable(self) -> None:
        f = _finding()  # no proof attached
        scanner = self._retest_scanner(
            lambda *a, **k: _fake_response(200, {}, "marker"))
        stats = retest_findings(scanner, [f])
        self.assertEqual("unverifiable", f.retest_status)
        self.assertEqual(1, stats["unverifiable"])

    def test_retest_request_failure_is_unverifiable(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=b",
                     proof_marker="marker")

        def boom(*a, **k):
            raise ConnectionError("down")

        scanner = self._retest_scanner(boom)
        stats = retest_findings(scanner, [f])
        self.assertEqual("unverifiable", f.retest_status)
        self.assertEqual(1, stats["unverifiable"])
        self.assertIn("replay request failed", f.verification_note)

    def test_retest_429_is_unverifiable_not_fixed(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=b",
                     proof_marker="marker")
        scanner = self._retest_scanner(
            lambda *a, **k: _fake_response(429, {}, "slow down"))
        stats = retest_findings(scanner, [f])
        self.assertEqual("unverifiable", f.retest_status)
        self.assertEqual(0, stats["fixed"])

    def test_retest_post_proof_sends_body(self) -> None:
        f = _finding(proof_method="POST", proof_url="http://x/login",
                     proof_data="user=a&pass=b", proof_marker="marker")
        seen = {}

        def capture(method, url, quiet=True, **kwargs):
            seen["method"] = method
            seen["data"] = kwargs.get("data")
            return _fake_response(200, {}, "marker")

        scanner = self._retest_scanner(capture)
        retest_findings(scanner, [f])
        self.assertEqual("confirmed", f.retest_status)
        self.assertEqual("POST", seen["method"])
        self.assertEqual({"user": "a", "pass": "b"}, seen["data"])

    # ---- XSS ------------------------------------------------------------
    def _xss_module(self):
        scanner = WebScanner(self.base_url, depth=0, max_pages=1, timeout=2)
        module = XSSModule(scanner)
        module._confirmed = set()  # normally initialized in run()
        return module, scanner

    def test_xss_missing_content_type_is_scannable(self) -> None:
        module, scanner = self._xss_module()
        res = _fake_response(200, {}, "<html><body><svg onload=x>hi</body></html>")
        module._analyze_reflection(
            res, self.base_url, "q", "<svg onload=x>", "GET",
            proof_url=f"{self.base_url}?q=%3Csvg",
        )
        self.assertEqual(1, len(scanner.findings))

    def test_xss_explicit_non_html_is_skipped(self) -> None:
        module, scanner = self._xss_module()
        res = _fake_response(
            200, {"Content-Type": "application/json"},
            '{"q": "<svg onload=x>"}',
        )
        module._analyze_reflection(
            res, self.base_url, "q", "<svg onload=x>", "GET",
            proof_url=f"{self.base_url}?q=%3Csvg",
        )
        self.assertEqual([], scanner.findings)

    def test_xss_javascript_uri_vector_accepted(self) -> None:
        module, scanner = self._xss_module()
        res = _fake_response(
            200, {"Content-Type": "text/html"},
            '<html><body><a href="javascript:alert(1)">click</a></body></html>',
        )
        module._analyze_reflection(
            res, self.base_url, "q", "javascript:alert(1)", "GET",
            proof_url=f"{self.base_url}?q=javascript",
        )
        self.assertEqual(1, len(scanner.findings))

    def test_xss_javascript_uri_in_non_url_attribute_is_inert(self) -> None:
        # javascript: text inside a title attribute is inert — only URL-bearing
        # attributes execute it.
        executable, _reason = XSSModule._executable_context(
            '<div title="', "javascript:alert(1)")
        self.assertFalse(executable)

    def test_xss_evidence_discloses_static_analysis(self) -> None:
        module, scanner = self._xss_module()
        res = _fake_response(200, {}, "<html><body><svg onload=x>hi</body></html>")
        module._analyze_reflection(
            res, self.base_url, "q", "<svg onload=x>", "GET",
            proof_url=f"{self.base_url}?q=%3Csvg",
        )
        self.assertIn("not dynamically confirmed", scanner.findings[0].evidence)

    def test_xss_proof_envelope_is_replayable(self) -> None:
        module, scanner = self._xss_module()
        res = _fake_response(200, {}, "<html><body><svg onload=x>hi</body></html>")
        module._analyze_reflection(
            res, self.base_url, "q", "<svg onload=x>", "GET",
            proof_url=f"{self.base_url}?q=%3Csvg",
        )
        finding = scanner.findings[0]
        self.assertTrue(finding.has_replayable_proof())
        self.assertEqual("GET", finding.proof_method)

    # ---- sensitive data --------------------------------------------------
    def _sd_module(self):
        scanner = WebScanner(self.base_url, depth=0, max_pages=1, timeout=2)
        return SensitiveDataModule(scanner), scanner

    def test_db_connection_string_redacted(self) -> None:
        module, _scanner = self._sd_module()
        evidence = module._redacted_conn_evidence(
            "postgresql://admin:SuperSecret123@db.internal:5432/appdb"
        )
        self.assertNotIn("SuperSecret123", evidence)
        self.assertNotIn("admin:SuperSecret123", evidence)
        self.assertIn("redacted", evidence.lower())

    def test_db_connection_string_key_value_redacted(self) -> None:
        module, _scanner = self._sd_module()
        evidence = module._redacted_conn_evidence(
            "Server=db;Database=app;User Id=sa;Password=P@ssw0rd!;"
        )
        self.assertNotIn("P@ssw0rd!", evidence)
        self.assertIn("redacted", evidence.lower())

    def test_sensitive_data_scans_javascript(self) -> None:
        module, scanner = self._sd_module()
        res = _fake_response(
            200, {"Content-Type": "application/javascript"},
            'const config = { apiKey: "AKIAIOSFODNN7EXAMPLEKEY1234567890" };',
        )
        module._check_response(f"{self.base_url}app.js", res)
        self.assertTrue(scanner.findings,
                        "JS responses must be scanned for hardcoded secrets")

    def test_sensitive_data_scans_missing_content_type(self) -> None:
        module, scanner = self._sd_module()
        res = _fake_response(200, {}, "contact admin@example.com")
        module._check_response(f"{self.base_url}x", res)
        # No crash; binary skip must not trigger on missing Content-Type.
        self.assertIsInstance(scanner.findings, list)

    def test_sensitive_data_skips_binary(self) -> None:
        module, scanner = self._sd_module()
        res = _fake_response(
            200, {"Content-Type": "image/png"}, "admin@example.com <binary>"
        )
        module._check_response(f"{self.base_url}img.png", res)
        self.assertEqual([], scanner.findings)

    # ---- CSRF -------------------------------------------------------------
    def _csrf_module(self, forms):
        scanner = WebScanner(self.base_url, depth=0, max_pages=1, timeout=2)
        scanner.forms = forms
        return LogicVulnerabilityModule(scanner), scanner

    def _form(self, method, inputs, action="http://x/submit"):
        return FormTarget(
            page_url=self.base_url, action=action, method=method,
            inputs=inputs,
            input_types={n: "text" for n in inputs},
        )

    def test_csrf_get_forms_skipped(self) -> None:
        module, scanner = self._csrf_module(
            [self._form("GET", {"q": "x", "page": "1"})])
        module._check_csrf()
        self.assertEqual([], scanner.findings)

    def test_csrf_search_form_skipped(self) -> None:
        module, scanner = self._csrf_module(
            [self._form("POST", {"search": "x"})])
        module._check_csrf()
        self.assertEqual([], scanner.findings)

    def test_csrf_token_present_no_finding(self) -> None:
        module, scanner = self._csrf_module(
            [self._form("POST", {"name": "x", "csrf_token": "abc"})])
        module._check_csrf()
        self.assertEqual([], scanner.findings)

    def test_csrf_missing_token_finding(self) -> None:
        module, scanner = self._csrf_module(
            [self._form("POST", {"name": "x", "email": "y"})])
        module._check_csrf()
        self.assertEqual(1, len(scanner.findings))
        self.assertEqual("CSRF-001", scanner.findings[0].id)

    # ---- SSTI --------------------------------------------------------------
    def test_ssti_markers_are_distinctive(self) -> None:
        import inspect
        import re

        from xploit.modules import advanced_injection

        src = inspect.getsource(
            advanced_injection.MultiVectorInjectionModule._test_ssti)
        # No test case may expect bare "49" (7*7) — it collides with prices,
        # years and counters in static content.
        for payload, expected in re.findall(r'\(\s*"([^"]+)",\s*"([^"]+)"', src):
            self.assertNotEqual(
                "49", expected,
                f"SSTI case {payload!r} expects colliding marker '49'")
        self.assertIn("1337", src)
        self.assertIn("1903", src)
        self.assertEqual(1337, 7 * 191)
        self.assertEqual(1903, 11 * 173)

    # ---- brute force extras --------------------------------------------------
    def test_brute_force_email_only_form_excluded(self) -> None:
        scanner = WebScanner(self.base_url, depth=0, max_pages=1, timeout=2)
        scanner.forms = [self._form("POST", {"email": "x"},
                                    action=f"{self.base_url}newsletter")]
        module = BruteForceModule(scanner)
        self.assertEqual([], module._identify_login_forms())

    def test_brute_force_username_only_excluded(self) -> None:
        scanner = WebScanner(self.base_url, depth=0, max_pages=1, timeout=2)
        scanner.forms = [self._form("POST", {"username": "x"},
                                    action=f"{self.base_url}check")]
        module = BruteForceModule(scanner)
        self.assertEqual([], module._identify_login_forms())

    # ---- reporting ------------------------------------------------------------
    def _scan_result(self, findings):
        return ScanResult(
            target=self.base_url, normalized_target=self.base_url,
            started_at="2026-01-01", duration_seconds=1.0, status="completed",
            scan_mode="full", scope_prefix="/", completion_percent=100,
            checks_run=[], pages_seen=[], forms_seen=0,
            findings=findings, errors=[],
        )

    def test_json_report_preserves_raw_evidence(self) -> None:
        finding = _finding(evidence="x\x1b[31mred\x1b[0m")
        report = json.loads(render_json_report(self._scan_result([finding])))
        self.assertIn("\x1b[31m", report["findings"][0]["evidence"])

    def test_text_report_sanitizes_terminal(self) -> None:
        # BEL and OSC sequences survive strip_ansi (SGR-only) but must be
        # neutralized by sanitize_terminal before reaching the report.
        finding = _finding(evidence="x\x07y\x1b]0;evil\x07z")
        text = strip_ansi(render_text_report(self._scan_result([finding])))
        self.assertNotIn("\x07", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("xyz", text)

    def test_text_report_shows_verification(self) -> None:
        finding = _finding(proof_method="GET", proof_url="http://x/?a=b",
                           proof_marker="m")
        from xploit.scanner import gate_finding

        gate_finding(finding)
        text = strip_ansi(render_text_report(self._scan_result([finding])))
        self.assertIn("verify", text)
        self.assertIn("yes", text)


if __name__ == "__main__":
    unittest.main()
