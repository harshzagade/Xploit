"""Sharpened active proofs: time-based blind SQLi and stored-XSS persistence.

Covers the new confirmation techniques end-to-end against local HTTP
servers, plus the timing-proof plumbing through the evidence gate,
--retest, and the text report.
"""
from __future__ import annotations

import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from xploit.modules.sqli import SQLInjectionModule
from xploit.modules.xss import XSSModule
from xploit.reporting import render_text_report
from xploit.retest import (
    RETEST_CONFIRMED,
    RETEST_FIXED,
    RETEST_UNVERIFIABLE,
    retest_findings,
)
from xploit.scanner import (
    FULL,
    Finding,
    ScanResult,
    WebScanner,
    gate_finding,
)


# --------------------------------------------------------------------------
# Local test servers
# --------------------------------------------------------------------------

class _SleepHandler(BaseHTTPRequestHandler):
    """Sleeps ~4.2s when the query carries a SLEEP() payload (simulates a
    MySQL backend executing the injected SLEEP)."""

    def do_GET(self) -> None:
        # Note: mutate_query() percent-encodes the payload, so match "sleep"
        # rather than the literal "sleep(".
        if "sleep" in self.path.lower():
            time.sleep(4.2)
        body = b"<html><body>search page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _FastHandler(BaseHTTPRequestHandler):
    """Never sleeps: no injectable delay."""

    def do_GET(self) -> None:
        body = b"<html><body>search page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _SlowHandler(BaseHTTPRequestHandler):
    """Always slow (~2s): the differential must NOT confirm on a uniformly
    slow endpoint."""

    def do_GET(self) -> None:
        time.sleep(2.0)
        body = b"<html><body>slow page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _StoredXSSHandler(BaseHTTPRequestHandler):
    """Reflects probe payloads and persists them (simulates stored XSS)."""
    stored: list[str] = []

    def do_GET(self) -> None:
        q = parse_qs(urlparse(self.path).query)
        qval = q.get("q", [""])[0]
        body = "<html><body>"
        if "xploit" in qval and any(
            s in qval for s in ("<svg", "<img", "onerror", "onload")
        ):
            type(self).stored.append(qval)
            body += f"<div>results for: {qval}</div>"
        for s in type(self).stored:
            body += f"<div>previous search: {s}</div>"
        body += "</body></html>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        return


class _ReflectOnlyHandler(BaseHTTPRequestHandler):
    """Reflects but never stores: reflected XSS only."""

    def do_GET(self) -> None:
        q = parse_qs(urlparse(self.path).query)
        qval = q.get("q", [""])[0]
        body = f"<html><body><div>results for: {qval}</div></body></html>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        return


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _finding(**over) -> Finding:
    base = dict(
        id="T-001", name="n", category="c", severity="HIGH", confidence="High",
        url="http://x/", evidence="e", impact="i", remediation="r",
    )
    base.update(over)
    return Finding(**base)


# --------------------------------------------------------------------------
# Time-based blind SQLi
# --------------------------------------------------------------------------

class TimeBasedSQLiTest(unittest.TestCase):
    def test_sleep_payload_confirms_and_verifies(self) -> None:
        server = _serve(_SleepHandler)
        try:
            url = f"http://127.0.0.1:{server.server_port}/search?q=1"
            scanner = WebScanner(url, timeout=6.0, mode=FULL)
            scanner.pages = {url: None}
            scanner.forms = []
            SQLInjectionModule(scanner).run()
            timed = [f for f in scanner.findings if f.id == "SQLI-002"]
            self.assertEqual(len(timed), 1, "expected one time-based blind SQLi")
            f = timed[0]
            self.assertTrue(f.verified, "timing proof must verify")
            self.assertEqual(f.proof_kind, "timing")
            self.assertGreater(f.proof_delay_s, 0)
            self.assertIn("timing proof", f.verification_note)
        finally:
            server.shutdown()

    def test_no_delay_no_finding(self) -> None:
        server = _serve(_FastHandler)
        try:
            url = f"http://127.0.0.1:{server.server_port}/search?q=1"
            scanner = WebScanner(url, timeout=6.0, mode=FULL)
            scanner.pages = {url: None}
            scanner.forms = []
            SQLInjectionModule(scanner).run()
            timed = [f for f in scanner.findings if f.id == "SQLI-002"]
            self.assertEqual(timed, [])
        finally:
            server.shutdown()

    def test_uniformly_slow_endpoint_does_not_confirm(self) -> None:
        server = _serve(_SlowHandler)
        try:
            url = f"http://127.0.0.1:{server.server_port}/search?q=1"
            scanner = WebScanner(url, timeout=6.0, mode=FULL)
            scanner.pages = {url: None}
            scanner.forms = []
            SQLInjectionModule(scanner).run()
            timed = [f for f in scanner.findings if f.id == "SQLI-002"]
            self.assertEqual(timed, [],
                             "differential must reject a uniformly slow endpoint")
        finally:
            server.shutdown()

    def test_skipped_when_timeout_too_small(self) -> None:
        scanner = WebScanner("http://127.0.0.1:9/", timeout=4.0, mode=FULL)
        mod = SQLInjectionModule(scanner)
        # SLEEP(4) cannot fit inside a 4s timeout: the technique must stand
        # down instead of measuring a truncated delay.
        self.assertFalse(mod._test_time_based("http://127.0.0.1:9/x?a=1",
                                              "a", "GET"))

    def test_gate_verifies_timing_proof(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=%27+OR+SLEEP%284%29--",
                     proof_kind="timing", proof_delay_s=3.0)
        gate_finding(f)
        self.assertTrue(f.verified)
        self.assertIn("timing", f.verification_note)

    def test_gate_rejects_timing_proof_without_threshold(self) -> None:
        f = _finding(proof_method="GET", proof_url="http://x/?a=1",
                     proof_kind="timing", proof_delay_s=0.0)
        gate_finding(f)
        self.assertFalse(f.verified)


# --------------------------------------------------------------------------
# Stored XSS persistence probe
# --------------------------------------------------------------------------

class StoredXSSTest(unittest.TestCase):
    def _run_xss(self, handler) -> WebScanner:
        server = _serve(handler)
        try:
            if handler is _StoredXSSHandler:
                handler.stored = []
            url = f"http://127.0.0.1:{server.server_port}/search?q=hello"
            scanner = WebScanner(url, timeout=6.0, mode=FULL)
            scanner.pages = {url: None}
            scanner.forms = []
            XSSModule(scanner).run()
            return scanner
        finally:
            server.shutdown()

    def test_persisted_payload_reports_stored_xss(self) -> None:
        scanner = self._run_xss(_StoredXSSHandler)
        reflected = [f for f in scanner.findings if f.id == "XSS-001"]
        stored = [f for f in scanner.findings if f.id == "XSS-002"]
        self.assertEqual(len(reflected), 1)
        self.assertEqual(len(stored), 1, "persisted payload must report XSS-002")
        self.assertTrue(stored[0].verified, "stored XSS carries marker proof")
        self.assertIn("persisted", stored[0].evidence.lower())

    def test_reflect_only_reports_no_stored_xss(self) -> None:
        scanner = self._run_xss(_ReflectOnlyHandler)
        reflected = [f for f in scanner.findings if f.id == "XSS-001"]
        stored = [f for f in scanner.findings if f.id == "XSS-002"]
        self.assertEqual(len(reflected), 1)
        self.assertEqual(stored, [])


# --------------------------------------------------------------------------
# Retest + report plumbing for timing proofs
# --------------------------------------------------------------------------

class _StubScanner:
    def __init__(self, mode: str, delay: float) -> None:
        self.mode = mode
        self._delay = delay

    def _request(self, method, url, quiet=False, **kwargs):
        if self._delay:
            time.sleep(self._delay)

        class _Res:
            status_code = 200
            headers = {}
            text = "<html><body>ok</body></html>"

        return _Res()


class TimingRetestTest(unittest.TestCase):
    def _timing_finding(self) -> Finding:
        return _finding(proof_method="GET",
                        proof_url="http://x/?a=%27+OR+SLEEP%284%29--",
                        proof_kind="timing", proof_delay_s=1.0)

    def test_retest_confirms_reproduced_delay(self) -> None:
        scanner = _StubScanner(FULL, delay=1.2)
        stats = retest_findings(scanner, [self._timing_finding()])
        self.assertEqual(stats[RETEST_CONFIRMED], 1)

    def test_retest_marks_gone_delay_fixed(self) -> None:
        scanner = _StubScanner(FULL, delay=0.0)
        findings = [self._timing_finding()]
        stats = retest_findings(scanner, findings)
        self.assertEqual(stats[RETEST_FIXED], 1)
        self.assertEqual(findings[0].retest_status, RETEST_FIXED)

    def test_retest_failed_replay_is_unverifiable(self) -> None:
        class _Failing(_StubScanner):
            def _request(self, method, url, quiet=False, **kwargs):
                return None

        stats = retest_findings(_Failing(FULL, 0.0), [self._timing_finding()])
        self.assertEqual(stats[RETEST_UNVERIFIABLE], 1)


class TimingReportTest(unittest.TestCase):
    def test_report_names_timing_proof(self) -> None:
        f = _finding(name="Time-based Blind SQL Injection", id="SQLI-002",
                     proof_method="GET", proof_url="http://x/?a=1",
                     proof_kind="timing", proof_delay_s=3.0)
        gate_finding(f)
        result = ScanResult(
            target="http://x/", normalized_target="http://x/",
            started_at="t", duration_seconds=1.0, status="done",
            scan_mode=FULL, scope_prefix="", completion_percent=100,
            checks_run=[], pages_seen=[], forms_seen=0,
            findings=[f], errors=[],
        )
        out = render_text_report(result, colors=False)
        self.assertIn("timing proof", out)



# --------------------------------------------------------------------------
# sqlite "unrecognized token" error marker
# --------------------------------------------------------------------------

class _SqliteErrorHandler(BaseHTTPRequestHandler):
    """Simulates the bundled vulnerable_test_app /sqli endpoint: returns a
    sqlite diagnostic when the id param carries an injected quote, and a
    normal user-info page otherwise."""

    def do_GET(self) -> None:
        q = parse_qs(urlparse(self.path).query)
        ival = q.get("id", [""])[0]
        if "'" in ival:
            body = ("<html><body><h1>Database Error</h1>"
                    "<pre>unrecognized token: \"'\"</pre></body></html>")
        else:
            body = ("<html><body><h1>User Info</h1>"
                    "<p>id: 1, name: alice</p></body></html>")
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        return


class _SqliteErrorDocsHandler(BaseHTTPRequestHandler):
    """Benign docs page that literally describes the sqlite diagnostic. The
    baseline gate must suppress the marker here: it is already present in
    the benign response."""

    def do_GET(self) -> None:
        body = ("<html><body><h1>Error reference</h1>"
                "<p>The sqlite diagnostic 'unrecognized token' means the "
                "query string contained an unterminated quote.</p></body></html>")
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        return


class SqliteErrorMarkerTest(unittest.TestCase):
    """Regression for the sqlite SQLi blind spot: the bundled test app's
    /sqli endpoint leaks 'unrecognized token' but no SQL_ERRORS marker
    matched it, so error-based detection fired zero findings."""

    def _run_sqli(self, handler) -> WebScanner:
        server = _serve(handler)
        try:
            url = f"http://127.0.0.1:{server.server_port}/sqli?id=1"
            scanner = WebScanner(url, timeout=3.0, mode=FULL)
            scanner.pages = {url: None}
            scanner.forms = []
            SQLInjectionModule(scanner).run()
            return scanner
        finally:
            server.shutdown()

    def test_sqlite_error_marker_fires(self) -> None:
        scanner = self._run_sqli(_SqliteErrorHandler)
        err = [f for f in scanner.findings if f.id == "SQLI-001"]
        self.assertEqual(len(err), 1,
                         "expected one error-based SQLi finding")
        self.assertIn("unrecognized token", err[0].evidence)
        self.assertEqual(err[0].parameter, "id")

    def test_marker_in_baseline_stays_quiet(self) -> None:
        scanner = self._run_sqli(_SqliteErrorDocsHandler)
        err = [f for f in scanner.findings if f.id == "SQLI-001"]
        self.assertEqual(err, [],
                         "marker already in benign baseline: must not fire")


if __name__ == "__main__":
    unittest.main()
