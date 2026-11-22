"""TLS certificate expiry: an HTTPS target whose leaf certificate is
already expired is flagged MEDIUM (TLS-001, CWE-295), and one lapsing
within 30 days is flagged INFO. A healthy certificate, an unreachable
host, or an HTTP target flags nothing. The check reads only the expiry
date over an unverified handshake — it never trusts the certificate.
"""
from __future__ import annotations

import http.server
import shutil
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from xploit.modules import general as general_module
from xploit.modules.general import GeneralModule
from xploit.scanner import INFO, MEDIUM


class FakeScanner:
    """Minimal scanner stub; the TLS check only reads root/timeout/mode."""
    def __init__(self, root="https://x/"):
        self.root = root
        self.param_hints = {}
        self.findings = []
        self.errors = []
        self._lock = threading.Lock()
        self._finding_keys = set()
        self.timeout = 10
        self.target_profile = {}
        self.pages = {}
        self.forms = []
        self.request_count = 0
        self.mode = "active"
        self.on_finding = None

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        return None

    def map_probes(self, func, items):
        for item in items:
            func(item)

    def add_finding_deduped(self, finding, key=None):
        with self._lock:
            self.findings.append(finding)

    def gate_and_add(self, finding):
        with self._lock:
            self.findings.append(finding)


def _not_after_in(days: float) -> float:
    """Epoch seconds that many days from now, padded so the whole-day
    floor the check computes is exactly ``int(days)``."""
    return time.time() + days * 86400 + 1800


def _run_tls(scanner, monkeypatch, not_after):
    monkeypatch.setattr(
        general_module, "_fetch_cert_not_after",
        lambda host, port, timeout: not_after,
    )
    module = GeneralModule(scanner)
    module._check_tls_cert_expiry()
    return [f for f in scanner.findings if f.id == "TLS-001"]


class TestTlsCertExpiry:
    def test_expired_certificate_flags_medium(self, monkeypatch):
        not_after = _not_after_in(-2)
        scanner = FakeScanner()
        findings = _run_tls(scanner, monkeypatch, not_after)
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].cwe == "CWE-295"
        assert findings[0].category == "TLS Certificate"
        assert "expired 2 day(s) ago" in findings[0].evidence
        assert datetime.fromtimestamp(
            not_after, tz=timezone.utc
        ).date().isoformat() in findings[0].evidence

    def test_expiring_soon_flags_info(self, monkeypatch):
        scanner = FakeScanner()
        findings = _run_tls(scanner, monkeypatch, _not_after_in(5))
        assert len(findings) == 1
        assert findings[0].severity == INFO
        assert findings[0].cwe == "CWE-295"
        assert "expires in 5 day(s)" in findings[0].evidence

    def test_exactly_30_days_still_warns(self, monkeypatch):
        scanner = FakeScanner()
        findings = _run_tls(scanner, monkeypatch, _not_after_in(30))
        assert len(findings) == 1
        assert findings[0].severity == INFO

    def test_31_days_does_not_flag(self, monkeypatch):
        scanner = FakeScanner()
        assert _run_tls(scanner, monkeypatch, _not_after_in(31)) == []

    def test_healthy_certificate_does_not_flag(self, monkeypatch):
        scanner = FakeScanner()
        assert _run_tls(scanner, monkeypatch, _not_after_in(365)) == []

    def test_fetch_failure_does_not_flag(self, monkeypatch):
        scanner = FakeScanner()
        assert _run_tls(scanner, monkeypatch, None) == []

    def test_http_target_does_not_flag_and_never_connects(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            general_module, "_fetch_cert_not_after",
            lambda host, port, timeout: calls.append((host, port)) or _not_after_in(-1),
        )
        scanner = FakeScanner(root="http://x/")
        GeneralModule(scanner)._check_tls_cert_expiry()
        assert calls == []
        assert scanner.findings == []

    def test_nonstandard_port_is_used(self, monkeypatch):
        calls = []
        def fake_fetch(host, port, timeout):
            calls.append((host, port, timeout))
            return _not_after_in(-1)
        monkeypatch.setattr(general_module, "_fetch_cert_not_after", fake_fetch)
        scanner = FakeScanner(root="https://x:8443/")
        GeneralModule(scanner)._check_tls_cert_expiry()
        findings = [f for f in scanner.findings if f.id == "TLS-001"]
        assert calls == [("x", 8443, 10)]
        assert len(findings) == 1

    def test_check_does_not_run_in_passive_mode(self, monkeypatch):
        monkeypatch.setattr(
            general_module, "_fetch_cert_not_after",
            lambda host, port, timeout: _not_after_in(-1),
        )
        scanner = FakeScanner()
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert [f for f in scanner.findings if f.id == "TLS-001"] == []

    def test_check_runs_in_active_mode_via_run(self, monkeypatch):
        monkeypatch.setattr(
            general_module, "_fetch_cert_not_after",
            lambda host, port, timeout: _not_after_in(-1),
        )
        scanner = FakeScanner()
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert [f for f in scanner.findings if f.id == "TLS-001"]


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl needed to mint test certs"
)
class TestNotAfterFromDer:
    def test_parses_real_certificate(self, tmp_path):
        cert, _key = _make_cert(tmp_path, 30)
        pem = Path(cert).read_text()
        der = ssl.PEM_cert_to_DER_cert(pem)
        parsed = general_module._not_after_from_der(der)
        assert parsed is not None
        expected = subprocess.run(
            ["openssl", "x509", "-in", cert, "-noout", "-enddate"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        # "notAfter=Dec 22 04:51:48 2026 GMT"
        assert parsed == ssl.cert_time_to_seconds(expected.split("=", 1)[1])

    def test_garbage_returns_none(self):
        assert general_module._not_after_from_der(b"not a certificate") is None

    def test_truncated_der_returns_none(self, tmp_path):
        cert, _key = _make_cert(tmp_path, 30)
        der = ssl.PEM_cert_to_DER_cert(Path(cert).read_text())
        assert general_module._not_after_from_der(der[:40]) is None
        assert general_module._not_after_from_der(der[:-10]) is None

    def test_empty_returns_none(self):
        assert general_module._not_after_from_der(b"") is None


# --- Live end-to-end: real TLS handshake against a local server ----------

class _OK(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def _make_cert(tmp_path: Path, days: int) -> tuple[str, str]:
    key = tmp_path / f"key-{days}.pem"
    cert = tmp_path / f"cert-{days}.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert),
         "-days", str(days), "-nodes", "-subj", "/CN=127.0.0.1"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


def _serve_tls(certfile: str, keyfile: str):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OK)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl needed to mint test certs"
)
class TestTlsCertExpiryLive:
    def test_expiring_cert_flags_over_real_handshake(self, tmp_path):
        cert, key = _make_cert(tmp_path, 1)
        server = _serve_tls(cert, key)
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"https://127.0.0.1:{port}/")
            GeneralModule(scanner)._check_tls_cert_expiry()
            findings = [f for f in scanner.findings if f.id == "TLS-001"]
            assert len(findings) == 1
            assert findings[0].severity == INFO
            assert "127.0.0.1" in findings[0].evidence
        finally:
            server.shutdown()
            server.server_close()

    def test_healthy_cert_does_not_flag_over_real_handshake(self, tmp_path):
        cert, key = _make_cert(tmp_path, 365)
        server = _serve_tls(cert, key)
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"https://127.0.0.1:{port}/")
            GeneralModule(scanner)._check_tls_cert_expiry()
            assert [f for f in scanner.findings if f.id == "TLS-001"] == []
        finally:
            server.shutdown()
            server.server_close()
