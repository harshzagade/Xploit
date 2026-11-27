"""TLS 1.0/1.1 support audit: an HTTPS target whose server completes a
handshake pinned to TLS 1.0 or TLS 1.1 is flagged once as TLS-002
(MEDIUM, CWE-327). A server that refuses both versions, an unreachable
host, or an HTTP target flags nothing. The probe never trusts the
certificate and sends no application data — only the handshake outcome
is read.
"""
from __future__ import annotations

import http.server
import shutil
import ssl
import subprocess
import threading
import warnings
from pathlib import Path

import pytest

from xploit.modules import general as general_module
from xploit.modules.general import GeneralModule
from xploit.scanner import MEDIUM


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


def _run_tls_old_versions(scanner, monkeypatch, accepted):
    """Drive the check with a stubbed probe: ``accepted`` is the set of
    version labels ("TLS 1.0" / "TLS 1.1") the fake server accepts."""
    def fake_probe(host, port, version, timeout):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            label = {
                ssl.TLSVersion.TLSv1: "TLS 1.0",
                ssl.TLSVersion.TLSv1_1: "TLS 1.1",
            }.get(version)
        return label in accepted

    monkeypatch.setattr(
        general_module, "_tls_version_supported", fake_probe,
    )
    module = GeneralModule(scanner)
    module._check_tls_old_versions()
    return [f for f in scanner.findings if f.id == "TLS-002"]


class TestTlsOldVersions:
    def test_both_versions_accepted_flags_once(self, monkeypatch):
        scanner = FakeScanner()
        findings = _run_tls_old_versions(
            scanner, monkeypatch, {"TLS 1.0", "TLS 1.1"},
        )
        assert len(findings) == 1
        assert findings[0].severity == MEDIUM
        assert findings[0].cwe == "CWE-327"
        assert findings[0].category == "TLS Configuration"
        assert "TLS 1.0" in findings[0].evidence
        assert "TLS 1.1" in findings[0].evidence

    def test_only_tls10_accepted_names_it_alone(self, monkeypatch):
        scanner = FakeScanner()
        findings = _run_tls_old_versions(scanner, monkeypatch, {"TLS 1.0"})
        assert len(findings) == 1
        assert "TLS 1.0" in findings[0].evidence
        assert "TLS 1.1" not in findings[0].evidence

    def test_only_tls11_accepted_names_it_alone(self, monkeypatch):
        scanner = FakeScanner()
        findings = _run_tls_old_versions(scanner, monkeypatch, {"TLS 1.1"})
        assert len(findings) == 1
        assert "TLS 1.1" in findings[0].evidence
        assert "TLS 1.0" not in findings[0].evidence

    def test_neither_accepted_does_not_flag(self, monkeypatch):
        scanner = FakeScanner()
        assert _run_tls_old_versions(scanner, monkeypatch, set()) == []

    def test_http_target_does_not_flag_and_never_probes(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            general_module, "_tls_version_supported",
            lambda host, port, version, timeout: calls.append(version) or True,
        )
        scanner = FakeScanner(root="http://x/")
        GeneralModule(scanner)._check_tls_old_versions()
        assert calls == []
        assert scanner.findings == []

    def test_nonstandard_port_is_used(self, monkeypatch):
        calls = []
        def fake_probe(host, port, version, timeout):
            calls.append((host, port, timeout))
            return True
        monkeypatch.setattr(general_module, "_tls_version_supported", fake_probe)
        scanner = FakeScanner(root="https://x:8443/")
        GeneralModule(scanner)._check_tls_old_versions()
        findings = [f for f in scanner.findings if f.id == "TLS-002"]
        assert calls == [("x", 8443, 10), ("x", 8443, 10)]
        assert len(findings) == 1

    def test_probe_failure_does_not_flag(self, monkeypatch):
        monkeypatch.setattr(
            general_module, "_tls_version_supported",
            lambda host, port, version, timeout: False,
        )
        scanner = FakeScanner()
        GeneralModule(scanner)._check_tls_old_versions()
        assert scanner.findings == []

    def test_check_does_not_run_in_passive_mode(self, monkeypatch):
        monkeypatch.setattr(
            general_module, "_tls_version_supported",
            lambda host, port, version, timeout: True,
        )
        monkeypatch.setattr(
            general_module, "_fetch_cert_not_after", lambda *a: None,
        )
        scanner = FakeScanner()
        scanner.mode = "passive"
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert [f for f in scanner.findings if f.id == "TLS-002"] == []

    def test_check_runs_in_active_mode_via_run(self, monkeypatch):
        monkeypatch.setattr(
            general_module, "_tls_version_supported",
            lambda host, port, version, timeout: True,
        )
        monkeypatch.setattr(
            general_module, "_fetch_cert_not_after", lambda *a: None,
        )
        scanner = FakeScanner()
        scanner.pages = {}
        scanner.forms = []
        GeneralModule(scanner).run()
        assert len([f for f in scanner.findings if f.id == "TLS-002"]) == 1


# --- Live end-to-end: real handshakes against local servers ---------------

class _OK(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def _make_cert(tmp_path: Path) -> tuple[str, str]:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


def _serve_tls(certfile: str, keyfile: str, min_version):
    """TLS server pinned to ``min_version``. SECLEVEL=0 is needed on
    this host's OpenSSL 3 before the server can speak TLS 1.0/1.1 at
    all; the probe under test lowers its own client the same way."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OK)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = min_version
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl needed to mint test certs"
)
class TestTlsOldVersionsLive:
    def test_old_tls_server_flags_over_real_handshake(self, tmp_path):
        cert, key = _make_cert(tmp_path)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            server = _serve_tls(cert, key, ssl.TLSVersion.TLSv1)
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"https://127.0.0.1:{port}/")
            GeneralModule(scanner)._check_tls_old_versions()
            findings = [f for f in scanner.findings if f.id == "TLS-002"]
            assert len(findings) == 1
            assert findings[0].severity == MEDIUM
            assert "TLS 1.0" in findings[0].evidence
        finally:
            server.shutdown()
            server.server_close()

    def test_modern_tls_server_does_not_flag_over_real_handshake(self, tmp_path):
        cert, key = _make_cert(tmp_path)
        server = _serve_tls(cert, key, ssl.TLSVersion.TLSv1_2)
        try:
            port = server.server_address[1]
            scanner = FakeScanner(root=f"https://127.0.0.1:{port}/")
            GeneralModule(scanner)._check_tls_old_versions()
            assert [f for f in scanner.findings if f.id == "TLS-002"] == []
        finally:
            server.shutdown()
            server.server_close()
