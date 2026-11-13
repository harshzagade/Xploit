"""Multi-target checkpoint files: one <base>.<target-slug>.json per target."""
import json
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from xploit import checkpoint as cp
from xploit.cli import _run_multi_target, run_scan
from xploit.scanner import Finding, ScanResult


# --- slug / path derivation ----------------------------------------------

def test_slug_host_only():
    assert cp.target_slug("https://example.com/") == "example.com"


def test_slug_host_and_path():
    assert cp.target_slug("https://example.com/app/api") == "example.com-app-api"


def test_slug_non_default_port_kept():
    assert cp.target_slug("http://127.0.0.1:8123/") == "127.0.0.1-8123"


def test_slug_default_ports_dropped():
    assert cp.target_slug("http://example.com:80/") == "example.com"
    assert cp.target_slug("https://example.com:443/") == "example.com"


def test_slug_lowercases_host_and_sanitizes():
    assert cp.target_slug("https://EXAMPLE.com/My Page/") == "example.com-my-page"


def test_slug_empty_falls_back():
    assert cp.target_slug("") == "target"


def test_path_for_target_json_suffix():
    assert cp.checkpoint_path_for_target("scan.json", "https://example.com/app") == \
        "scan.example.com-app.json"


def test_path_for_target_no_suffix_gains_json():
    assert cp.checkpoint_path_for_target("cp", "https://example.com/") == \
        "cp.example.com.json"


def test_path_for_target_keeps_directory():
    assert cp.checkpoint_path_for_target(
        "/tmp/x/scan.json", "http://127.0.0.1:8123/") == \
        "/tmp/x/scan.127.0.0.1-8123.json"


# --- CLI: per-target paths handed to the scanner --------------------------

class _FakeScanner:
    def __init__(self, result):
        self._result = result
        self.on_finding = None
        self.on_progress = None
        self.on_request = None

    def scan(self):
        return self._result


def _result(target, severities=()):
    return ScanResult(
        target=target, normalized_target=target, started_at="",
        duration_seconds=1.0, status="completed", scan_mode="full",
        scope_prefix="/", completion_percent=100, checks_run=[],
        pages_seen=[], forms_seen=0, findings=[], errors=[],
    )


def _args(*urls, **kw):
    base = dict(
        url=urls[0], extra_urls=list(urls[1:]),
        depth=4, max_pages=500, timeout=6.0, mode="full",
        rate_limit=0.0, jitter=0.0, scope_prefix="/", exclude=[],
        format="text", output=None, retest=False, header=[], cookie=[],
        insecure=False, no_color=True, quiet=True,
        min_severity="MEDIUM", threads=5, parallel_modules=1,
        checkpoint=None, resume=None,
    )
    base.update(kw)
    return Namespace(**base)


def _finding(**overrides):
    base = dict(
        id="RESTORED-001",
        name="Restored finding",
        category="Test",
        severity="MEDIUM",
        confidence="HIGH",
        url="http://127.0.0.1/",
        evidence="restored from checkpoint",
        impact="none",
        remediation="none",
    )
    base.update(overrides)
    return Finding(**base)


def test_multi_target_checkpoint_paths_are_per_target(tmp_path, capsys):
    args = _args("http://a/", "http://b/",
                 checkpoint=str(tmp_path / "scan.json"))
    seen = {}

    def fake_build(a, t):
        seen[t] = (a.checkpoint, a.resume)
        return _FakeScanner(_result(t))

    with patch("xploit.cli._build_scanner", side_effect=fake_build):
        code = _run_multi_target(args, ["http://a/", "http://b/"])
    assert code == 0
    assert seen["http://a/"][0] == str(tmp_path / "scan.a.json")
    assert seen["http://b/"][0] == str(tmp_path / "scan.b.json")
    assert seen["http://a/"][1] is None


def test_multi_target_missing_resume_file_scans_fresh(tmp_path, capsys):
    args = _args("http://a/", "http://b/",
                 resume=str(tmp_path / "scan.json"))
    seen = {}

    def fake_build(a, t):
        seen[t] = (a.checkpoint, a.resume)
        return _FakeScanner(_result(t))

    with patch("xploit.cli._build_scanner", side_effect=fake_build):
        code = _run_multi_target(args, ["http://a/", "http://b/"])
    assert code == 0
    # No per-target file exists yet: both targets scan fresh.
    assert seen["http://a/"][1] is None
    assert seen["http://b/"][1] is None


def test_multi_target_finished_checkpoint_restores_without_scanning(tmp_path, capsys):
    base = str(tmp_path / "scan.json")
    path_a = cp.checkpoint_path_for_target(base, "http://a/")
    cp.write_checkpoint(
        path_a, target="http://a/", crawled=["http://a/"], forms=[],
        completed_modules=["General Security"],
        findings=cp.serialize_findings([_finding()]),
        finished=True,
    )
    args = _args("http://a/", "http://b/", resume=base, format="json")
    built = []

    def fake_build(a, t):
        built.append(t)
        return _FakeScanner(_result(t))

    with patch("xploit.cli._build_scanner", side_effect=fake_build):
        code = _run_multi_target(args, ["http://a/", "http://b/"])
    assert code == 0
    # Target A never got a scanner — its result came from the checkpoint.
    assert built == ["http://b/"]
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2
    restored = data[0]
    assert restored["status"] == "completed"
    assert restored["checks_run"] == ["General Security"]
    assert [f["id"] for f in restored["findings"]] == ["RESTORED-001"]


def test_multi_target_corrupt_checkpoint_is_an_error_result(tmp_path, capsys):
    base = str(tmp_path / "scan.json")
    path_a = cp.checkpoint_path_for_target(base, "http://a/")
    open(path_a, "w").write("{not json")
    args = _args("http://a/", "http://b/", resume=base, format="json")

    def fake_build(a, t):
        return _FakeScanner(_result(t))

    with patch("xploit.cli._build_scanner", side_effect=fake_build):
        code = _run_multi_target(args, ["http://a/", "http://b/"])
    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert data[0]["status"] == "error"
    assert data[1]["status"] == "completed"


def test_run_scan_no_longer_rejects_checkpoint_for_multi_target(capsys):
    args = _args("http://a/", "http://b/",
                 checkpoint="scan.json")
    with patch("xploit.cli._run_multi_target", return_value=9) as m:
        assert run_scan(args) == 9
        m.assert_called_once_with(args, ["http://a/", "http://b/"])


# --- live end-to-end: two fixture servers, real scanners ------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def do_GET(self):
        body = b"home page"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def test_live_multi_target_writes_one_checkpoint_per_target(tmp_path, capsys):
    server_a, url_a = _serve()
    server_b, url_b = _serve()
    try:
        base = str(tmp_path / "scan.json")
        args = _args(url_a, url_b, mode="passive",
                     checkpoint=base, format="json", quiet=True)
        code = run_scan(args)
        assert code == 0
        path_a = cp.checkpoint_path_for_target(base, url_a)
        path_b = cp.checkpoint_path_for_target(base, url_b)
        assert path_a != path_b
        data = json.loads(capsys.readouterr().out)
        assert [r["target"] for r in data] == [url_a, url_b]
        for path, row in ((path_a, data[0]), (path_b, data[1])):
            loaded = cp.load_checkpoint(path)
            assert loaded["finished"] is True
            assert loaded["target"] == row["normalized_target"]
        # The shared base path itself was never written.
        assert not (tmp_path / "scan.json").exists()
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()


def test_live_multi_target_resume_skips_completed_module(tmp_path, capsys):
    server_a, url_a = _serve()
    server_b, url_b = _serve()
    try:
        from xploit.scanner import WebScanner
        base = str(tmp_path / "scan.json")
        # Unfinished checkpoint for A only: General Security done, with a
        # restored finding; B has no checkpoint at all.
        path_a = cp.checkpoint_path_for_target(base, url_a)
        cp.write_checkpoint(
            path_a, target=WebScanner(url_a).root, crawled=[url_a],
            forms=[], completed_modules=["General Security"],
            findings=cp.serialize_findings([_finding(url=url_a)]),
            finished=False,
        )
        args = _args(url_a, url_b, mode="passive",
                     resume=base, format="json", quiet=True)
        code = run_scan(args)
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        result_a = data[0]
        assert "General Security" in result_a["checks_run"]
        assert any(f["id"] == "RESTORED-001"
                   for f in result_a["findings"])
        # Progress was written back to A's per-target file, now finished.
        loaded = cp.load_checkpoint(path_a)
        assert loaded["finished"] is True
        assert any(f["id"] == "RESTORED-001" for f in loaded["findings"])
    finally:
        server_a.shutdown()
        server_a.server_close()
        server_b.shutdown()
        server_b.server_close()
