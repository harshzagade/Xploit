"""Tests for scan checkpointing (--checkpoint / --resume)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xploit import checkpoint as cp
from xploit.cli import build_parser
from xploit.scanner import Finding, FormTarget, WebScanner


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


def _form():
    return FormTarget(
        page_url="http://127.0.0.1/",
        action="http://127.0.0.1/login",
        method="POST",
        inputs={"user": "xploit"},
        input_types={"user": "text"},
    )


def _write(tmp_path, **overrides):
    payload = dict(
        target="http://127.0.0.1/",
        crawled=["http://127.0.0.1/"],
        forms=cp.serialize_forms([_form()]),
        completed_modules=["General Security"],
        findings=cp.serialize_findings([_finding()]),
        finished=False,
    )
    payload.update(overrides)
    path = str(tmp_path / "cp.json")
    cp.write_checkpoint(path, **payload)
    return path


# --- write/load round-trip ----------------------------------------------

def test_write_load_round_trip(tmp_path):
    path = _write(tmp_path)
    # Atomic write: no .tmp litter left behind.
    assert not (tmp_path / "cp.json.tmp").exists()
    loaded = cp.load_checkpoint(path)
    assert loaded["tool"] == "xploit"
    assert loaded["checkpoint_version"] == cp.CHECKPOINT_VERSION
    assert loaded["target"] == "http://127.0.0.1/"
    assert loaded["crawled"] == ["http://127.0.0.1/"]
    assert loaded["completed_modules"] == ["General Security"]
    assert loaded["finished"] is False
    forms = cp.deserialize_forms(loaded["forms"])
    assert forms[0].action == "http://127.0.0.1/login"
    assert forms[0].inputs == {"user": "xploit"}
    findings = cp.deserialize_findings(loaded["findings"])
    assert findings[0].id == "RESTORED-001"
    assert findings[0].url == "http://127.0.0.1/"


def test_load_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        cp.load_checkpoint(str(tmp_path / "nope.json"))


def test_load_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        cp.load_checkpoint(str(path))


def test_load_wrong_tool(tmp_path):
    path = _write(tmp_path)
    payload = json.loads(open(path).read())
    payload["tool"] = "durbx"
    open(path, "w").write(json.dumps(payload))
    with pytest.raises(ValueError, match="not written by Xploit"):
        cp.load_checkpoint(path)


def test_load_wrong_version(tmp_path):
    path = _write(tmp_path)
    payload = json.loads(open(path).read())
    payload["checkpoint_version"] = 99
    open(path, "w").write(json.dumps(payload))
    with pytest.raises(ValueError, match="Unsupported checkpoint version"):
        cp.load_checkpoint(path)


def test_load_missing_key(tmp_path):
    path = _write(tmp_path)
    payload = json.loads(open(path).read())
    del payload["findings"]
    open(path, "w").write(json.dumps(payload))
    with pytest.raises(ValueError, match="missing 'findings'"):
        cp.load_checkpoint(path)


def test_deserialize_drops_unknown_keys_and_bad_rows():
    full = _finding(id="X-1").to_dict()
    full["future_field"] = "ignored"
    findings = cp.deserialize_findings([
        full,
        {"id": "X-2", "name": "incomplete, skipped"},
        "not a dict",
    ])
    assert [f.id for f in findings] == ["X-1"]


# --- CLI parser ----------------------------------------------------------

def test_parser_checkpoint_resume_defaults():
    args = build_parser().parse_args(["http://x/"])
    assert args.checkpoint is None
    assert args.resume is None


def test_parser_checkpoint_resume_flags():
    args = build_parser().parse_args(
        ["http://x/", "--checkpoint", "a.json", "--resume", "b.json"])
    assert args.checkpoint == "a.json"
    assert args.resume == "b.json"


# --- fixture server + scan integration -----------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def do_GET(self):
        # text/plain on purpose: this environment has no bs4, and the
        # crawl only parses HTML for text/html pages. Plain pages still
        # exercise checkpoint write/resume/module-skip end to end, and
        # the repo's own HTML-crawl tests already cover the soup path
        # where bs4 is installed.
        if self.path == "/":
            self._send(200, "text/plain", b"home page")
        elif self.path == "/page":
            self._send(200, "text/plain", b"plain page")
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    server.server_close()


def test_scan_writes_finished_checkpoint(tmp_path, base_url):
    path = str(tmp_path / "scan.json")
    result = WebScanner(
        base_url, mode="passive", modules="general,exposure",
        checkpoint=path, timeout=5,
    ).scan()
    assert result.status == "completed"
    loaded = cp.load_checkpoint(path)
    assert loaded["finished"] is True
    assert loaded["target"] == result.normalized_target
    assert base_url in loaded["crawled"]
    assert "General Security" in loaded["completed_modules"]
    assert "Exposure & Access Control Heuristics" in loaded["completed_modules"]


def test_resume_skips_completed_module_and_restores_findings(tmp_path, base_url):
    path = _write(
        tmp_path,
        target=WebScanner(base_url).root,
        crawled=[base_url],
        completed_modules=["General Security"],
        findings=cp.serialize_findings([_finding()]),
        forms=[],
    )
    # One module remains after the skip, so the scanner takes the
    # sequential path: it reports progress phases, not module hooks.
    phases = []
    scanner = WebScanner(
        base_url, mode="passive", modules="general,exposure",
        resume=path, timeout=5,
    )
    scanner.on_progress = lambda c, t, phase: phases.append(phase)
    result = scanner.scan()
    assert not any("General Security" in p for p in phases)
    assert any("Exposure & Access Control Heuristics" in p for p in phases)
    assert "General Security" in result.checks_run
    assert any(f.id == "RESTORED-001" for f in result.findings)
    # Progress was written back to the resume file, now finished.
    loaded = cp.load_checkpoint(path)
    assert loaded["finished"] is True
    assert "Exposure & Access Control Heuristics" in loaded["completed_modules"]
    assert any(f["id"] == "RESTORED-001" for f in loaded["findings"])


def test_resume_seeds_crawl_from_checkpoint_pages(tmp_path, base_url):
    # Crawled list holds only /page: the resumed crawl must fetch it
    # without re-running discovery from the root.
    page_url = base_url + "page"
    path = _write(
        tmp_path,
        target=WebScanner(base_url).root,
        crawled=[page_url],
        completed_modules=[],
        findings=[],
        forms=[],
    )
    result = WebScanner(
        base_url, mode="passive", modules="general",
        resume=path, timeout=5, depth=0,
    ).scan()
    assert page_url in result.pages_seen
    assert base_url not in result.pages_seen


def test_resume_finished_checkpoint_refused(tmp_path, base_url):
    path = _write(tmp_path, target=WebScanner(base_url).root, finished=True)
    with pytest.raises(ValueError, match="already finished"):
        WebScanner(base_url, resume=path).scan()


def test_resume_target_mismatch_refused(tmp_path, base_url):
    path = _write(tmp_path, target="http://other.example/")
    with pytest.raises(ValueError, match="does not match"):
        WebScanner(base_url, resume=path).scan()


def test_checkpoint_write_failure_does_not_fail_scan(tmp_path, base_url):
    bad_path = str(tmp_path / "missing-dir" / "cp.json")
    result = WebScanner(
        base_url, mode="passive", modules="general",
        checkpoint=bad_path, timeout=5,
    ).scan()
    assert result.status == "completed"
    assert any("Could not write checkpoint" in e for e in result.errors)
