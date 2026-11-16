"""Tests for WAF-bypass payload rotation (--waf-rotation)."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from xploit.cli import _build_scanner, build_parser
from xploit.encodings import (
    ENCODINGS, PayloadRotator, encode_payload, host_of,
)
from xploit.modules.sqli import SQLInjectionModule
from xploit.scanner import WebScanner

PAYLOAD = "' OR 1=1--"


# --- encode_payload: unit tests -------------------------------------------

def test_encode_plain_is_identity():
    assert encode_payload(PAYLOAD, "plain") == PAYLOAD


def test_encode_url_percent_encodes_everything():
    assert encode_payload(PAYLOAD, "url") == "%27%20OR%201%3D1--"


def test_encode_double_url_encodes_the_percent_signs():
    assert encode_payload(PAYLOAD, "double-url") == "%2527%2520OR%25201%253D1--"


def test_encode_unicode_uses_percent_u_form():
    assert encode_payload("'", "unicode") == "%u0027"
    assert encode_payload("AB", "unicode") == "%u0041%u0042"


def test_encode_unknown_name_fails_fast():
    with pytest.raises(ValueError, match="unknown payload encoding"):
        encode_payload(PAYLOAD, "rot13")


def test_host_of_lowercases_and_keeps_port():
    assert host_of("HTTP://Example.COM:8080/x") == "example.com:8080"
    assert host_of("http://127.0.0.1:9/") == "127.0.0.1:9"


# --- PayloadRotator: unit tests -------------------------------------------

def test_rotator_cycles_in_order_and_never_repeats_consecutively():
    rotator = PayloadRotator()
    seen = [rotator.next_encoding("example.com") for _ in range(9)]
    assert seen == list(ENCODINGS) + list(ENCODINGS) + [ENCODINGS[0]]
    assert all(a != b for a, b in zip(seen, seen[1:]))


def test_rotator_hosts_rotate_independently():
    rotator = PayloadRotator()
    assert rotator.next_encoding("a.example") == "plain"
    assert rotator.next_encoding("b.example") == "plain"
    assert rotator.next_encoding("a.example") == "url"
    assert rotator.next_encoding("b.example") == "url"


def test_rotator_reset_restarts_one_host_only():
    rotator = PayloadRotator()
    rotator.next_encoding("a.example")
    rotator.next_encoding("a.example")
    rotator.reset("a.example")
    assert rotator.next_encoding("a.example") == "plain"


def test_rotator_rejects_empty_and_unknown_encodings():
    with pytest.raises(ValueError):
        PayloadRotator(())
    with pytest.raises(ValueError, match="unknown payload encoding"):
        PayloadRotator(("plain", "rot13"))


# --- WebScanner.rotate_payload --------------------------------------------

def test_rotation_off_by_default_returns_plain():
    scanner = WebScanner("http://127.0.0.1:9/", threads=1)
    assert scanner.waf_rotation is False
    assert scanner.rotate_payload(PAYLOAD, "http://example.com/x") == (PAYLOAD, "plain")


def test_rotation_on_cycles_per_host():
    scanner = WebScanner("http://127.0.0.1:9/", threads=1, waf_rotation=True)
    assert scanner.rotate_payload(PAYLOAD, "http://example.com/x") == (PAYLOAD, "plain")
    encoded, name = scanner.rotate_payload(PAYLOAD, "http://example.com/x")
    assert name == "url" and encoded == "%27%20OR%201%3D1--"
    # A different host starts its own rotation at plain.
    assert scanner.rotate_payload(PAYLOAD, "http://other.example/") == (PAYLOAD, "plain")


# --- SQLi integration: wire encodings actually sent -----------------------

class _RecordingHandler(BaseHTTPRequestHandler):
    queries: list[str] = []
    bodies: list[str] = []
    json_bodies: list[str] = []
    lock = threading.Lock()

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        with self.lock:
            self.queries.append(urlparse(self.path).query)
            self.bodies.append(raw)
            if self.headers.get("Content-Type") == "application/json":
                self.json_bodies.append(raw)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record

    def log_message(self, *args):  # silence the test server
        pass


@pytest.fixture()
def recording_server():
    _RecordingHandler.queries = []
    _RecordingHandler.bodies = []
    _RecordingHandler.json_bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _decoded_param(raw_query: str) -> str:
    return parse_qs(raw_query, keep_blank_values=True)["q"][0]


def test_sqli_get_probes_cycle_encodings(recording_server):
    scanner = WebScanner(recording_server + "/", threads=1, waf_rotation=True)
    module = SQLInjectionModule(scanner)
    url = recording_server + "/search"
    for _ in range(4):
        module._send_payload(url, "q", "GET", PAYLOAD)
    sent = [_decoded_param(q) for q in _RecordingHandler.queries]
    assert sent == [
        PAYLOAD,
        "%27%20OR%201%3D1--",
        "%2527%2520OR%25201%253D1--",
        "%u0027%u0020%u004f%u0052%u0020%u0031%u003d%u0031%u002d%u002d",
    ]
    assert all(a != b for a, b in zip(sent, sent[1:]))


def test_sqli_post_probes_cycle_encodings(recording_server):
    scanner = WebScanner(recording_server + "/", threads=1, waf_rotation=True)
    module = SQLInjectionModule(scanner)
    url = recording_server + "/search"
    for _ in range(2):
        module._send_payload(url, "q", "POST", PAYLOAD)
    sent = [_decoded_param(b) for b in _RecordingHandler.bodies]
    assert sent == [PAYLOAD, "%27%20OR%201%3D1--"]


def test_sqli_rotation_off_sends_plain_every_time(recording_server):
    scanner = WebScanner(recording_server + "/", threads=1)
    module = SQLInjectionModule(scanner)
    url = recording_server + "/search"
    for _ in range(3):
        module._send_payload(url, "q", "GET", PAYLOAD)
    assert [_decoded_param(q) for q in _RecordingHandler.queries] == [PAYLOAD] * 3


def test_sqli_json_body_stays_plain_under_rotation(recording_server):
    scanner = WebScanner(recording_server + "/", threads=1, waf_rotation=True)
    module = SQLInjectionModule(scanner)
    module._send_payload(recording_server + "/api", "q", "POST", PAYLOAD,
                         base_data={"other": "x"}, json_body=True)
    assert _RecordingHandler.json_bodies
    import json
    assert json.loads(_RecordingHandler.json_bodies[0])["q"] == PAYLOAD


# --- CLI wiring ------------------------------------------------------------

def test_cli_flag_wires_rotation_into_scanner():
    args = build_parser().parse_args(
        ["http://127.0.0.1:9/", "--waf-rotation"])
    assert _build_scanner(args, "http://127.0.0.1:9/").waf_rotation is True
    args = build_parser().parse_args(["http://127.0.0.1:9/"])
    assert _build_scanner(args, "http://127.0.0.1:9/").waf_rotation is False
