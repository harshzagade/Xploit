"""Tests for the --proxy CLI flag (queue item 2, 2026-10-29 evening)."""
import pytest

from xploit.cli import _build_scanner, build_parser
from xploit.scanner import WebScanner, parse_proxy_url


def parse(*argv):
    return build_parser().parse_args(list(argv))


# --- parser --------------------------------------------------------------

def test_parser_default_proxy_is_none():
    assert parse("http://x/").proxy is None


def test_parser_accepts_proxy():
    assert parse("http://x/", "--proxy", "http://127.0.0.1:8080").proxy == "http://127.0.0.1:8080"


# --- parse_proxy_url -----------------------------------------------------

def test_parse_proxy_http_url():
    assert parse_proxy_url("http://127.0.0.1:8080") == {
        "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_parse_proxy_bare_host_port_assumes_http():
    assert parse_proxy_url("127.0.0.1:8080") == {
        "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_parse_proxy_https_scheme_preserved():
    assert parse_proxy_url("https://proxy.example.com:8443") == {
        "http": "https://proxy.example.com:8443",
        "https": "https://proxy.example.com:8443"}


def test_parse_proxy_credentials_preserved():
    assert parse_proxy_url("http://user:pass@127.0.0.1:8080") == {
        "http": "http://user:pass@127.0.0.1:8080",
        "https": "http://user:pass@127.0.0.1:8080"}


def test_parse_proxy_none_is_none():
    assert parse_proxy_url(None) is None


@pytest.mark.parametrize("bad", ["", "   ", "ftp://proxy:21", "http://", "http://:8080",
                                 "http://host:99999", "socks5://127.0.0.1:1080"])
def test_parse_proxy_bad_values_fail_fast(bad):
    with pytest.raises(ValueError):
        parse_proxy_url(bad)


# --- WebScanner wiring ---------------------------------------------------

def test_scanner_no_proxy_leaves_session_proxies_empty():
    sc = WebScanner("http://example.com/", mode="passive")
    assert sc.proxies == {}
    assert sc.proxy is None
    assert sc.session.proxies == {}


def test_scanner_proxy_applied_to_session():
    sc = WebScanner("http://example.com/", mode="passive", proxy="127.0.0.1:8080")
    assert sc.proxy == "http://127.0.0.1:8080"
    assert sc.session.proxies == {
        "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_scanner_bad_proxy_fails_at_construction():
    with pytest.raises(ValueError):
        WebScanner("http://example.com/", mode="passive", proxy="ftp://x:21")


def test_build_scanner_wires_proxy():
    args = parse("http://example.com/", "--proxy", "http://127.0.0.1:8080")
    sc = _build_scanner(args, "http://example.com/")
    assert sc.session.proxies["http"] == "http://127.0.0.1:8080"
    assert sc.session.proxies["https"] == "http://127.0.0.1:8080"


def test_build_scanner_no_proxy_when_flag_absent():
    args = parse("http://example.com/")
    sc = _build_scanner(args, "http://example.com/")
    assert sc.session.proxies == {}
