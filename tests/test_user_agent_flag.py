"""Tests for the --user-agent CLI flag (queue item 1, 2026-10-29 evening)."""
import pytest

from xploit.cli import _build_scanner, apply_request_overrides, build_parser
from xploit.scanner import DEFAULT_USER_AGENT, WebScanner


def parse(*argv):
    return build_parser().parse_args(list(argv))


def test_parser_default_user_agent_is_none():
    # None = "WebScanner's default"; the default string itself lives in
    # scanner.DEFAULT_USER_AGENT, not duplicated in the parser.
    assert parse("http://x/").user_agent is None


def test_parser_accepts_user_agent():
    assert parse("http://x/", "--user-agent", "MyBot/1.0").user_agent == "MyBot/1.0"


def test_scanner_default_user_agent():
    sc = WebScanner("http://example.com/", mode="passive")
    assert sc.user_agent == DEFAULT_USER_AGENT
    assert sc.session.headers["User-Agent"] == DEFAULT_USER_AGENT


def test_scanner_custom_user_agent():
    sc = WebScanner("http://example.com/", mode="passive", user_agent="MyBot/1.0")
    assert sc.user_agent == "MyBot/1.0"
    assert sc.session.headers["User-Agent"] == "MyBot/1.0"


def test_scanner_none_user_agent_means_default():
    sc = WebScanner("http://example.com/", mode="passive", user_agent=None)
    assert sc.session.headers["User-Agent"] == DEFAULT_USER_AGENT


def test_scanner_blank_user_agent_fails_fast():
    with pytest.raises(ValueError):
        WebScanner("http://example.com/", mode="passive", user_agent="   ")


def test_build_scanner_wires_user_agent():
    args = parse("http://example.com/", "--user-agent", "AuditBot/2.0")
    sc = _build_scanner(args, "http://example.com/")
    assert sc.session.headers["User-Agent"] == "AuditBot/2.0"


def test_build_scanner_default_when_flag_absent():
    args = parse("http://example.com/")
    sc = _build_scanner(args, "http://example.com/")
    assert sc.session.headers["User-Agent"] == DEFAULT_USER_AGENT


def test_header_override_still_wins_over_user_agent_flag():
    # _build_scanner sets the UA, then apply_request_overrides runs after
    # it in the real flow — an explicit --header User-Agent must win.
    args = parse("http://example.com/", "--user-agent", "AuditBot/2.0")
    sc = _build_scanner(args, "http://example.com/")
    apply_request_overrides(sc, ["User-Agent: Override/9.9"], [])
    assert sc.session.headers["User-Agent"] == "Override/9.9"
