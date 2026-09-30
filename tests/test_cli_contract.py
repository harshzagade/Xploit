"""Contract tests for the Xploit CLI surface (round 2)."""
import pytest

from xploit import cli
from xploit.cli import (
    apply_request_overrides,
    banner,
    build_parser,
    color,
)
from xploit.scanner import WebScanner


def parse(*argv):
    return build_parser().parse_args(list(argv))


def make_scanner():
    return WebScanner("http://example.com/", mode="passive")


# --- parser defaults -----------------------------------------------------

def test_parser_default_mode_is_full():
    assert parse("http://x/").mode == "full"


def test_parser_default_depth_is_4():
    assert parse("http://x/").depth == 4


def test_parser_default_max_pages_is_500():
    assert parse("http://x/").max_pages == 500


def test_parser_default_timeout_is_6():
    assert parse("http://x/").timeout == 6.0


def test_parser_default_rate_limit_is_0():
    assert parse("http://x/").rate_limit == 0.0


def test_parser_default_scope_prefix_is_root():
    assert parse("http://x/").scope_prefix == "/"


def test_parser_default_format_is_text():
    assert parse("http://x/").format == "text"


def test_parser_default_output_is_none():
    assert parse("http://x/").output is None


def test_parser_flags_default_off():
    args = parse("http://x/")
    assert args.retest is False
    assert args.insecure is False
    assert args.no_color is False
    assert args.quiet is False


def test_parser_header_and_cookie_default_empty():
    args = parse("http://x/")
    assert args.header == []
    assert args.cookie == []


# --- parser choices / validation -----------------------------------------

def test_parser_accepts_all_modes():
    for mode in ("passive", "active", "full"):
        assert parse("http://x/", "--mode", mode).mode == mode


def test_parser_rejects_bad_mode():
    with pytest.raises(SystemExit):
        parse("http://x/", "--mode", "stealth")


def test_parser_rejects_bad_format():
    with pytest.raises(SystemExit):
        parse("http://x/", "--format", "yaml")


def test_parser_parses_depth_and_pages():
    args = parse("http://x/", "--depth", "2", "--max-pages", "10")
    assert args.depth == 2
    assert args.max_pages == 10


def test_parser_collects_multiple_headers():
    args = parse("http://x/", "--header", "A: 1", "--header", "B: 2")
    assert args.header == ["A: 1", "B: 2"]


# --- color / banner ------------------------------------------------------

def test_color_disabled_returns_plain_text():
    assert color("hi", "HIGH", enabled=False) == "hi"


def test_color_enabled_wraps_ansi():
    out = color("hi", "HIGH", enabled=True)
    assert out != "hi" and "hi" in out and "\x1b[" in out


def test_color_unknown_name_does_not_crash():
    assert color("hi", "NOPE", enabled=True) == f"hi{cli.RESET}"


def test_banner_no_color_contains_logo_blocks():
    assert "██╗" in banner(colors=False)


def test_banner_enabled_contains_ansi():
    assert "\x1b[" in banner(colors=True)


# --- request overrides ---------------------------------------------------

def test_override_header_with_colon_in_value():
    sc = make_scanner()
    apply_request_overrides(sc, ["X-Api: token:with:colons"], [])
    assert sc.session.headers["X-Api"] == "token:with:colons"


def test_override_rejects_header_without_colon():
    with pytest.raises(ValueError):
        apply_request_overrides(make_scanner(), ["no-colon-here"], [])


def test_override_rejects_empty_header_name():
    with pytest.raises(ValueError):
        apply_request_overrides(make_scanner(), [": value"], [])


def test_override_cookie_value_with_equals():
    sc = make_scanner()
    apply_request_overrides(sc, [], ["sess=abc=def"])
    assert sc.session.cookies.get("sess") == "abc=def"


def test_override_rejects_bad_cookie():
    with pytest.raises(ValueError):
        apply_request_overrides(make_scanner(), [], ["no-equals"])
