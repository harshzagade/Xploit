"""--modules: run only the named scan modules for faster targeted scans.

Selection is validated eagerly (a typo fails at scanner construction, not
mid-scan), aliases resolve to canonical keys, the fan-out keeps canonical
registry order regardless of typing order, and an explicit selection
overrides the mode-based module gating.
"""
import pytest
from argparse import Namespace

from xploit.cli import _build_scanner, build_parser
from xploit.scanner import (
    MODULE_ALIASES,
    MODULE_REGISTRY,
    WebScanner,
    load_module_class,
    parse_module_keys,
)


CANONICAL = list(MODULE_REGISTRY)


def _args(**kw):
    base = dict(
        url="http://t/", extra_urls=[],
        depth=4, max_pages=500, timeout=6.0, mode="full",
        rate_limit=0.0, jitter=0.0, scope_prefix="/", exclude=[],
        modules=[], format="text", output=None, retest=False,
        header=[], cookie=[],
        insecure=False, no_color=True, quiet=True,
        min_severity="MEDIUM", threads=5, parallel_modules=1,
    )
    base.update(kw)
    return Namespace(**base)


def _install_stubs(monkeypatch):
    """Replace all 10 scan modules with stubs; skip the crawl."""
    stubs = {}
    for key, (mod_name, class_name) in MODULE_REGISTRY.items():
        stub = type(f"Stub{class_name}", (), {
            "name": class_name,
            "__init__": lambda self, scanner: setattr(self, "scanner", scanner),
            "run": lambda self: None,
        })
        monkeypatch.setattr(f"xploit.modules.{mod_name}.{class_name}", stub)
        stubs[key] = class_name
    monkeypatch.setattr(
        WebScanner, "_crawl",
        lambda self: setattr(self, "pages", {"http://t/": None}))
    return stubs


# --- parse_module_keys --------------------------------------------------------

def test_parse_single_key():
    assert parse_module_keys("xss") == ["xss"]


def test_parse_comma_string_and_list():
    assert parse_module_keys("xss,sqli") == ["sqli", "xss"]
    assert parse_module_keys(["xss,sqli", "general"]) == ["general", "sqli", "xss"]


def test_parse_case_insensitive_and_whitespace():
    assert parse_module_keys("XSS,  SQLi ") == ["sqli", "xss"]


def test_parse_dedupes():
    assert parse_module_keys("xss,xss,sqli") == ["sqli", "xss"]


def test_parse_canonical_order_not_typing_order():
    # Fan-out order follows the registry, not the order the user typed.
    assert parse_module_keys("brute,xss,general") == ["general", "xss", "brute"]


def test_parse_aliases_resolve():
    assert parse_module_keys("traversal") == parse_module_keys("cmd")
    assert parse_module_keys("sensitive") == parse_module_keys("data")
    assert parse_module_keys("injection") == parse_module_keys("advanced")


def test_parse_empty_string_ok():
    assert parse_module_keys("") == []
    assert parse_module_keys([]) == []
    assert parse_module_keys(None) == []


@pytest.mark.parametrize("key", CANONICAL)
def test_registry_covers_ten_keys(key):
    assert isinstance(key, str) and key


def test_parse_unknown_raises_with_valid_list():
    with pytest.raises(ValueError) as exc_info:
        parse_module_keys("xss,nope")
    message = str(exc_info.value)
    assert "'nope'" in message
    assert "xss" in message and "sqli" in message


# --- scanner construction -----------------------------------------------------

def test_scanner_modules_default_none():
    assert WebScanner("http://t/").modules is None


def test_scanner_modules_normalized():
    scanner = WebScanner("http://t/", modules="XSS,sqli")
    assert scanner.modules == ["sqli", "xss"]


def test_scanner_rejects_unknown_module_eagerly():
    with pytest.raises(ValueError, match="unknown scan module"):
        WebScanner("http://t/", modules="nope")


def test_scanner_rejects_empty_selection():
    with pytest.raises(ValueError, match="at least one module"):
        WebScanner("http://t/", modules="")
    with pytest.raises(ValueError, match="at least one module"):
        WebScanner("http://t/", modules=[])


def test_load_module_class_resolves_real_classes():
    for key in CANONICAL:
        cls = load_module_class(key)
        assert isinstance(cls, type)
        assert isinstance(cls.name, str)


# --- scan() filtering ---------------------------------------------------------

def test_scan_runs_only_selected_modules(monkeypatch):
    stubs = _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", mode="full", modules=["xss", "sqli"],
                         parallel_modules=1)
    result = scanner.scan()
    assert scanner._checks_run == [stubs["sqli"], stubs["xss"]]
    assert result.status == "completed"
    assert result.modules == ["sqli", "xss"]


def test_scan_modules_alias_applies(monkeypatch):
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", modules="traversal", parallel_modules=1)
    scanner.scan()
    assert scanner.modules == ["cmd"]
    assert scanner._checks_run == ["CommandTraversalModule"]


def test_explicit_modules_override_mode_gating(monkeypatch):
    # In passive mode, injection modules never run normally — but an
    # explicit --modules selection is the caller's deliberate choice.
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", mode="passive", modules="xss",
                         parallel_modules=1)
    scanner.scan()
    assert scanner._checks_run == ["XSSModule"]


def test_scan_without_modules_runs_all(monkeypatch):
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", mode="full", parallel_modules=1)
    result = scanner.scan()
    assert scanner._checks_run == [
        "GeneralModule", "ExposureModule", "SensitiveDataModule",
        "SQLInjectionModule", "XSSModule", "CommandTraversalModule",
        "LogicVulnerabilityModule", "AdvancedAuthModule",
        "MultiVectorInjectionModule", "BruteForceModule"]
    assert result.modules == []


def test_result_to_dict_carries_modules(monkeypatch):
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", modules="xss,sqli", parallel_modules=1)
    result = scanner.scan()
    assert result.to_dict()["modules"] == ["sqli", "xss"]


# --- CLI ----------------------------------------------------------------------

def test_parser_modules_default_empty():
    assert build_parser().parse_args(["http://t/"]).modules == []


def test_parser_modules_comma_and_repeatable():
    args = build_parser().parse_args(
        ["http://t/", "--modules", "xss,sqli", "--modules", "general"])
    assert args.modules == ["xss,sqli", "general"]


def test_build_scanner_passes_modules():
    scanner = _build_scanner(_args(modules=["xss,sqli"]), "http://t/")
    assert scanner.modules == ["sqli", "xss"]


def test_build_scanner_none_without_flag():
    scanner = _build_scanner(_args(), "http://t/")
    assert scanner.modules is None


def test_build_scanner_rejects_bad_module():
    with pytest.raises(ValueError, match="unknown scan module"):
        _build_scanner(_args(modules=["nope"]), "http://t/")


def test_help_lists_valid_modules():
    help_text = build_parser().format_help()
    for key in CANONICAL:
        assert key in help_text
