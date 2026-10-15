"""Test-only stubs for optional third-party deps.

bs4 is not installed in this environment and nothing may be installed
without Harsh's word, so the import is stubbed. The stub only needs to
satisfy `from bs4 import BeautifulSoup` at module import time — tests that
exercise actual HTML parsing supply their own fakes.
"""
import sys
import types


def _ensure_bs4_stub():
    try:
        import bs4  # noqa: F401
        return
    except ImportError:
        pass
    mod = types.ModuleType("bs4")

    class BeautifulSoup:  # noqa: D101
        def __init__(self, *args, **kwargs):
            raise RuntimeError("bs4 stub: HTML parsing unavailable in tests")

    mod.BeautifulSoup = BeautifulSoup
    sys.modules["bs4"] = mod


_ensure_bs4_stub()
