"""Stage 2 tests: param-hint pre-pass, hint-driven skipping in SQLi/XSS,
external form-action scope guard, and the shared SQLi baseline cache.

Drafted by Gemini (2026-10-30) from the Stage 2 spec; integration fixes by
Muse (real lock, XSS _confirmed init, _check_form arity, FormTarget arg
order, inert-count assertion).
"""
import threading
from types import SimpleNamespace

from xploit.modules.sqli import SQLInjectionModule
from xploit.modules.xss import XSSModule
from xploit.scanner import FormTarget, WebScanner


class Resp:
    def __init__(self, text="", status_code=200, headers=None, url="http://x/"):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode()


class FakeScanner:
    def __init__(self, root="http://x/"):
        self.root = root
        self.param_hints = {}
        self.findings = []
        self.errors = []
        self._lock = threading.Lock()
        self.timeout = 10
        self.target_profile = {}
        self.pages = {}
        self.request_count = 0

    def _request(self, method, url, **kwargs):
        self.request_count += 1
        return Resp("")

    def map_probes(self, func, items):
        for item in items:
            func(item)

    def add_finding_deduped(self, finding, key=None):
        self.findings.append(finding)

    def gate_and_add(self, finding):
        self.findings.append(finding)


class RecorderSQLI(SQLInjectionModule):
    def __init__(self, scanner):
        super().__init__(scanner)
        self.calls = []

    def _test_error_based(self, *a, **k):
        self.calls.append("error")
        return False

    def _test_union_based(self, *a, **k):
        self.calls.append("union")
        return False

    def _test_boolean_based(self, *a, **k):
        self.calls.append("boolean")
        return False

    def _test_time_based(self, *a, **kw):
        self.calls.append(("time", kw.get("max_payloads")))
        return False

    def _test_stacked_queries(self, *a, **k):
        self.calls.append("stacked")
        return False


# ---------------------------------------------------------------------------
# SQLi reduced / full chains
# ---------------------------------------------------------------------------

def test_sqli_reduced_chain_for_inert_param():
    mod = RecorderSQLI(FakeScanner())
    mod._probe_param("http://x/", "p", "GET", None, {"changes": False})
    assert mod.calls == ["error", ("time", 1)]


def test_sqli_full_chain_when_param_changes():
    mod = RecorderSQLI(FakeScanner())
    mod._probe_param("http://x/", "p", "GET", None, {"changes": True})
    assert mod.calls == ["error", "union", "boolean", ("time", None), "stacked"]


def test_sqli_full_chain_when_no_hint():
    mod = RecorderSQLI(FakeScanner())
    mod._probe_param("http://x/", "p", "GET", None, None)
    assert mod.calls == ["error", "union", "boolean", ("time", None), "stacked"]


def test_sqli_external_form_skipped():
    mod = RecorderSQLI(FakeScanner())
    form = SimpleNamespace(action="https://other.example/submit",
                           method="POST", inputs={"a": "1"})
    mod._check_form(form)
    assert mod.calls == []


# ---------------------------------------------------------------------------
# SQLi shared baseline cache
# ---------------------------------------------------------------------------

def test_sqli_baseline_cache_fetches_once_per_param():
    mod = SQLInjectionModule(FakeScanner())
    calls = {"n": 0}

    def stub_send(url, param, method, payload, base_data=None):
        calls["n"] += 1
        return Resp("base")

    mod._send_payload = stub_send
    mod._baseline("http://x/a", "q", "GET", None)
    mod._baseline("http://x/a", "q", "GET", None)   # cached
    mod._baseline("http://x/a", "z", "GET", None)   # new param
    assert calls["n"] == 2


# ---------------------------------------------------------------------------
# XSS hint skips
# ---------------------------------------------------------------------------

def _xss_module(scanner):
    mod = XSSModule(scanner)
    mod._confirmed = set()  # normally initialised in run()
    return mod


def test_xss_skips_non_reflecting_param():
    scanner = FakeScanner()
    scanner.param_hints = {
        ("http://x/f", "POST", "name"): {
            "reflects": False, "changes": False,
            "baseline_status": 200, "baseline_len": 0,
        }
    }
    mod = _xss_module(scanner)
    form = SimpleNamespace(action="http://x/f", method="POST",
                           inputs={"name": "a"})
    mod._check_form(form, "<svg onload=alert(1)>")
    assert scanner.request_count == 0


def test_xss_probes_when_no_hint():
    scanner = FakeScanner()
    mod = _xss_module(scanner)
    form = SimpleNamespace(action="http://x/f", method="POST",
                           inputs={"name": "a"})
    mod._check_form(form, "<svg onload=alert(1)>")
    assert scanner.request_count > 0


def test_xss_skips_external_form():
    scanner = FakeScanner()
    mod = _xss_module(scanner)
    form = SimpleNamespace(action="https://other.example/f", method="POST",
                           inputs={"name": "a"})
    mod._check_form(form, "<svg onload=alert(1)>")
    assert scanner.request_count == 0


# ---------------------------------------------------------------------------
# Pre-pass (_build_param_hints)
# ---------------------------------------------------------------------------

def _prepass_scanner(request_stub):
    scanner = WebScanner("http://x/", mode="passive")
    scanner.forms = [FormTarget("http://x/", "http://x/search", "GET",
                                {"q": "hello"})]
    scanner.pages = {}
    scanner.target_profile = {}
    scanner._request = request_stub
    scanner._build_param_hints()
    return scanner


def test_prepass_records_reflection():
    def stub(method, url, params=None, data=None, **kwargs):
        val = (params or data or {}).get("q", "")
        if val == "xp7f3a9z":
            return Resp("results for xp7f3a9z")
        return Resp("results for hello")

    scanner = _prepass_scanner(stub)
    hint = scanner.param_hints.get(("http://x/search", "GET", "q"))
    assert hint is not None and hint["reflects"] is True
    assert scanner.target_profile["params_probed"] == 1
    assert scanner.target_profile["params_inert"] == 0


def test_prepass_records_inert_param():
    scanner = _prepass_scanner(lambda *a, **k: Resp("static"))
    hint = scanner.param_hints.get(("http://x/search", "GET", "q"))
    assert hint is not None
    assert hint["reflects"] is False and hint["changes"] is False
    assert scanner.target_profile["params_probed"] == 1
    assert scanner.target_profile["params_inert"] == 1
