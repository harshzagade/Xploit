"""--parallel-modules: run scan modules concurrently side by side.

Sequential mode (parallel_modules=1, the default) must behave exactly as
before. Parallel mode fans the module list out on a thread pool; findings
still flow through the locked dedupe, one crashing module must not kill its
siblings, and the lifecycle hooks must fire once per module.
"""
import threading
import time
from argparse import Namespace

from xploit.cli import _build_scanner, build_parser
from xploit.scanner import HIGH, Finding, WebScanner


MODULE_PATHS = [
    ("xploit.modules.sqli", "SQLInjectionModule"),
    ("xploit.modules.xss", "XSSModule"),
    ("xploit.modules.injection_advanced", "CommandTraversalModule"),
    ("xploit.modules.general", "GeneralModule"),
    ("xploit.modules.logic_vulnerabilities", "LogicVulnerabilityModule"),
    ("xploit.modules.exposure", "ExposureModule"),
    ("xploit.modules.advanced_injection", "MultiVectorInjectionModule"),
    ("xploit.modules.sensitive_data", "SensitiveDataModule"),
    ("xploit.modules.auth_advanced", "AdvancedAuthModule"),
    ("xploit.modules.brute_force", "BruteForceModule"),
]

# Construction order inside WebScanner.scan().
EXPECTED_ORDER = [attr for _, attr in [
    ("xploit.modules.general", "GeneralModule"),
    ("xploit.modules.exposure", "ExposureModule"),
    ("xploit.modules.sensitive_data", "SensitiveDataModule"),
    ("xploit.modules.sqli", "SQLInjectionModule"),
    ("xploit.modules.xss", "XSSModule"),
    ("xploit.modules.injection_advanced", "CommandTraversalModule"),
    ("xploit.modules.logic_vulnerabilities", "LogicVulnerabilityModule"),
    ("xploit.modules.auth_advanced", "AdvancedAuthModule"),
    ("xploit.modules.advanced_injection", "MultiVectorInjectionModule"),
    ("xploit.modules.brute_force", "BruteForceModule"),
]]


class _StubModule:
    """Stand-in for a real scan module. Behaviour driven by the shared
    cfg dict: sleep seconds, findings count, raise_name to crash one."""
    name = "stub"
    _cfg = {}

    def __init__(self, scanner):
        self.scanner = scanner
        # Mirrors BaseModule.findings_added: incremented inside the locked
        # section whenever this stub records a finding.
        self.findings_added = 0

    def run(self):
        cfg = type(self)._cfg
        if cfg.get("on_run"):
            cfg["on_run"](self.scanner, self.name)
        time.sleep(cfg.get("sleep", 0))
        if self.name == cfg.get("raise_name"):
            raise RuntimeError("boom")
        for i in range(cfg.get("findings", 0)):
            with self.scanner._lock:
                self.scanner.findings.append(Finding(
                    id=f"F-{self.name}-{i}", name=f"Finding {self.name}",
                    category="C", severity=HIGH, confidence="High",
                    url="http://t/", evidence="e", impact="i",
                    remediation="r"))
                self.findings_added += 1


def _install_stubs(monkeypatch, **cfg_overrides):
    """Replace all 10 scan modules with stubs; skip the crawl."""
    cfg = {"sleep": 0, "findings": 0, "raise_name": None, "on_run": None}
    cfg.update(cfg_overrides)
    for mod_path, attr in MODULE_PATHS:
        stub = type(f"Stub{attr}", (_StubModule,),
                    {"name": attr, "_cfg": cfg})
        monkeypatch.setattr(f"{mod_path}.{attr}", stub)
    monkeypatch.setattr(
        WebScanner, "_crawl",
        lambda self: setattr(self, "pages", {"http://t/": None}))
    return cfg


def _args(**kw):
    base = dict(
        url="http://t/", extra_urls=[],
        depth=4, max_pages=500, timeout=6.0, mode="full",
        rate_limit=0.0, jitter=0.0, scope_prefix="/", exclude=[],
        format="text", output=None, retest=False, header=[], cookie=[],
        insecure=False, no_color=True, quiet=True,
        min_severity="MEDIUM", threads=5, parallel_modules=1,
    )
    base.update(kw)
    return Namespace(**base)


# --- CLI --------------------------------------------------------------------

def test_parser_parallel_modules_default():
    assert build_parser().parse_args(["http://t/"]).parallel_modules == 4


def test_parser_parallel_modules_flag():
    args = build_parser().parse_args(["http://t/", "--parallel-modules", "4"])
    assert args.parallel_modules == 4


def test_build_scanner_passes_parallel_modules():
    scanner = _build_scanner(_args(parallel_modules=3), "http://t/")
    assert scanner.parallel_modules == 3


def test_parallel_modules_clamped_to_one():
    assert WebScanner("http://t/", parallel_modules=0).parallel_modules == 1
    assert WebScanner("http://t/", parallel_modules=-3).parallel_modules == 1


# --- sequential default -----------------------------------------------------

def test_sequential_mode_preserves_module_order(monkeypatch):
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", mode="full", parallel_modules=1)
    result = scanner.scan()
    assert scanner._checks_run == EXPECTED_ORDER
    assert result.status == "completed"
    assert result.errors == []


# --- parallel execution -----------------------------------------------------

def test_parallel_runs_every_module_once(monkeypatch):
    _install_stubs(monkeypatch, findings=1)
    scanner = WebScanner("http://t/", mode="full", parallel_modules=10)
    result = scanner.scan()
    assert sorted(scanner._checks_run) == sorted(EXPECTED_ORDER)
    assert len(scanner._checks_run) == len(EXPECTED_ORDER)
    assert len(scanner.findings) == len(EXPECTED_ORDER)
    assert result.status == "completed"


def test_parallel_modules_actually_overlap(monkeypatch):
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def on_run(scanner, name):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.2)
        with lock:
            state["active"] -= 1

    _install_stubs(monkeypatch, on_run=on_run)
    scanner = WebScanner("http://t/", mode="full", parallel_modules=10)
    scanner.scan()
    assert state["peak"] > 1, "modules did not overlap — not actually parallel"


def test_parallel_module_crash_does_not_kill_siblings(monkeypatch):
    _install_stubs(monkeypatch, raise_name="XSSModule")
    scanner = WebScanner("http://t/", mode="full", parallel_modules=10)
    result = scanner.scan()
    assert any("XSSModule" in e and "crashed" in e for e in scanner.errors)
    # crashed module is still recorded; every sibling completed
    assert sorted(scanner._checks_run) == sorted(EXPECTED_ORDER)
    assert result.status == "completed"


def test_parallel_module_hooks_fire_once_per_module(monkeypatch):
    _install_stubs(monkeypatch, findings=2)
    started, done = [], []
    scanner = WebScanner("http://t/", mode="full", parallel_modules=4)
    scanner.on_module_start = started.append
    scanner.on_module_done = (
        lambda name, added, secs: done.append((name, added, secs)))
    scanner.scan()
    assert sorted(started) == sorted(EXPECTED_ORDER)
    assert sorted(n for n, _, _ in done) == sorted(EXPECTED_ORDER)
    assert all(added == 2 for _, added, _ in done)
    assert all(secs >= 0 for _, _, secs in done)


def test_parallel_hook_exception_does_not_fail_scan(monkeypatch):
    _install_stubs(monkeypatch)

    def bad_start(name):
        raise RuntimeError("ui blew up")

    scanner = WebScanner("http://t/", mode="full", parallel_modules=4)
    scanner.on_module_start = bad_start
    result = scanner.scan()
    assert sorted(scanner._checks_run) == sorted(EXPECTED_ORDER)
    assert result.status == "completed"


def test_parallel_worker_count_capped_at_module_count(monkeypatch):
    seen_workers = set()
    real_pool = __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor

    class SpyPool(real_pool):
        def __init__(self, max_workers=None, **kw):
            seen_workers.add(max_workers)
            super().__init__(max_workers=max_workers, **kw)

    import concurrent.futures
    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", SpyPool)
    _install_stubs(monkeypatch)
    scanner = WebScanner("http://t/", mode="full", parallel_modules=99)
    scanner.scan()
    # 10 modules -> pool must not be created with 99 workers
    assert seen_workers == {10}
