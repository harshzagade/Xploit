"""Stage 1 'smart scanner' — unit tests.

Covers:
  1. is_binary_asset(): extension and Content-Type classification.
  2. _build_target_profile(): MSSQL fingerprint vs plain (unknown) fixture.
  3. SQLi time-based payload filtering: mssql hint -> WAITFOR only;
     unknown hint -> all 4 families fired.
  4. CORS _check_cors: binary-asset URLs excluded from probe list.

These tests deliberately avoid real HTTP servers and BeautifulSoup so they
run in any environment (including the bs4-stubbed test runner used here).
"""
from __future__ import annotations

import pytest

from xploit.scanner import WebScanner, is_binary_asset, BINARY_ASSET_EXTS
from xploit.modules.general import GeneralModule
from xploit.modules.sqli import SQLInjectionModule


# ---------------------------------------------------------------------------
# Minimal response stub shared across tests
# ---------------------------------------------------------------------------

class Resp:
    """Minimal requests.Response stand-in used across existing tests."""
    def __init__(self, text="", status_code=200, headers=None, url="http://x/"):
        self.text = text
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = headers or {}
        self.url = url
        self.content = text.encode() if isinstance(text, str) else text
        self._content = self.content
        self._content_consumed = True

    def get(self, key, default=None):
        return self.headers.get(key, default)


# ---------------------------------------------------------------------------
# 1. is_binary_asset()
# ---------------------------------------------------------------------------

class TestIsBinaryAsset:
    def test_webp_url_is_binary(self):
        assert is_binary_asset("http://x/logo.webp") is True

    def test_png_url_is_binary(self):
        assert is_binary_asset("http://x/img/photo.PNG") is True

    def test_woff2_url_is_binary(self):
        assert is_binary_asset("http://x/fonts/myfont.woff2") is True

    def test_html_url_is_not_binary(self):
        assert is_binary_asset("http://x/page.html") is False

    def test_js_url_is_not_binary(self):
        assert is_binary_asset("http://x/app.js") is False

    def test_json_url_is_not_binary(self):
        assert is_binary_asset("http://x/api/data.json") is False

    def test_no_extension_is_not_binary(self):
        assert is_binary_asset("http://x/search") is False

    def test_html_content_type_overrides_ambiguous_ext(self):
        # Even if the URL has no extension, text/html is never binary.
        res = Resp(headers={"Content-Type": "text/html; charset=utf-8"})
        assert is_binary_asset("http://x/page", res) is False

    def test_image_content_type_is_binary(self):
        res = Resp(headers={"Content-Type": "image/png"})
        assert is_binary_asset("http://x/no-ext", res) is True

    def test_font_content_type_is_binary(self):
        res = Resp(headers={"Content-Type": "font/woff2"})
        assert is_binary_asset("http://x/f", res) is True

    def test_application_octet_stream_is_binary(self):
        res = Resp(headers={"Content-Type": "application/octet-stream"})
        assert is_binary_asset("http://x/download", res) is True

    def test_application_json_content_type_is_not_binary(self):
        res = Resp(headers={"Content-Type": "application/json"})
        assert is_binary_asset("http://x/api", res) is False

    def test_application_javascript_content_type_is_not_binary(self):
        res = Resp(headers={"Content-Type": "application/javascript"})
        assert is_binary_asset("http://x/bundle.js", res) is False

    def test_text_plain_is_not_binary(self):
        res = Resp(headers={"Content-Type": "text/plain"})
        assert is_binary_asset("http://x/readme.txt", res) is False

    def test_binary_ext_set_nonempty(self):
        # Sanity: the set exists and contains expected members.
        assert ".png" in BINARY_ASSET_EXTS
        assert ".woff2" in BINARY_ASSET_EXTS
        assert ".html" not in BINARY_ASSET_EXTS


# ---------------------------------------------------------------------------
# 2. _build_target_profile()
# ---------------------------------------------------------------------------

def _make_scanner_with_pages(pages_dict, forms=None):
    """Return a WebScanner with self.pages pre-populated (no crawl)."""
    sc = WebScanner("http://x/", mode="passive", depth=0, max_pages=16)
    sc.root = "http://x/"
    sc.pages = pages_dict
    sc.forms = forms or []
    return sc


class TestBuildTargetProfile:
    def _iis_pages(self):
        """Pages that strongly signal ASP.NET/IIS/MSSQL."""
        pages = {
            "http://x/": Resp(
                headers={
                    "Content-Type": "text/html",
                    "Server": "Microsoft-IIS/10.0",
                    "X-Powered-By": "ASP.NET",
                },
                url="http://x/",
            ),
            "http://x/login.aspx": Resp(
                headers={"Content-Type": "text/html"},
                url="http://x/login.aspx",
            ),
        }
        return pages

    def test_mssql_hint_from_iis_aspnet_headers_and_aspx_path(self):
        sc = _make_scanner_with_pages(self._iis_pages())
        sc._build_target_profile()
        assert sc.target_profile["dbms_hint"] == "mssql"

    def test_mssql_signals_nonempty(self):
        sc = _make_scanner_with_pages(self._iis_pages())
        sc._build_target_profile()
        assert len(sc.target_profile["dbms_signals"]) > 0

    def test_stack_hints_contains_aspnet_iis(self):
        sc = _make_scanner_with_pages(self._iis_pages())
        sc._build_target_profile()
        hints = sc.target_profile["stack_hints"]
        assert any("ASP" in h or "IIS" in h for h in hints)

    def test_plain_fixture_is_unknown(self):
        pages = {
            "http://x/": Resp(
                headers={"Content-Type": "text/html", "Server": "Apache/2.4"},
                url="http://x/",
            ),
        }
        sc = _make_scanner_with_pages(pages)
        sc._build_target_profile()
        assert sc.target_profile["dbms_hint"] == "unknown"

    def test_profile_has_all_required_keys(self):
        sc = _make_scanner_with_pages(self._iis_pages())
        sc._build_target_profile()
        required = {
            "server", "powered_by", "stack_hints", "dbms_hint",
            "dbms_signals", "html_pages", "forms", "query_params",
            "external_form_actions",
        }
        assert required <= set(sc.target_profile)

    def test_html_pages_count(self):
        sc = _make_scanner_with_pages(self._iis_pages())
        sc._build_target_profile()
        # Both pages have text/html Content-Type.
        assert sc.target_profile["html_pages"] == 2

    def test_aspnet_version_header_adds_signal(self):
        pages = {
            "http://x/": Resp(
                headers={
                    "Content-Type": "text/html",
                    "Server": "Microsoft-IIS/10.0",
                    "X-Powered-By": "ASP.NET",
                    "X-AspNet-Version": "4.0.30319",
                },
                url="http://x/",
            ),
        }
        sc = _make_scanner_with_pages(pages)
        sc._build_target_profile()
        # Should score >= 2 from IIS + ASP.NET alone; version header adds +1.
        assert sc.target_profile["dbms_hint"] == "mssql"
        signals = sc.target_profile["dbms_signals"]
        assert any("AspNet-Version" in s or "aspnet-version" in s.lower() for s in signals)

    def test_php_hint_from_php_path_and_server(self):
        pages = {
            "http://x/index.php": Resp(
                headers={"Content-Type": "text/html", "Server": "Apache/2.4 (PHP/8.1)"},
                url="http://x/index.php",
            ),
        }
        sc = _make_scanner_with_pages(pages)
        sc._build_target_profile()
        assert sc.target_profile["dbms_hint"] == "mysql"

    def test_empty_pages_gives_unknown(self):
        sc = _make_scanner_with_pages({})
        sc._build_target_profile()
        assert sc.target_profile["dbms_hint"] == "unknown"

    def test_target_profile_accessible_without_crash_when_absent(self):
        """Modules that use getattr(scanner, 'target_profile', {}) must never
        crash even when the attribute is missing (older scanner stubs)."""
        # Simulate a scanner stub with no target_profile attribute.
        class BareScanner:
            pass
        sc = BareScanner()
        profile = getattr(sc, "target_profile", None) or {}
        assert profile.get("dbms_hint", "unknown") == "unknown"


# ---------------------------------------------------------------------------
# 3. SQLi payload filtering by dbms_hint
# ---------------------------------------------------------------------------

class _FakeScanner:
    """Minimal scanner stub for SQLInjectionModule tests.

    _request always returns a fast (empty) response so time-based probes
    return False naturally without sleeping. target_profile is set by tests.
    """
    def __init__(self, target_profile=None):
        self.target_profile = target_profile or {}
        self.findings = []
        self.errors = []
        self.timeout = 10  # > SLEEP_S + 2 so the timeout gate passes
        self._lock = __import__("threading").Lock()
        self.pages = {}

    def _request(self, method, url, **kwargs):
        return Resp(text="", status_code=200)

    def map_probes(self, func, items):
        for item in items:
            func(item)

    def add_finding_deduped(self, finding, key):
        self.findings.append(finding)

    def gate_and_add(self, finding):
        self.findings.append(finding)


class _CapturingSQLiModule(SQLInjectionModule):
    """SQLInjectionModule subclass that records every payload passed to
    _timed_payload so tests can assert on which payloads were attempted."""

    def __init__(self, scanner):
        super().__init__(scanner)
        self.attempted_payloads: list[str] = []

    def _timed_payload(self, url, param, method, payload, base_data=None):
        self.attempted_payloads.append(payload)
        # Return a fast response so delay checks always fail (dt ~= 0).
        return Resp(), 0.001


class TestSQLiPayloadFiltering:
    def _module(self, dbms_hint):
        scanner = _FakeScanner({"dbms_hint": dbms_hint})
        return _CapturingSQLiModule(scanner)

    def test_mssql_hint_fires_only_waitfor(self):
        m = self._module("mssql")
        m._test_time_based("http://x/?id=1", "id", "GET")
        # Must include WAITFOR and must NOT include SLEEP or pg_sleep.
        payloads = m.attempted_payloads
        assert any("WAITFOR" in p for p in payloads), "WAITFOR not attempted"
        assert not any("SLEEP(" in p for p in payloads), "SLEEP fired on mssql hint"
        assert not any("pg_sleep" in p for p in payloads), "pg_sleep fired on mssql hint"

    def test_mysql_hint_fires_only_sleep(self):
        m = self._module("mysql")
        m._test_time_based("http://x/?id=1", "id", "GET")
        payloads = m.attempted_payloads
        assert any("SLEEP(" in p for p in payloads), "SLEEP not attempted on mysql hint"
        assert not any("WAITFOR" in p for p in payloads), "WAITFOR fired on mysql hint"
        assert not any("pg_sleep" in p for p in payloads), "pg_sleep fired on mysql hint"

    def test_postgres_hint_fires_only_pg_sleep(self):
        m = self._module("postgres")
        m._test_time_based("http://x/?id=1", "id", "GET")
        payloads = m.attempted_payloads
        assert any("pg_sleep" in p for p in payloads), "pg_sleep not attempted on postgres hint"
        assert not any("SLEEP(" in p for p in payloads), "SLEEP fired on postgres hint"
        assert not any("WAITFOR" in p for p in payloads), "WAITFOR fired on postgres hint"

    def test_unknown_hint_fires_all_families(self):
        m = self._module("unknown")
        m._test_time_based("http://x/?id=1", "id", "GET")
        payloads = m.attempted_payloads
        assert any("SLEEP(" in p for p in payloads), "SLEEP not attempted on unknown hint"
        assert any("WAITFOR" in p for p in payloads), "WAITFOR not attempted on unknown hint"
        assert any("pg_sleep" in p for p in payloads), "pg_sleep not attempted on unknown hint"

    def test_missing_target_profile_fires_all_families(self):
        """Scanner with no target_profile attribute must not crash and fires
        all families (getattr default path)."""
        class BareScanner(_FakeScanner):
            pass
        scanner = BareScanner()
        del scanner.target_profile  # remove attribute entirely
        m = _CapturingSQLiModule(scanner)
        m._test_time_based("http://x/?id=1", "id", "GET")
        payloads = m.attempted_payloads
        assert any("SLEEP(" in p for p in payloads)
        assert any("WAITFOR" in p for p in payloads)
        assert any("pg_sleep" in p for p in payloads)

    def test_mssql_stacked_includes_exec_sp(self):
        """EXEC sp_MSforeachtable must fire on mssql hint."""
        scanner = _FakeScanner({"dbms_hint": "mssql"})
        m = SQLInjectionModule(scanner)
        fired_payloads: list[str] = []

        def _fake_send(url, param, method, payload, base_data=None):
            fired_payloads.append(payload)
            return Resp()

        m._send_payload = _fake_send
        m._test_stacked_queries("http://x/?id=1", "id", "GET")
        assert any("sp_MSforeachtable" in p for p in fired_payloads)

    def test_non_mssql_stacked_skips_exec_sp(self):
        """EXEC sp_MSforeachtable must NOT fire when hint is mysql."""
        scanner = _FakeScanner({"dbms_hint": "mysql"})
        m = SQLInjectionModule(scanner)
        fired_payloads: list[str] = []

        def _fake_send(url, param, method, payload, base_data=None):
            fired_payloads.append(payload)
            return Resp()

        m._send_payload = _fake_send
        m._test_stacked_queries("http://x/?id=1", "id", "GET")
        assert not any("sp_MSforeachtable" in p for p in fired_payloads)
        # information_schema probe still fires.
        assert any("information_schema" in p for p in fired_payloads)

    def test_unknown_stacked_includes_exec_sp(self):
        """EXEC sp_MSforeachtable fires when hint is unknown."""
        scanner = _FakeScanner({"dbms_hint": "unknown"})
        m = SQLInjectionModule(scanner)
        fired_payloads: list[str] = []

        def _fake_send(url, param, method, payload, base_data=None):
            fired_payloads.append(payload)
            return Resp()

        m._send_payload = _fake_send
        m._test_stacked_queries("http://x/?id=1", "id", "GET")
        assert any("sp_MSforeachtable" in p for p in fired_payloads)


# ---------------------------------------------------------------------------
# 4. CORS _check_cors: binary assets excluded from probe list
# ---------------------------------------------------------------------------

class _CorsFakeScanner:
    """Minimal scanner stub for GeneralModule._check_cors tests.

    Exposes is_binary_asset (the full production function) so the CORS
    code exercises the real helper path.
    """
    def __init__(self, pages_dict):
        self.root = "http://x/"
        self.pages = pages_dict
        self.findings = []
        self.errors = []
        self._lock = __import__("threading").Lock()
        self._probed: list[str] = []
        # Expose the real is_binary_asset helper.
        self.is_binary_asset = staticmethod(is_binary_asset)
        self.mode = "active"

    def map_probes(self, func, items):
        # Record which URLs were scheduled for CORS probing.
        self._probed.extend(items)
        # Do NOT actually fire HTTP requests.

    def _request(self, method, url, **kwargs):
        return None

    def add_finding_deduped(self, finding, key):
        self.findings.append(finding)


class TestCorsSkipsBinaryAssets:
    def _run_cors_probe_collection(self, pages_dict):
        """Return the list of URLs that _check_cors collected for probing."""
        scanner = _CorsFakeScanner(pages_dict)
        module = GeneralModule(scanner)
        module._check_cors()
        return scanner._probed

    def test_image_url_excluded_from_cors_probes(self):
        pages = {
            "http://x/": Resp(headers={"Content-Type": "text/html"}),
            "http://x/logo.png": Resp(headers={"Content-Type": "image/png"}),
            "http://x/api/data": Resp(headers={"Content-Type": "application/json"}),
        }
        probed = self._run_cors_probe_collection(pages)
        assert not any(".png" in u for u in probed), \
            f"image URL should be excluded, got {probed}"

    def test_html_page_included_in_cors_probes(self):
        pages = {
            "http://x/": Resp(headers={"Content-Type": "text/html"}),
            "http://x/logo.png": Resp(headers={"Content-Type": "image/png"}),
        }
        probed = self._run_cors_probe_collection(pages)
        assert "http://x/" in probed

    def test_font_url_excluded_from_cors_probes(self):
        pages = {
            "http://x/": Resp(headers={"Content-Type": "text/html"}),
            "http://x/fonts/sans.woff2": Resp(headers={"Content-Type": "font/woff2"}),
        }
        probed = self._run_cors_probe_collection(pages)
        assert not any(".woff2" in u for u in probed)

    def test_only_html_page_in_probes_when_all_others_are_binary(self):
        pages = {
            "http://x/": Resp(headers={"Content-Type": "text/html"}),
            "http://x/a.jpg": Resp(headers={"Content-Type": "image/jpeg"}),
            "http://x/b.mp4": Resp(headers={"Content-Type": "video/mp4"}),
        }
        probed = self._run_cors_probe_collection(pages)
        assert probed == ["http://x/"]

    def test_js_url_included_in_cors_probes(self):
        """JavaScript URLs should NOT be excluded (sensitive data checks need them)."""
        pages = {
            "http://x/": Resp(headers={"Content-Type": "text/html"}),
            "http://x/app.js": Resp(headers={"Content-Type": "application/javascript"}),
        }
        probed = self._run_cors_probe_collection(pages)
        assert "http://x/app.js" in probed
