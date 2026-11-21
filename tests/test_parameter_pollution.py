"""HTTP parameter pollution detection (HPP-001).

Three responses are compared per parameter: the crawled URL as-is, the same
URL with the parameter replaced by the probe value, and the URL with the
parameter sent twice. A polluted answer that matches NEITHER single-value
answer is flagged; first-wins and last-wins servers are (correctly) not.
Tests simulate a server per handling behavior (never a real target).
"""
from urllib.parse import parse_qsl, urlparse

from xploit.modules.logic_vulnerabilities import (
    HPP_SECOND_VALUE,
    LogicVulnerabilityModule,
    _hpp_response_differs,
    duplicate_query_param,
)
from xploit.scanner import WebScanner

PAD_A = "A" * 500


class Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def _pairs(url):
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def _effective_values(url, param="id"):
    return [v for k, v in _pairs(url) if k == param]


def _make_scanner(behavior, pages=None):
    """Fake scanner whose _request answers per the handling behavior.

    behavior: "first" | "last" | "concat" | "error" | "reflect" | "none".
    The page body embeds the server's effective value inside 500 bytes of
    padding, so a different effective value means a genuinely different
    result page (delta >> the 64-byte / 5% threshold), while a pure
    reflection of the query string only adds ~20 bytes and stays below it.
    """
    scanner = WebScanner("http://t/", mode="passive", threads=1)
    scanner.pages = pages or {"http://t/page?id=1": None}
    requested = []

    def fake_request(method, url, **kwargs):
        requested.append(url)
        if behavior == "none":
            return None
        values = _effective_values(url)
        if behavior == "reflect":
            return Resp(200, "page?" + urlparse(url).query + PAD_A)
        if behavior == "error" and len(values) > 1:
            return Resp(500, "error" + PAD_A)
        if behavior == "error":
            # Single-value requests behave normally (first value wins).
            effective = values[0]
        elif behavior == "first":
            effective = values[0]
        elif behavior == "last":
            effective = values[-1]
        elif behavior == "concat":
            effective = ",".join(values)
        else:  # pragma: no cover - unknown behavior in test setup
            raise AssertionError(behavior)
        # Concat changes the result set: the duplicated value yields extra
        # result rows, so the divergent page is genuinely longer (a
        # same-length page with different bytes alone stays below the
        # length threshold by design).
        extra = ""
        if behavior == "concat" and len(values) > 1:
            extra = "\n" + "extra-result-row\n" * 20
        return Resp(200, f"results for {effective}\n{PAD_A}{extra}")

    scanner._request = fake_request
    scanner.requested = requested
    return scanner


def _run(behavior, pages=None):
    scanner = _make_scanner(behavior, pages)
    module = LogicVulnerabilityModule(scanner)
    module.run()
    return scanner, module


def _findings(scanner):
    return [f for f in scanner.findings if f.id == "HPP-001"]


# --- helpers ---------------------------------------------------------------

def test_duplicate_query_param_appends_second_occurrence():
    url = duplicate_query_param("http://t/page?id=1&x=2", "id", HPP_SECOND_VALUE)
    pairs = _pairs(url)
    assert pairs == [("id", "1"), ("x", "2"), ("id", HPP_SECOND_VALUE)]


def test_hpp_response_differs_status_change():
    assert _hpp_response_differs(Resp(200, "x" * 500), Resp(500, "x" * 500))


def test_hpp_response_differs_small_delta_is_not_divergence():
    assert not _hpp_response_differs(Resp(200, "x" * 500), Resp(200, "x" * 520))


def test_hpp_response_differs_large_delta_counts():
    assert _hpp_response_differs(Resp(200, "x" * 500), Resp(200, "y" * 600))


def test_hpp_response_differs_none_is_never_divergence():
    assert not _hpp_response_differs(None, Resp(200, "x"))
    assert not _hpp_response_differs(Resp(200, "x"), None)


# --- detection -------------------------------------------------------------

def test_first_wins_server_not_flagged():
    scanner, _ = _run("first")
    assert _findings(scanner) == []


def test_last_wins_server_not_flagged():
    scanner, _ = _run("last")
    assert _findings(scanner) == []


def test_concat_server_flagged():
    scanner, _ = _run("concat")
    findings = _findings(scanner)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.parameter == "id"
    assert finding.severity == "MEDIUM"
    assert finding.cwe == "CWE-235"
    assert "matches neither single-value answer" in finding.evidence
    # The proof URL is the polluted request, replayable by --retest.
    assert _effective_values(finding.proof_url) == ["1", HPP_SECOND_VALUE]
    assert finding.proof_method == "GET"
    # Behavioral confirmation, not a marker: not machine-verified.
    assert finding.verified is False


def test_error_on_duplicate_flagged():
    scanner, _ = _run("error")
    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0].parameter == "id"
    assert "500" in findings[0].evidence


def test_reflection_only_page_not_flagged():
    # The page echoes the raw query string; the duplicate adds ~20 bytes,
    # below the 64-byte floor, so reflection alone never fires.
    scanner, _ = _run("reflect")
    assert _findings(scanner) == []


def test_only_divergent_param_flagged():
    # Two params; only `id` is handled divergently, `q` takes first value.
    def _two_param_request(method, url, **kwargs):
        values_id = _effective_values(url, "id")
        if len(values_id) > 1:
            # Duplicated id yields extra result rows: a genuinely longer page.
            return Resp(200, f"results for {','.join(values_id)}\n{PAD_A}\n" + "extra-result-row\n" * 20)
        return Resp(200, f"results for {values_id[0]}\n{PAD_A}")

    scanner = WebScanner("http://t/", mode="passive", threads=1)
    scanner.pages = {"http://t/page?id=1&q=hello": None}
    scanner._request = _two_param_request
    module = LogicVulnerabilityModule(scanner)
    module.run()
    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0].parameter == "id"


def test_no_query_params_no_findings():
    scanner, _ = _run("concat", pages={"http://t/page": None})
    assert _findings(scanner) == []


def test_failed_probes_do_not_crash_or_flag():
    scanner, _ = _run("none")
    assert _findings(scanner) == []
