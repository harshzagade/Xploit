"""Open-redirect payload coverage: the bypass family.

The standard payload catches naive implementations; each bypass form catches
a validator that strips or compares only one representation of the
destination. Tests simulate a server per variant-behavior (never a real
target) and verify detection, attribution, and the one-finding-per-parameter
rule.
"""
from urllib.parse import parse_qsl, urlparse

from xploit.modules.logic_vulnerabilities import (
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAMS,
    LogicVulnerabilityModule,
    _redirect_netloc,
)
from xploit.scanner import WebScanner

MARKER = "https://example.com/xploit-redirect"


class Resp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def _payload_of(url: str) -> str:
    """The decoded `next` value the scanner actually sent."""
    pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    return dict(pairs).get("next", "")


def _make_scanner(behaviors: dict[str, str]):
    """Fake scanner whose _request answers per the decoded payload value.

    behaviors maps decoded payload -> Location header to 302 with;
    payloads absent from the map get a plain 200.
    """
    scanner = WebScanner("http://t/", mode="passive", threads=1)
    scanner.pages = {"http://t/page?next=home": None}
    requested = []

    def fake_request(method, url, **kwargs):
        requested.append(url)
        payload = _payload_of(url)
        if payload in behaviors:
            return Resp(302, {"Location": behaviors[payload]})
        return Resp(200)

    scanner._request = fake_request
    scanner.requested = requested
    return scanner


def _run(behaviors):
    scanner = _make_scanner(behaviors)
    module = LogicVulnerabilityModule(scanner)
    module.run()
    return scanner, module


def _findings(scanner):
    return [f for f in scanner.findings if f.id == "REDIR-001"]


# --- detection per bypass form ------------------------------------------------

def test_standard_payload_fires():
    scanner, _ = _run({MARKER: MARKER})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert findings[0].parameter == "next"
    assert "(payload form: standard)" in findings[0].evidence


def test_protocol_relative_fires_when_standard_does_not():
    # Server validates the literal scheme: standard gets 200, the
    # schema-less form slips through. Old single-payload code missed this.
    scanner, _ = _run({"//example.com/xploit-redirect": "//example.com/xploit-redirect"})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert "(payload form: protocol-relative)" in findings[0].evidence


def test_backslash_location_fires():
    # Stack echoes the payload verbatim; normalization catches it.
    payload = "\\/\\/example.com/xploit-redirect"
    scanner, _ = _run({payload: payload})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert "(payload form: backslash)" in findings[0].evidence


def test_backslash_normalized_location_fires():
    # Stack (or browser) normalizes \ to / before redirecting.
    payload = "\\/\\/example.com/xploit-redirect"
    scanner, _ = _run({payload: "//example.com/xploit-redirect"})
    assert len(_findings(scanner)) == 1


def test_encoded_scheme_fires_when_decoded():
    payload = "https%3A%2F%2Fexample.com/xploit-redirect"
    scanner, _ = _run({payload: MARKER})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert "(payload form: encoded-scheme)" in findings[0].evidence


def test_double_encoded_fires_when_decoded_twice():
    payload = "https%253A%252F%252Fexample.com/xploit-redirect"
    scanner, _ = _run({payload: MARKER})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert "(payload form: double-encoded)" in findings[0].evidence


def test_null_byte_fires_when_truncated():
    payload = "%00https://example.com/xploit-redirect"
    scanner, _ = _run({payload: MARKER})
    findings = _findings(scanner)
    assert len(findings) == 1
    assert "(payload form: null-byte)" in findings[0].evidence


# --- no false positives ---------------------------------------------------------

def test_relative_redirect_does_not_fire():
    scanner, _ = _run({MARKER: "/local/path"})
    assert _findings(scanner) == []


def test_other_host_does_not_fire():
    scanner, _ = _run({MARKER: "https://evil.example.net/phish"})
    assert _findings(scanner) == []


def test_sibling_domain_does_not_fire():
    # example.com.evil.com must not match the example.com marker.
    scanner, _ = _run({MARKER: "https://example.com.evil.com/x"})
    assert _findings(scanner) == []


def test_non_redirect_param_ignored():
    scanner = WebScanner("http://t/", mode="passive", threads=1)
    scanner.pages = {"http://t/page?q=1": None}
    scanner._request = lambda method, url, **kw: Resp(
        302, {"Location": MARKER})
    LogicVulnerabilityModule(scanner).run()
    assert _findings(scanner) == []


# --- one finding per parameter --------------------------------------------------

def test_one_finding_per_parameter_across_variants():
    behaviors = {
        "https://example.com/xploit-redirect": MARKER,
        "//example.com/xploit-redirect": "//example.com/xploit-redirect",
        "\\/\\/example.com/xploit-redirect": "//example.com/xploit-redirect",
    }
    scanner, _ = _run(behaviors)
    findings = _findings(scanner)
    assert len(findings) == 1
    # First successful form wins and is named in the evidence.
    assert "(payload form: standard)" in findings[0].evidence


# --- payload integrity through the query mutation -------------------------------

def test_payloads_sent_verbatim_not_double_encoded():
    # mutate_query/urlencode must not corrupt the bypass forms: after the
    # server's single query-decode, the value must equal the payload string.
    scanner = _make_scanner({})
    LogicVulnerabilityModule(scanner).run()
    sent = {_payload_of(url) for url in scanner.requested}
    for _form, payload in OPEN_REDIRECT_PAYLOADS:
        assert payload in sent, f"payload {payload!r} not sent intact"


def test_all_six_forms_probed():
    scanner = _make_scanner({})
    LogicVulnerabilityModule(scanner).run()
    assert len(scanner.requested) == len(OPEN_REDIRECT_PAYLOADS)


# --- _redirect_netloc -------------------------------------------------------------

def test_redirect_netloc_standard():
    assert _redirect_netloc("https://example.com/x") == "example.com"


def test_redirect_netloc_protocol_relative():
    assert _redirect_netloc("//example.com/x") == "example.com"


def test_redirect_netloc_backslash():
    assert _redirect_netloc("\\/\\/example.com/x") == "example.com"


def test_redirect_netloc_relative_is_empty():
    assert _redirect_netloc("/local/path") == ""


def test_redirect_netloc_unparsable_is_empty():
    assert _redirect_netloc("http://[::1") == ""


# --- registry sanity --------------------------------------------------------------

def test_redirect_params_unchanged():
    assert REDIRECT_PARAMS == {"next", "url", "redirect", "return", "dest"}


def test_payload_family_has_expected_forms():
    forms = [form for form, _ in OPEN_REDIRECT_PAYLOADS]
    assert forms == ["standard", "protocol-relative", "backslash",
                     "encoded-scheme", "double-encoded", "null-byte"]
