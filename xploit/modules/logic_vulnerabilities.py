from __future__ import annotations
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, mutate_query

# Whole-token matches for CSRF token field names. Matched against tokenized
# field names so 'residue' (contains 'sid') doesn't count as CSRF-protected.
_CSRF_TOKEN_WORDS = {'csrf', 'xsrf', 'token', 'sid', 'nonce', 'crumb', 'authenticity'}

# Open-redirect probe family: (form name, payload). The standard form
# catches naive implementations; each bypass form catches a validator that
# strips or compares only one representation of the destination:
#   protocol-relative — no scheme at all (//host/...)
#   backslash        — \\/\\/host/... (stacks/browsers normalize \ to /)
#   encoded-scheme   — scheme percent-encoded once (naive string-prefix checks)
#   double-encoded   — encoded twice (validators that decode exactly once)
#   null-byte        — %00 prefix (old truncation-style filters)
# example.com is a reserved documentation domain, safe as a canary host.
OPEN_REDIRECT_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("standard", "https://example.com/xploit-redirect"),
    ("protocol-relative", "//example.com/xploit-redirect"),
    ("backslash", "\\/\\/example.com/xploit-redirect"),
    ("encoded-scheme", "https%3A%2F%2Fexample.com/xploit-redirect"),
    ("double-encoded", "https%253A%252F%252Fexample.com/xploit-redirect"),
    ("null-byte", "%00https://example.com/xploit-redirect"),
)

# Query parameters that commonly carry a redirect destination.
REDIRECT_PARAMS = {"next", "url", "redirect", "return", "dest"}

# HTTP parameter pollution (HPP) probe: the distinct second value sent as a
# duplicate occurrence of the parameter. Three responses are compared:
#   baseline — the crawled URL as-is (param = original value)
#   single   — the same URL with the param replaced by HPP_SECOND_VALUE
#   polluted — the URL with the param sent twice (original + HPP_SECOND_VALUE)
# A server that deterministically takes the first or the last occurrence
# answers the polluted request like one of the two single-value requests.
# A polluted answer that diverges from BOTH means the duplicate changed how
# the parameter is handled (concatenation, array coercion, error, ...) —
# exactly the divergence a WAF/app parser mismatch can turn into a bypass.
HPP_SECOND_VALUE = "xploit_hpp_2nd"

# Divergence threshold, mirroring the param-hint pre-pass in scanner.py:
# a length delta counts only above max(64 bytes, 5% of the baseline), so a
# page that merely echoes the query string back (the duplicate adds ~20
# bytes to the URL) cannot false-positive on reflection alone.
HPP_MIN_DELTA_BYTES = 64
HPP_MIN_DELTA_FRACTION = 0.05


def duplicate_query_param(url: str, param: str, value: str) -> str:
    """Append a second occurrence of ``param`` with ``value`` to the URL.

    Unlike ``mutate_query`` (which replaces), this keeps the original pair
    and appends ``(param, value)`` at the end, producing the classic
    ``?id=1&id=2`` duplicate-parameter probe.
    """
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _hpp_response_differs(a, b) -> bool:
    """True when response ``b`` diverges meaningfully from response ``a``.

    Status-code change always counts; otherwise the body-length delta must
    clear the same floor the param-hint pre-pass uses (max 64 bytes / 5%),
    so trivial reflection noise stays below the bar.
    """
    if a is None or b is None:
        return False
    if a.status_code != b.status_code:
        return True
    # getattr: test fakes sometimes carry no .text; a missing body is empty.
    base_len = len(getattr(a, "text", None) or "")
    delta = abs(len(getattr(b, "text", None) or "") - base_len)
    return delta > max(HPP_MIN_DELTA_BYTES, HPP_MIN_DELTA_FRACTION * base_len)


def _redirect_netloc(location: str) -> str:
    """Effective destination host of a Location header value.

    Backslashes are normalized to slashes first: some stacks emit the
    payload verbatim (\\/\\/example.com/...) and urlparse sees no netloc
    in that raw form, while browsers/stacks treat backslash as a path
    separator. Normalization turns \\/\\/host into ////host, so a run of
    3+ slashes is collapsed back to the protocol-relative form //host
    before parsing. Returns "" for relative redirects and unparsable
    values.
    """
    try:
        text = location.replace("\\", "/")
        text = re.sub(r"/{3,}", "//", text)
        return urlparse(text).netloc.lower()
    except ValueError:
        return ""

def _has_csrf_token(field_names) -> bool:
    for name in field_names:
        spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', name)
        tokens = {t.lower() for t in re.split(r'[_\-\s]+', spaced) if t}
        if tokens & _CSRF_TOKEN_WORDS:
            return True
        # Known suffix forms like __requestverificationtoken
        if name.lower().endswith('token'):
            return True
    return False

class LogicVulnerabilityModule(BaseModule):
    name = "Business Logic Vulnerabilities"
    category = "Logic"

    def run(self):
        self._check_csrf()
        self._check_open_redirect()
        self._check_parameter_pollution()

    # GET forms are read-only by convention and a lone search field is not
    # state-changing, so neither is flagged; every other method can mutate
    # server state, and a missing token on any of them is the same hole
    # the POST-only check used to miss on PUT/PATCH/DELETE forms.
    _STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

    def _check_csrf(self):
        for form in self.scanner.forms:
            if form.method not in self._STATE_CHANGING_METHODS:
                continue
            # Check if it looks like a state-changing form (has more than just a search field)
            if len(form.inputs) <= 1 and any("search" in n.lower() for n in form.inputs):
                continue

            if not _has_csrf_token(form.inputs):
                self.add_finding(Finding(
                    id="CSRF-001", name="State-Changing Form Missing Anti-CSRF Token",
                    category="Cross-Site Request Forgery (CSRF)", severity="MEDIUM", confidence="Medium",
                    url=form.action, method=form.method,
                    evidence=f"{form.method} form lacks common CSRF token names in its input fields.",
                    impact="If the application relies solely on cookies for authentication and lacks other CSRF defenses (like custom headers), attackers may be able to perform actions on behalf of the user.",
                    remediation="Implement unique, per-session CSRF tokens for all state-changing requests.", cwe="CWE-352"
                ))

    def _check_open_redirect(self):
        payload_netloc = urlparse(OPEN_REDIRECT_PAYLOADS[0][1]).netloc.lower()
        self._redirect_payload_netloc = payload_netloc
        self.scanner.map_probes(self._check_open_redirect_url, list(self.scanner.pages))

    def _check_open_redirect_url(self, url):
        from ..scanner import query_parameters
        payload_netloc = self._redirect_payload_netloc
        for param in query_parameters(url):
            if param.lower() not in REDIRECT_PARAMS:
                continue
            for form, payload in OPEN_REDIRECT_PAYLOADS:
                test_url = mutate_query(url, param, payload)
                res = self.scanner._request("GET", test_url, allow_redirects=False)
                if not (res and res.status_code in (301, 302, 303, 307, 308)):
                    continue
                location = res.headers.get("Location", "")
                # Compare parsed netlocs instead of startswith: catches
                # protocol-relative and backslash destinations (//example.com/...
                # and \\/\\/example.com/...) too, and won't fire on
                # relative-path redirects.
                if _redirect_netloc(location) and _redirect_netloc(location) == payload_netloc:
                    self.add_finding(Finding(
                        id="REDIR-001", name="Open Redirect",
                        category="Open Redirect", severity=HIGH, confidence="High",
                        url=test_url, parameter=param,
                        evidence=f"Redirects to external {location} (payload form: {form})",
                        impact="The application accepts an external redirect destination, which enables phishing, redirect-chain abuse, and possible token forwarding to attacker-controlled sites.",
                        remediation="Use relative redirects.", cwe="CWE-601"
                    ))
                    # One finding per vulnerable parameter — the successful
                    # form is named in the evidence; probing the rest would
                    # only duplicate the same vulnerable parameter.
                    break

    def _check_parameter_pollution(self):
        self.scanner.map_probes(self._check_parameter_pollution_url,
                                list(self.scanner.pages))

    def _check_parameter_pollution_url(self, url):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            # Baseline: the crawled URL as-is.
            baseline = self.scanner._request("GET", url)
            if baseline is None:
                continue
            # Single-value control: the param replaced by the probe value.
            second_url = mutate_query(url, param, HPP_SECOND_VALUE)
            second = self.scanner._request("GET", second_url)
            if second is None:
                continue
            # Polluted: the param sent twice (original + probe value).
            polluted_url = duplicate_query_param(url, param, HPP_SECOND_VALUE)
            polluted = self.scanner._request("GET", polluted_url)
            if polluted is None:
                continue
            # Divergent handling = the duplicate answer matches NEITHER
            # single-value answer. First-wins and last-wins servers answer
            # the polluted request like the baseline or the control, so
            # they are (correctly) not flagged — only a handling that
            # neither single value explains is.
            if not (_hpp_response_differs(baseline, polluted)
                    and _hpp_response_differs(second, polluted)):
                continue
            finding = Finding(
                id="HPP-001", name="HTTP Parameter Pollution",
                category="HTTP Parameter Pollution", severity=MEDIUM,
                confidence="Medium",
                url=polluted_url, parameter=param,
                evidence=(
                    f"Duplicating '{param}' changes the response: baseline "
                    f"{baseline.status_code}/{len(getattr(baseline, 'text', None) or '')}B, "
                    f"single-value {second.status_code}/{len(getattr(second, 'text', None) or '')}B, "
                    f"duplicated {polluted.status_code}/{len(getattr(polluted, 'text', None) or '')}B — "
                    f"the duplicated answer matches neither single-value answer."
                ),
                impact="The application handles duplicated parameters differently from either single value, so a WAF that reads the first occurrence and an application that reads the last (or vice versa) can disagree about the request — the classic parameter-pollution bypass for filters and validation.",
                remediation="Reject requests with duplicate query parameters, or define and document a single deterministic rule (first or last wins) and enforce it at every layer (WAF, framework, application).",
                cwe="CWE-235",
            )
            # Behavioral confirmation (status/length delta), not a response
            # marker: the proof URL replays the polluted request, but the
            # gate records it as not machine-verifiable rather than verified.
            self.attach_proof(finding, method="GET", url=polluted_url)
            self.add_finding(finding)
