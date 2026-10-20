from __future__ import annotations
import re
from urllib.parse import urlparse
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

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

    def _check_csrf(self):
        for form in self.scanner.forms:
            if form.method == "POST":
                # Check if it looks like a state-changing form (has more than just a search field)
                if len(form.inputs) <= 1 and any("search" in n.lower() for n in form.inputs):
                    continue

                if not _has_csrf_token(form.inputs):
                    self.add_finding(Finding(
                        id="CSRF-001", name="State-Changing POST Form Missing Anti-CSRF Token",
                        category="Cross-Site Request Forgery (CSRF)", severity="MEDIUM", confidence="Medium",
                        url=form.action, method="POST",
                        evidence="POST form lacks common CSRF token names in its input fields.",
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
