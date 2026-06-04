from __future__ import annotations
from urllib.parse import urlparse, urlunparse
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

class LogicVulnerabilityModule(BaseModule):
    name = "Business Logic Vulnerabilities"
    category = "Logic"

    def run(self):
        self._check_csrf()
        self._check_open_redirect()

    def _check_csrf(self):
        # Expanded list of common CSRF token names and prefixes
        TOKEN_NAMES = (
            "csrf", "xsrf", "token", "authenticity", "_sync", 
            "__requestverificationtoken", "crumb", "sid"
        )
        for form in self.scanner.forms:
            if form.method == "POST":
                # Check if it looks like a state-changing form (has more than just a search field)
                if len(form.inputs) <= 1 and any("search" in n.lower() for n in form.inputs):
                    continue

                has_token = any(any(t in name.lower() for t in TOKEN_NAMES) for name in form.inputs)
                if not has_token:
                    self.add_finding(Finding(
                        id="CSRF-001", name="State-Changing POST Form Missing Anti-CSRF Token",
                        category="Cross-Site Request Forgery (CSRF)", severity="MEDIUM", confidence="Medium",
                        url=form.action, method="POST",
                        evidence="POST form lacks common CSRF token names in its input fields.",
                        impact="If the application relies solely on cookies for authentication and lacks other CSRF defenses (like custom headers), attackers may be able to perform actions on behalf of the user.",
                        remediation="Implement unique, per-session CSRF tokens for all state-changing requests.", cwe="CWE-352"
                    ))

    def _check_open_redirect(self):
        REDIRECT_PARAMS = {"next", "url", "redirect", "return", "dest"}
        payload = "https://example.com/xploit-redirect"
        for url in self.scanner.pages:
            from ..scanner import query_parameters
            for param in query_parameters(url):
                if param.lower() in REDIRECT_PARAMS:
                    test_url = mutate_query(url, param, payload)
                    res = self.scanner._request("GET", test_url, allow_redirects=False)
                    if res and res.status_code in (301, 302, 303, 307, 308):
                        if res.headers.get("Location", "").startswith(payload):
                            self.add_finding(Finding(
                                id="REDIR-001", name="Open Redirect",
                                category="Open Redirect", severity=HIGH, confidence="High",
                                url=test_url, parameter=param,
                                evidence=f"Redirects to external {payload}",
                                impact="The application accepts an external redirect destination, which enables phishing, redirect-chain abuse, and possible token forwarding to attacker-controlled sites.",
                                remediation="Use relative redirects.", cwe="CWE-601"
                            ))
