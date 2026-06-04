from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW, INFO, PASSIVE

class GeneralModule(BaseModule):
    name = "General Security"
    category = "General"

    def run(self):
        self._check_headers()
        self._check_auth_issues()
        self._check_file_upload()
        self._check_clickjacking()
        if self.scanner.mode != PASSIVE:
            self._check_misconfig()
            self._check_cors()

    def _check_headers(self):
        res = self.scanner.pages.get(self.scanner.root)
        if not res: return
        headers = {k.lower(): v for k, v in res.headers.items()}
        checks = {
            "content-security-policy": ("Missing Content-Security-Policy", MEDIUM, "CWE-693"),
            "x-frame-options": ("Missing X-Frame-Options", LOW, "CWE-1021"),
            "x-content-type-options": ("Missing X-Content-Type-Options", INFO, "CWE-16"),
        }
        if res.url.startswith("https://"):
            checks["strict-transport-security"] = ("Missing Strict-Transport-Security", LOW, "CWE-319")
        for h, (name, sev, cwe) in checks.items():
            if h not in headers:
                impact = f"Browsers receive no server-defined content policy on this response, which weakens mitigation against injected scripts and untrusted resource loading." if h == "content-security-policy" else "Reduced client-side security."
                self.add_finding(Finding(
                    id="HDR-001", name=name, category="Insecure HTTP Headers",
                    severity=sev, confidence="High", url=res.url, evidence=f"Missing {h} header",
                    impact=impact, remediation=f"Set {h} header.", cwe=cwe
                ))
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = headers.get(header)
            if value:
                self.add_finding(Finding(
                    id="INFO-002",
                    name="Technology Header Disclosure",
                    category="Information Disclosure",
                    severity=LOW,
                    confidence="High",
                    url=res.url,
                    evidence=f"{header}: {value}",
                    impact="Version or framework banners help attackers fingerprint the stack and prioritize targeted checks.",
                    remediation="Suppress unnecessary technology/version headers at the application or reverse proxy.",
                    cwe="CWE-200"
                ))

    def _check_auth_issues(self):
        for form in self.scanner.forms:
            from urllib.parse import urlparse
            if any(t == "password" for t in form.input_types.values()):
                if urlparse(form.action).scheme == "http":
                    self.add_finding(Finding(
                        id="AUTH-001", name="Authentication Form Submitted Over HTTP",
                        category="Broken Authentication", severity=HIGH, confidence="High",
                        url=form.action, evidence="Password submitted over unencrypted HTTP.",
                        impact="Credentials submitted through this form can be observed or modified by a network attacker before they reach the server.", 
                        remediation="Use HTTPS.", cwe="CWE-319"
                    ))

    def _check_file_upload(self):
        for form in self.scanner.forms:
            if any(t == "file" for t in form.input_types.values()):
                self.add_finding(Finding(
                    id="FILE-001", name="File Upload Surface Detected",
                    category="File Upload Surface", severity=INFO, confidence="High",
                    url=form.action, evidence="Form contains a file upload field.",
                    impact="File upload functionality expands the attack surface and deserves direct review for type, size, and storage controls.",
                    remediation="Validate file types.", cwe="CWE-434"
                ))

    def _check_clickjacking(self):
        res = self.scanner.pages.get(self.scanner.root)
        if not res: return
        if "x-frame-options" not in res.headers and "frame-ancestors" not in res.headers.get("content-security-policy", "").lower():
            self.add_finding(Finding(
                id="CLK-001", name="Clickjacking Exposure",
                category="Clickjacking", severity=MEDIUM, confidence="High",
                url=res.url, evidence="No anti-framing headers found.",
                impact="This response can likely be framed by another origin unless other controls exist, which increases clickjacking exposure.", 
                remediation="Set X-Frame-Options.", cwe="CWE-1021"
            ))

    def _check_misconfig(self):
        res = self.scanner._request("OPTIONS", self.scanner.root)
        if res and "allow" in res.headers:
            allow = res.headers["allow"].upper()
            if any(m in allow for m in ("PUT", "DELETE", "TRACE")):
                self.add_finding(Finding(
                    id="MISCFG-001", name="Risky HTTP Methods Enabled",
                    category="Security Misconfiguration", severity=MEDIUM, confidence="High",
                    url=self.scanner.root, evidence=f"Enabled methods: {allow}",
                    impact="Writable or reflective HTTP methods appear enabled and usable, which increases exposure to unauthorized content changes or request-based abuse.", 
                    remediation="Disable risky methods.", cwe="CWE-16"
                ))

    def _check_cors(self):
        origin = "https://evil.example"
        for url in self.scanner.pages:
            res = self.scanner._request("GET", url, headers={"Origin": origin})
            if not res: continue
            acao = res.headers.get("Access-Control-Allow-Origin")
            if acao == "*" or acao == origin:
                self.add_finding(Finding(
                    id="CORS-001", name="Permissive CORS Policy",
                    category="CORS Misconfiguration", severity=MEDIUM, confidence="High",
                    url=url, evidence=f"ACAO header is {acao}",
                    impact="Any origin can read cross-origin responses when the browser accepts the policy, which broadens data exposure.", 
                    remediation="Restrict Origin allowlist.", cwe="CWE-942"
                ))
                break
