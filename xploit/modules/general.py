from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW, INFO, PASSIVE

class GeneralModule(BaseModule):
    name = "General Security"
    category = "General"

    def run(self):
        self._check_headers()
        self._check_session_cookies()
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
            "content-security-policy": ("Missing Content-Security-Policy", MEDIUM, "CWE-693", "HDR-CSP"),
            # x-frame-options is intentionally omitted here — _check_clickjacking() covers
            # framing exposure as a MEDIUM finding and avoids a duplicate LOW for the same header.
            "x-content-type-options": ("Missing X-Content-Type-Options", INFO, "CWE-16", "HDR-XCTO"),
        }
        if res.url.startswith("https://"):
            checks["strict-transport-security"] = ("Missing Strict-Transport-Security", LOW, "CWE-319", "HDR-HSTS")
        for h, (name, sev, cwe, fid) in checks.items():
            if h not in headers:
                impact = "Browsers receive no server-defined content policy on this response, which weakens mitigation against injected scripts and untrusted resource loading." if h == "content-security-policy" else "Reduced client-side security."
                self.add_finding(Finding(
                    id=fid, name=name, category="Insecure HTTP Headers",
                    severity=sev, confidence="High", url=res.url, evidence=f"Missing {h} header",
                    impact=impact, remediation=f"Set {h} header.", cwe=cwe
                ))
        tech_header_ids = {
            "server": "INFO-SVR",
            "x-powered-by": "INFO-XPB",
            "x-aspnet-version": "INFO-ASP",
        }
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = headers.get(header)
            if value:
                self.add_finding(Finding(
                    id=tech_header_ids[header],
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

    def _check_session_cookies(self):
        import re
        seen_cookie_names: set[str] = set()
        session_pattern = re.compile(r"(?i)(phpsessid|sessionid|sess|sid|jsessionid|aspsessionid|auth_token|remember_token)")

        for url, res in self.scanner.pages.items():
            # Check Set-Cookie headers on every response
            raw_cookies = res.headers.get("Set-Cookie", "")
            # requests only exposes the last Set-Cookie; use raw response headers for all
            all_set_cookie = res.raw.headers.getlist("Set-Cookie") if hasattr(res.raw, "headers") and hasattr(res.raw.headers, "getlist") else ([raw_cookies] if raw_cookies else [])

            for cookie_str in all_set_cookie:
                if not cookie_str:
                    continue
                # Extract cookie name
                name_part = cookie_str.split(";")[0]
                cookie_name = name_part.split("=")[0].strip()
                flags = cookie_str.lower()

                is_session_like = bool(session_pattern.search(cookie_name))

                # HttpOnly missing
                if "httponly" not in flags and cookie_name not in seen_cookie_names:
                    seen_cookie_names.add(cookie_name)
                    self.add_finding(Finding(
                        id="COOK-001",
                        name="Session Cookie Missing HttpOnly Flag",
                        category="Insecure Cookie Configuration",
                        severity=MEDIUM if is_session_like else LOW,
                        confidence="High",
                        url=url,
                        evidence=f"Cookie '{cookie_name}' set without HttpOnly flag.",
                        parameter=cookie_name,
                        impact="Without HttpOnly, client-side scripts can read the cookie. An XSS vulnerability on any page can exfiltrate the session token.",
                        remediation="Set the HttpOnly attribute on all session and authentication cookies.",
                        cwe="CWE-1004"
                    ))

                # Secure flag missing on HTTPS site
                if url.startswith("https://") and "secure" not in flags and f"{cookie_name}_secure" not in seen_cookie_names:
                    seen_cookie_names.add(f"{cookie_name}_secure")
                    self.add_finding(Finding(
                        id="COOK-002",
                        name="Session Cookie Missing Secure Flag",
                        category="Insecure Cookie Configuration",
                        severity=MEDIUM if is_session_like else LOW,
                        confidence="High",
                        url=url,
                        evidence=f"Cookie '{cookie_name}' set without Secure flag on HTTPS response.",
                        parameter=cookie_name,
                        impact="Without Secure, the cookie may be transmitted over plain HTTP if the user navigates to an HTTP URL, allowing interception.",
                        remediation="Set the Secure attribute on all session and authentication cookies.",
                        cwe="CWE-614"
                    ))

                # SameSite missing
                if "samesite" not in flags and f"{cookie_name}_samesite" not in seen_cookie_names:
                    seen_cookie_names.add(f"{cookie_name}_samesite")
                    self.add_finding(Finding(
                        id="COOK-003",
                        name="Session Cookie Missing SameSite Attribute",
                        category="Insecure Cookie Configuration",
                        severity=LOW,
                        confidence="High",
                        url=url,
                        evidence=f"Cookie '{cookie_name}' set without SameSite attribute.",
                        parameter=cookie_name,
                        impact="Without SameSite, the cookie is sent on cross-site requests, contributing to CSRF attack surface.",
                        remediation="Set SameSite=Lax or SameSite=Strict on all cookies.",
                        cwe="CWE-352"
                    ))


    def _check_auth_issues(self):
        import re
        _password_name = re.compile(r"(?i)^(password|passwd|pass|new[_\-]?password|confirm[_\-]?password|repeat[_\-]?password|current[_\-]?password)$")

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

            # Check for password-named fields rendered as type=text
            for name, ftype in form.input_types.items():
                if _password_name.match(name) and ftype != "password":
                    self.add_finding(Finding(
                        id="AUTH-002",
                        name="Password Field Rendered as Plaintext Input",
                        category="Broken Authentication",
                        severity=MEDIUM,
                        confidence="High",
                        url=form.page_url,
                        parameter=name,
                        evidence=f"Field '{name}' has type='{ftype}' instead of type='password'.",
                        impact="The password is visible on screen as the user types, captured in browser autocomplete history as plain text, and may be logged by browser extensions or proxies.",
                        remediation="Set type='password' on all password input fields.",
                        cwe="CWE-549"
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
