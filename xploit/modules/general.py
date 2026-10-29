from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW, INFO, PASSIVE, normalize_path

# Fallback binary-extension check used by _check_cors when the scanner does
# not expose is_binary_asset (e.g. in lightweight test stubs). Mirrors the
# BINARY_ASSET_EXTS set in scanner.py without importing it so this module
# has no hard dependency on that constant.
_BINARY_EXTS_FALLBACK = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".wav",
    ".pdf", ".zip", ".gz",
})

def _ext_is_binary(url: str) -> bool:
    """Return True if the URL path ends with a known binary-asset extension."""
    from urllib.parse import urlparse
    try:
        path = urlparse(url).path
        segment = path.rsplit("/", 1)[-1]
        ext = f".{segment.rsplit('.', 1)[-1].lower()}" if "." in segment else ""
        return ext in _BINARY_EXTS_FALLBACK
    except (ValueError, AttributeError):
        return False

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
        # Version-fingerprint headers are a property of the host, not of a
        # single URL: the same banner on fifty crawled pages used to mean
        # fifty report rows (or, when only the root page was checked, a
        # banner served only on sub-pages was missed entirely). Sweep every
        # crawled page, but collapse to one finding per (host, header,
        # value) — the first page carrying it is the finding URL, and the
        # evidence counts how many pages repeated it.
        from urllib.parse import urlparse
        grouped: dict[tuple[str, str, str], list] = {}
        for page_url, page_res in self.scanner.pages.items():
            if page_res is None:
                continue
            page_headers = {k.lower(): v for k, v in page_res.headers.items()}
            host = urlparse(page_url).netloc.lower()
            for header in ("server", "x-powered-by", "x-aspnet-version"):
                value = page_headers.get(header)
                if not value:
                    continue
                key = (host, header, value)
                if key in grouped:
                    grouped[key][1] += 1
                else:
                    grouped[key] = [page_url, 1]
        for (host, header, value), (first_url, count) in grouped.items():
            evidence = f"{header}: {value}"
            if count > 1:
                evidence += f" (seen on {count} pages on {host})"
            self.add_finding(Finding(
                id=tech_header_ids[header],
                name="Technology Header Disclosure",
                category="Information Disclosure",
                severity=LOW,
                confidence="High",
                url=first_url,
                evidence=evidence,
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
                # Check flags only in the attribute segments (after the first
                # name=value pair), so a cookie VALUE containing e.g.
                # 'secure_mode' can't fake the presence of a flag.
                attr_names = {
                    seg.strip().split("=")[0].lower()
                    for seg in cookie_str.split(";")[1:]
                    if seg.strip()
                }

                is_session_like = bool(session_pattern.search(cookie_name))

                # HttpOnly missing
                if "httponly" not in attr_names and cookie_name not in seen_cookie_names:
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
                if url.startswith("https://") and "secure" not in attr_names and f"{cookie_name}_secure" not in seen_cookie_names:
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
                if "samesite" not in attr_names and f"{cookie_name}_samesite" not in seen_cookie_names:
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
        import threading
        origin = "https://evil.example"
        # One probe per path shape — the crawler stores /item?id=1 and
        # /item?id=2 as separate pages, but CORS policy is per endpoint.
        # Binary assets (images, fonts, media) are also skipped: they carry
        # no session context worth testing for CORS misconfiguration, and
        # probing them inflates the request count for no finding value.
        # Shapes are filtered sequentially first (cheap, deterministic),
        # then the actual probes fan out concurrently.
        seen_shapes: set[str] = set()
        probe_urls: list[str] = []
        for url in self.scanner.pages:
            # Skip binary assets — use the scanner helper when available,
            # fall back to extension check only (for test stubs that don't
            # expose pages as Response objects).
            page_res = self.scanner.pages.get(url)
            _is_binary = (
                self.scanner.is_binary_asset(url, page_res)
                if callable(getattr(self.scanner, "is_binary_asset", None))
                else _ext_is_binary(url)
            )
            if _is_binary:
                continue
            shape = normalize_path(url)
            if shape in seen_shapes:
                continue
            seen_shapes.add(shape)
            probe_urls.append(url)
        self._cors_origin = origin
        # Thread-safe accumulator for (url, severity, confidence, evidence, impact) hits.
        self._cors_hits: list[tuple[str, str, str, str, str]] = []
        self._cors_hits_lock = threading.Lock()
        self.scanner.map_probes(self._check_cors_url, probe_urls)

        # --- Group hits by (host, severity) and emit one Finding per group ---
        from urllib.parse import urlparse
        groups: dict[tuple[str, str], list[tuple[str, str, str, str, str]]] = {}
        for hit in self._cors_hits:
            url, severity, confidence, evidence, impact = hit
            host = urlparse(url).netloc.lower()
            key = (host, severity)
            groups.setdefault(key, []).append(hit)

        for (host, severity), hits in sorted(groups.items()):
            # Sort hits deterministically by URL so the "first URL" is stable.
            hits_sorted = sorted(hits, key=lambda h: h[0])
            first_url, _, confidence, evidence, impact = hits_sorted[0]
            n = len(hits_sorted)
            if n > 1:
                paths = sorted({urlparse(h[0]).path for h in hits_sorted})
                sample = paths[:5]
                suffix = "…" if len(paths) > 5 else ""
                evidence = evidence + f" — observed on {n} endpoint(s): " + ", ".join(sample) + suffix
            self.add_finding(Finding(
                id="CORS-001", name="Permissive CORS Policy",
                category="CORS Misconfiguration", severity=severity, confidence=confidence,
                url=first_url, evidence=evidence, impact=impact,
                remediation="Restrict Origin allowlist.", cwe="CWE-942"
            ))

    def _check_cors_url(self, url):
        origin = self._cors_origin
        res = self.scanner._request("GET", url, headers={"Origin": origin})
        if not res:
            return
        acao = res.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return
        allow_creds = res.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        reflected = acao == origin
        if reflected and allow_creds:
            # Worst case: attacker origin whitelisted WITH credentials.
            severity, confidence = HIGH, "High"
            evidence = f"Origin {origin} reflected with Access-Control-Allow-Credentials: true"
            impact = "Any site can make credentialed cross-origin requests and read the responses, exposing session data to attackers."
        elif acao == "*":
            # Bare wildcard without credentials: readable cross-origin but
            # not with cookies — LOW, not MEDIUM.
            severity, confidence = LOW, "Medium"
            evidence = "Access-Control-Allow-Origin: *" + (" (with Allow-Credentials: true, which browsers ignore for '*')" if allow_creds else "")
            impact = "Any origin can read non-credentialed cross-origin responses, which broadens data exposure for public endpoints."
        elif reflected:
            severity, confidence = MEDIUM, "Medium"
            evidence = f"Origin {origin} reflected without Access-Control-Allow-Credentials"
            impact = "Any origin is reflected, so non-credentialed cross-origin reads are permitted from attacker sites."
        else:
            return
        with self._cors_hits_lock:
            self._cors_hits.append((url, severity, confidence, evidence, impact))
