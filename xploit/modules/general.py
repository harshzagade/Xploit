from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlparse

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
    try:
        path = urlparse(url).path
        segment = path.rsplit("/", 1)[-1]
        ext = f".{segment.rsplit('.', 1)[-1].lower()}" if "." in segment else ""
        return ext in _BINARY_EXTS_FALLBACK
    except (ValueError, AttributeError):
        return False


# --- <script> tag parsing (SRI + CSP-nonce checks) ---------------------------
# Deliberately regex-based instead of BeautifulSoup: the SRI/CSP checks run
# over already-crawled page bodies, and a small parser keeps this module free
# of the bs4 import (the test environment stubs bs4). Attribute order and
# quoting (double, single, unquoted) are handled; a tag inside an HTML
# comment or a JS string literal is still matched, which can only add a
# false positive when the "script" text is not a real element.
_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL
)
_SCRIPT_ATTR_RE = re.compile(
    r"""([A-Za-z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)


def _parse_script_tags(html: str) -> list[dict[str, str | None]]:
    """Parse <script> elements into {src, integrity, nonce, body} dicts.

    ``src``/``integrity``/``nonce`` are None when the attribute is absent;
    ``body`` is the raw text between the tags ("" for external scripts).
    Attribute names are lowercased; an empty ``integrity=""`` stays "" so
    callers can treat it as missing.
    """
    tags: list[dict[str, str | None]] = []
    for match in _SCRIPT_TAG_RE.finditer(html or ""):
        attrs: dict[str, str] = {}
        for attr_match in _SCRIPT_ATTR_RE.finditer(match.group(1)):
            name = attr_match.group(1).lower()
            value = next(
                (g for g in attr_match.groups()[1:] if g is not None), ""
            )
            attrs.setdefault(name, value)
        tags.append({
            "src": attrs.get("src"),
            "integrity": attrs.get("integrity"),
            "nonce": attrs.get("nonce"),
            "body": match.group(2),
        })
    return tags


def _is_same_site(script_host: str, page_host: str) -> bool:
    """True when the script host is the page host or one of its subdomains."""
    script_host = script_host.lower()
    page_host = page_host.lower()
    return script_host == page_host or script_host.endswith("." + page_host)


class GeneralModule(BaseModule):
    name = "General Security"
    category = "General"

    def run(self):
        self._check_headers()
        self._check_sri()
        self._check_csp_nonce()
        self._check_session_cookies()
        self._check_auth_issues()
        self._check_file_upload()
        self._check_clickjacking()
        if self.scanner.mode != PASSIVE:
            self._check_misconfig()
            self._check_trace_method()
            self._check_cors()

    def _check_headers(self):
        res = self.scanner.pages.get(self.scanner.root)
        if res is None: return
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

    def _check_sri(self):
        # Subresource Integrity: an external <script src> without an
        # integrity attribute lets a compromised third-party host inject
        # arbitrary code into every page that loads it. Passive check — it
        # only reads HTML the crawler already fetched, so it runs in every
        # mode. Only HTTPS scripts are flagged: an HTTP script is already
        # trivially tamperable in transit, and SRI is the HTTPS story.
        # Same-host and subdomain scripts are skipped (first-party code is
        # the site's own trust boundary, same rule as JsRecon's SRI check).
        # Findings collapse to one SRI-001 per (page host, script host) so
        # a page loading ten CDN scripts is one report row, not ten.
        grouped: dict[tuple[str, str], tuple[str, set[str]]] = {}
        for page_url, page_res in self.scanner.pages.items():
            if page_res is None:
                continue
            content_type = (page_res.headers.get("Content-Type") or "").lower()
            if content_type and "text/html" not in content_type:
                continue
            html = getattr(page_res, "text", "") or ""
            if not html:
                continue
            page_host = urlparse(page_url).netloc.lower()
            for tag in _parse_script_tags(html):
                src = tag["src"]
                if not src:
                    continue
                abs_url = urljoin(page_url, src)
                parsed = urlparse(abs_url)
                if parsed.scheme != "https":
                    continue
                script_host = parsed.netloc.lower()
                if not script_host or _is_same_site(script_host, page_host):
                    continue
                if (tag["integrity"] or "").strip():
                    continue
                key = (page_host, script_host)
                if key in grouped:
                    grouped[key][1].add(abs_url)
                else:
                    grouped[key] = (page_url, {abs_url})
        for (page_host, script_host), (first_url, scripts) in sorted(grouped.items()):
            scripts_sorted = sorted(scripts)
            sample = scripts_sorted[:5]
            suffix = "…" if len(scripts_sorted) > 5 else ""
            self.add_finding(Finding(
                id="SRI-001",
                name="External Script Without Subresource Integrity",
                category="Subresource Integrity",
                severity=MEDIUM,
                confidence="High",
                url=first_url,
                evidence=(
                    f"{len(scripts_sorted)} external script(s) from {script_host} "
                    "loaded without an integrity attribute: "
                    + ", ".join(sample) + suffix
                ),
                impact="A compromise of the third-party host lets an attacker inject arbitrary JavaScript into this site, running in the page's origin with full access to its DOM and session.",
                remediation="Add an integrity=\"sha384-…\" attribute (plus crossorigin=\"anonymous\") to each external <script> tag, generated from the file you audited.",
                cwe="CWE-829",
                # parameter carries the script host: the scanner-wide dedupe
                # key is (id, url, parameter), and two script hosts seen on
                # the same page would otherwise collapse into one finding.
                parameter=script_host
            ))

    def _check_csp_nonce(self):
        # CSP nonce enforcement: when a page sets Content-Security-Policy
        # but its effective script-src still lets inline scripts run without
        # a nonce, an attacker who can inject markup gets script execution
        # the policy was supposed to prevent. Passive check — it only reads
        # headers + HTML the crawler already fetched, so it runs in every
        # mode. A page is flagged only when it actually contains a
        # non-empty inline <script> (a permissive policy with no inline
        # scripts is not an exposure). The effective directive is
        # script-src, falling back to default-src; a policy with neither
        # does not restrict scripts at all. 'unsafe-inline' counts only
        # when no nonce-/sha256-/sha384-/sha512- token is present, because
        # browsers ignore 'unsafe-inline' once a nonce or hash is in play
        # (same for a nonce-gated policy: matching inline scripts are
        # legitimate, the rest are blocked, so there is nothing to flag).
        # Only script-src/default-src are evaluated — script-src-elem and
        # script-src-attr are out of scope. Findings collapse to one
        # CSP-001 per host; pages without a CSP header are already covered
        # by the HDR-CSP missing-policy finding.
        grouped: dict[str, tuple[str, int, list[str], str]] = {}
        for page_url, page_res in self.scanner.pages.items():
            if page_res is None:
                continue
            headers = {k.lower(): v for k, v in page_res.headers.items()}
            csp = headers.get("content-security-policy")
            if not csp:
                continue
            content_type = (headers.get("content-type") or "").lower()
            if content_type and "text/html" not in content_type:
                continue
            html = getattr(page_res, "text", "") or ""
            if not html:
                continue
            inline = [
                tag for tag in _parse_script_tags(html)
                if tag["src"] is None and (tag["body"] or "").strip()
            ]
            if not inline:
                continue
            directives: dict[str, list[str]] = {}
            for part in csp.split(";"):
                tokens = part.split()
                if not tokens:
                    continue
                directives[tokens[0].lower()] = [
                    tok.strip("'\"") for tok in tokens[1:]
                ]
            effective = directives.get("script-src", directives.get("default-src"))
            if effective is None:
                reason = "CSP sets no script-src or default-src, so inline scripts are unrestricted"
            elif "unsafe-inline" in effective and not any(
                tok.startswith(("nonce-", "sha256-", "sha384-", "sha512-"))
                for tok in effective
            ):
                reason = "script-src allows 'unsafe-inline' without a nonce"
            else:
                continue
            host = urlparse(page_url).netloc.lower()
            if host in grouped:
                first_url, count, paths, _ = grouped[host]
                grouped[host] = (first_url, count + 1, paths, reason)
            else:
                grouped[host] = (page_url, 1, [], reason)
            if len(grouped[host][2]) < 5:
                grouped[host][2].append(urlparse(page_url).path)
        for host, (first_url, count, paths, reason) in sorted(grouped.items()):
            sample = sorted(set(paths))[:5]
            suffix = "…" if len(set(paths)) > 5 else ""
            self.add_finding(Finding(
                id="CSP-001",
                name="Inline Scripts Allowed Without Nonce",
                category="Content Security Policy",
                severity=MEDIUM,
                confidence="High",
                url=first_url,
                evidence=(
                    f"{reason} — {count} page(s) with inline scripts on {host}: "
                    + ", ".join(sample) + suffix
                ),
                impact="Inline scripts run without a nonce, so markup injection on these pages can execute attacker JavaScript despite the Content-Security-Policy.",
                remediation="Remove 'unsafe-inline' from script-src and give each legitimate inline script a per-response nonce (script-src 'nonce-<random>'), or move inline code into external files.",
                cwe="CWE-693"
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
        if res is None: return
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

    def _check_trace_method(self):
        # HTTP TRACE echo test (TRACE-001): _check_misconfig() already flags
        # a server that merely ADVERTISES TRACE in its OPTIONS Allow header
        # (MISCFG-001). This check proves the method is actually live — it
        # sends a real TRACE request to a unique path and looks for the
        # request line echoed back in the response body (RFC 9110: a TRACE
        # response carries the request message as received). The echo must
        # contain the method name adjacent to the probe path, so a page
        # that merely reflects the requested URL (e.g. a 404/debug page)
        # cannot false-positive. The probe path token is the proof marker,
        # so a later --retest replay (TRACE to the same URL, no custom
        # headers) reproduces it exactly.
        token = "xploit-trace-" + secrets.token_hex(8)
        probe_url = urljoin(self.scanner.root, token)
        res = self.scanner._request("TRACE", probe_url, quiet=True)
        if res is None:
            return
        if not 200 <= getattr(res, "status_code", 0) < 300:
            return
        body = getattr(res, "text", "") or ""
        if not re.search(r"TRACE\s+\S*" + re.escape(token), body, re.IGNORECASE):
            return
        finding = Finding(
            id="TRACE-001",
            name="HTTP TRACE Method Enabled (Cross-Site Tracing)",
            category="Security Misconfiguration",
            severity=MEDIUM,
            confidence="High",
            url=probe_url,
            evidence=(
                f"TRACE {probe_url} returned HTTP {res.status_code} and "
                "echoed the request line back in the response body"
            ),
            impact="An enabled TRACE method lets an attacker read request headers — including cookies and Authorization headers — via cross-site tracing (XST) when combined with a script-injection flaw.",
            remediation="Disable the TRACE method at the web server (e.g. TraceEnable Off in Apache, or block TRACE at the reverse proxy) and confirm the method returns 405.",
            cwe="CWE-693",
        )
        self.attach_proof(finding, method="TRACE", url=probe_url, marker=token)
        self.add_finding(finding)

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
        if res is None:
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
