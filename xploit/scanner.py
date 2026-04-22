from __future__ import annotations

import html
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"


@dataclass(slots=True)
class Finding:
    id: str
    name: str
    category: str
    severity: str
    confidence: str
    url: str
    evidence: str
    impact: str
    remediation: str
    trigger: str = ""
    cwe: str = ""
    parameter: str = ""
    method: str = "GET"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class FormTarget:
    page_url: str
    action: str
    method: str
    inputs: dict[str, str] = field(default_factory=dict)
    input_types: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ScanResult:
    target: str
    normalized_target: str
    started_at: str
    duration_seconds: float
    status: str
    pages_seen: list[str]
    forms_seen: int
    findings: list[Finding]
    errors: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "normalized_target": self.normalized_target,
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "pages_seen": self.pages_seen,
            "forms_seen": self.forms_seen,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "summary": summarize_findings(self.findings),
        }


SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "postgresql query failed",
    "sqlite error",
    "sqlstate",
    "ora-01756",
    "microsoft ole db provider for sql server",
)

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
)

REDIRECT_PARAMS = {
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "continue",
    "dest",
    "destination",
    "callback",
}

TOKEN_NAMES = ("csrf", "xsrf", "nonce", "authenticity", "token")
AUTH_FIELDS = {"password", "passwd", "pwd", "login", "username", "email"}


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("target URL is required")
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"http://{raw_url}"
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an HTTP or HTTPS URL")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def same_origin(url: str, root: str) -> bool:
    a = urlparse(url)
    b = urlparse(root)
    return a.scheme in {"http", "https"} and a.netloc == b.netloc


def mutate_query(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = [(key, payload if key == parameter else value) for key, value in pairs]
    return urlunparse(parsed._replace(query=urlencode(changed, doseq=True)))


def query_parameters(url: str) -> list[str]:
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())


def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


class WebScanner:
    def __init__(
        self,
        target: str,
        *,
        max_pages: int = 16,
        depth: int = 1,
        timeout: float = 6.0,
        user_agent: str = "Xploit/1.0 Authorized Security Scanner",
    ) -> None:
        self.target = target
        self.root = normalize_url(target)
        self.max_pages = max(1, max_pages)
        self.depth = max(0, depth)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "text/html,*/*;q=0.8"})
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.pages: dict[str, requests.Response] = {}
        self.forms: list[FormTarget] = []
        self._dedupe: set[tuple[str, str, str, str]] = set()

    def scan(self) -> ScanResult:
        started = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        start_time = time.monotonic()
        self._crawl()
        if not self.pages:
            return ScanResult(
                target=self.target,
                normalized_target=self.root,
                started_at=started,
                duration_seconds=round(time.monotonic() - start_time, 2),
                status="unreachable",
                pages_seen=[],
                forms_seen=0,
                findings=[],
                errors=self.errors,
            )
        self._check_security_headers()
        self._check_insecure_methods()
        self._check_query_injection("SQL Injection", "SQLI", "' OR '1'='1", self._sql_evidence)
        self._check_query_injection("Cross-Site Scripting", "XSS", 'xploit"><svg/onload=alert(1)>', self._xss_evidence)
        self._check_query_injection("Command Injection", "CMDI", ";echo XPLOIT_CMD_TEST", self._cmd_evidence)
        self._check_query_injection("Directory Traversal", "TRAV", "../../../../../../etc/passwd", self._traversal_evidence)
        self._check_forms()
        self._check_open_redirects()
        self._check_sensitive_exposure()
        self._check_broken_authentication()
        self._check_security_misconfiguration()
        return ScanResult(
            target=self.target,
            normalized_target=self.root,
            started_at=started,
            duration_seconds=round(time.monotonic() - start_time, 2),
            status="completed",
            pages_seen=list(self.pages.keys()),
            forms_seen=len(self.forms),
            findings=self.findings,
            errors=self.errors,
        )

    def _request(self, method: str, url: str, **kwargs) -> requests.Response | None:
        try:
            return self.session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", True),
                verify=True,
                **kwargs,
            )
        except requests.RequestException as exc:
            self.errors.append(f"{method} {url}: {exc}")
            return None

    def _crawl(self) -> None:
        queue: list[tuple[str, int]] = [(self.root, 0)]
        seen: set[str] = set()
        while queue and len(self.pages) < self.max_pages:
            url, depth = queue.pop(0)
            clean_url = urlunparse(urlparse(url)._replace(fragment=""))
            if clean_url in seen or not same_origin(clean_url, self.root):
                continue
            seen.add(clean_url)
            response = self._request("GET", clean_url)
            if not response:
                continue
            self.pages[clean_url] = response
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            self.forms.extend(self._extract_forms(clean_url, soup))
            if depth >= self.depth:
                continue
            for link in soup.find_all("a", href=True):
                next_url = urljoin(clean_url, link["href"])
                if same_origin(next_url, self.root):
                    queue.append((next_url, depth + 1))

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> list[FormTarget]:
        forms: list[FormTarget] = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(page_url, form.get("action") or page_url)
            inputs: dict[str, str] = {}
            input_types: dict[str, str] = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                field_type = (field.get("type") or field.name or "text").lower()
                inputs[name] = field.get("value") or "xploit"
                input_types[name] = field_type
            forms.append(FormTarget(page_url, action, method, inputs, input_types))
        return forms

    def _add(self, finding: Finding) -> None:
        key = (finding.category, finding.url, finding.parameter, finding.name)
        if key not in self._dedupe:
            self._dedupe.add(key)
            self.findings.append(finding)

    def _check_security_headers(self) -> None:
        response = self.pages.get(self.root) or self._request("GET", self.root)
        if not response:
            return
        headers = {key.lower(): value for key, value in response.headers.items()}
        required = {
            "strict-transport-security": ("Missing HSTS", "CWE-319"),
            "content-security-policy": ("Missing Content-Security-Policy", "CWE-693"),
            "x-frame-options": ("Missing X-Frame-Options", "CWE-1021"),
            "x-content-type-options": ("Missing X-Content-Type-Options", "CWE-16"),
            "referrer-policy": ("Missing Referrer-Policy", "CWE-200"),
            "permissions-policy": ("Missing Permissions-Policy", "CWE-693"),
        }
        for header, (name, cwe) in required.items():
            if header not in headers:
                self._add(Finding(
                    id="HDR-001",
                    name=name,
                    category="Insecure HTTP Headers",
                    severity=MEDIUM if header != "content-security-policy" else HIGH,
                    confidence="High",
                    url=response.url,
                    evidence=f"Response does not include `{header}`.",
                    trigger=f"missing_header={header}",
                    impact="Missing browser security controls can increase exposure to clickjacking, MIME sniffing, data leakage, or downgrade attacks.",
                    remediation=f"Set a strict `{header}` header at the application or reverse-proxy layer.",
                    cwe=cwe,
                ))
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        if server or powered_by:
            self._add(Finding(
                id="HDR-002",
                name="Technology Disclosure",
                category="Insecure HTTP Headers",
                severity=LOW,
                confidence="High",
                url=response.url,
                evidence=f"Server={server or 'not set'}; X-Powered-By={powered_by or 'not set'}",
                trigger=f"header_disclosure=Server:{server or 'not set'}|X-Powered-By:{powered_by or 'not set'}",
                impact="Exposed platform details can help attackers select targeted exploits.",
                remediation="Suppress verbose framework and server banners.",
                cwe="CWE-200",
            ))

    def _check_query_injection(self, name: str, short: str, payload: str, evidence_fn) -> None:
        for url in list(self.pages):
            for parameter in query_parameters(url):
                test_url = mutate_query(url, parameter, payload)
                response = self._request("GET", test_url)
                evidence = evidence_fn(response, payload) if response else ""
                if evidence:
                    self._add(Finding(
                        id=f"{short}-001",
                        name=name,
                        category=name,
                        severity=HIGH,
                        confidence="Medium",
                        url=test_url,
                        parameter=parameter,
                        evidence=evidence,
                        trigger=f"payload={payload}",
                        impact=self._impact_for(name),
                        remediation=self._remediation_for(name),
                        cwe=self._cwe_for(name),
                    ))

    def _check_forms(self) -> None:
        for form in self.forms:
            names = {name.lower() for name in form.inputs}
            has_token = any(any(token in name for token in TOKEN_NAMES) for name in names)
            if form.method == "POST" and not has_token:
                self._add(Finding(
                    id="CSRF-001",
                    name="POST Form Missing Anti-CSRF Token",
                    category="Cross-Site Request Forgery (CSRF)",
                    severity=HIGH,
                    confidence="Medium",
                    url=form.action,
                    method=form.method,
                    evidence=f"POST form discovered on {form.page_url} without token-like fields.",
                    trigger="missing_csrf_token=true",
                    impact="Attackers may be able to force authenticated users to submit state-changing requests.",
                    remediation="Require unpredictable per-request CSRF tokens and validate Origin/Referer for state-changing requests.",
                    cwe="CWE-352",
                ))
            self._test_form_payload(form, "SQL Injection", "SQLI", "' OR '1'='1", self._sql_evidence)
            self._test_form_payload(form, "Cross-Site Scripting", "XSS", 'xploit"><svg/onload=alert(1)>', self._xss_evidence)
            self._test_form_payload(form, "Command Injection", "CMDI", ";echo XPLOIT_CMD_TEST", self._cmd_evidence)
            self._test_form_payload(form, "Directory Traversal", "TRAV", "../../../../../../etc/passwd", self._traversal_evidence)

    def _test_form_payload(self, form: FormTarget, name: str, short: str, payload: str, evidence_fn) -> None:
        if not form.inputs:
            return
        for parameter in form.inputs:
            data = dict(form.inputs)
            data[parameter] = payload
            if form.method == "GET":
                response = self._request("GET", form.action, params=data)
            else:
                response = self._request("POST", form.action, data=data)
            evidence = evidence_fn(response, payload) if response else ""
            if evidence:
                self._add(Finding(
                    id=f"{short}-FORM-001",
                    name=name,
                    category=name,
                    severity=HIGH,
                    confidence="Medium",
                    url=form.action,
                    parameter=parameter,
                    method=form.method,
                    evidence=evidence,
                    trigger=f"payload={payload}",
                    impact=self._impact_for(name),
                    remediation=self._remediation_for(name),
                    cwe=self._cwe_for(name),
                ))

    def _check_open_redirects(self) -> None:
        payload = "https://example.com/xploit-redirect"
        for url in list(self.pages):
            for parameter in query_parameters(url):
                if parameter.lower() not in REDIRECT_PARAMS:
                    continue
                test_url = mutate_query(url, parameter, payload)
                response = self._request("GET", test_url, allow_redirects=False)
                location = response.headers.get("Location", "") if response else ""
                if location.startswith(payload):
                    self._add(Finding(
                        id="REDIR-001",
                        name="Open Redirect",
                        category="Open Redirect",
                        severity=HIGH,
                        confidence="High",
                        url=test_url,
                        parameter=parameter,
                        evidence=f"Location header points to external URL: {location}",
                        trigger=f"parameter={parameter};payload={payload}",
                        impact="Attackers can abuse trusted domains for phishing, token leakage, and redirect-chain attacks.",
                        remediation="Allow only relative redirects or validate destinations against a strict allowlist.",
                        cwe="CWE-601",
                    ))

    def _check_sensitive_exposure(self) -> None:
        probes = {
            "/.env": ("Environment File Exposure", "DB_PASSWORD|APP_KEY|SECRET|TOKEN"),
            "/.git/config": ("Git Repository Exposure", r"\[core\]|\[remote "),
            "/backup.zip": ("Backup Archive Exposure", ""),
            "/db.sql": ("Database Dump Exposure", r"CREATE TABLE|INSERT INTO"),
            "/phpinfo.php": ("PHP Info Exposure", r"phpinfo\(\)|PHP Version"),
        }
        base = f"{urlparse(self.root).scheme}://{urlparse(self.root).netloc}"
        for path, (name, pattern) in probes.items():
            url = urljoin(base, path)
            response = self._request("GET", url)
            if not response or response.status_code >= 400:
                continue
            body = response.text[:4000]
            if not pattern or re.search(pattern, body, re.I):
                self._add(Finding(
                    id="DATA-001",
                    name=name,
                    category="Sensitive Data Exposure",
                    severity=HIGH,
                    confidence="High" if pattern else "Medium",
                    url=url,
                    evidence=f"Accessible resource returned HTTP {response.status_code}.",
                    trigger=f"path_probe={path}",
                    impact="Sensitive application data, source control metadata, or credentials may be exposed publicly.",
                    remediation="Remove public access, rotate exposed secrets, and block sensitive file patterns at the web server.",
                    cwe="CWE-200",
                ))
        for url, response in self.pages.items():
            body = response.text[:100000]
            for pattern in SECRET_PATTERNS:
                if pattern.search(body):
                    self._add(Finding(
                        id="DATA-002",
                        name="Secret Pattern in Response Body",
                        category="Sensitive Data Exposure",
                        severity=HIGH,
                        confidence="Medium",
                        url=url,
                        evidence=f"Matched sensitive-data pattern `{pattern.pattern}`.",
                        trigger=f"body_pattern={pattern.pattern}",
                        impact="Secrets in client-visible responses can enable account takeover or infrastructure compromise.",
                        remediation="Remove secrets from responses and rotate any exposed credentials.",
                        cwe="CWE-200",
                    ))

    def _check_broken_authentication(self) -> None:
        for form in self.forms:
            names = {name.lower() for name in form.inputs}
            has_auth_field = bool(names & AUTH_FIELDS) or any(
                field_type == "password" for field_type in form.input_types.values()
            )
            if not has_auth_field:
                continue
            if urlparse(form.action).scheme != "https":
                self._add(Finding(
                    id="AUTH-001",
                    name="Authentication Form Submitted Over HTTP",
                    category="Broken Authentication",
                    severity=HIGH,
                    confidence="High",
                    url=form.action,
                    method=form.method,
                    evidence="Authentication-related form action does not use HTTPS.",
                    trigger="auth_form_over_http=true",
                    impact="Credentials may be intercepted or modified in transit.",
                    remediation="Serve all authentication flows exclusively over HTTPS and enable HSTS.",
                    cwe="CWE-319",
                ))
            page = self.pages.get(form.page_url)
            if page and "set-cookie" in {key.lower() for key in page.headers}:
                cookie = page.headers.get("Set-Cookie", "")
                missing = [flag for flag in ("HttpOnly", "Secure", "SameSite") if flag.lower() not in cookie.lower()]
                if missing:
                    self._add(Finding(
                        id="AUTH-002",
                        name="Weak Session Cookie Attributes",
                        category="Broken Authentication",
                        severity=HIGH,
                        confidence="Medium",
                        url=form.page_url,
                        evidence=f"Set-Cookie missing: {', '.join(missing)}",
                        trigger=f"missing_cookie_flags={','.join(missing)}",
                        impact="Session cookies may be stolen, sent over plaintext, or abused cross-site.",
                        remediation="Set HttpOnly, Secure, and SameSite attributes on session cookies.",
                        cwe="CWE-614",
                    ))

    def _check_security_misconfiguration(self) -> None:
        response = self._request("OPTIONS", self.root, allow_redirects=False)
        allow = response.headers.get("Allow", "") if response else ""
        risky = sorted({method for method in ("PUT", "DELETE", "TRACE") if method in allow.upper()})
        if risky:
            self._add(Finding(
                id="MISCFG-001",
                name="Risky HTTP Methods Enabled",
                category="Security Misconfiguration",
                severity=HIGH,
                confidence="High",
                url=self.root,
                method="OPTIONS",
                evidence=f"Allow header includes: {', '.join(risky)}",
                trigger=f"allow_methods={','.join(risky)}",
                impact="Dangerous methods can allow content tampering, deletion, or request reflection attacks.",
                remediation="Disable unused HTTP methods at the application or reverse proxy.",
                cwe="CWE-16",
            ))
        debug_paths = ("/debug", "/server-status", "/actuator/env", "/actuator/heapdump", "/.well-known/security.txt")
        base = f"{urlparse(self.root).scheme}://{urlparse(self.root).netloc}"
        for path in debug_paths:
            url = urljoin(base, path)
            probe = self._request("GET", url)
            if probe and probe.status_code == 200 and path != "/.well-known/security.txt":
                self._add(Finding(
                    id="MISCFG-002",
                    name="Exposed Diagnostic Endpoint",
                    category="Security Misconfiguration",
                    severity=HIGH,
                    confidence="Medium",
                    url=url,
                    evidence=f"Diagnostic path returned HTTP {probe.status_code}.",
                    trigger=f"exposed_path={path}",
                    impact="Debug and diagnostic endpoints may disclose secrets, system state, or operational controls.",
                    remediation="Restrict diagnostic endpoints to authenticated administrators or internal networks.",
                    cwe="CWE-16",
                ))

    def _check_insecure_methods(self) -> None:
        response = self._request("TRACE", self.root, allow_redirects=False)
        if response and response.status_code < 400:
            self._add(Finding(
                id="HDR-003",
                name="HTTP TRACE Enabled",
                category="Insecure HTTP Headers",
                severity=HIGH,
                confidence="High",
                url=self.root,
                method="TRACE",
                evidence=f"TRACE returned HTTP {response.status_code}.",
                trigger=f"trace_status={response.status_code}",
                impact="TRACE can assist cross-site tracing attacks and expose request headers.",
                remediation="Disable TRACE at the web server or reverse proxy.",
                cwe="CWE-16",
            ))

    @staticmethod
    def _sql_evidence(response: requests.Response, _: str) -> str:
        body = response.text.lower()[:20000]
        for needle in SQL_ERRORS:
            if needle in body:
                return f"Database error signature detected: `{needle}`."
        return ""

    @staticmethod
    def _xss_evidence(response: requests.Response, payload: str) -> str:
        if payload in response.text:
            return "Injected XSS probe was reflected verbatim in the response body."
        escaped = html.escape(payload)
        if escaped in response.text:
            return "Injected XSS probe was reflected HTML-escaped; review context-specific encoding."
        return ""

    @staticmethod
    def _cmd_evidence(response: requests.Response, _: str) -> str:
        if "XPLOIT_CMD_TEST" in response.text:
            return "Command-injection marker appeared in the response body."
        return ""

    @staticmethod
    def _traversal_evidence(response: requests.Response, _: str) -> str:
        if "root:x:0:0:" in response.text or "[boot loader]" in response.text.lower():
            return "Traversal probe returned operating-system file content signature."
        return ""

    @staticmethod
    def _impact_for(name: str) -> str:
        return {
            "SQL Injection": "Attackers may read, modify, or delete database records and potentially execute database-layer commands.",
            "Cross-Site Scripting": "Attackers may execute JavaScript in users' browsers, steal sessions, or perform actions as victims.",
            "Command Injection": "Attackers may execute operating-system commands with the application process privileges.",
            "Directory Traversal": "Attackers may read sensitive server-side files outside the intended web root.",
        }.get(name, "Security impact depends on application context.")

    @staticmethod
    def _remediation_for(name: str) -> str:
        return {
            "SQL Injection": "Use parameterized queries, typed ORM bindings, strict input validation, and least-privileged database accounts.",
            "Cross-Site Scripting": "Apply context-aware output encoding, sanitize HTML, and deploy a restrictive Content-Security-Policy.",
            "Command Injection": "Avoid shell execution; use safe APIs, strict allowlists, and argument arrays without shell interpolation.",
            "Directory Traversal": "Canonicalize paths, reject traversal sequences, and enforce strict file allowlists rooted in safe directories.",
        }.get(name, "Apply secure design controls and validate the affected code path.")

    @staticmethod
    def _cwe_for(name: str) -> str:
        return {
            "SQL Injection": "CWE-89",
            "Cross-Site Scripting": "CWE-79",
            "Command Injection": "CWE-78",
            "Directory Traversal": "CWE-22",
        }.get(name, "")
