from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW, PASSIVE


class ExposureModule(BaseModule):
    name = "Exposure & Access Control Heuristics"
    category = "Exposure"

    COMMENT_PATTERNS = (
        re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret|token)\s*[:=]"),
        re.compile(r"(?i)\b(internal ip|todo:|fixme:)\b"),
        re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        # Industrial Secret Patterns
        re.compile(r"(?i)AKIA[0-9A-Z]{16}"), # AWS Access Key
        re.compile(r"(?i)firebase-?[a-z0-9-]+\.firebaseio\.com"), # Firebase URL
        re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), # Slack Token
        re.compile(r"(?i)AIza[0-9A-Za-z-_]{35}"), # Google API Key
        re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24}"), # Stripe Secret Key
        re.compile(r"(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), # PayPal Token
    )
    IDOR_URL_PATTERNS = (
        re.compile(r"(?i)(?:^|[?&])(id|user|user_id|account|account_id|order|order_id|profile|uid|guid|uuid)=([0-9a-fA-F-]{8,}|[0-9]+)"),
    )
    IDOR_FIELD_NAMES = {"id", "uid", "user_id", "account_id", "order_id", "profile_id", "guid", "uuid", "key", "handle"}
    SENSITIVE_FILES = {
        "/.env": (r"(?i)(DB_|DATABASE_URL|APP_KEY|SECRET|API[_-]?KEY|PASSWORD|TOKEN)", "Environment File Exposure"),
        "/.git/config": (r"(?i)(\[core\]|\[remote )", "Git Repository Metadata Exposure"),
        "/.git/head": (r"(?i)ref:", "Git HEAD Disclosure"),
        "/.svn/entries": (r"(?i)svn:", "Subversion Metadata Exposure"),
        "/.dockerignore": (r"(?i)(node_modules|\.git|env)", "Docker Metadata Disclosure"),
        "/.htaccess": (r"(?i)(RewriteEngine|AuthType)", "Apache Config Disclosure"),
        "/.ssh/id_rsa": (r"(?i)PRIVATE KEY", "SSH Private Key Disclosure"),
        "/.bash_history": (r"(?i)(cd|ls|curl|mysql)", "Shell History Disclosure"),
        "/.DS_Store": (r"(?s)\x00\x00\x00\x01\x42\x75\x64\x31|Bud1|\x00\x00\x00", "macOS Desktop Metadata Disclosure"),
        "/wp-config.php": (r"(?i)(DB_NAME|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY)", "WordPress Config Exposure"),
        "/config.php": (r"(?i)(\$config|database|db_password|secret)", "Application Config Exposure"),
        "/config/database.yml": (r"(?i)(adapter|database|password)", "Rails Database Config Exposure"),
        "/web.config": (r"(?i)(<configuration>|<system.webServer>)", "IIS Config Disclosure"),
        "/package.json": (r"(?i)(\"name\"|\"dependencies\"|\"scripts\")", "Node.js Project Disclosure"),
        "/composer.json": (r"(?i)(\"name\"|\"require\")", "PHP Project Disclosure"),
    }
    DEBUG_PATHS = {
        "/phpinfo.php": r"(?i)(phpinfo\(\)|PHP Version \d)",
        "/server-status": r"(?i)(Apache Server Status|Server uptime|requests currently being processed)",
        "/debug": r"(?i)(Traceback \(most recent call|stack trace|Exception in thread)",
        "/trace": r"(?i)(Traceback \(most recent call|stack trace|request headers)",
        "/actuator/env": r"(?i)(propertySources|activeProfiles|systemEnvironment)",
        "/actuator/heapdump": r"(?i)(JAVA PROFILE|HotSpot)",
        "/actuator/health": r"(?i)(\"status\"\s*:\s*\"(UP|DOWN)\")",
        "/actuator/metrics": r"(?i)(jvm_|http_server_requests)",
        "/metrics": r"(?i)(jvm_memory|http_server_requests|process_cpu)",
        "/console": r"(?i)(Groovy Web Console|H2 Console|Hawtio|terminal emulator)",
        "/jenkins/": r"(?i)(Jenkins|hudson\.model)",
    }

    def run(self) -> None:
        self._check_observed_directory_listing()
        self._check_html_comment_disclosure()
        self._check_idor_indicators()
        if self.scanner.mode != PASSIVE:
            self._check_sensitive_files()
            self._check_debug_endpoints()

    def _check_observed_directory_listing(self) -> None:
        for url, response in self.scanner.pages.items():
            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue
            if re.search(r"(?i)<title>\s*(Index of /|Directory Listing)", response.text):
                self.add_finding(Finding(
                    id="MISCFG-002",
                    name="Directory Listing Enabled",
                    category="Security Misconfiguration",
                    severity=MEDIUM,
                    confidence="High",
                    url=url,
                    evidence="Response body looks like a web server directory listing.",
                    impact="Directory listings can expose application files, backups, source paths, and deployment metadata.",
                    remediation="Disable auto-indexing/directory listing at the web server or reverse proxy.",
                    cwe="CWE-548",
                ))

    def _check_html_comment_disclosure(self) -> None:
        seen_comment_sets: set[frozenset[str]] = set()
        for url, response in self.scanner.pages.items():
            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue
            matched_excerpts = []
            for comment in re.findall(r"<!--(.*?)-->", response.text, re.S):
                if any(pattern.search(comment) for pattern in self.COMMENT_PATTERNS):
                    matched_excerpts.append(" ".join(comment.strip().split())[:80])
            if not matched_excerpts:
                continue
            # Skip if we already reported this exact set of comments from another URL
            # (happens when the crawler stores the same response body under a redirect URL).
            key = frozenset(matched_excerpts)
            if key in seen_comment_sets:
                continue
            seen_comment_sets.add(key)
            evidence = f"{len(matched_excerpts)} sensitive comment(s) found: {matched_excerpts[0]!r}"
            self.add_finding(Finding(
                id="INFO-001",
                name="Sensitive Information in HTML Comment",
                category="Information Disclosure",
                severity=LOW,
                confidence="Medium",
                url=url,
                evidence=evidence,
                impact="Developer notes, internal addresses, or secret-like values in client-visible comments help attackers map the application.",
                remediation="Remove sensitive comments from rendered HTML and keep operational notes outside client-visible templates.",
                cwe="CWE-200",
            ))

    def _check_idor_indicators(self) -> None:
        # Active IDOR testing: for each URL/form param that looks like a numeric
        # object ID, request the original, then probe adjacent IDs (+1, -1, +2, -2).
        # A confirmed IDOR is when an adjacent ID returns a substantially different
        # successful response — meaning the server returned a different object.
        for url in list(self.scanner.pages):
            self._test_idor_url(url)
        for form in self.scanner.forms:
            self._test_idor_form(form)

    def _test_idor_url(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        id_param_names = self.IDOR_FIELD_NAMES | {"id", "user", "account", "order", "profile"}
        for param, value in params.items():
            if param.lower() not in {p.lower() for p in id_param_names}:
                continue
            if not str(value).isdigit():
                continue
            orig_id = int(value)
            self._probe_idor(url, param, orig_id, method="GET", base_data=None)

    def _test_idor_form(self, form) -> None:
        for name, value in form.inputs.items():
            if name.lower() not in self.IDOR_FIELD_NAMES:
                continue
            if not str(value).isdigit():
                continue
            orig_id = int(value)
            self._probe_idor(form.action, name, orig_id, method=form.method, base_data=form.inputs)

    def _probe_idor(self, url: str, param: str, orig_id: int, method: str, base_data) -> None:
        # Fetch the baseline response for the original ID first.
        orig_res = self._fetch(url, param, str(orig_id), method, base_data)
        if not orig_res or orig_res.status_code not in (200, 201):
            return
        orig_text = orig_res.text
        orig_len = len(orig_text)
        # Skip responses too short to contain meaningful object data.
        if orig_len < 100:
            return

        for delta in (1, -1, 2, -2):
            probe_id = orig_id + delta
            if probe_id <= 0:
                continue
            res = self._fetch(url, param, str(probe_id), method, base_data)
            if not res or res.status_code not in (200, 201):
                continue
            probe_text = res.text
            probe_len = len(probe_text)

            # Skip if the response is identical to original — same object,
            # same content, no IDOR. Require both size and text to match.
            if probe_text == orig_text:
                continue

            # Skip responses that look like error/not-found pages.
            error_phrases = ["not found", "no record", "invalid", "error", "unauthorized",
                             "forbidden", "access denied", "does not exist", "404"]
            if any(p in probe_text.lower() for p in error_phrases):
                continue

            # The probe returned a different successful response — the server
            # handed over a different object without any visible auth check.
            # Show a snippet of what the probe returned as evidence.
            snippet = probe_text.strip()[:120].replace("\n", " ")
            self.add_finding(Finding(
                id="IDOR-001",
                name="Insecure Direct Object Reference (IDOR)",
                category="Broken Access Control",
                severity=MEDIUM,
                confidence="Medium",
                url=url,
                parameter=param,
                method=method,
                evidence=(
                    f"{method} {param}={orig_id} → {orig_len}B; "
                    f"{param}={probe_id} (Δ{delta:+d}) → {probe_len}B, different content: \"{snippet}\""
                ),
                trigger=f"{param}={probe_id}",
                impact="An attacker can enumerate object IDs to access other users' records, files, or account data without authorization.",
                remediation="Enforce object-level authorization on every request. Verify the authenticated user owns or has permission to access the requested object before returning it.",
                cwe="CWE-639",
            ))
            return  # One confirmed probe per param is enough

    def _fetch(self, url: str, param: str, value: str, method: str, base_data) -> object:
        if method == "GET":
            parsed = urlparse(url)
            pairs = [(k, value if k == param else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
            new_url = urlunparse(parsed._replace(query=urlencode(pairs)))
            return self.scanner._request("GET", new_url)
        else:
            data = dict(base_data) if base_data else {}
            data[param] = value
            return self.scanner._request("POST", url, data=data)

    def _check_sensitive_files(self) -> None:
        # Get a baseline for a known non-existent file to detect "soft 404" behavior
        baseline_path = f"/xploit-random-{secrets.token_hex(16)}.html"
        baseline_target = self._root_url(baseline_path)
        baseline_res = self.scanner._request("GET", baseline_target, allow_redirects=False)
        baseline_len = len(baseline_res.text) if baseline_res and baseline_res.status_code == 200 else -1

        for path, (pattern, name) in self.SENSITIVE_FILES.items():
            target = self._root_url(path)
            if not self.scanner._in_scope(target):
                continue
            response = self.scanner._request("GET", target, allow_redirects=False)
            if not response or response.status_code != 200:
                continue

            # Soft-404 guard: some apps return 200 for every path with a generic page.
            # Use a wider tolerance (500 bytes) to account for encoding differences and
            # minor template variations while still catching genuine content.
            if baseline_len > 0 and abs(len(response.text) - baseline_len) < 500:
                continue

            if re.search(pattern, response.text[:20000]):
                self.add_finding(Finding(
                    id="DATA-001",
                    name=name,
                    category="Sensitive Data Exposure",
                    severity=HIGH,
                    confidence="High",
                    url=target,
                    evidence=f"Accessible {path} matched sensitive configuration signatures.",
                    impact="Public configuration files can disclose credentials, repository metadata, or application secrets.",
                    remediation="Remove the file from the web root, block sensitive paths at the server, and rotate any exposed secrets.",
                    cwe="CWE-200",
                ))

    def _check_debug_endpoints(self) -> None:
        # Similar logic for debug endpoints
        baseline_path = f"/xploit-random-{secrets.token_hex(16)}.html"
        baseline_target = self._root_url(baseline_path)
        baseline_res = self.scanner._request("GET", baseline_target, allow_redirects=False)
        baseline_len = len(baseline_res.text) if baseline_res and baseline_res.status_code == 200 else -1

        for path, pattern in self.DEBUG_PATHS.items():
            target = self._root_url(path)
            if not self.scanner._in_scope(target):
                continue
            response = self.scanner._request("GET", target, allow_redirects=False)
            if not response or response.status_code != 200:
                continue

            if baseline_len > 0 and abs(len(response.text) - baseline_len) < 500:
                continue

            if re.search(pattern, response.text[:20000]):
                self.add_finding(Finding(
                    id="MISCFG-003",
                    name="Exposed Diagnostic Endpoint",
                    category="Security Misconfiguration",
                    severity=HIGH,
                    confidence="High",
                    url=target,
                    evidence=f"Diagnostic path {path} returned matching debug or runtime content.",
                    impact="Diagnostic endpoints can disclose secrets, runtime state, stack traces, or operational details.",
                    remediation="Disable public diagnostic endpoints or restrict them to authenticated administrators on trusted networks.",
                    cwe="CWE-200",
                ))

    def _root_url(self, path: str) -> str:
        parsed = urlparse(self.scanner.root)
        origin = f"{parsed.scheme}://{parsed.netloc}/"
        return urljoin(origin, path.lstrip("/"))
