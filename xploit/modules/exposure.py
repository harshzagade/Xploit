from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlparse

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
        "/.DS_Store": (r".", "macOS Desktop Metadata Disclosure"),
        "/wp-config.php": (r"(?i)(DB_NAME|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY)", "WordPress Config Exposure"),
        "/config.php": (r"(?i)(\$config|database|db_password|secret)", "Application Config Exposure"),
        "/config/database.yml": (r"(?i)(adapter|database|password)", "Rails Database Config Exposure"),
        "/web.config": (r"(?i)(<configuration>|<system.webServer>)", "IIS Config Disclosure"),
        "/package.json": (r"(?i)(\"name\"|\"dependencies\"|\"scripts\")", "Node.js Project Disclosure"),
        "/composer.json": (r"(?i)(\"name\"|\"require\")", "PHP Project Disclosure"),
    }
    DEBUG_PATHS = {
        "/phpinfo.php": r"(?i)(phpinfo\(\)|PHP Version)",
        "/.well-known/": r".",
        "/debug": r"(?i)(debug|traceback|stack trace|environment)",
        "/trace": r"(?i)(traceback|stack trace|request headers)",
        "/info": r"(?i)(environment|build|version|runtime)",
        "/status": r"(?i)(uptime|status|ok)",
        "/server-status": r"(?i)(apache server status|server uptime)",
        "/actuator/env": r"(?i)(propertySources|activeProfiles|systemEnvironment)",
        "/actuator/heapdump": r"(?i)(JAVA PROFILE|heap|HotSpot)",
        "/actuator/health": r"(?i)(status|UP|DOWN)",
        "/metrics": r"(?i)(jvm_|http_server_requests|prometheus)",
        "/console": r"(?i)(terminal|bash|exec|login)",
        "/jenkins/": r"(?i)Jenkins",
        "/login.php": r"(?i)(login|username|password)",
        "/admin/": r"(?i)(admin|dashboard|management)",
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
            if re.search(r"(?i)<title>\s*Index of /|Index of /|Directory Listing", response.text):
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
        for url, response in self.scanner.pages.items():
            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue
            for comment in re.findall(r"<!--(.*?)-->", response.text, re.S):
                evidence = " ".join(comment.strip().split())[:120]
                if any(pattern.search(comment) for pattern in self.COMMENT_PATTERNS):
                    self.add_finding(Finding(
                        id="INFO-001",
                        name="Sensitive Information in HTML Comment",
                        category="Information Disclosure",
                        severity=LOW,
                        confidence="Medium",
                        url=url,
                        evidence=f"HTML comment contains sensitive-looking text: {evidence}",
                        impact="Developer notes, internal addresses, or secret-like values in client-visible comments can help attackers map the application.",
                        remediation="Remove sensitive comments from rendered HTML and keep operational notes outside client-visible templates.",
                        cwe="CWE-200",
                    ))

    def _check_idor_indicators(self) -> None:
        for url in self.scanner.pages:
            if any(pattern.search(url) for pattern in self.IDOR_URL_PATTERNS):
                self.add_finding(Finding(
                    id="IDOR-001",
                    name="Predictable Object Identifier",
                    category="Access Control Heuristic",
                    severity=LOW,
                    confidence="Medium",
                    url=url,
                    evidence="URL contains numeric object identifier parameters.",
                    impact="Predictable identifiers are not vulnerabilities by themselves, but they require server-side authorization checks to prevent IDOR/BOLA issues.",
                    remediation="Validate object-level authorization for every request and avoid relying on obscurity of sequential IDs.",
                    cwe="CWE-639",
                ))
        for form in self.scanner.forms:
            for name, value in form.inputs.items():
                if name.lower() in self.IDOR_FIELD_NAMES and str(value).isdigit():
                    self.add_finding(Finding(
                        id="IDOR-002",
                        name="Predictable Object Identifier in Form",
                        category="Access Control Heuristic",
                        severity=LOW,
                        confidence="Medium",
                        url=form.action,
                        parameter=name,
                        method=form.method,
                        evidence=f"Form field {name!r} contains numeric object identifier {value!r}.",
                        impact="Client-supplied object identifiers require authorization checks to prevent horizontal privilege escalation.",
                        remediation="Enforce object-level authorization server-side before reading or modifying referenced records.",
                        cwe="CWE-639",
                    ))

    def _check_sensitive_files(self) -> None:
        # Get a baseline for a known non-existent file to detect "soft 404" behavior
        baseline_path = f"/xploit-random-{secrets.token_hex(4)}.html"
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
            
            # If the response size is identical to our "soft 404" baseline, ignore it
            if baseline_len > 0 and abs(len(response.text) - baseline_len) < 100:
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
        baseline_path = f"/xploit-random-{secrets.token_hex(4)}.html"
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

            if baseline_len > 0 and abs(len(response.text) - baseline_len) < 100:
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
