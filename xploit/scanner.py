from __future__ import annotations

import concurrent.futures
import json
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, Callable, Set
from time import sleep
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# Severity Constants
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

# Scan Modes
PASSIVE = "passive"
ACTIVE = "active"
FULL = "full"

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
    scan_mode: str
    scope_prefix: str
    completion_percent: int
    checks_run: list[str]
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
            "scan_mode": self.scan_mode,
            "scope_prefix": self.scope_prefix,
            "completion_percent": self.completion_percent,
            "checks_run": self.checks_run,
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
    "syntax error near",
    "unexpected end of input",
    "invalid input syntax",
    "division by zero",
    "column does not exist",
    "relation does not exist",
    "database error",
    "internal server error",
    "error in your query",
)

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

def normalize_path(url: str) -> str:
    """Normalizes paths by replacing numeric segments with placeholders to avoid redundant scanning."""
    parsed = urlparse(url)
    parts = parsed.path.split('/')
    normalized_parts = []
    for part in parts:
        if part.isdigit():
            normalized_parts.append("{ID}")
        elif re.match(r"^[0-9a-fA-F-]{32,40}$", part): # Simple UUID/Hash check
            normalized_parts.append("{UUID}")
        else:
            normalized_parts.append(part)
    return urlunparse(parsed._replace(path='/'.join(normalized_parts), query="", fragment=""))

class WebScanner:
    def __init__(
        self,
        target: str,
        *,
        max_pages: int = 16,
        depth: int = 1,
        timeout: float = 6.0,
        mode: str = FULL,
        rate_limit: float = 0.0,
        scope_prefix: str | None = None,
        threads: int = 5,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        verify: bool = True,
    ) -> None:
        self.target = target
        self.root = normalize_url(target)
        self.max_pages = max(1, max_pages)
        self.depth = max(0, depth)
        self.timeout = timeout
        self.mode = mode
        self.rate_limit = rate_limit
        self.scope_prefix = self._normalize_scope_prefix(scope_prefix)
        self.threads = threads
        self.verify = verify
        
        if not verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.session = requests.Session()
        # Expert Move: Implement robust retries at the adapter level
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({"User-Agent": user_agent})
        
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.pages: dict[str, requests.Response] = {}
        self.forms: list[FormTarget] = []
        self._normalized_seen: Set[str] = set()
        self._checks_run: list[str] = []
        self._last_request_at = 0.0
        self.on_progress: Callable[[int, int, str], None] | None = None
        self.on_finding: Callable[[Finding], None] | None = None

    def scan(self) -> ScanResult:
        started = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        start_time = time.monotonic()
        
        self._crawl()
        
        if not self.pages:
            return self._empty_result(started, start_time)

        # Load and run modules
        from .modules.sqli import SQLInjectionModule
        from .modules.xss import XSSModule
        from .modules.injection_advanced import AdvancedInjectionModule
        from .modules.general import GeneralModule
        from .modules.logic_vulnerabilities import LogicVulnerabilityModule
        from .modules.exposure import ExposureModule
        from .modules.advanced_injection import AdvancedInjectionModule as NewAdvancedInjection
        from .modules.sensitive_data import SensitiveDataModule
        from .modules.auth_advanced import AdvancedAuthModule
        from .modules.brute_force import BruteForceModule

        modules_to_run = []
        if self.mode in {PASSIVE, FULL}:
            modules_to_run.extend([
                GeneralModule(self),
                ExposureModule(self),
                SensitiveDataModule(self),
            ])
        if self.mode in {ACTIVE, FULL}:
            modules_to_run.extend([
                SQLInjectionModule(self),
                XSSModule(self),
                AdvancedInjectionModule(self),
                NewAdvancedInjection(self),
                LogicVulnerabilityModule(self),
                AdvancedAuthModule(self),
                BruteForceModule(self),
            ])
            if self.mode == ACTIVE:
                modules_to_run.append(ExposureModule(self))

        for i, module in enumerate(modules_to_run, start=1):
            if self.on_progress:
                self.on_progress(i - 1, len(modules_to_run), f"Running {module.name}")
            self._checks_run.append(module.name)
            module.run()
            if self.on_progress:
                phase = "Checks complete" if i == len(modules_to_run) else f"Completed {module.name}"
                self.on_progress(i, len(modules_to_run), phase)

        return ScanResult(
            target=self.target,
            normalized_target=self.root,
            started_at=started,
            duration_seconds=round(time.monotonic() - start_time, 2),
            status="completed",
            scan_mode=self.mode,
            scope_prefix=self.scope_prefix,
            completion_percent=100,
            checks_run=list(self._checks_run),
            pages_seen=list(self.pages.keys()),
            forms_seen=len(self.forms),
            findings=self.findings,
            errors=self.errors,
        )

    def _request(self, method: str, url: str, **kwargs) -> requests.Response | None:
        self._respect_rate_limit()
        try:
            res = self.session.request(
                method, url, timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", True),
                verify=self.verify,
                **kwargs
            )
            if not res.ok:
                self.errors.append(f"{method} {url}: {res.status_code} {res.reason}")
            return res
        except Exception as exc:
            self.errors.append(f"{method} {url}: {exc}")
            return None

    def _crawl(self) -> None:
        """Parallelized crawler with path normalization."""
        queue = [(self.root, 0)]
        seen = {self.root}
        self._normalized_seen.add(normalize_path(self.root))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._request, "GET", self.root): (self.root, 0)}
            
            while futures and len(self.pages) < self.max_pages:
                done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                
                for future in done:
                    url, depth = futures.pop(future)
                    res = future.result()
                    if not res: continue
                    
                    self.pages[url] = res
                    if self.on_progress:
                        self.on_progress(len(self.pages), self.max_pages, f"Crawled {urlparse(url).path or '/'}")

                    if "text/html" in res.headers.get("Content-Type", "").lower():
                        soup = BeautifulSoup(res.text, "html.parser")
                        self.forms.extend(self._extract_forms(res.url, soup))
                        
                        if depth < self.depth:
                            for link in self._extract_links(res):
                                norm = normalize_path(link)
                                if link not in seen and norm not in self._normalized_seen and self._in_scope(link):
                                    seen.add(link)
                                    self._normalized_seen.add(norm)
                                    futures[executor.submit(self._request, "GET", link)] = (link, depth + 1)

        if self.on_progress:
            self.on_progress(1, 1, "Crawl complete")

    def _extract_links(self, res: requests.Response) -> Set[str]:
        links = set()
        if "text/html" in res.headers.get("Content-Type", "").lower():
            soup = BeautifulSoup(res.text, "html.parser")
            for a in soup.find_all(["a", "area", "link"], href=True):
                links.add(urljoin(res.url, a["href"]))
            for script in soup.find_all(["script", "img", "iframe"], src=True):
                links.add(urljoin(res.url, script["src"]))
        # Broad extraction
        links.update(self._urls_from_text(res.text))
        return links

    def _discover_entry_points(self) -> list[str]:
        entry_points = {self.root}
        robots = self._request("GET", urljoin(self.root, "/robots.txt"))
        if robots and robots.status_code < 400:
            entry_points.update(self._urls_from_text(robots.text))
        sitemap_urls = [urljoin(self.root, "/sitemap.xml"), urljoin(self.root, "/sitemap_index.xml")]
        for sitemap_url in sitemap_urls:
            response = self._request("GET", sitemap_url)
            if response and response.status_code < 400:
                entry_points.update(self._urls_from_text(response.text))
        return [url for url in entry_points if self._in_scope(url)]

    @staticmethod
    def _urls_from_text(text: str) -> set[str]:
        urls: set[str] = set()
        # Absolute URLs
        for match in re.findall(r"https?://[^<>\s\"']+", text):
            urls.add(match.strip())
        
        # Path-like strings in quotes (common in JS/JSON)
        # e.g. "/api/v1/user", "actions/login"
        for match in re.findall(r"[\"'](/[a-zA-Z0-9._/-]+)[\"']", text):
            urls.add(match.strip())
            
        # Sitemap patterns
        for match in re.findall(r"(?im)^\s*(?:sitemap|allow)\s*[:=]\s*(\S+)\s*$", text):
            urls.add(match.strip())
        for match in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.S):
            urls.add(match.strip())
            
        return {url for url in urls if url and not url.startswith("data:")}

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> list[FormTarget]:
        forms = []
        for f in soup.find_all("form"):
            method = (f.get("method") or "GET").upper()
            action = urljoin(page_url, f.get("action") or page_url)
            inputs, types = {}, {}
            for field in f.find_all(["input", "textarea", "select", "button"]):
                name = field.get("name")
                if not name: continue
                ftype = (field.get("type") or field.name or "text").lower()
                # Store default values if present, else use 'xploit'
                inputs[name] = field.get("value") or "xploit"
                types[name] = ftype
            forms.append(FormTarget(page_url, action, method, inputs, types))
        return forms

    def _in_scope(self, url: str) -> bool:
        if not same_origin(url, self.root): return False
        return (urlparse(url).path or "/").startswith(self.scope_prefix)

    def _normalize_scope_prefix(self, prefix: str | None) -> str:
        if not prefix: return "/"
        val = prefix.strip()
        if not val.startswith("/"): val = f"/{val}"
        return val.rstrip("/") or "/"

    def _respect_rate_limit(self):
        if self.rate_limit <= 0: return
        now = time.monotonic()
        elapsed = now - self._last_request_at
        if elapsed < self.rate_limit: sleep(self.rate_limit - elapsed)
        self._last_request_at = time.monotonic()

    def _empty_result(self, started, start_time):
        return ScanResult(
            self.target, self.root, started, round(time.monotonic() - start_time, 2),
            "unreachable", self.mode, self.scope_prefix, 0, [], [], 0, [], self.errors
        )
