from __future__ import annotations

import concurrent.futures
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, Callable, Set
from time import sleep
from urllib.parse import parse_qsl, urldefrag, urlencode, urljoin, urlparse, urlunparse

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
    # --- Evidence envelope (provenance-strict verification) ---
    # A finding is "verified" only when it carries replayable proof: the exact
    # request that demonstrated the vulnerability plus the response marker that
    # confirmed it. Prose in `evidence` alone is analyst-readable, not proof.
    proof_method: str = ""
    proof_url: str = ""
    proof_data: str = ""    # urlencoded POST body used to replay the proof
    proof_marker: str = ""  # response substring (lowercased) confirming the finding
    # proof_kind "timing": confirmation was a reproducible response delay, not
    # a substring. proof_delay_s is the delay threshold (seconds) the proof
    # request must meet or exceed on replay.
    proof_kind: str = "marker"
    proof_delay_s: float = 0.0
    verified: bool = False
    verification_note: str = ""
    # Retest lifecycle: not_run | confirmed | fixed | unverifiable | skipped
    retest_status: str = "not_run"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def has_replayable_proof(self) -> bool:
        if self.proof_method and self.proof_url and self.proof_marker:
            return True
        # Timing proof: no substring marker, but the delay is reproducible —
        # re-firing the proof request must reproduce the delay.
        return (self.proof_kind == "timing" and bool(self.proof_method)
                and bool(self.proof_url) and self.proof_delay_s > 0)


def gate_finding(finding: Finding) -> Finding:
    """Provenance gate — the honesty spine for findings.

    A finding is marked `verified` only when backed by replayable, machine-made
    proof (request + response marker), not prose. A severity assertion with no
    proof is an overclaim: HIGH findings without proof are explicitly flagged.
    The gate never invents provenance; it states WHY a finding is unverified.
    """
    if finding.has_replayable_proof():
        finding.verified = True
        if finding.proof_kind == "timing":
            finding.verification_note = (
                "Replayable timing proof attached: proof request reproducibly "
                f"delayed the response by >= {finding.proof_delay_s:g}s."
            )
        else:
            finding.verification_note = "Replayable proof attached (request + response marker)."
    elif finding.proof_method and finding.proof_url:
        finding.verified = False
        finding.verification_note = (
            "Replayable request attached, but confirmation was behavioral "
            "(e.g. response-length delta), not a response marker — not machine-verifiable."
        )
    else:
        finding.verified = False
        if finding.severity == HIGH:
            finding.verification_note = (
                "HIGH severity asserted on analyst-readable evidence only; "
                "no replayable proof attached — treat as unverified until retested."
            )
        else:
            finding.verification_note = "Analyst-readable evidence only; no replayable proof attached."
    return finding

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
        summary = summarize_findings(self.findings)
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
            "summary": summary,
            "total_findings": len(self.findings),
            "verified_findings": sum(1 for f in self.findings if f.verified),
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
    "error in your query",
)

def normalize_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("target must be a non-empty URL string")
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        if "://" in raw_url:
            raise ValueError("target must be an HTTP or HTTPS URL")
        raw_url = f"http://{raw_url}"
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an HTTP or HTTPS URL")
    # Strip userinfo (user:pass@) — credentials must never land in
    # logs or reports keyed by URL.
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, ""))

def _netloc_key(parsed) -> str:
    """Case-insensitive netloc with default ports stripped, for origin comparison."""
    host = (parsed.hostname or "").lower()
    port = parsed.port
    default = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    if port is None or default:
        return host
    return f"{host}:{port}"
def same_origin(url: str, root: str) -> bool:
    try:
        a = urlparse(url)
        b = urlparse(root)
        if a.scheme not in {"http", "https"} or a.scheme != b.scheme:
            return False
        return _netloc_key(a) == _netloc_key(b)
    except ValueError:
        return False  # unparseable URL (e.g. malformed IPv6 literal or bad port) — out of scope

def mutate_query(url: str, parameter: str, payload: str,
                 extra_params: dict | None = None) -> str:
    """Replace `parameter` in the URL query string with `payload`.

    If `parameter` is absent from the query (e.g. a GET form whose action URL
    carries no query string), it is appended instead of silently dropped —
    along with any `extra_params` (sibling form fields) — so the payload is
    actually sent. Previously the payload never left the machine in that case.
    """
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    seen = False
    changed = []
    for key, value in pairs:
        if key == parameter:
            changed.append((key, payload))
            seen = True
        else:
            changed.append((key, value))
    if not seen:
        if extra_params:
            for k, v in extra_params.items():
                if k != parameter:
                    changed.append((k, v))
        changed.append((parameter, payload))
    return urlunparse(parsed._replace(query=urlencode(changed, doseq=True)))

def query_parameters(url: str) -> list[str]:
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())

def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary

def normalize_path(url: str) -> str:
    """Normalizes paths by replacing numeric segments with placeholders to avoid redundant scanning.

    Query parameter *names* are kept (values dropped): /?sessionid=abc crawls as its
    own page, while /item?id=1 and /item?id=2 dedupe by shape.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return url  # unparseable URL (e.g. malformed IPv6 literal) — use as-is
    parts = parsed.path.split('/')
    normalized_parts = []
    for part in parts:
        if part.isdigit():
            normalized_parts.append("{ID}")
        elif re.match(r"^[0-9a-fA-F-]{32,40}$", part): # Simple UUID/Hash check
            normalized_parts.append("{UUID}")
        else:
            normalized_parts.append(part)
    query_keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    query = urlencode([(key, "") for key in query_keys])
    return urlunparse(parsed._replace(path='/'.join(normalized_parts), query=query, fragment=""))

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
        self.threads = max(1, threads)
        self.verify = verify
        # Guards _request_count and _last_request_at, which are touched from
        # crawler worker threads.
        self._lock = threading.Lock()
        
        if not verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.session = requests.Session()
        # Retries are bounded and idempotent-only. Connect/read failures are
        # retried at most once each (within total=2), status retries fire only
        # for 429/502/503/504, and only HEAD/GET/OPTIONS are ever retried —
        # POSTs are never retried, so a form submission can't be duplicated
        # by the retry layer. Honest worst case: a hanging GET can still take
        # roughly 3x the configured timeout plus backoff delays before it fails.
        retry_strategy = Retry(
            total=2,
            connect=1,
            read=1,
            backoff_factor=0.5,
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
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
        # Fired on every HTTP request attempt (any thread). Lets the UI show
        # liveness during long sequential module runs instead of appearing
        # frozen on a single phase label.
        self.on_request: Callable[[int], None] | None = None
        self._request_count = 0

    def scan(self) -> ScanResult:
        started = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        start_time = time.monotonic()
        
        self._crawl()
        
        if not self.pages:
            return self._empty_result(started, start_time)

        # Load and run modules
        from .modules.sqli import SQLInjectionModule
        from .modules.xss import XSSModule
        from .modules.injection_advanced import CommandTraversalModule
        from .modules.general import GeneralModule
        from .modules.logic_vulnerabilities import LogicVulnerabilityModule
        from .modules.exposure import ExposureModule
        from .modules.advanced_injection import MultiVectorInjectionModule
        from .modules.sensitive_data import SensitiveDataModule
        from .modules.auth_advanced import AdvancedAuthModule
        from .modules.brute_force import BruteForceModule

        modules_to_run = []
        # Passive checks always run — headers, exposure, and data disclosure
        # are relevant regardless of whether injection testing is enabled.
        modules_to_run.extend([
            GeneralModule(self),
            ExposureModule(self),
            SensitiveDataModule(self),
        ])
        if self.mode in {ACTIVE, FULL}:
            modules_to_run.extend([
                SQLInjectionModule(self),
                XSSModule(self),
                CommandTraversalModule(self),
                LogicVulnerabilityModule(self),
                AdvancedAuthModule(self),
            ])
        if self.mode == FULL:
            # Heavy modules — SSTI/LDAP/NoSQL/XML injection and brute force
            # are thorough but slow; only run in full mode.
            modules_to_run.extend([
                MultiVectorInjectionModule(self),
                BruteForceModule(self),
            ])
            # ExposureModule already runs in PASSIVE/FULL above.
            # Do NOT add it again for ACTIVE — was causing double findings.

        for i, module in enumerate(modules_to_run, start=1):
            if self.on_progress:
                self.on_progress(i - 1, len(modules_to_run), f"Running {module.name}")
            self._checks_run.append(module.name)
            try:
                module.run()
            except Exception as exc:
                # One crashing module must not discard every other module's findings.
                self.errors.append(f"Module {module.name} crashed: {exc}")
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

    # Bound for manual redirect following. requests' own default is 30, which
    # turns a redirect loop into a 30-request stall before failing.
    MAX_REDIRECTS = 10

    def _request(self, method: str, url: str, *, quiet: bool = False, **kwargs) -> requests.Response | None:
        with self._lock:
            self._request_count += 1
            count = self._request_count
        if self.on_request:
            try:
                self.on_request(count)
            except Exception:
                pass
        self._respect_rate_limit()
        follow_redirects = kwargs.pop("allow_redirects", True)
        try:
            res = self.session.request(
                method, url, timeout=self.timeout,
                allow_redirects=False,  # manual: bounded, same-origin only
                verify=self.verify,
                **kwargs
            )
        except (requests.exceptions.InvalidSchema,
                requests.exceptions.MissingSchema):
            # e.g. a crawled "javascript:..." pseudo-URL — not a site failure.
            if not quiet:
                self.errors.append(f"{method} {url}: unsupported URL scheme")
            return None
        except Exception as exc:
            if not quiet:
                self.errors.append(f"{method} {url}: {exc}")
            return None

        if follow_redirects:
            seen = {(method.upper(), url)}
            for _ in range(self.MAX_REDIRECTS):
                if res.status_code not in (301, 302, 303, 307, 308):
                    break
                location = res.headers.get("Location")
                if not location:
                    break
                target = urljoin(res.url, location)
                if urlparse(target).scheme not in ("http", "https"):
                    # Never follow javascript:/data:/etc. pseudo-URLs.
                    break
                if not same_origin(target, url):
                    # Off-origin redirect: return the bare 3xx so the redirect
                    # stays visible. Payloads — including 307/308 POST bodies,
                    # which requests would forward — are never delivered
                    # off-origin.
                    break
                next_method = method if res.status_code in (307, 308) else "GET"
                key = (next_method, target)
                if key in seen:
                    if not quiet:
                        self.errors.append(
                            f"{method} {url}: redirect loop detected")
                    break
                seen.add(key)
                if next_method == "GET":
                    # 301/302/303: drop the body, per requests' convention.
                    kwargs = {k: v for k, v in kwargs.items()
                              if k not in ("data", "json", "files")}
                    method = "GET"
                self._respect_rate_limit()
                try:
                    res = self.session.request(
                        next_method, target, timeout=self.timeout,
                        allow_redirects=False,
                        verify=self.verify,
                        **kwargs
                    )
                except Exception as exc:
                    if not quiet:
                        self.errors.append(f"{next_method} {target}: {exc}")
                    return None
            else:
                if not quiet:
                    self.errors.append(
                        f"{method} {url}: exceeded {self.MAX_REDIRECTS} redirects")
                # res is the last 3xx; fall through and return it.

        if not res.ok and not quiet and res.status_code != 404:
            # 404s are expected during sensitive-file probing; logging every
            # one as an error buries real failures in noise.
            self.errors.append(f"{method} {url}: {res.status_code} {res.reason}")
        return res

    def _crawl(self) -> None:
        """Parallelized crawler with path normalization."""
        entry_points = self._discover_entry_points()
        seen = set(entry_points)
        for ep in entry_points:
            self._normalized_seen.add(normalize_path(ep))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._request, "GET", ep): (ep, 0) for ep in entry_points}
            
            while futures and len(self.pages) < self.max_pages:
                # Bound the wait: without a timeout a hung request (e.g.
                # uninterruptible DNS/connect) stalls the crawl forever.
                crawl_timeout = max(60.0, self.timeout * 5)
                done, not_done = concurrent.futures.wait(
                    futures, timeout=crawl_timeout,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    for f in not_done:
                        f.cancel()
                    self.errors.append(
                        f"Crawl stalled: no request finished within {crawl_timeout:.0f}s; "
                        f"cancelled {len(not_done)} hanging request(s).")
                    break

                for future in done:
                    url, depth = futures.pop(future)
                    # Re-check the cap per completed future: wait() returns
                    # every future finished so far, so a whole batch can land
                    # at once and overshoot max_pages without this guard.
                    if len(self.pages) >= self.max_pages:
                        break
                    res = future.result()
                    # NB: `Response.__bool__` is `.ok`, so `if not res` would
                    # silently discard every 4xx/5xx page (forms/links lost).
                    if res is None:
                        continue

                    self.pages[url] = res
                    if self.on_progress:
                        self.on_progress(len(self.pages), self.max_pages, f"Crawled {urlparse(url).path or '/'}")

                    # Size cap: record oversize pages but never parse them —
                    # unbounded res.text + BeautifulSoup is a memory-DoS vector
                    # on hostile targets.
                    oversize = len(res.content) > 5_000_000
                    if oversize:
                        self.errors.append(
                            f"Skipped HTML parsing for {url}: "
                            f"{len(res.content)} bytes exceeds 5 MB cap")

                    if "text/html" in res.headers.get("Content-Type", "").lower() and not oversize:
                        soup = BeautifulSoup(res.text, "html.parser")
                        self.forms.extend(self._extract_forms(res.url, soup))
                        
                        if depth < self.depth:
                            for raw_link in self._extract_links(res):
                                link, _frag = urldefrag(raw_link)
                                if not link:
                                    continue
                                norm = normalize_path(link)
                                if link not in seen and norm not in self._normalized_seen and self._in_scope(link):
                                    seen.add(link)
                                    self._normalized_seen.add(norm)
                                    futures[executor.submit(self._request, "GET", link)] = (link, depth + 1)

                # Cap reached mid-batch: stop feeding the crawl and cancel
                # anything still in flight — the executor would otherwise
                # wait for (and the target would receive) pointless requests.
                if len(self.pages) >= self.max_pages:
                    for f in futures:
                        f.cancel()
                    break

        if self.on_progress:
            self.on_progress(1, 1, "Crawl complete")

    def _extract_links(self, res: requests.Response) -> Set[str]:
        links = set()
        if "text/html" in res.headers.get("Content-Type", "").lower():
            soup = BeautifulSoup(res.text, "html.parser")
            for a in soup.find_all(["a", "area", "link"], href=True):
                try:
                    links.add(urljoin(res.url, a["href"]))
                except ValueError:
                    continue  # malformed href (e.g. bad IPv6 literal) — skip
            for script in soup.find_all(["script", "img", "iframe"], src=True):
                try:
                    links.add(urljoin(res.url, script["src"]))
                except ValueError:
                    continue
        # Broad extraction
        links.update(self._urls_from_text(res.text))
        return links

    def _discover_entry_points(self) -> list[str]:
        entry_points = {self.root}
        # With --scope-prefix, the root itself is usually out of scope — seed
        # the prefixed path directly so a live target isn't misreported as
        # unreachable.
        if self.scope_prefix and self.scope_prefix != "/":
            entry_points.add(urljoin(self.root, self.scope_prefix))
        robots = self._request("GET", urljoin(self.root, "/robots.txt"), quiet=True)
        if robots and robots.status_code < 400:
            for candidate in self._urls_from_text(robots.text):
                # Relative paths (no scheme) — resolve against root before adding
                if not candidate.startswith(("http://", "https://")):
                    try:
                        candidate = urljoin(self.root, candidate)
                    except ValueError:
                        continue
                entry_points.add(candidate)
        sitemap_urls = [urljoin(self.root, "/sitemap.xml"), urljoin(self.root, "/sitemap_index.xml")]
        for sitemap_url in sitemap_urls:
            response = self._request("GET", sitemap_url, quiet=True)
            if response and response.status_code < 400:
                for candidate in self._urls_from_text(response.text):
                    if not candidate.startswith(("http://", "https://")):
                        try:
                            candidate = urljoin(self.root, candidate)
                        except ValueError:
                            continue
                    entry_points.add(candidate)
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
            for el in f.find_all(["input", "textarea", "select", "button"]):
                name = el.get("name")
                if not name: continue
                ftype = (el.get("type") or el.name or "text").lower()
                # Store default values if present, else use 'xploit'
                inputs[name] = el.get("value") or "xploit"
                types[name] = ftype
            forms.append(FormTarget(page_url, action, method, inputs, types))
        return forms

    def _in_scope(self, url: str) -> bool:
        if not same_origin(url, self.root):
            return False
        path = urlparse(url).path or "/"
        prefix = self.scope_prefix
        if prefix == "/":
            return True
        # '/'-boundary: /apiv2/ must not match a /api prefix.
        return path == prefix or path.startswith(prefix.rstrip("/") + "/")

    def _normalize_scope_prefix(self, prefix: str | None) -> str:
        if not prefix: return "/"
        val = prefix.strip()
        if not val.startswith("/"): val = f"/{val}"
        return val.rstrip("/") or "/"

    def _respect_rate_limit(self):
        if self.rate_limit <= 0: return
        # Reserve the next slot under the lock so concurrent crawler threads
        # can't all observe a stale _last_request_at and burst together.
        # The sleep itself happens outside the lock.
        with self._lock:
            now = time.monotonic()
            earliest = self._last_request_at + self.rate_limit
            if now < earliest:
                delay = earliest - now
                self._last_request_at = earliest
            else:
                delay = 0.0
                self._last_request_at = now
        if delay:
            sleep(delay)

    def _empty_result(self, started, start_time):
        return ScanResult(
            self.target, self.root, started, round(time.monotonic() - start_time, 2),
            "unreachable", self.mode, self.scope_prefix, 0, [], [], 0, [], self.errors
        )
