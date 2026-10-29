"""xploit.scanner — the core scan engine.

A scan has three phases:

1. Crawl — parallel workers (see ``--threads``) walk the target's links
   within the same origin (plus an optional ``--scope-prefix``), collecting
   pages, forms, and JavaScript-referenced URLs. Path shapes are normalized
   (numeric segments become ``{ID}``) so pagination does not explode the
   crawl budget.
2. Entry-point discovery — every crawled page's query parameters and forms
   become probe targets.
3. Module fan-out — scan modules (SQLi, XSS, command/traversal, exposure,
   auth, ...) each sweep the entry points. By default up to four modules run
   concurrently (``--parallel-modules N``; ``1`` restores the sequential
   loop), and each module fans its own probe requests over the
   ``--threads`` pool.

Thread-safety model: crawler workers and probe threads never share mutable
scan state directly. ``BaseModule.add_finding`` serializes the finding
dedupe under the scanner lock so finding order stays deterministic; the
request counter and rate-limit bookkeeping are likewise locked.

Findings pass through :func:`gate_finding` — the provenance gate. A finding
is marked ``verified`` only when it carries replayable proof (the exact
request plus the response marker confirming it); analyst-readable prose
alone is never presented as proof.

Public surface used by ``xploit.cli`` and ``xploit.retest``:

- :class:`WebScanner` — configure a scan, call :meth:`WebScanner.scan`.
- :class:`Finding` — one vulnerability finding with its evidence envelope.
- :class:`ScanResult` — the finished scan, serializable via ``to_dict()``.
- URL helpers (:func:`normalize_url`, :func:`same_origin`,
  :func:`mutate_query`, :func:`query_parameters`, :func:`normalize_path`)
  shared by modules.

Example:
    scanner = WebScanner("https://example.com", mode="active", max_pages=8)
    result = scanner.scan()
    print(result.to_dict()["summary"])
"""
from __future__ import annotations

import concurrent.futures
import importlib
import random
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

# Default User-Agent sent on every request unless WebScanner(user_agent=...)
# or the CLI --user-agent flag overrides it. A --header "User-Agent: ..."
# override applied after construction still wins (see cli._build_scanner).
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# File extensions that are known binary/media assets. URLs with these
# extensions are never enqueued for crawling and their fetched responses are
# not stored in scanner.pages — they carry no injection entry points and
# storing them wastes memory. Extensions are lower-cased for comparison.
BINARY_ASSET_EXTS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".wav",
    ".pdf", ".zip", ".gz",
})

# Content-Type prefixes that identify binary/media responses regardless of
# the URL extension. text/* and application/javascript are NOT in this set.
_BINARY_CT_PREFIXES: tuple[str, ...] = (
    "image/", "font/", "audio/", "video/",
    "application/octet-stream", "application/pdf", "application/zip",
)

@dataclass(slots=True)
class Finding:
    """One vulnerability finding.

    The base fields (``id``, ``name``, ``category``, ``severity``,
    ``confidence``, ``url``, ``evidence``, ``impact``, ``remediation``)
    describe the finding for reports; ``gate_finding`` fills the honesty
    spine below them.

    Evidence envelope (provenance-strict verification): a finding is
    ``verified`` only when it carries replayable proof — the exact request
    that demonstrated the vulnerability plus the response marker that
    confirmed it. Prose in ``evidence`` alone is analyst-readable, not
    proof.
    """

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
        """Serialize the finding (proof envelope included) for JSON reports."""
        return asdict(self)

    def has_replayable_proof(self) -> bool:
        """True when the proof envelope is sufficient for a machine retest.

        Marker proofs need method + URL + response marker; timing proofs
        (confirmation was a reproducible response delay, not a substring)
        need method + URL + a positive delay threshold.
        """
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
    """One HTML form discovered during the crawl: where it posts, how, and
    its fields with their current values/types (``input_types`` maps names
    to the input ``type``, e.g. ``password`` — values are defaults)."""
    page_url: str
    action: str
    method: str
    inputs: dict[str, str] = field(default_factory=dict)
    input_types: dict[str, str] = field(default_factory=dict)

@dataclass(slots=True)
class ScanResult:
    """The finished scan: target identity, coverage, findings, and errors.

    ``checks_run`` names the modules that executed; ``summary``,
    ``total_findings`` and ``verified_findings`` are computed by
    ``to_dict()`` so reports always reflect the final finding list.
    """

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
    exclude_patterns: list[str] = field(default_factory=list)
    # --modules selection (canonical registry keys) that restricted this
    # scan's module fan-out; empty means every mode-appropriate module ran.
    modules: list[str] = field(default_factory=list)
    # Target fingerprint derived from crawled page headers/paths after the
    # crawl phase. See WebScanner._build_target_profile for the key schema.
    target_profile: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize the result for JSON reports, including the computed
        severity summary and the total/verified finding counts."""
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
            "exclude_patterns": list(self.exclude_patterns),
            "modules": list(self.modules),
            "summary": summary,
            "total_findings": len(self.findings),
            "verified_findings": sum(1 for f in self.findings if f.verified),
            "unique_issue_count": len({f.id for f in self.findings}),
            "target_profile": self.target_profile,
        }

# Registry of scan modules selectable via --modules / WebScanner(modules=...).
# Keys are the short CLI names; each entry maps to (module file, class name)
# inside xploit.modules. The dict order is the canonical fan-out order: an
# explicit --modules selection keeps this order (not the order typed) so
# restricted scans stay deterministic.
MODULE_REGISTRY: dict[str, tuple[str, str]] = {
    "general": ("general", "GeneralModule"),
    "exposure": ("exposure", "ExposureModule"),
    "data": ("sensitive_data", "SensitiveDataModule"),
    "sqli": ("sqli", "SQLInjectionModule"),
    "xss": ("xss", "XSSModule"),
    "cmd": ("injection_advanced", "CommandTraversalModule"),
    "logic": ("logic_vulnerabilities", "LogicVulnerabilityModule"),
    "auth": ("auth_advanced", "AdvancedAuthModule"),
    "advanced": ("advanced_injection", "MultiVectorInjectionModule"),
    "brute": ("brute_force", "BruteForceModule"),
}

# Friendly spellings that resolve to the canonical registry keys above.
MODULE_ALIASES: dict[str, str] = {
    "traversal": "cmd",
    "command": "cmd",
    "sensitive": "data",
    "sensitive-data": "data",
    "injection": "advanced",
    "multivector": "advanced",
    "multi-vector": "advanced",
}


def parse_module_keys(raw: str | Iterable[str] | None) -> list[str]:
    """Normalize a --modules selection to canonical registry keys.

    Accepts a comma-separated string or a list of them (matching the
    repeatable CLI flag). Keys are lowercased and stripped, aliases resolve
    to the canonical key, duplicates are dropped. The result follows the
    canonical MODULE_REGISTRY order. Unknown names raise ValueError listing
    every valid key — fail fast at construction, not mid-scan.
    """
    parts: list[str] = []
    for chunk in ([raw] if isinstance(raw, str) else (raw or [])):
        parts.extend(chunk.split(","))
    keys: list[str] = []
    for part in parts:
        name = part.strip().lower()
        if not name:
            continue
        name = MODULE_ALIASES.get(name, name)
        if name not in MODULE_REGISTRY:
            valid = ", ".join(list(MODULE_REGISTRY) + sorted(MODULE_ALIASES))
            raise ValueError(
                f"unknown scan module {part.strip()!r}; "
                f"valid modules: {valid}"
            )
        if name not in keys:
            keys.append(name)
    order = {key: i for i, key in enumerate(MODULE_REGISTRY)}
    return sorted(keys, key=order.__getitem__)


def load_module_class(key: str) -> type:
    """Import and return the scan-module class for a registry key.

    Lazy import keeps `xploit.scanner`'s import cheap — scan() only pays
    for the modules it actually runs.
    """
    module_name, class_name = MODULE_REGISTRY[key]
    module = importlib.import_module(f"{__package__}.modules.{module_name}")
    return getattr(module, class_name)


SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "postgresql query failed",
    "sqlite error",
    "unrecognized token",
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
    """Normalize a target URL for scanning.

    Strips whitespace, prepends ``http://`` when no scheme is given (other
    schemes are rejected — only ``http``/``https`` scan), drops userinfo
    (``user:pass@``) so credentials never land in logs or reports, and
    discards the fragment.
    """
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


def normalize_dedupe_url(url: str) -> str:
    """Canonical URL form for finding-dedupe keys.

    A GET hit on the crawled page URL (``http://x/search?q=a``) and a POST
    hit on the bare form action (``http://x/search``) are the same logical
    target, so the query string, fragment, host case, default ports, and
    trailing-slash noise are all folded away here. Only dedupe keys use
    this form — the finding's own ``url`` is left untouched for the report.
    Unparseable input falls back to the raw string so dedupe can never
    crash a scan.
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return url
        path = parsed.path.rstrip("/") or ""
        return f"{parsed.scheme.lower()}://{_netloc_key(parsed)}{path}"
    except (ValueError, TypeError):
        return url


def finding_dedupe_key(finding: "Finding") -> tuple:
    """Canonical dedupe key for a finding: (id, normalized URL, parameter).

    The HTTP method is deliberately excluded — the same vulnerability found
    via both GET and POST is one finding, reported once (first reporter
    wins; its method is what the report shows).
    """
    return (finding.id, normalize_dedupe_url(finding.url), finding.parameter or "")
def parse_proxy_url(raw: str | None) -> dict[str, str] | None:
    """Normalize a --proxy value to the ``{"http": ..., "https": ...}``
    mapping ``requests`` expects for a session.

    A bare ``host:port`` is treated as ``http://host:port`` (the Burp-style
    local-intercept spelling). Only http/https proxies are accepted, and a
    value with no host (or an unparseable port) fails fast at scanner
    construction instead of mid-scan. Proxy credentials in the URL
    (``http://user:pass@host:port``) are preserved verbatim — callers must
    not log the normalized value. Returns None when no proxy was given.
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        raise ValueError("proxy must be a non-empty URL")
    if "://" not in value:
        value = f"http://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"proxy scheme must be http or https, got {parsed.scheme!r}")
    try:
        host = parsed.hostname
        _port = parsed.port  # raises ValueError on an out-of-range port
    except ValueError as exc:
        raise ValueError(f"invalid proxy URL {raw!r}: {exc}") from exc
    if not host:
        raise ValueError(f"invalid proxy URL {raw!r}: no host")
    normalized = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return {"http": normalized, "https": normalized}


def same_origin(url: str, root: str) -> bool:
    """True when ``url`` shares ``root``'s scheme and (case-insensitive)
    host-with-port. Default ports are stripped, so ``https://a:443`` matches
    ``https://a``; unparseable URLs are out of scope (False)."""
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
    """Return the URL's query parameter names, deduplicated, in first-seen
    order. These become injection entry points for the scan modules."""
    return list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())

def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings by severity. Unknown severity labels are kept as their
    own bucket instead of being dropped, so a module's new label still
    shows up in reports."""
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

def is_binary_asset(url: str, res=None) -> bool:
    """Return True when *url* or *res* represents a binary/media asset.

    Decision order:
    1. If a response object is provided, its Content-Type header is checked
       first. A Content-Type of text/html, text/*, application/json, or
       application/javascript is never considered binary (False). A prefix
       in _BINARY_CT_PREFIXES returns True.
    2. Fall through to the URL path extension: if the lowercase extension is
       in BINARY_ASSET_EXTS, return True.
    3. Otherwise return False.

    ``res`` may be None (for pre-fetch URL checks) or any object with a
    ``headers`` dict-like attribute (requests.Response or the Resp test stub).
    """
    if res is not None:
        raw_ct: str = ""
        # Support both requests.Response (.headers dict-like) and test stubs
        # that carry a plain dict in .headers.
        try:
            raw_ct = (res.headers.get("Content-Type") or "").lower()
        except (AttributeError, TypeError):
            raw_ct = ""
        if raw_ct:
            ct = raw_ct.split(";")[0].strip()
            # These types are never binary assets even if the extension looks bad.
            if (ct.startswith("text/") or ct in (
                    "application/json", "application/javascript",
                    "application/x-javascript")):
                return False
            for prefix in _BINARY_CT_PREFIXES:
                if ct.startswith(prefix):
                    return True
    # Fallback: extension check on the URL path.
    try:
        path = urlparse(url).path
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        return f".{ext}" in BINARY_ASSET_EXTS if ext else False
    except (ValueError, AttributeError):
        return False


class WebScanner:
    """Configurable web vulnerability scanner.

    Lifecycle: create with the target and tuning knobs, optionally set the
    callback hooks (``on_progress``/``on_finding``/``on_request``, plus the
    parallel-module ``on_module_start``/``on_module_done``), then call
    :meth:`scan`, which runs crawl -> entry-point discovery -> module
    fan-out and returns a :class:`ScanResult`.

    Key knobs (see ``--help`` in ``xploit.cli`` for the CLI mirror):

    - ``mode``: ``passive`` (headers/exposure/data only), ``active`` (adds
      injection modules), or ``full`` (adds heavy SSTI/LDAP/NoSQL/XML and
      brute force).
    - ``threads``: concurrency for crawling and per-module probe requests.
    - ``parallel_modules``: how many scan modules may run concurrently
      (default 4; ``1`` restores the sequential loop).
    - ``modules``: run only the named scan modules (canonical registry
      keys, e.g. ``modules="xss,sqli"``), validated eagerly so a typo fails
      fast. An explicit selection overrides the mode-based module gating in
      :meth:`scan` — the caller asked for exactly these modules.
    - ``rate_limit``/``jitter``: minimum request spacing plus a random
      smoothing delay, to avoid metronomic traffic signatures.
    - ``read_deadline``: hard total bound for reading one response body —
      ``requests``' ``timeout`` is per socket operation, so without this a
      slow-drip server bypasses ``--timeout`` and the scan hangs.
    - ``scope_prefix``/``exclude``: restrict crawling to a path prefix, or
      skip URLs matching Python regexes (compiled eagerly, fail fast).

    Safety baked into the request layer: retries are idempotent-only
    (GET/HEAD/OPTIONS, never POST), redirects are followed manually with a
    loop bound and same-origin rule so payloads never leave the origin,
    and response bodies are capped at ``MAX_BODY_BYTES``.
    """

    # Modules (e.g. general.py CORS) call scanner.is_binary_asset(url, res);
    # the implementation is the module-level function above — expose it on
    # the class so production scanners take the Content-Type-aware path,
    # not the extension-only fallback.
    is_binary_asset = staticmethod(is_binary_asset)

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
        exclude: list[str] | None = None,
        threads: int = 5,
        parallel_modules: int = 4,
        modules: str | list[str] | None = None,
        user_agent: str | None = DEFAULT_USER_AGENT,
        verify: bool = True,
        read_deadline: float | None = None,
        jitter: float = 0.0,
        proxy: str | None = None,
    ) -> None:
        self.target = target
        self.root = normalize_url(target)
        self.max_pages = max(1, max_pages)
        self.depth = max(0, depth)
        self.timeout = timeout
        self.mode = mode
        self.rate_limit = rate_limit
        self.scope_prefix = self._normalize_scope_prefix(scope_prefix)
        # URL exclusion patterns (--exclude): each is a Python regex matched
        # against the full URL with re.search. Compiled eagerly so a bad
        # pattern fails fast with a clear error instead of mid-crawl.
        self.exclude: list[str] = list(exclude or [])
        self._exclude_res: list[re.Pattern[str]] = self._compile_exclude_patterns(self.exclude)
        self.threads = max(1, threads)
        # How many scan modules may run concurrently (default 4; 1 restores
        # the historical sequential loop). Each module already fans its own
        # probes out over self.threads, so module-level parallelism
        # multiplies in-flight requests — lower it for fragile targets.
        self.parallel_modules = max(1, parallel_modules)
        # --modules: run only the named scan modules (canonical registry
        # keys, comma-separated string or list). Validated eagerly so a typo
        # fails fast at construction instead of mid-scan; an explicit
        # selection overrides the mode-based gating in scan(). None means
        # run every mode-appropriate module.
        self.modules = parse_module_keys(modules) if modules is not None else None
        if modules is not None and not self.modules:
            raise ValueError("--modules requires at least one module name")
        self.verify = verify
        # None (e.g. a hand-built CLI Namespace that predates --user-agent)
        # means "the default"; an empty/blank value fails fast instead of
        # silently sending a blank User-Agent header.
        if user_agent is None:
            user_agent = DEFAULT_USER_AGENT
        if not user_agent.strip():
            raise ValueError("user_agent must be a non-empty string")
        self.user_agent = user_agent
        # Proxy routing (--proxy): validated eagerly via parse_proxy_url
        # so a bad value fails at construction, not mid-scan. Stored as
        # the requests session mapping; the session applies it to every
        # request, including manual redirect hops in _request.
        self.proxies = parse_proxy_url(proxy) or {}
        self.proxy = self.proxies.get("http")
        if read_deadline is not None and read_deadline <= 0:
            raise ValueError("read_deadline must be positive")
        if jitter < 0:
            raise ValueError("jitter must be >= 0")
        # Random extra delay (seconds) added to each request's spacing.
        # A fixed --rate-limit produces metronomic traffic that naive
        # rate-based WAF rules fingerprint easily; jitter smooths it out.
        self.jitter = jitter
        # Total bound for reading one response body (see _consume_body).
        # requests' `timeout` is per socket operation, so without this a
        # slow-drip server bypasses --timeout entirely and the scan hangs.
        self.read_deadline = (max(timeout * self.READ_DEADLINE_FACTOR,
                                  self.MIN_READ_DEADLINE)
                              if read_deadline is None else read_deadline)
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
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            # Scale the urllib3 connection pool with --threads: the pool
            # defaults (10 conns/host) otherwise cap keep-alive reuse on
            # high-thread scans, forcing needless TCP+TLS handshakes while
            # threads sit on a too-small pool. Never shrink below the
            # urllib3 defaults for low thread counts.
            pool_connections=max(10, self.threads),
            pool_maxsize=max(10, self.threads),
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        if self.proxies:
            self.session.proxies.update(self.proxies)

        self.session.headers.update({"User-Agent": user_agent})
        
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.pages: dict[str, requests.Response] = {}
        self.forms: list[FormTarget] = []
        self._normalized_seen: Set[str] = set()
        self._checks_run: list[str] = []
        self._last_request_at = 0.0
        # Count of binary/media asset URLs skipped during the crawl (not
        # stored in self.pages). Useful for reporting and diagnostics.
        self.assets_skipped: int = 0
        # Target fingerprint populated by _build_target_profile() after the
        # crawl. Keys: server, powered_by, stack_hints, dbms_hint,
        # dbms_signals, html_pages, forms, query_params,
        # external_form_actions.
        self.target_profile: dict = {}
        # Param-hint pre-pass results populated by _build_param_hints() in
        # active/full modes right after _build_target_profile(). Key:
        # (endpoint_url, METHOD_upper, param_name). Value dict:
        # {baseline_status, baseline_len, reflects, changes}.
        # Modules use getattr(scanner, 'param_hints', {}) so old test fakes
        # without this attribute keep working.
        self.param_hints: dict = {}
        self.on_progress: Callable[[int, int, str], None] | None = None
        self.on_finding: Callable[[Finding], None] | None = None
        # Per-module lifecycle hooks, used by the parallel-module UI.
        # on_module_start(name); on_module_done(name, findings_added, seconds).
        # A raising hook must never kill a scan, so the parallel runner
        # guards every hook call.
        self.on_module_start: Callable[[str], None] | None = None
        self.on_module_done: Callable[[str, int, float], None] | None = None
        # Fired on every HTTP request attempt (any thread). Lets the UI show
        # liveness during long sequential module runs instead of appearing
        # frozen on a single phase label.
        self.on_request: Callable[[int], None] | None = None
        self._request_count = 0

    def _run_one_module(self, module) -> None:
        """Execute a single scan module with a crash guard.

        Safe to call from worker threads: error and bookkeeping appends
        are serialized under the scanner lock, and findings flow through
        BaseModule.add_finding's locked dedupe.
        """
        try:
            module.run()
        except Exception as exc:
            # One crashing module must not discard every other module's findings.
            with self._lock:
                self.errors.append(f"Module {module.name} crashed: {exc}")
        with self._lock:
            self._checks_run.append(module.name)

    def _run_one_module_tracked(self, module) -> None:
        """Parallel-mode wrapper: fire the module lifecycle hooks around
        _run_one_module. Hook exceptions are swallowed — a UI callback must
        never fail a scan."""
        name = module.name
        if self.on_module_start:
            try:
                self.on_module_start(name)
            except Exception:
                pass
        t0 = time.monotonic()
        self._run_one_module(module)
        # Per-module count from the module itself: a global len() diff would
        # race with sibling modules appending concurrently.
        added = getattr(module, "findings_added", 0)
        if self.on_module_done:
            try:
                self.on_module_done(name, added, time.monotonic() - t0)
            except Exception:
                pass

    def _run_modules_parallel(self, modules_to_run) -> None:
        """Run scan modules concurrently on a small thread pool.

        Module count here is worker count, not probe threads: each module
        already fans its own probes out over self.threads, so this
        multiplies in-flight requests by up to --parallel-modules.

        Keeps the same on_progress contract as the sequential loop —
        bounded (current, total) events plus a final "Checks complete" —
        so API consumers don't lose their completion signal.
        """
        total = len(modules_to_run)
        workers = max(1, min(self.parallel_modules, total))
        finished = [0]

        def _track(module) -> None:
            self._run_one_module_tracked(module)
            with self._lock:
                finished[0] += 1
                n = finished[0]
            if self.on_progress:
                self.on_progress(n, total, f"Completed {module.name}")

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="xploit-module") as executor:
            list(executor.map(_track, modules_to_run))
        if self.on_progress:
            self.on_progress(total, total, "Checks complete")

    def scan(self) -> ScanResult:
        """Run the full pipeline: crawl, entry-point discovery, module fan-out.

        Always-on (passive) modules run in every mode; ``active`` adds the
        injection modules; ``full`` adds the heavy multi-vector and
        brute-force modules. One crashing module is recorded in ``errors``
        and never discards the other modules' findings. An empty crawl
        yields a partial result rather than a bare exception.
        """
        started = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        start_time = time.monotonic()
        
        self._crawl()
        self._build_target_profile()
        if self.mode in {ACTIVE, FULL}:
            self._build_param_hints()
        
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
        if self.modules is not None:
            # Explicit --modules selection: run only the named modules, in
            # canonical registry order. Overrides the mode-based gating below —
            # the caller asked for exactly these modules.
            modules_to_run = [load_module_class(key)(self) for key in self.modules]
        else:
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

        if self.parallel_modules <= 1 or len(modules_to_run) <= 1:
            for i, module in enumerate(modules_to_run, start=1):
                if self.on_progress:
                    self.on_progress(i - 1, len(modules_to_run), f"Running {module.name}")
                self._run_one_module(module)
                if self.on_progress:
                    phase = "Checks complete" if i == len(modules_to_run) else f"Completed {module.name}"
                    self.on_progress(i, len(modules_to_run), phase)
        else:
            self._run_modules_parallel(modules_to_run)

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
            exclude_patterns=list(self.exclude),
            modules=list(self.modules or []),
            target_profile=self.target_profile,
        )

    # Bound for manual redirect following. requests' own default is 30, which
    # turns a redirect loop into a 30-request stall before failing.
    MAX_REDIRECTS = 10
    # Hard cap on response-body bytes read per request (memory bound). Pages
    # bigger than this are truncated; _crawl already skips HTML parsing above
    # 5 MB, so analysis never depends on the tail.
    MAX_BODY_BYTES = 10_000_000
    # Total seconds allowed for reading one response body, derived from the
    # per-request --timeout. requests' timeout is per socket operation, so a
    # server dribbling bytes just under the timeout holds the connection open
    # forever; this deadline bounds the read phase instead.
    READ_DEADLINE_FACTOR = 5
    MIN_READ_DEADLINE = 30.0

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
                stream=True,  # body is consumed by _consume_body with a hard deadline
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
                # Hop bodies are never read — release the connection before
                # following so streamed responses don't pin pool connections.
                res.close()
                self._respect_rate_limit()
                try:
                    res = self.session.request(
                        next_method, target, timeout=self.timeout,
                        allow_redirects=False,
                        verify=self.verify,
                        stream=True,
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

        res = self._consume_body(res, method, res.url, quiet=quiet)

        if not res.ok and not quiet and res.status_code != 404:
            # 404s are expected during sensitive-file probing; logging every
            # one as an error buries real failures in noise.
            self.errors.append(f"{method} {url}: {res.status_code} {res.reason}")
        return res

    def _consume_body(self, res: requests.Response, method: str, url: str,
                      *, quiet: bool = False) -> requests.Response:
        """Read the response body with a hard total deadline.

        `requests`' `timeout` applies per socket operation, so a server that
        dribbles one byte every (timeout - 1) seconds holds the connection
        open forever while `res.text`/`res.content` never return — the
        multi-minute `poll()` stall observed on full/active scans. A single
        blocking `read()` can't be deadline-checked from the same thread
        (small chunks make every large page crawl; big chunks stall on a
        drip), so the body is read in a daemon thread with large chunks and
        the deadline is enforced with `join()`. On expiry the socket is shut
        down for reading to unblock the reader; whatever arrived by then is
        kept (truncated) so the passive modules still see partial content
        instead of the scan hanging. Never raises: a body-read failure must
        not kill the crawl.
        """
        box: dict[str, object] = {}

        def _read() -> None:
            chunks: list[bytes] = []
            total = 0
            note = ""
            try:
                # Lenient length enforcement: a server that declares
                # Content-Length: N but closes after fewer bytes should yield
                # those bytes, not an IncompleteRead that discards them. (A
                # shortfall is still reported below via the header check.)
                try:
                    res.raw.enforce_content_length = False
                except Exception:
                    pass
                for chunk in res.iter_content(chunk_size=65536):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= self.MAX_BODY_BYTES:
                        note = (f"response body exceeded "
                                f"{self.MAX_BODY_BYTES:,} bytes; truncated")
                        break
            except Exception as exc:
                # Mid-body failure (connection reset, ...): keep what
                # arrived; partial content still feeds the passive modules.
                note = (f"response body read failed after {total:,} "
                        f"byte(s): {exc}")
            box["chunks"] = chunks
            box["note"] = note

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(max(0.0, self.read_deadline))
        if reader.is_alive():
            # Deadline hit while a read() is still blocked. Shut the socket
            # down for reading: this wakes the reader's blocked recv()
            # promptly. (A cross-thread res.close() instead blocks on the
            # BufferedReader lock held by the in-flight read — the exact
            # hang this deadline exists to fix.)
            try:
                shutdown = getattr(res.raw, "shutdown", None)
                if shutdown is not None:
                    shutdown()
            except Exception:
                pass
            reader.join(self.timeout + 1.0)
            chunks = box.get("chunks", [])
            total = sum(len(c) for c in chunks)
            note = (f"response body read exceeded the {self.read_deadline:g}s "
                    f"deadline; kept {total:,} byte(s) received so far")
        else:
            # .get with defaults: even if the reader thread died to a
            # BaseException (not caught by `except Exception` above), the
            # crawl must not die with it.
            chunks = box.get("chunks", [])
            note = box.get("note", "")
        if note:
            # Truncated or failed read: the socket may still hold unread
            # data, so close it outright instead of handing a dirty
            # connection back to the pool.
            try:
                res.raw.close()
            except Exception:
                pass
        # Populate the cache requests normally fills, so .content/.text
        # behave exactly as before for every module.
        res._content = b"".join(chunks)
        res._content_consumed = True
        if not note:
            # With lenient length enforcement a short body no longer raises;
            # report the shortfall explicitly so truncated pages are visible
            # instead of silently feeding partial content to the modules.
            declared = (res.headers.get("Content-Length") or "").strip()
            if declared.isdigit() and int(declared) > len(res._content):
                note = (f"server closed the connection after "
                        f"{len(res._content):,} of {int(declared):,} "
                        f"declared byte(s)")
        res.close()
        if note and not quiet:
            self.errors.append(f"{method} {url}: {note}")
        return res

    def _build_target_profile(self) -> None:
        """Fingerprint the target stack from crawled page headers and URLs.

        Scores DBMS evidence from four independent signals and sets
        self.target_profile with:
          server, powered_by, stack_hints (sorted list of human labels),
          dbms_hint ('mssql'|'mysql'|'postgres'|'unknown'),
          dbms_signals (list of short evidence strings),
          html_pages, forms, query_params, external_form_actions.

        Called by scan() right after _crawl() so all modules have access to
        the profile via self.scanner.target_profile.
        """
        from urllib.parse import urlparse

        # --- Collect representative header values across all crawled pages ---
        server_vals: list[str] = []
        powered_by_vals: list[str] = []
        has_asp_version: bool = False

        for page_url, page_res in self.pages.items():
            if page_res is None:
                continue
            headers_lower = {k.lower(): v for k, v in page_res.headers.items()}
            sv = headers_lower.get("server", "")
            if sv:
                server_vals.append(sv.lower())
            pb = headers_lower.get("x-powered-by", "")
            if pb:
                powered_by_vals.append(pb.lower())
            if "x-aspnet-version" in headers_lower:
                has_asp_version = True

        # Use the most common server/powered-by value for scoring
        server = max(set(server_vals), key=server_vals.count) if server_vals else ""
        powered_by = max(set(powered_by_vals), key=powered_by_vals.count) if powered_by_vals else ""

        # --- URL-based signals ---
        has_asp_path = any(
            urlparse(u).path.lower().endswith((".asp", ".aspx"))
            for u in self.pages
        )
        has_php_path = any(
            urlparse(u).path.lower().endswith(".php")
            for u in self.pages
        )

        # --- DBMS scoring ---
        mssql_score = 0
        mysql_score = 0
        postgres_score = 0
        signals: list[str] = []
        stack_hints: list[str] = []

        # MSSQL / IIS / ASP.NET
        if "microsoft-iis" in server:
            mssql_score += 1
            signals.append("Server: Microsoft-IIS")
        if "asp.net" in powered_by:
            mssql_score += 1
            signals.append("X-Powered-By: ASP.NET")
        if has_asp_path:
            mssql_score += 1
            signals.append(".asp/.aspx path extension")
        if has_asp_version:
            mssql_score += 1
            signals.append("X-AspNet-Version header present")

        # MySQL / PHP
        if has_php_path:
            mysql_score += 1
            signals.append(".php path extension")
        if "php" in server or "php" in powered_by:
            mysql_score += 1
            signals.append("PHP in Server/Powered-By")

        # PostgreSQL
        if "postgres" in server or "postgres" in powered_by:
            postgres_score += 2
            signals.append("postgres in Server/Powered-By")

        # Stack hints (human-readable labels)
        if mssql_score >= 1:
            if "asp.net" in powered_by or "microsoft-iis" in server:
                stack_hints.append("ASP.NET/IIS")
        if mysql_score >= 1:
            stack_hints.append("PHP")
        if postgres_score >= 1:
            stack_hints.append("PostgreSQL")

        # dbms_hint: winner must score >= 2
        scores = {"mssql": mssql_score, "mysql": mysql_score, "postgres": postgres_score}
        best_dbms = max(scores, key=scores.__getitem__)
        dbms_hint = best_dbms if scores[best_dbms] >= 2 else "unknown"
        # Only keep signals that contributed to the winning hint (if known),
        # otherwise keep all collected signals so 'unknown' is still useful.
        dbms_signals = signals if dbms_hint == "unknown" else [
            s for s in signals
            if (dbms_hint == "mssql" and s in (
                "Server: Microsoft-IIS", "X-Powered-By: ASP.NET",
                ".asp/.aspx path extension", "X-AspNet-Version header present"))
            or (dbms_hint == "mysql" and s in (
                ".php path extension", "PHP in Server/Powered-By"))
            or (dbms_hint == "postgres" and s in ("postgres in Server/Powered-By",))
        ]

        # --- Coverage metrics ---
        html_pages = sum(
            1 for u, r in self.pages.items()
            if r is not None and "text/html" in r.headers.get("Content-Type", "").lower()
        )

        query_params = len({
            (u, k)
            for u in self.pages
            for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True)
        })

        root_host = urlparse(self.root).netloc.lower()
        external_form_actions = sum(
            1 for f in self.forms
            if urlparse(f.action).netloc.lower() not in ("", root_host)
        )

        self.target_profile = {
            "server": server,
            "powered_by": powered_by,
            "stack_hints": sorted(stack_hints),
            "dbms_hint": dbms_hint,
            "dbms_signals": dbms_signals,
            "html_pages": html_pages,
            "forms": len(self.forms),
            "query_params": query_params,
            "external_form_actions": external_form_actions,
        }

    _PARAM_HINT_MARKER = "xp7f3a9z"
    _PARAM_HINT_CAP = 80

    def _build_param_hints(self) -> None:
        """Cheap shared learning pre-pass: probe each URL param / form field
        with a benign marker to learn which parameters actually reflect or
        change the response.  Called by scan() after _build_target_profile()
        ONLY when mode is ACTIVE or FULL.

        Results are stored in self.param_hints keyed by
        (endpoint_url, METHOD_upper, param_name).  Modules access them via
        self.param_hint(endpoint, method, param) or directly via
        getattr(scanner, 'param_hints', {}).

        At most _PARAM_HINT_CAP params are probed (deterministic order:
        pages sorted, forms in crawl order) to keep the pre-pass cheap.
        A request returning None means we record no hint for that param so
        the module falls back to full probing.
        """
        MARKER = self._PARAM_HINT_MARKER
        cap = self._PARAM_HINT_CAP
        probed = 0

        def _differs(res_a, res_b, base_len: int) -> bool:
            if res_a is None or res_b is None:
                return False
            if res_a.status_code != res_b.status_code:
                return True
            delta = abs(len(res_b.text) - base_len)
            return delta > max(64, 0.05 * base_len)

        # --- URL query params ---
        for url in sorted(self.pages):
            if probed >= cap:
                break
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            seen_params: set[str] = set()
            for param, orig_val in pairs:
                if probed >= cap:
                    break
                if param in seen_params:
                    continue
                seen_params.add(param)
                # Baseline: URL as-is
                baseline_res = self._request("GET", url, quiet=True)
                if baseline_res is None:
                    continue
                baseline_status = baseline_res.status_code
                baseline_len = len(baseline_res.text)
                # Marker probe: replace this param with MARKER
                marker_url = mutate_query(url, param, MARKER)
                marker_res = self._request("GET", marker_url, quiet=True)
                if marker_res is None:
                    continue
                # Quote probe: original value + single quote
                quote_url = mutate_query(url, param, orig_val + "'")
                quote_res = self._request("GET", quote_url, quiet=True)
                if quote_res is None:
                    continue
                reflects = MARKER in (marker_res.text or "")
                changes = (
                    _differs(baseline_res, marker_res, baseline_len)
                    or _differs(baseline_res, quote_res, baseline_len)
                )
                self.param_hints[(url, "GET", param)] = {
                    "baseline_status": baseline_status,
                    "baseline_len": baseline_len,
                    "reflects": reflects,
                    "changes": changes,
                }
                probed += 1

        # --- Form fields ---
        for form in self.forms:
            if probed >= cap:
                break
            method = form.method.upper()
            action = form.action
            for param, orig_val in form.inputs.items():
                if probed >= cap:
                    break
                # Baseline: submit form.inputs as-is
                if method == "GET":
                    baseline_res = self._request(
                        "GET", action, params=dict(form.inputs), quiet=True)
                else:
                    baseline_res = self._request(
                        "POST", action, data=dict(form.inputs), quiet=True)
                if baseline_res is None:
                    continue
                baseline_status = baseline_res.status_code
                baseline_len = len(baseline_res.text)
                # Marker probe: this field = MARKER, siblings keep defaults
                marker_data = dict(form.inputs)
                marker_data[param] = MARKER
                if method == "GET":
                    marker_res = self._request(
                        "GET", action, params=marker_data, quiet=True)
                else:
                    marker_res = self._request(
                        "POST", action, data=marker_data, quiet=True)
                if marker_res is None:
                    continue
                # Quote probe: this field = original value + single quote
                quote_data = dict(form.inputs)
                quote_data[param] = orig_val + "'"
                if method == "GET":
                    quote_res = self._request(
                        "GET", action, params=quote_data, quiet=True)
                else:
                    quote_res = self._request(
                        "POST", action, data=quote_data, quiet=True)
                if quote_res is None:
                    continue
                reflects = MARKER in (marker_res.text or "")
                changes = (
                    _differs(baseline_res, marker_res, baseline_len)
                    or _differs(baseline_res, quote_res, baseline_len)
                )
                self.param_hints[(action, method, param)] = {
                    "baseline_status": baseline_status,
                    "baseline_len": baseline_len,
                    "reflects": reflects,
                    "changes": changes,
                }
                probed += 1

        # Record coverage counts in target_profile
        params_inert = sum(
            1 for h in self.param_hints.values()
            if not h["reflects"] and not h["changes"]
        )
        self.target_profile["params_probed"] = len(self.param_hints)
        self.target_profile["params_inert"] = params_inert

    def param_hint(self, endpoint: str, method: str, param: str) -> dict | None:
        """Return the hint dict for (endpoint, METHOD_upper, param) or None.

        Modules should prefer this helper over direct dict access so they
        naturally get None (= full probing) for params that were not reached
        by the pre-pass cap or for scanner stubs in tests.
        """
        return self.param_hints.get((endpoint, method.upper(), param))

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

                    # Binary asset: don't store in self.pages (saves memory
                    # and keeps the injection entry-point list clean). Count
                    # instead so diagnostics can show how many were skipped.
                    if is_binary_asset(url, res):
                        self.assets_skipped += 1
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
                                # Skip binary assets by extension — no need to
                                # fetch images/fonts/media; they carry no
                                # injection entry points and bloat max_pages.
                                if is_binary_asset(link):
                                    self.assets_skipped += 1
                                    continue
                                norm = normalize_path(link)
                                if (link not in seen and norm not in self._normalized_seen
                                        and self._in_scope(link) and not self._excluded(link)):
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
        return [url for url in entry_points
                if self._in_scope(url) and not self._excluded(url)]

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

    @staticmethod
    def _compile_exclude_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(f"invalid --exclude pattern {pattern!r}: {exc}")
        return compiled

    def _excluded(self, url: str) -> bool:
        """True when any --exclude pattern matches the full URL."""
        return any(rx.search(url) for rx in self._exclude_res)

    def map_probes(self, func, items):
        """Run func(item) for every item concurrently, in input order.

        Probe requests are I/O-bound, so a thread pool sized by --threads
        (default 5) collapses the sequential probe phase dramatically —
        modules that fired hundreds of back-to-back requests now fan out.
        Findings still flow through BaseModule.add_finding, which serializes
        the dedupe check under the scanner lock, so finding order stays
        deterministic for a fixed input order. Per-item exceptions are
        recorded in self.errors (never raised), mirroring the module-level
        crash guard in scan(). With a single item or threads <= 1 the work
        runs inline: no pool overhead, fully deterministic for tests.
        """
        items = list(items)
        if not items:
            return
        if self.threads <= 1 or len(items) == 1:
            for item in items:
                self._guarded_probe(func, item)
            return
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads,
                thread_name_prefix="xploit-probe") as executor:
            futures = [executor.submit(self._guarded_probe, func, item)
                       for item in items]
            for future in futures:
                future.result()

    def _guarded_probe(self, func, item):
        try:
            func(item)
        except Exception as exc:
            with self._lock:
                self.errors.append(
                    f"Probe {getattr(func, '__name__', repr(func))} failed: {exc}")

    def _respect_rate_limit(self):
        if self.rate_limit <= 0 and self.jitter <= 0: return
        # Reserve the next slot under the lock so concurrent crawler threads
        # can't all observe a stale _last_request_at and burst together.
        # The sleep itself happens outside the lock.
        with self._lock:
            now = time.monotonic()
            gap = self.rate_limit
            if self.jitter > 0:
                gap += random.uniform(0, self.jitter)
            earliest = self._last_request_at + gap
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
            "unreachable", self.mode, self.scope_prefix, 0, [], [], 0, [], self.errors,
            exclude_patterns=list(self.exclude),
            modules=list(self.modules or []),
            target_profile=self.target_profile,
        )
