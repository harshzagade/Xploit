from __future__ import annotations

import base64
import calendar
import json
import re
import secrets
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urljoin, urlparse

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

# Technology/version banner headers. _check_headers() reports them per host
# on normal pages; _check_error_page_headers() compares an error page's
# copy against the same set.
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version")

# TLS certificate expiry: warn when the leaf certificate lapses within
# this many days; an already-expired certificate is a finding on its own.
_TLS_EXPIRY_WARNING_DAYS = 30

# security.txt (RFC 9116): a Contact: field line names a disclosure
# channel. Field names are case-insensitive; the value runs to end of
# line. A bare mention of "contact" inside prose is not a field.
_SECURITY_TXT_CONTACT_RE = re.compile(r"(?im)^contact\s*:\s*(.+?)\s*$")

# robots.txt sensitive-path audit (ROBOTS-001): a robots.txt Disallow
# entry naming an admin/backup/config-style path publishes hidden
# surface — the file itself is public, so any reader gets the target
# list. Only Disallow: lines are read; Allow: lines name public
# content. The segment set is deliberately tight: near-universal
# entries such as /login, /search, /cart, /tmp or /test are not leaks,
# so they are not flagged. A bare "Disallow: /" has no segments and
# never flags. Values are matched segment-wise (split on
# non-alphanumerics) so "/*.sql$" still matches "sql" while
# "/configure" does not match "config".
_ROBOTS_DISALLOW_RE = re.compile(r"(?im)^disallow\s*:\s*(.+?)\s*$")
_ROBOTS_SENSITIVE_SEGMENTS = frozenset({
    "admin", "administrator",
    "backup", "backups", "bak",
    "config", "configuration",
    "db", "database", "dump", "dumps", "sql",
    "private", "internal", "staging",
    "phpmyadmin", "cpanel", "webmail",
    "secret", "secrets", "credentials", "passwd", "htpasswd",
    "console", "manage", "management",
    "cgi", "git", "svn", "env", "logs", "debug",
})


def _robots_path_is_sensitive(path: str) -> bool:
    """True when a robots.txt Disallow path names sensitive surface.

    The value is split into lowercase alphanumeric segments, so
    "/admin/", "/.git/config" and "/*.sql$" all match while "/",
    "/configure" and "/search" do not.
    """
    segments = re.split(r"[^A-Za-z0-9]+", path or "")
    return any(
        seg.lower() in _ROBOTS_SENSITIVE_SEGMENTS for seg in segments if seg
    )


# Session-cookie name pattern, shared by the cookie audits and the
# cacheability audit: a response setting one of these names is serving an
# authenticated page.
_SESSION_COOKIE_RE = re.compile(
    r"(?i)(phpsessid|sessionid|sess|sid|jsessionid|aspsessionid|auth_token|remember_token)"
)

# Response cacheability audit (CACHE-001): path segments that mark a page
# as sensitive even when it sets no session cookie (an account page behind
# a bearer token, for instance). A sensitive page is cacheable when its
# Cache-Control says `public`, or carries none of private / no-store /
# no-cache — a shared cache may then serve one user's authenticated page
# to the next visitor.
_CACHE_SENSITIVE_SEGMENTS = frozenset({
    "account", "accounts", "profile", "settings", "dashboard", "admin",
    "checkout", "cart", "orders", "order", "payment", "payments",
    "billing", "private", "user", "users", "inbox", "messages",
    "security", "preferences", "wallet", "subscription",
})
_CACHE_SAFE_DIRECTIVES = frozenset({"private", "no-store", "no-cache"})

# Directory listing detection (DIRLIST-001): Apache mod_autoindex and
# nginx autoindex both emit "<title>Index of /path</title>" and
# "<h1>Index of /path</h1>". Both markers are required — a page merely
# discussing listings in prose carries at most one of them.
_DIRLIST_TITLE_RE = re.compile(
    r"<title[^>]*>\s*Index of\s+[^<]*</title\s*>", re.IGNORECASE
)
_DIRLIST_H1_RE = re.compile(
    r"<h1[^>]*>\s*Index of\s+[^<]*</h1\s*>", re.IGNORECASE
)


# JWT in URL (JWT-001): three base64url segments of 4+ characters, so
# dotted version strings like "1.2.3" never match. Shape alone is not
# enough — _jwt_alg() also requires the first segment to decode to a
# JSON object carrying "alg", which is a real JWT header.
_JWT_SHAPE_RE = re.compile(r"[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")


def _jwt_alg(value: str) -> str | None:
    """The ``alg`` of the first JWT-shaped token in ``value``, else None.

    A candidate must be three base64url segments of 4+ characters and
    its first segment must base64url-decode to a JSON object carrying
    an "alg" key — that is a real JWT header, not a random three-part
    token. The token itself is never returned or logged: only the
    algorithm name leaves this function, so reports never carry a
    bearer token.
    """
    if not value:
        return None
    for match in _JWT_SHAPE_RE.finditer(value):
        header_b64 = match.group(0).split(".")[0]
        try:
            padded = header_b64 + "=" * (-len(header_b64) % 4)
            header = json.loads(
                base64.urlsafe_b64decode(padded).decode("utf-8")
            )
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(header, dict) and isinstance(header.get("alg"), str):
            return header["alg"]
    return None


def _redact_jwt(value: str) -> str:
    """Replace every JWT-shaped token in ``value`` with a placeholder.

    The finding is *about* a URL that carries a bearer token, so the
    URL itself must never reach the report intact — the scanner would
    reproduce the leak it is flagging. Only the shape is kept.
    """
    return _JWT_SHAPE_RE.sub("<jwt-redacted>", value or "")


def _response_sets_session_cookie(res) -> bool:
    """True when the response sets a session-like cookie.

    Reads every Set-Cookie line (urllib3 getlist when available, else the
    single header requests exposes) and tests only the cookie NAME, so a
    cookie value containing e.g. 'sessionid' cannot fake it.
    """
    raw_cookies = res.headers.get("Set-Cookie", "")
    all_set_cookie = (
        res.raw.headers.getlist("Set-Cookie")
        if hasattr(res.raw, "headers") and hasattr(res.raw.headers, "getlist")
        else ([raw_cookies] if raw_cookies else [])
    )
    for cookie_str in all_set_cookie:
        if not cookie_str:
            continue
        name = cookie_str.split(";")[0].split("=")[0].strip()
        if name and _SESSION_COOKIE_RE.search(name):
            return True
    return False


def _override_honored(control, override, method: str) -> bool:
    """True when the override response proves the server routed the POST as ``method``.

    Both halves of the signal are required. First, the status must change:
    a server that ignores the header answers the override exactly like
    the control. Second, the override answer must either name the
    overridden method — word-boundary match, so "INPUT" or "compute"
    cannot fake it — while the control answer does not, or reach a 2xx
    answer the control did not reach (a PUT that creates a resource
    answers 201 where a POST answers 405), or answer 201/204 where the
    control answered some other 2xx (a POST returning a page versus a
    PUT creating a resource). A header-echo page fails the status half;
    a server that ignores the header fails both.
    """
    if control is None or override is None:
        return False
    status_c = getattr(control, "status_code", 0)
    status_o = getattr(override, "status_code", 0)
    if status_o == status_c:
        return False
    body_c = getattr(control, "text", "") or ""
    body_o = getattr(override, "text", "") or ""
    method_re = re.compile(r"\b" + re.escape(method) + r"\b")
    if method_re.search(body_o) and not method_re.search(body_c):
        return True
    if 200 <= status_o < 300 and not 200 <= status_c < 300:
        return True
    if status_o in (201, 204) and status_c not in (201, 204):
        return True
    return False


def _der_read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value at ``offset``.

    Returns (tag, value_bytes, next_offset). Only the short and long
    definite-length forms are supported — enough for a certificate's
    outer structure. Raises ValueError on truncation or a bad length.
    """
    if offset >= len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or offset + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    if offset + length > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:offset + length], offset + length


def _not_after_from_der(der: bytes) -> float | None:
    """Extract notAfter (epoch seconds) from a DER-encoded certificate.

    Walks Certificate -> TBSCertificate -> validity -> notAfter, so no
    ASN.1 library is needed. UTCTime (tag 0x17) and GeneralizedTime
    (0x18) are both handled; both are UTC ("Z") in practice for issued
    certificates, and a numeric offset suffix is ignored. Returns None
    when the structure is not a certificate.
    """
    try:
        tag, cert, _ = _der_read_tlv(der, 0)
        if tag != 0x30:
            return None
        tag, tbs, _ = _der_read_tlv(cert, 0)
        if tag != 0x30:
            return None
        offset = 0
        tag, _, offset = _der_read_tlv(tbs, offset)
        if tag == 0xA0:  # [0] version is optional
            _, _, offset = _der_read_tlv(tbs, offset)  # serialNumber
        # serialNumber already consumed above in the version case; in the
        # no-version case the read above WAS the serialNumber. Either way,
        # the next two fields are signature and issuer.
        for _ in range(2):
            _, _, offset = _der_read_tlv(tbs, offset)
        tag, validity, _ = _der_read_tlv(tbs, offset)
        if tag != 0x30:
            return None
        _, _, offset = _der_read_tlv(validity, 0)  # notBefore
        tag, raw, _ = _der_read_tlv(validity, offset)  # notAfter
        text = raw.decode("ascii")
        if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        elif tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
            year = int(text[0:4])
            rest = text[4:]
        else:
            return None
        month, day, hour, minute, second = (
            int(rest[i:i + 2]) for i in range(0, 10, 2)
        )
        return calendar.timegm(
            (year, month, day, hour, minute, second, 0, 0, 0)
        )
    except (ValueError, IndexError):
        return None


# TLS 1.0/1.1 support audit (TLS-002): deprecated protocol versions to
# probe, as (TLSVersion attribute, display label). RFC 8996 deprecated
# both; PCI DSS has required TLS 1.2+ since 2018. The attributes are
# resolved lazily (getattr) because accessing TLSVersion.TLSv1 raises a
# DeprecationWarning on Python 3.12+ and the HAS_TLSv1* flags may be
# absent on builds that cannot offer the version at all.
_TLS_OLD_VERSIONS = (("TLSv1", "TLS 1.0"), ("TLSv1_1", "TLS 1.1"))


def _tls_version_supported(host: str, port: int, version, timeout: float) -> bool:
    """True when the server completes a handshake pinned to ``version``.

    The context is pinned to exactly that version (minimum == maximum)
    and unverified — the certificate is never trusted, only the
    handshake outcome is read. Any failure (refused handshake, alert,
    timeout, unreachable host) returns False, which the caller reads as
    "not supported": a modern server rejecting the old version is the
    secure outcome, so there is nothing to flag.

    OpenSSL 3 ships at SECLEVEL=2 on Debian/Ubuntu, which refuses to
    even offer TLS 1.0/1.1 — without dropping the client to SECLEVEL=0
    the probe could never succeed and the check would silently never
    fire. The cipher string only widens what the client offers; the
    verdict still comes from whether the server completes the handshake.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        try:
            context.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError):
        return False


def _fetch_cert_not_after(host: str, port: int, timeout: float) -> float | None:
    """Return the leaf certificate's notAfter as epoch seconds, or None.

    Connects with an unverified context: the dates are read, never trusted,
    so an expired or self-signed certificate still yields its expiry
    instead of failing the handshake. Any connection/handshake failure
    returns None so the caller flags nothing.

    The dict form of ``getpeercert()`` is empty under CERT_NONE (the
    handshake retains no verified peer certificate), so the DER form is
    read and the validity parsed directly.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    return _not_after_from_der(der)


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
        self._check_cacheability()
        self._check_directory_listing()
        self._check_jwt_in_url()
        self._check_auth_issues()
        self._check_file_upload()
        self._check_clickjacking()
        if self.scanner.mode != PASSIVE:
            self._check_misconfig()
            self._check_trace_method()
            self._check_method_override()
            self._check_error_page_headers()
            self._check_tls_cert_expiry()
            self._check_tls_old_versions()
            self._check_security_txt()
            self._check_robots_txt()
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
            "referrer-policy": ("Missing Referrer-Policy", INFO, "CWE-200", "HDR-RP"),
            "permissions-policy": ("Missing Permissions-Policy", INFO, "CWE-693", "HDR-PP"),
        }
        if res.url.startswith("https://"):
            checks["strict-transport-security"] = ("Missing Strict-Transport-Security", LOW, "CWE-319", "HDR-HSTS")
        for h, (name, sev, cwe, fid) in checks.items():
            if h in headers:
                continue
            # The legacy Feature-Policy header is the predecessor of
            # Permissions-Policy: a site still sending it has set a
            # feature policy, so do not flag the newer name as missing.
            if h == "permissions-policy" and "feature-policy" in headers:
                continue
            if h == "content-security-policy":
                impact = "Browsers receive no server-defined content policy on this response, which weakens mitigation against injected scripts and untrusted resource loading."
            elif h == "referrer-policy":
                impact = "Without a Referrer-Policy the browser sends full URLs, including query strings that may carry tokens, as the Referer header to third parties."
            elif h == "permissions-policy":
                impact = "Without a Permissions-Policy the page leaves powerful browser features (camera, microphone, geolocation) available to any embedded content by default."
            else:
                impact = "Reduced client-side security."
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
            for header in _TECH_HEADERS:
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
        seen_cookie_names: set[str] = set()
        session_pattern = _SESSION_COOKIE_RE

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

                # __Host- / __Secure- prefix audit (HTTPS only — the
                # prefixes are meaningless over plain HTTP, and browsers
                # reject a prefixed cookie set over HTTP outright).
                if url.startswith("https://") and f"{cookie_name}_prefix" not in seen_cookie_names:
                    # Attribute values, for the __Host- rules (Domain must
                    # be absent, Path must be "/").
                    attr_values = {}
                    for seg in cookie_str.split(";")[1:]:
                        seg = seg.strip()
                        if not seg:
                            continue
                        key, _, value = seg.partition("=")
                        attr_values[key.strip().lower()] = value.strip()
                    lname = cookie_name.lower()
                    prefix_problem = None
                    if lname.startswith("__host-"):
                        if "secure" not in attr_names:
                            prefix_problem = "uses the __Host- prefix but is set without the Secure attribute"
                        elif "domain" in attr_values:
                            prefix_problem = "uses the __Host- prefix but sets a Domain attribute"
                        elif attr_values.get("path", "/") != "/":
                            prefix_problem = "uses the __Host- prefix but sets Path to something other than '/'"
                    elif lname.startswith("__secure-"):
                        if "secure" not in attr_names:
                            prefix_problem = "uses the __Secure- prefix but is set without the Secure attribute"
                    elif is_session_like:
                        prefix_problem = "is a session cookie set without the __Host- or __Secure- prefix"
                    if prefix_problem is not None:
                        seen_cookie_names.add(f"{cookie_name}_prefix")
                        self.add_finding(Finding(
                            id="COOK-004",
                            name="Session Cookie Missing __Host- / __Secure- Prefix",
                            category="Insecure Cookie Configuration",
                            severity=LOW,
                            confidence="High",
                            url=url,
                            evidence=f"Cookie '{cookie_name}' {prefix_problem}.",
                            parameter=cookie_name,
                            impact="Without a cookie prefix, a cookie set from a compromised subdomain or over an insecure channel can overwrite the session cookie (cookie tossing), letting an attacker fixate or hijack the session. A misused prefix is silently rejected by browsers, so the cookie the server thinks it set never takes effect.",
                            remediation="Name session cookies __Host-<name> (with Secure, Path=/ and no Domain) or __Secure-<name> (with Secure) so the browser refuses to accept them from anywhere else.",
                            cwe="CWE-1004"
                        ))


    def _check_cacheability(self):
        # Passive: inspects Cache-Control on pages already crawled, no new
        # requests. A page is sensitive when it sets a session cookie or
        # its path names account-like surface; it is cacheable when
        # Cache-Control says `public`, or carries none of private /
        # no-store / no-cache. Such a page can be stored by a shared cache
        # and served to the next visitor — web-cache deception by
        # misconfiguration rather than by a crafted URL.
        for url, res in self.scanner.pages.items():
            if res is None:
                continue
            path_segments = {
                seg.lower()
                for seg in re.split(r"[^A-Za-z0-9]+", urlparse(url).path or "")
                if seg
            }
            sensitive = bool(
                path_segments & _CACHE_SENSITIVE_SEGMENTS
            ) or _response_sets_session_cookie(res)
            if not sensitive:
                continue
            headers = {k.lower(): v for k, v in res.headers.items()}
            cache_control = headers.get("cache-control", "")
            directives = {
                part.strip().split("=")[0].lower()
                for part in cache_control.split(",")
                if part.strip()
            }
            if "public" in directives:
                reason = "Cache-Control: public"
            elif not directives & _CACHE_SAFE_DIRECTIVES:
                reason = (
                    "no Cache-Control header"
                    if not cache_control
                    else f"Cache-Control: {cache_control} (no private/no-store/no-cache)"
                )
            else:
                continue
            self.add_finding(Finding(
                id="CACHE-001",
                name="Sensitive Page Served With Cacheable Response",
                category="Insecure Cache Configuration",
                severity=LOW,
                confidence="High",
                url=url,
                evidence=f"Sensitive page served with {reason}.",
                impact="A shared or proxy cache may store this authenticated page and serve it to a different user, leaking account data, order history or session state.",
                remediation="Serve authenticated pages with Cache-Control: private, no-store (or no-cache) and add the same directives to any sensitive path.",
                cwe="CWE-524"
            ))

    def _check_directory_listing(self):
        # Directory listing detection (DIRLIST-001, LOW, CWE-548): a
        # crawled page whose body is an autoindex listing publishes the
        # directory's contents to anyone who asks. Apache mod_autoindex
        # and nginx autoindex both emit "<title>Index of /path</title>"
        # and "<h1>Index of /path</h1>"; both markers are required, so a
        # page merely discussing listings in prose never flags. Passive:
        # only pages already crawled are inspected, no new requests. One
        # finding per host, listing up to five URLs.
        listings: dict[str, list[str]] = {}
        for url, res in self.scanner.pages.items():
            if res is None:
                continue
            body = getattr(res, "text", "") or ""
            if not _DIRLIST_TITLE_RE.search(body):
                continue
            if not _DIRLIST_H1_RE.search(body):
                continue
            host = urlparse(url).netloc.lower()
            listings.setdefault(host, []).append(url)
        for host, urls in listings.items():
            shown = ", ".join(urls[:5])
            suffix = f" (+{len(urls) - 5} more)" if len(urls) > 5 else ""
            self.add_finding(Finding(
                id="DIRLIST-001",
                name="Directory Listing Exposed",
                category="Information Disclosure",
                severity=LOW,
                confidence="High",
                url=urls[0],
                evidence=(
                    f"Directory listing exposed on {host}: {len(urls)} "
                    f"page(s) serve an autoindex listing: {shown}{suffix}"
                ),
                impact=(
                    "A directory listing publishes the name of every file "
                    "in the directory — backups, config fragments, source "
                    "files — so an attacker can enumerate content the site "
                    "never links to."
                ),
                remediation=(
                    "Disable directory listings (Apache: Options -Indexes; "
                    "nginx: remove autoindex on) and return 403/404 for "
                    "unlinked directories instead."
                ),
                cwe="CWE-548",
            ))

    def _check_jwt_in_url(self):
        # JWT in URL (JWT-001): a JWT carried in a query string or a
        # Location header leaks into server access logs, browser history,
        # Referer headers and shared links — a bearer token that was
        # meant for an Authorization header can be replayed by anyone
        # who sees the URL. Passive: inspects crawled page URLs and
        # their Location headers, no new requests. A candidate must be
        # JWT-shaped AND decode to a header carrying "alg" (see
        # _jwt_alg), so random three-part tokens and version strings are
        # not flagged. Hits are grouped per (host, parameter) — the same
        # token repeated across pages is one finding — and the evidence
        # names the algorithm, never the token itself; the URL stored on
        # the finding is redacted for the same reason (see _redact_jwt).
        hits: dict[tuple[str, str, str], list[str]] = {}
        for url, res in self.scanner.pages.items():
            host = urlparse(url).netloc.lower()
            for name, value in parse_qsl(
                urlparse(url).query, keep_blank_values=True
            ):
                alg = _jwt_alg(value)
                if alg is not None:
                    hits.setdefault((host, name, alg), []).append(url)
            if res is None:
                continue
            headers = {k.lower(): v for k, v in res.headers.items()}
            alg = _jwt_alg(headers.get("location", ""))
            if alg is not None:
                hits.setdefault((host, "Location", alg), []).append(url)
        for (host, param, alg), urls in sorted(hits.items()):
            distinct = sorted(set(urls))
            # The URL itself carries the token: redact it before it
            # reaches the finding, or the report reproduces the leak.
            first_url = _redact_jwt(distinct[0])
            n = len(distinct)
            suffix = f" (+{n - 1} more URL(s))" if n > 1 else ""
            self.add_finding(Finding(
                id="JWT-001",
                name="JWT Exposed in URL",
                category="Information Disclosure",
                severity=MEDIUM,
                confidence="High",
                url=first_url,
                parameter=param,
                evidence=(
                    f"JWT (alg {alg}) in {param} on {host}, first seen on "
                    f"{first_url}{suffix}"
                ),
                impact="JWTs in URLs are written to server access logs, browser history, Referer headers and shared links, so a bearer token meant for an Authorization header can be replayed by anyone who sees the URL.",
                remediation="Move tokens out of URLs: send them in the Authorization header (or a Secure, HttpOnly, SameSite cookie) and stop putting them in query strings or redirect targets.",
                cwe="CWE-598",
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

    def _check_method_override(self):
        # X-HTTP-Method-Override test (MTHD-001): some frameworks let a
        # POST carry X-HTTP-Method-Override: PUT/DELETE and route the
        # request as that method, so a client that can only POST can still
        # reach PUT/DELETE handlers — method confusion that bypasses
        # method-based access control (a proxy blocking PUT but allowing
        # POST, for instance). One control POST (no header) and one
        # override POST per method go to the root URL with an empty body,
        # so no real handler runs with data; _override_honored() decides
        # from the response pair. No replayable proof is attached: a
        # --retest replay (plain POST, no header) cannot reproduce the
        # override, so the evidence text carries both statuses instead.
        # Runs only in non-passive modes: it sends requests outside the
        # crawl, like the TRACE probe.
        control = self.scanner._request("POST", self.scanner.root, quiet=True)
        honored: list[str] = []
        for method in ("PUT", "DELETE"):
            override = self.scanner._request(
                "POST", self.scanner.root, quiet=True,
                headers={"X-HTTP-Method-Override": method},
            )
            if _override_honored(control, override, method):
                honored.append(
                    f"{method}: control POST -> "
                    f"{getattr(control, 'status_code', '?')}, override -> "
                    f"{getattr(override, 'status_code', '?')}"
                )
        if not honored:
            return
        self.add_finding(Finding(
            id="MTHD-001",
            name="HTTP Method Override Honored",
            category="Security Misconfiguration",
            severity=MEDIUM,
            confidence="High",
            url=self.scanner.root,
            evidence=(
                "Server honored X-HTTP-Method-Override (" + "; ".join(honored)
                + "); the override response differs from the plain POST "
                "and names or executes the overridden method"
            ),
            impact="A client that can only send POST can reach PUT/DELETE handlers, so method-based access controls (PUT blocked at the proxy, POST allowed) are bypassed and state-changing handlers the server meant to restrict become callable.",
            remediation="Ignore or strip the X-HTTP-Method-Override header at the reverse proxy or framework (disable method-override middleware), and enforce authorization per handler rather than per HTTP method.",
            cwe="CWE-650",
        ))

    def _check_error_page_headers(self):
        # Header leak audit on error pages (ERRHDR-001): error pages are
        # often rendered by a different layer than the app's normal pages
        # (reverse-proxy default error page, framework error handler), so
        # they can leak a Server/X-Powered-By banner the app suppresses
        # everywhere else. Probe a path that cannot exist and compare the
        # error response's tech headers against the values seen on normal
        # (2xx) crawled pages for the same host. A header is a leak only
        # when its error-page value differs from every normal-page value
        # (or normal pages carry no such header at all) — a banner the
        # normal pages already disclose is the INFO-SVR/INFO-XPB finding's
        # job, not this one. A 2xx answer to the probe means the site
        # serves a catch-all page, so there is no error page to compare.
        host = urlparse(self.scanner.root).netloc.lower()
        baseline: dict[str, set[str]] = {}
        for page_url, page_res in self.scanner.pages.items():
            if page_res is None:
                continue
            if urlparse(page_url).netloc.lower() != host:
                continue
            if getattr(page_res, "status_code", 200) >= 300:
                continue
            headers = {k.lower(): v for k, v in page_res.headers.items()}
            for header in _TECH_HEADERS:
                value = headers.get(header)
                if value:
                    baseline.setdefault(header, set()).add(value)
        probe_url = urljoin(
            self.scanner.root, "xploit-404-probe-" + secrets.token_hex(8)
        )
        res = self.scanner._request("GET", probe_url, quiet=True)
        if res is None:
            return
        if getattr(res, "status_code", 200) < 400:
            return
        err_headers = {k.lower(): v for k, v in res.headers.items()}
        leaks: list[tuple[str, str, list[str]]] = []
        for header in _TECH_HEADERS:
            value = err_headers.get(header)
            if not value:
                continue
            if value in baseline.get(header, set()):
                continue
            leaks.append((header, value, sorted(baseline.get(header, set()))))
        if not leaks:
            return
        parts = []
        for header, value, normal in leaks:
            if normal:
                parts.append(
                    f"{header}: {value} (normal pages show: "
                    + ", ".join(normal) + ")"
                )
            else:
                parts.append(f"{header}: {value} (suppressed on normal pages)")
        self.add_finding(Finding(
            id="ERRHDR-001",
            name="Technology Header Disclosure on Error Page",
            category="Information Disclosure",
            severity=LOW,
            confidence="High",
            url=probe_url,
            evidence="; ".join(parts),
            impact="Error pages disclose server/framework banners that normal pages suppress, giving attackers a version fingerprint for targeted checks.",
            remediation="Apply the same header-suppression rules to error responses as to normal pages (strip Server/X-Powered-By at the reverse proxy, and serve custom error pages).",
            cwe="CWE-200",
        ))

    def _check_tls_cert_expiry(self):
        # TLS certificate expiry (TLS-001): read the leaf certificate's
        # notAfter over a raw TLS handshake and flag it when already
        # expired (MEDIUM — validating clients will refuse the connection)
        # or lapsing within 30 days (INFO — renewal warning). A healthy
        # certificate flags nothing. Only HTTPS targets have a certificate
        # to read; an unreachable host or a handshake failure flags nothing
        # rather than guessing. Runs only in non-passive modes: it opens a
        # connection outside the crawl, like the TRACE and error-page
        # probes. The check never trusts the certificate — the context is
        # unverified and only the expiry date is read.
        parsed = urlparse(self.scanner.root)
        if parsed.scheme.lower() != "https":
            return
        host = parsed.hostname
        if not host:
            return
        port = parsed.port or 443
        not_after = _fetch_cert_not_after(
            host, port, getattr(self.scanner, "timeout", 10)
        )
        if not_after is None:
            return
        now = datetime.now(timezone.utc).timestamp()
        days_left = int((not_after - now) // 86400)
        expiry = datetime.fromtimestamp(
            not_after, tz=timezone.utc
        ).date().isoformat()
        if days_left < 0:
            severity, name = MEDIUM, "TLS Certificate Expired"
            evidence = (
                f"TLS certificate for {host} expired "
                f"{-days_left} day(s) ago ({expiry})"
            )
            impact = (
                "Clients that validate certificates will refuse the "
                "connection, and an expired certificate offers no assurance "
                "the endpoint is still operated by its owner."
            )
            remediation = (
                "Renew the certificate and install the new one before the "
                "old one lapses; automate renewal so expiry cannot recur."
            )
        elif days_left <= _TLS_EXPIRY_WARNING_DAYS:
            severity, name = INFO, "TLS Certificate Expiring Soon"
            evidence = (
                f"TLS certificate for {host} expires in "
                f"{days_left} day(s) ({expiry})"
            )
            impact = (
                "The certificate will lapse soon; once expired, validating "
                "clients will refuse the connection."
            )
            remediation = (
                "Renew the certificate before it expires and confirm the "
                "new one is served."
            )
        else:
            return
        self.add_finding(Finding(
            id="TLS-001",
            name=name,
            category="TLS Certificate",
            severity=severity,
            confidence="High",
            url=self.scanner.root,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe="CWE-295",
        ))

    def _check_tls_old_versions(self):
        # TLS 1.0/1.1 support audit (TLS-002, MEDIUM, CWE-327): probe a
        # handshake pinned to each deprecated version and flag the host
        # once when it accepts either. TLS 1.0 and 1.1 are deprecated by
        # RFC 8996 — no AEAD ciphers, BEAST/POODLE-era weaknesses — and a
        # server that still negotiates them lets a downgraded client use
        # them. A server that refuses both flags nothing; an HTTP target
        # has no TLS to probe. Runs only in non-passive modes: it opens
        # connections outside the crawl, like the TLS-expiry probe. The
        # finding names the accepted versions only — the probe never
        # sends application data, so no content is exchanged.
        parsed = urlparse(self.scanner.root)
        if parsed.scheme.lower() != "https":
            return
        host = parsed.hostname
        if not host:
            return
        port = parsed.port or 443
        timeout = getattr(self.scanner, "timeout", 10)
        accepted = []
        for attr, label in _TLS_OLD_VERSIONS:
            if not getattr(ssl, "HAS_" + attr, True):
                continue
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                version = getattr(ssl.TLSVersion, attr, None)
            if version is None:
                continue
            if _tls_version_supported(host, port, version, timeout):
                accepted.append(label)
        if not accepted:
            return
        versions = " and ".join(accepted)
        self.add_finding(Finding(
            id="TLS-002",
            name="Server Accepts Deprecated TLS Versions",
            category="TLS Configuration",
            severity=MEDIUM,
            confidence="High",
            url=self.scanner.root,
            evidence=f"Server accepts deprecated TLS version(s): {versions}.",
            impact=(
                "TLS 1.0 and 1.1 are deprecated (RFC 8996) and lack modern "
                "authenticated encryption; a client that can be downgraded "
                "to them is exposed to BEAST-style and weak-cipher attacks, "
                "and PCI DSS requires TLS 1.2 or higher."
            ),
            remediation=(
                "Disable TLS 1.0 and 1.1 on the server and set TLS 1.2 as "
                "the minimum negotiated version; verify no legacy client "
                "still depends on the old versions first."
            ),
            cwe="CWE-327",
        ))

    def _check_security_txt(self):
        # security.txt presence (SECTXT-001, RFC 9116): a site publishing
        # /.well-known/security.txt with a Contact: field has a documented
        # vulnerability-disclosure channel, and the report notes it as an
        # INFO finding so the analyst knows where reports should go. A
        # missing file, a non-200 answer, or a file with no Contact: field
        # flags nothing — without a contact there is no channel to note.
        # Runs only in non-passive modes: it fetches a URL outside the
        # crawl, like the TRACE and error-page probes.
        url = urljoin(self.scanner.root, "/.well-known/security.txt")
        res = self.scanner._request("GET", url, quiet=True)
        if res is None:
            return
        if getattr(res, "status_code", 0) != 200:
            return
        body = getattr(res, "text", "") or ""
        contacts = [
            c.strip() for c in _SECURITY_TXT_CONTACT_RE.findall(body) if c.strip()
        ]
        if not contacts:
            return
        shown = ", ".join(contacts[:3])
        suffix = f" (+{len(contacts) - 3} more)" if len(contacts) > 3 else ""
        self.add_finding(Finding(
            id="SECTXT-001",
            name="security.txt Disclosure Channel Present",
            category="Security Policy",
            severity=INFO,
            confidence="High",
            url=url,
            evidence=(
                f"security.txt is published at {url} with contact "
                f"channel(s): {shown}{suffix}"
            ),
            impact=(
                "A published security.txt gives researchers a documented "
                "channel to report vulnerabilities instead of guessing an "
                "address."
            ),
            remediation=(
                "Keep security.txt current: review the listed contacts and "
                "the Expires field on a schedule so reports still reach a "
                "monitored inbox."
            ),
        ))

    def _check_robots_txt(self):
        # robots.txt sensitive-path audit (ROBOTS-001, LOW, CWE-200): a
        # Disallow entry naming an admin/backup/config-style path tells
        # anyone reading the public file where the hidden surface is, so
        # the report notes it as one finding per host listing up to five
        # sensitive paths. A missing file, a non-200 answer, a file with
        # no sensitive Disallow entries — or a bare "Disallow: /" — flags
        # nothing. All user-agent groups count: the file is public no
        # matter which group a rule sits under. Runs only in non-passive
        # modes: it fetches a URL outside the crawl, like the security.txt
        # and TRACE probes.
        url = urljoin(self.scanner.root, "/robots.txt")
        res = self.scanner._request("GET", url, quiet=True)
        if res is None:
            return
        if getattr(res, "status_code", 0) != 200:
            return
        body = getattr(res, "text", "") or ""
        sensitive: list[str] = []
        seen: set[str] = set()
        for raw in _ROBOTS_DISALLOW_RE.findall(body):
            # Strip a trailing "# comment" before matching or reporting.
            path = raw.split("#", 1)[0].strip()
            if not path or path in seen:
                continue
            seen.add(path)
            if _robots_path_is_sensitive(path):
                sensitive.append(path)
        if not sensitive:
            return
        shown = ", ".join(sensitive[:5])
        suffix = f" (+{len(sensitive) - 5} more)" if len(sensitive) > 5 else ""
        self.add_finding(Finding(
            id="ROBOTS-001",
            name="Sensitive Paths Disclosed in robots.txt",
            category="Information Disclosure",
            severity=LOW,
            confidence="High",
            url=url,
            evidence=(
                f"robots.txt disallows sensitive path(s): {shown}{suffix}"
            ),
            impact=(
                "Disallow entries naming admin, backup, config or similar "
                "paths publish the site's hidden surface in a public file, "
                "giving attackers a ready-made target list."
            ),
            remediation=(
                "Remove sensitive paths from robots.txt — blocking crawlers "
                "is not access control. Protect admin and backup areas with "
                "authentication instead, and keep backups outside the web root."
            ),
            cwe="CWE-200",
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
