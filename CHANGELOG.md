# Changelog

## Unreleased

### Added
- `--format csv`: one row per finding (`id`, `severity`, `url`, `parameter`,
  `evidence`) for spreadsheet pipelines. All findings are included (like JSON),
  multi-target runs share a single header row, and the csv module's quoting
  round-trips evidence containing commas, quotes or newlines.
  `tests/test_csv_format.py` covers the header/rows, quoting round-trip,
  empty-result and multi-target cases.
- **Stage 3 — judge findings in context** (context-aware deduplication and scoping):
  - CORS findings are now collapsed to one `CORS-001` per `(host, severity)` class
    instead of one per probed URL; the collapsed evidence notes the endpoint count
    and up to five sample paths, eliminating duplicate-flood reports on sites with
    a uniform CORS policy.
  - `ScanResult.to_dict()` now includes `unique_issue_count`: the number of distinct
    finding IDs in the result, giving JSON consumers a quick measure of issue breadth.
  - The Stage 2 inert-param skip (zero-signal params bypass injection probing) and the
    external-form-action scope guard are now applied to `advanced_injection`
    (LDAP, XML/XXE, NoSQL, SSTI) and `injection_advanced` (command injection,
    traversal) in addition to SQLi and XSS — no hint or any signal always falls
    back to full probing.  `tests/test_stage3_context.py` covers all new behavior.

- **Stage 2 — learn during scan** (param-hint pre-pass, hint-driven skipping):
  - `_build_param_hints()` probes each URL param / form field once with a
    unique marker after the crawl (active/full modes, capped at 80 params)
    and records whether it reflects input or changes the response.
    Counts land in `target_profile` as `params_probed` / `params_inert`.
  - SQLi: params with zero response signal run a reduced chain (error-based
    plus one time-based payload; union/boolean/stacked skipped), and the
    error/boolean/stacked techniques now share one cached baseline request
    per param instead of fetching three.
  - XSS: reflected payloads are skipped for params whose marker never
    reflected; stored-XSS probing is unchanged.
  - SQLi and XSS both skip forms whose action points at a different host —
    probing third-party endpoints is out of scope.
  - No hint (or any signal) always falls back to the full pre-Stage-2
    probing. `tests/test_stage2_learning.py` covers the new behavior.

- **Stage 1 — smart scanner** (binary-asset filtering, target profiling, DBMS-aware SQLi):
  - Binary assets (images, fonts, media, archives) are now skipped during the
    crawl — their links are never enqueued and their responses are never stored
    in `pages`, cutting wasted max_pages slots and memory on asset-heavy sites.
    A new `assets_skipped` counter tracks how many were dropped.
  - `_build_target_profile()` fingerprints the target stack (IIS/ASP.NET,
    PHP, PostgreSQL) from crawled headers and URL extensions. The resulting
    `target_profile` dict (with `dbms_hint`, `dbms_signals`, and `stack_hints`)
    is stored on the scanner and included in `ScanResult.to_dict()`.
  - SQLi time-based probes are now DBMS-aware: when `dbms_hint` is `'mssql'`
    only the `WAITFOR DELAY` payload fires; `'mysql'` fires only `SLEEP()`
    payloads; `'postgres'` fires only `pg_sleep()`. `'unknown'` fires all
    families (unchanged). The MSSQL-only `EXEC sp_MSforeachtable` stacked-
    query payload is similarly skipped when the hint points to another DBMS.
  - CORS probing now skips binary-asset URLs before the per-endpoint
    shape-dedupe pass, further reducing redundant requests.
  - `tests/test_stage1_smart.py` (40+ tests) covers all four changes.

- `--max-depth DEPTH`: alias for `--depth` (crawl depth); when both flags
  are given, `--max-depth` wins, so there is exactly one effective depth
  per run. `tests/test_max_depth.py` covers the alias, the precedence,
  and hand-built namespaces that predate the flag.
- LDAP-001 retest coverage: `tests/test_ldap_retest.py` proves the
  generic `--retest` pass replays LDAP findings (GET confirmed/fixed,
  blocked replay unverifiable, POST form-data round-trip, passive skip) —
  the module already attached replayable proof, but no test covered it.
- CSRF token detection now covers PUT, PATCH, and DELETE forms, not just
  POST: any state-changing form method without a CSRF token field is
  flagged as CSRF-001 (GET forms and lone search fields are still
  skipped). `tests/test_csrf_methods.py` covers the new methods, the
  GET skip, and the token-present case.
- Version-fingerprint header findings (`Server:`, `X-Powered-By:`,
  `X-AspNet-Version:`) are now collapsed to one report row per (host,
  header, value) across all crawled pages instead of one row per URL —
  and banners served only on sub-pages are now found too (previously
  only the root page was checked). The evidence counts the pages that
  repeated the banner. `tests/test_header_collapse.py` covers the
  collapse, the sub-page-only case, and distinct values staying
  separate.
- Finding dedupe key: the same (id, URL, parameter) finding is now reported
  once across GET and POST instead of twice. The dedupe key
  (`finding_dedupe_key()` in scanner.py) normalizes the URL — query string,
  fragment, host case, default ports, and trailing-slash noise are folded
  away — so a GET hit on the crawled page URL and a POST hit on the bare
  form action collapse into one report row (first reporter wins; the HTTP
  method is deliberately excluded from the key). Both the module-local and
  the scanner-wide dedupe sets now use this single canonical key (previously
  two inconsistent ad-hoc tuples), and auth_advanced's COOK-flag suppression
  lookup normalizes its comparison URL the same way.
  `tests/test_finding_dedupe.py` (18 tests) covers GET/POST collapse,
  normalization variants, non-collapse cases, malformed-URL safety, and the
  suppression lookup.
- Per-host connection pool tuning: the urllib3 `HTTPAdapter` is now created
  with `pool_connections`/`pool_maxsize` scaled from the thread count
  (`max(10, threads)`) instead of the fixed 10/10 defaults, so high-thread
  scans reuse keep-alive connections instead of churning TCP+TLS handshakes
  against a too-small pool. Low thread counts keep the urllib3 defaults
  (never shrunk). The `--threads` help text documents the effect.
  `tests/test_pool_sizing.py` (4 tests) covers default preservation,
  high-thread scaling, the no-shrink floor, and http/https adapter parity.
- `--proxy URL`: route all scan traffic through an HTTP/HTTPS proxy
  (Burp-style local intercept) via the requests session — previously no
  proxy support existed at all. A bare `host:port` is treated as
  `http://host:port`, credentials in the URL are preserved, and bad values
  (non-http(s) scheme, no host, bad port, blank) fail fast at scanner
  construction via `scanner.parse_proxy_url`. The session mapping applies
  to every request including manual redirect hops in `_request`.
  `tests/test_proxy_flag.py` (19 tests) covers parser wiring, normalization,
  credential preservation, fail-fast validation, and session application.
- `--user-agent STRING`: the CLI now exposes the `WebScanner(user_agent=...)`
  knob that already existed but was never wired through — a custom UA is
  sent on every request, defaulting to the previous Chrome 125 string
  (`scanner.DEFAULT_USER_AGENT`). A `--header "User-Agent: ..."` override
  applied after construction still wins, and a blank UA fails fast at
  scanner construction. `tests/test_user_agent_flag.py` (9 tests) covers
  parser defaults/wiring, the scanner default, None-means-default for
  hand-built Namespaces, blank rejection, and header-override precedence.
- Open-redirect payload coverage: `next`/`url`/`redirect`/`return`/`dest`
  parameters are now probed with a 6-form bypass family (standard,
  protocol-relative `//host`, backslash `\\/\\/host`, percent-encoded
  scheme, double-encoded scheme, null-byte prefix) instead of one literal
  URL, catching validators that strip or compare only one representation
  of the destination. Detection normalizes backslashes before parsing the
  `Location` netloc; one finding per vulnerable parameter, with the
  successful form named in the evidence. `tests/test_open_redirect_payloads.py`
  (21 tests) covers every form, sibling-domain/relative-URL non-fires,
  payload integrity through query mutation, and the one-finding rule.
- `--modules LIST`: run only the named scan modules (e.g.
  `--modules xss,sqli`) for faster targeted scans; repeatable and
  case-insensitive, with friendly aliases (`traversal`/`command` → `cmd`,
  `sensitive`/`sensitive-data` → `data`, `injection`/`multivector`/`multi-vector`
  → `advanced`). Unknown names fail fast at scanner construction with the
  valid key list; the fan-out keeps canonical registry order regardless of
  typing order. An explicit selection overrides the `--mode`-based module
  gating, and is recorded as `modules` in the JSON report plus a "Modules
  selected" line in the text summary. Mirrors as `WebScanner(modules=...)`.
  `tests/test_modules_flag.py` (34 tests) covers parsing, aliases, eager
  validation, CLI wiring, and end-to-end module filtering.
- `--parallel-modules N` (default 4, parallel by default): run up to N scan
  modules concurrently side by side on the same terminal instead of one
  after another (`1` restores the old sequential loop). Module
  findings still flow through the locked dedupe in
  `BaseModule.add_finding`, one crashing module cannot kill its siblings,
  and each module reports an exact per-module finding count via the new
  `findings_added` counter (a global len() diff would race). Parallel runs keep
  the same `on_progress` contract as sequential (bounded per-module events +
  final "Checks complete") and the CLI's per-module done lines now carry the
  running request count (`· N req`), since one animated bar cannot represent
  N concurrent modules — same rationale as multi-target mode.
  `tests/test_parallel_modules.py` (11 tests) covers the CLI wiring,
  sequential-order preservation, true overlap, crash isolation, hook
  behavior, and worker-count capping.

### Fixed
- LDAP error-pattern regression: the `--parallel-modules`-era rewrite of the
  pattern table (LDAP_ERROR_PATTERNS) had dropped 7 vendor signatures from
  the 2026-10-14 coverage pass (`LdapErr: DSID`, `80090308`, `Net::LDAP`,
  `LDAPFilterSyntaxError`, `Invalid search filter`, `Invalid attribute
  syntax`, `Server is unwilling to perform`) — those backends were no
  longer detected at all. Restored; `DirectoryServicesCOMException` is now
  ordered before `System.DirectoryServices` so the evidence names the
  precise exception type. `tests/test_ldap_patterns.py` +
  `tests/test_ldap_confirmation.py` back to 43/43 green.

### Docs
- README: added 4 real terminal captures (`assets/screenshots/`, 2026-10-06) —
  banner, live findings with `✓ verified` / `○ unverified` evidence gating,
  scan report, and `--retest` mode — taken from a real scan of the bundled
  deliberately-vulnerable test app.
- README: documented the `--output` and `--retest` CLI flags (previously
  missing from the CLI options section).
- README: removed the GitHub Actions workflow bullet — the repo has no
  `.github/` workflow; kept the JSON-output and quiet-mode CI notes, and
  documented the exit-code contract (1 when any HIGH finding is reported,
  0 otherwise).
- README/HOW_TO_TEST expected-results correction: the bundled test app yields
  11 findings (5 HIGH, 4 MEDIUM, 1 LOW, 1 INFO), verified by running
  Xploit v1.6.0 against it. (An earlier draft of this entry recorded
  10/4 here: a missing `"unrecognized token"` sqlite marker had blinded the
  SQLi module on the test app's `/sqli` endpoint — fixed under Unreleased,
  see "Fixed" below.)

### Fixed
- HTTP read-path hang: full/active scans could stall 15+ minutes on a single
  ESTABLISHED connection (process sleeping in `poll()`), ignoring `--timeout`.
  Root cause: `requests`' timeout is per socket operation, and response bodies
  were read with plain `res.text`/`res.content` — a server dribbling one byte
  every (timeout - 1) seconds holds the connection open forever. `_request`
  now streams every body through `_consume_body`, which reads in a daemon
  thread with a hard total deadline (`read_deadline`, default
  `max(5 * timeout, 30)`s, overridable via `WebScanner(read_deadline=...)`).
  On expiry the socket is shut down for reading (a cross-thread `close()`
  would block on the BufferedReader lock held by the in-flight read) and
  whatever arrived is kept, so modules see partial content instead of the
  scan hanging. Also new: a 10 MB per-response body cap, lenient
  Content-Length enforcement (short bodies are kept and the shortfall is
  logged instead of raising `IncompleteRead`), and explicit release of
  redirect-hop connections. `tests/test_read_deadline.py` covers the drip,
  abort, truncation, and derivation cases against a local HTTP server.
- Restored error-based SQLi detection on sqlite backends: added
  `"unrecognized token"` to `SQL_ERRORS` in `xploit/scanner.py`. The bundled
  test app's `/sqli` endpoint leaks exactly this sqlite diagnostic, but no
  marker matched it, so the SQLi module was blind there (0 findings). The
  marker is FP-safe: the fresh-baseline gate suppresses it whenever a benign
  response already contains it. Bundled-app expected results are back to
  11 findings (5 HIGH, 4 MEDIUM, 1 LOW, 1 INFO).
- Added regression tests (`SqliteErrorMarkerTest` in
  `tests/test_sharpened_proofs.py`, 2 tests): the sqlite diagnostic fires
  exactly one SQLI-001 finding with the real module end-to-end, and stays
  silent when the marker is already present in the benign baseline.

### Added
- LDAP error-pattern coverage: the `LDAP-001` error signature list grew from
  6 generic strings to 23 vendor-documented patterns (`LDAP_ERROR_PATTERNS` in
  `xploit/modules/advanced_injection.py`) — Java JNDI / Sun (`javax.naming.*`,
  `com.sun.jndi.ldap`), Novell eDirectory (`com.novell.ldap`), UnboundID
  (`com.unboundid.ldap`), Apache Directory (`org.apache.directory`),
  Spring LDAP (`org.springframework.ldap`), PHP `ldap_*` extension warnings,
  python-ldap errors, .NET `System.DirectoryServices`, OpenLDAP CLI error
  text, and Active Directory `LdapErr:`/`DSID-` diagnostics. Matching stays
  case-insensitive and baseline-differenced (a marker only counts when absent
  from the baseline response); `tests/test_ldap_coverage.py` pins the list,
  the matching rules, and an end-to-end flag on a new vendor signature.
- LDAP two-round-trip confirmation: `LDAP-001` now flags only when TWO
  structurally distinct malformed filters (`LDAP_CONFIRM_PAYLOADS`) both
  produce LDAP error output — a page where any changed input trips a generic
  error template no longer becomes a finding. `tests/test_ldap_confirmation.py`
  covers the confirm-required path, the clean-confirm negative, None-tolerant
  confirmation, and that confirmation requests are never sent when nothing
  matched in the discovery round.
- `--jitter N` CLI flag (and matching `WebScanner(jitter=...)` keyword):
  adds up to N extra random seconds to each request's spacing, on top of
  `--rate-limit`. A fixed rate limit produces metronomic traffic that naive
  rate-based WAF rules fingerprint easily; jitter smooths the timing out.
  Negative values are rejected; `tests/test_rate_jitter.py` covers
  validation, the delay math (deterministic via monkeypatched uniform/sleep),
  and the CLI surface.
- `--exclude PATTERN` CLI flag (repeatable): skips crawling any URL matching
  the pattern. Patterns are Python regexes matched against the full URL and are
  compiled eagerly, so an invalid pattern fails fast with a clear error.
  Exclusions apply to entry-point discovery (robots.txt/sitemap candidates)
  and to every followed link; excluded URLs are never requested. `WebScanner`
  takes a matching `exclude=[...]` keyword, `ScanResult` carries
  `exclude_patterns` (text report prints them, JSON report includes them), and
  `tests/test_exclude_flag.py` covers parsing, regex semantics, and an
  end-to-end crawl against a local HTTP server.
- XSS module: 8 new event-handler attribute context payloads — single-quote
  attribute breakout (`xploit' onfocus='alert(1)`), a no-interaction
  breakout pair (`xploit" autofocus onfocus="alert(1)`), autofocus carriers
  (`<input>` / `<select>` with `autofocus onfocus`), a modern pointer-handler
  breakout (`onpointerover`), an SMIL `onbegin` probe, an `<audio onerror>`
  carrier, and a tab-separated `<img onerror>` variant for space-based
  filters. The reflection check's active-vector markers were extended with
  `onfocus`, `autofocus`, `onpointerover`, and `onbegin` so the new probes
  confirm when reflected into executable contexts.
- JSON report now includes top-level `total_findings` and `verified_findings`
  counts alongside the per-severity `summary`, so dashboards and CI pipelines
  can consume scan totals without post-processing the findings array.
- Added 25 progress-heartbeat tests (`tests/test_progress_heartbeat.py`):
  on_request hook contract, end-to-end run_scan wiring of the live N-req
  counter, the redirect-hop bound (11 requests for a long chain, not 30),
  and the 5 MB oversize-page cap.
- Added 100 more regression tests (188 total passing at the time; the suite
  now stands at 229 passing).

### Bug-fix pass (deep audit)
- Fixed GET-form injection payloads being silently dropped: `mutate_query()`
  now appends the parameter (plus sibling form fields) when the action URL
  carries no query string, so SQLi/command/SSTI payloads actually reach the
  target.
- Fixed brute-force false positives: a redirect counts as login success only
  when its target differs from the baseline redirect and doesn't point at
  login/auth; removed bare "error" from failure indicators and the 2x-baseline
  response-size heuristic.
- Fixed brute-force credential stuffing of registration forms: signup/register
  actions and confirm-password forms are excluded; bare "name" no longer
  counts as a username (token-based matching).
- Fixed path-traversal false positives: markers must be new relative to a
  fresh benign baseline; generic `bin/bash` removed as standalone proof.
- Fixed SQLi false positives: removed generic "database error" /
  "internal server error" markers; error-based and stacked-query checks use
  fresh baseline probes instead of stale crawl responses.
- Fixed `max_pages` race in the parallel crawler: concurrent future
  completions could overshoot `max_pages`. The cap is now enforced per
  completed future, and leftover in-flight requests are cancelled when the
  cap is hit so the target gets no pointless traffic (plus a 5x hammer
  regression test).
- Fixed `--no-color` leaking ANSI escape codes into the saved report:
  report-file output is now clean under `--no-color` and colored otherwise.
- Fixed vacuous XSS confirmation: reflections are now judged by the markup
  *before* the payload (comments, textarea/title/style/script and inert
  attributes rejected); the payload itself must carry an active vector.
  Evidence states script execution was not dynamically confirmed in a browser.
- Fixed `--retest` misclassifying blocked/error responses as "fixed": HTTP
  4xx/5xx, WAF/block pages, rate limits, failed replays and login redirects
  are now `unverifiable`.
- Fixed crawler dropping HTTP error pages (4xx/5xx forms/links were lost).
- Fixed active payloads being delivered off-origin via cross-origin redirects
  (re-issued unfollowed; same-origin chains unchanged).
- Fixed unbounded crawl wait (now bounded, with stall reporting) and retries
  (bounded, idempotent-only, POSTs never retried).
- Fixed one crashing module aborting the whole scan (isolated per module).
- Fixed `--scope-prefix` seeding (prefixed entry point added) and path
  boundaries (`/api` no longer matches `/apiv2`).
- Fixed cookie flag checks reading attributes instead of substring-matching
  the raw header (a `secure_mode` cookie value no longer fakes the Secure
  flag); all Set-Cookie headers inspected; session/CSRF field names
  token-matched (`consideration`/`author`/`residue` no longer match).
- Fixed open-redirect check to catch protocol-relative destinations
  (`//example.com/...`).
- Fixed sensitive-file/debug probes skipping 301-served files (single
  in-scope redirect followed, off-origin never).
- Fixed CORS severity logic (credential-aware) and duplicate probing.
- Fixed duplicate cookie findings across modules (COOK-00x vs AUTH-006).
- Fixed duplicate query parameters being collapsed in SQLi URL checks and
  empty-body boolean-blind baselines being skipped.
- Fixed XXE/SSTI/NoSQL checks: baseline-relative markers, distinctive SSTI
  arithmetic (1337/1903), case-insensitive NoSQL matching, full payloads in
  evidence, replayable proof attached for LDAP/XXE/XML/NoSQL/SSTI.
- Fixed terminal escape injection via server-controlled finding fields
  (sanitized before display); report file output keeps JSON evidence intact.
- Fixed report box alignment, dangling verification dash, stale retest
  progress redraws; "report written" notice now goes to stderr so piped JSON
  stays parseable.
- Added 5 MB HTML-parsing cap, thread-count clamp, case-insensitive origin
  comparison with default-port handling, fragment stripping before crawl
  dedup, lock-guarded request counters/rate limiting, userinfo stripping in
  URLs, and clean `ValueError` for missing target URLs.
- Fixed redirect handling: manual same-origin-only following (max 10 hops,
  loop detection) replaces requests' 30-hop auto-follow. `javascript:`/non-HTTP
  `Location` targets are never followed, redirect loops are reported instead of
  stalling, and 307/308 POST bodies can never be forwarded off-origin.
- Fixed XSS context analysis: a `javascript:` URI payload reflected into a
  URL-bearing attribute (href/src/action/...) is now correctly treated as an
  executable context; other attributes holding the same text stay inert.
- Fixed `normalize_url`: non-HTTP(S) schemes like `ftp://` now raise
  ValueError instead of being mangled into `http://ftp://...`.
- Removed dead code: `IDOR_URL_PATTERNS`, `_render_finding_lines`.
- Regression suite grew from 13 to 44 tests covering every fix above.

### Evidence-gated findings + retest
- Added `--retest`: re-fires each verified finding's proof request after the
  scan and records `confirmed` / `fixed` / `unverifiable`. Refused in passive
  mode (retest is active traffic by definition).
- Added `--output PATH`: writes the report (text or JSON) to a file with ANSI
  colors stripped.
- SQLi and XSS modules now attach replayable proof to their findings.
- Fixed IDOR probes running in passive mode (now gated with the other active checks).
- Fixed crawler dedup keeping query parameter names (`/?sessionid=abc` crawls as
  its own page; `/item?id=1` vs `/item?id=2` still dedupe by shape).
- Fixed duplicate `AdvancedInjectionModule` class names
  (`MultiVectorInjectionModule`, `CommandTraversalModule`).
- Fixed email regex character class (`[A-Z|a-z]` → `[A-Za-z]`).
- 404 responses during probing no longer logged as scan errors.
- CORS check now evaluates every crawled page instead of stopping at the first hit.
- Corrected README claims: 4 SQLi techniques (not 5, no time-based), output-based
  command-injection detection, version badge 1.6.0, 11 expected findings on the
  vulnerable test app (5 HIGH, 4 MEDIUM, 1 LOW, 1 INFO).

## 1.6.0

- Consolidated the final scanner under the Xploit name.
- Added custom `--header` and `--cookie` options for authenticated scans.
- Added exposure checks for sensitive config files, exposed diagnostic endpoints, directory listing, technology headers, sensitive HTML comments, and predictable object identifiers.
- Kept passive mode limited to observed responses/forms and reserved active probes for active/full scans.
- Improved progress reporting, JSON output, CLI option coverage, and regression tests.

## 1.5.0

- Added modular scanner structure and richer report metadata.
- Added scan modes, path scoping, rate limiting, JSON output, and quiet/no-color controls.

## 1.0.0

- Initial CLI scanner release.
- Added bounded same-origin crawling.
- Added checks for SQL Injection, XSS, CSRF, Command Injection, Directory Traversal, Insecure HTTP Headers, Broken Authentication, Sensitive Data Exposure, Open Redirect, and Security Misconfiguration.
- Added detailed terminal output with evidence, impact, remediation, CWE, and validation guidance.
- Added universal `xploit` command support.
