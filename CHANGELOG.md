# Changelog

## Unreleased

### Added
- WAF fingerprint note: `_build_target_profile` now detects common
  WAF/protection markers (Cloudflare, Akamai, ModSecurity, Sucuri,
  Imperva, F5 BIG-IP) from response headers (`cf-ray`, `x-akamai-*`,
  `x-sucuri-*`, `x-iinfo`, `Server` values), protection cookies
  (`__cfduid`, `cf_clearance`, `incap_ses_*`) and vendor-distinctive
  block-page text (`xploit/scanner.py`: `detect_waf`, module-level
  marker tables). Block-page markers are only checked on error
  responses (status >= 400), so a 200 page merely discussing a WAF
  cannot false-positive. Detected vendors land in `target_profile`
  as `waf`/`waf_signals` (JSON) and in the text report's coverage line
  (`WAF: Cloudflare`). `tests/test_waf_fingerprint.py` covers each
  vendor via headers/cookies/block pages, the 200-page guard, profile
  integration and dedupe, and a live fixture-server end-to-end.
  Version 1.19.0 -> 1.20.0.
- Multi-target checkpoint files: `--checkpoint`/`--resume` no longer
  require a single target (`xploit/checkpoint.py`: `target_slug` /
  `checkpoint_path_for_target`, `xploit/cli.py`: per-target derivation
  in `_run_multi_target`). A multi-target run writes one checkpoint
  per target (`scan.json` -> `scan.<target-slug>.json`, slug from
  host + non-default port + path); `--resume` reads the matching
  per-target file, scans a target fresh when its file is missing, and
  reports a finished checkpoint's findings without re-scanning it
  (`--retest` is skipped for restored results — it needs a live
  scanner). A corrupt per-target checkpoint is an `error` result for
  that target only, and the message goes to stderr so piped
  `--format json` stays parseable. Single-target runs keep using the
  given path unchanged, so old checkpoints still resume.
  `tests/test_multitarget_checkpoint.py` covers slug/path derivation,
  the per-target paths handed to the scanner, missing-resume fresh
  scans, finished-checkpoint restore without scanning, corrupt
  checkpoints, and live two-server end-to-end write + resume.
  Version 1.18.0 -> 1.19.0.
- JUnit XML output format: `--format junit` renders findings as native
  CI test results (`xploit/reporting.py`: `render_junit_report` /
  `render_junit_reports`, stdlib ElementTree) — one testsuite per scan
  result, one testcase per finding (`xploit.<finding-id>`), HIGH
  findings as `<failure>` elements with URL/parameter/evidence/CWE/
  impact/remediation, MEDIUM/LOW/INFO listed as passing testcases so
  the run stays visible without breaking the build; an unreachable
  target is a single `<error>` testcase instead of a silent zero-test
  pass. Multi-target runs produce one testsuite per target in a single
  `<testsuites>` document. `tests/test_junit_format.py` covers the
  document shape, the HIGH-only failure mapping, field presence,
  payload escaping, empty/unreachable targets, multi-target suites and
  the CLI end-to-end. Version 1.17.0 -> 1.18.0.
- `--respect-robots`: honor the target's robots.txt Disallow rules while
  crawling (`WebScanner(respect_robots=True)`; stdlib `RobotFileParser`
  against the `*` group, fetched once per scan). Disallowed entry points,
  links and OpenAPI-derived JSON targets are never requested — the crawl
  skips them instead of fetching and dropping them — and the distinct
  skipped count is reported as `robots_skipped` on `ScanResult`, in JSON
  output, and in the text report's coverage line. Off by default: a
  scanner's job is to probe what robots.txt hides, so honoring it is
  opt-in for policy-compliant scans. Fail-open: a missing or unfetchable
  robots.txt disallows nothing. Known limit, documented in the code:
  CPython's parser applies the first matching rule in file order, not
  the longest match, so an Allow listed after a broader Disallow does
  not override it. `tests/test_respect_robots.py` covers the parser
  surface, the disallow check, live fixture-server crawls (flag on/off,
  missing robots.txt), the dry-run result field and the CLI end-to-end.
  Version 1.16.0 -> 1.17.0.
- HTML report format: `--format html` renders a single self-contained
  HTML document (`xploit/reporting.py`: `render_html_report` /
  `render_html_reports`) — inline CSS, no external resources — for
  sharing with clients who will not read terminal output. Findings are
  grouped by severity with coloured badges and carry URL, parameter,
  method, evidence, verified status, impact and remediation; the header
  shows target, mode, duration, coverage and the severity summary with
  the verified count. Every finding is included (like JSON/CSV) and all
  finding text is HTML-escaped, so reflected payloads render as text,
  never markup. Multi-target runs produce one section per target in a
  single document. `tests/test_html_format.py` covers the document
  shape, summary counts, field presence, payload escaping, severity
  classes, empty/unreachable targets, multi-target sections and CLI
  parsing. Version 1.14.0 -> 1.15.0.
- Login-form auto-auth: `--login-url` + `--login-user`/`--login-pass`
  submit the login form once before the scan and reuse the session
  cookie for the whole run (new `xploit/auth.py`: stdlib-only form
  parsing, so no bs4 dependency — the first form carrying a password
  input is filled, hidden fields such as CSRF tokens ride along, and
  the username field is picked by name/id hints with a first-text-field
  fallback). The run fails fast when the login establishes no session
  (no new cookie and no redirect away from the login page), so a scan
  never silently runs anonymously against a logged-out surface; the
  flags are all-or-nothing and single-target only, like
  `--checkpoint`. `tests/test_login_auth.py` covers form parsing, live
  fixture-server login success/failure/no-form/unreachable cases and
  CLI validation. Version 1.15.0 -> 1.16.0.
- SARIF output format: `--format sarif` renders a SARIF 2.1.0 document
  (`xploit/reporting.py`: `render_sarif_report` / `render_sarif_reports`)
  that GitHub code scanning and other SARIF consumers can ingest — one
  run per scan result, one rule per distinct finding id (first-seen
  order, with CWE + category in properties), one result per finding
  (ruleId, level, evidence message, finding URL as the artifact
  location, plus parameter/method/confidence/verified/remediation in
  properties). Severity maps onto SARIF levels: HIGH -> error, MEDIUM
  -> warning, LOW/INFO -> note; unknown severities default to warning.
  Multi-target runs produce one run per target. `tests/test_sarif_format.py`
  covers the document shape, rule dedupe, level mapping, result fields,
  empty findings, multi-target runs and CLI parsing. Version 1.13.0 -> 1.14.0.
- JSON-body injection probing: operations with a declared
  `application/json` requestBody in a served OpenAPI/Swagger spec are
  now collected as JSON-body targets (`xploit/openapi.py`:
  `extract_json_targets` + `JsonTarget` — `$ref` and `allOf` schemas
  resolve, path templates fill with `1`, declared query params seed
  with `xploit`, POST/PUT/PATCH only; same scope/exclude filtering as
  seeded URLs). The SQLi module runs its full technique chain against
  each declared body field, sending payloads as a JSON object body with
  sibling fields at placeholder values, and the XSS module checks for
  verbatim reflection into JSON responses (new XSS-003 at MEDIUM —
  reflection into a JSON body only becomes XSS if a client-side sink
  renders the value as HTML; an HTML response reflecting into an
  executable context still reports as XSS-001). JSON findings carry a
  JSON proof body and `retest.py` replays those proofs with `json=`
  instead of urlencoded form data. `WebScanner.json_targets` is
  re-derived on every scan (resume re-fetches the spec), counted in
  `target_profile["json_targets"]`, and listed by `--dry-run` as kind
  `json`. `tests/test_json_body.py` covers extraction, `$ref`/`allOf`,
  discovery filtering, and live fixture-server SQLi/XSS/retest/dry-run
  cases. Version 1.12.0 -> 1.13.0.
- Nested sitemap recursion: `_discover_entry_points` now follows
  `<sitemap>` entries inside sitemap index files via new
  `WebScanner._collect_sitemap_urls` — `<sitemap>` entries recurse,
  `<url>` entries are pages (so a `.xml` page URL stays a page), and a
  document with no wrappers falls back to the old bare-`<loc>` shape
  (`.xml` entries treated as nested sitemaps). Recursion stops at 3
  levels / 50 fetched documents, repeats are skipped, nested sitemaps
  must be same-origin, and `.xml.gz` sitemaps are skipped (gzipped
  bodies are not decompressed). Nested sitemap URLs are never entry
  points themselves. `tests/test_sitemap_recursion.py` covers index
  recursion, self-referencing indexes, the depth cap, off-origin
  entries, the `.xml`-page case, the unwrapped fallback, `.xml.gz`
  skipping and a live fixture server.
- YAML OpenAPI spec seeding: `_discover_entry_points` now also fetches
  `/openapi.yaml` and `/swagger.yaml` alongside the JSON spec paths, so
  YAML-only API docs seed the crawl too. New stdlib-only
  `xploit/yamlmini.py` (`parse_yaml_subset`) parses the subset real
  specs use — block mappings/sequences, quoted/plain/flow scalars with
  YAML typing, block scalars, comments, `---` markers — and returns
  `None` for anything outside it (anchors, aliases, tags, explicit
  keys, tabs, multi-document files) so an unparseable spec never breaks
  the crawl. `xploit/openapi.py` now also accepts numeric server-variable
  defaults/enums (YAML types its scalars; `default: 2` stringifies to
  `"2"`). `tests/test_openapi_yaml.py` covers the parser, discovery and
  a live fixture server.
- `--dry-run` entry-point listing: `WebScanner(dry_run=True)` crawls and
  returns a `ScanResult` with status `"dry-run"`, no findings, and an
  `entry_points` list (crawled pages with query parameters, discovered
  forms with action/method/field names, exact duplicates collapsed) that
  is serialized into JSON reports; the text report prints the listing
  instead of "No findings detected." No scan module runs, so no probe
  traffic is sent; no checkpoint is written, and `--checkpoint` /
  `--resume` / `--retest` combos fail fast (exit 2). The crawl itself
  is plain GET discovery, which is what is being listed.
  `tests/test_dry_run.py` covers the listing, dedupe, no-checkpoint
  write, text rendering and CLI guards.
- Blind LDAP detection (LDAP-002): boolean-based differential check for
  backends that swallow error text — a plain impossible value must sit
  within 150B of the baseline, and two structurally different wildcard
  probes (`*`, `*)(uid=*`) must both come back more than 200B longer
  (more directory entries returned). Any LDAP error marker in a blind
  probe aborts the verdict so LDAP-001's error path stays authoritative,
  and a single expanding wildcard never flags. Medium confidence: the
  confirmation is behavioral (a length gap), so the finding carries no
  substring marker and the provenance gate honestly leaves it
  unverified until an analyst confirms it; the proof URL replays the
  wildcard request for manual verification.
  `tests/test_blind_ldap.py` covers both-wildcards, one-wildcard,
  identical-response, unstable-page, error-marker-abort and
  error-path-wins cases.
- OpenAPI spec seeding: `_discover_entry_points` now also fetches
  `/openapi.json` and `/swagger.json` (quiet, best-effort) and feeds
  their declared paths into the crawl via new `xploit/openapi.py`
  (`extract_openapi_paths`). OpenAPI 3 server URLs (relative, absolute
  or templated with defaults/enums) and Swagger 2 host/scheme/basePath
  are resolved; path templates fill with `1`, declared query params
  seed with `xploit`, and same-origin/scope/exclude filtering still
  applies. Malformed specs yield no seeds and never break the crawl.
  `tests/test_openapi.py` covers both spec versions, templating,
  server variables, off-origin filtering and a live fixture server.
- Scan resume (`--checkpoint FILE` / `--resume FILE`, single-target):
  new `xploit/checkpoint.py` writes versioned JSON checkpoints via a
  temp file + rename (mirroring the DurbX pattern), recording the
  target, crawled pages, discovered forms, completed module names and
  their findings. A resumed scan seeds its crawl from the checkpoint's
  pages, skips completed modules entirely, restores their findings into
  the final report, and writes progress back to the same file; a
  target mismatch or an already-finished checkpoint fails fast, and a
  checkpoint write failure is recorded in `errors` without failing the
  scan. Page responses are not persisted, so crawled pages are
  re-fetched to rebuild the in-memory page table.
  `tests/test_checkpoint.py` covers the round-trip, validation errors,
  module skipping, finding restoration, crawl seeding and the
  write-failure path.
- `--format csv`: one row per finding (`id`, `severity`, `url`, `parameter`,
  `evidence`) for spreadsheet pipelines. All findings are included (like JSON),
  multi-target runs share a single header row, and the csv module's quoting
  round-trips evidence containing commas, quotes or newlines.
  `tests/test_csv_format.py` covers the header/rows, quoting round-trip,
  empty-result and multi-target cases.
- Retest summary in JSON reports: `_retest_if_requested` used to only print
  the tally, so pipelines lost it. The tally is now stored on
  `ScanResult.retest_summary` (`{confirmed, fixed, unverifiable, skipped}`,
  `null` when no retest ran) and serialized by `to_dict()`.
  `tests/test_retest_summary.py` covers the default, the stored tally
  (confirmed + passive-skipped) and the flag-off no-op.
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
