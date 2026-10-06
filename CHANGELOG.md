# Changelog

## Unreleased

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
