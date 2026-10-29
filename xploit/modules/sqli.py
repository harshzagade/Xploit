from __future__ import annotations
from urllib.parse import urlparse
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query, SQL_ERRORS

class SQLInjectionModule(BaseModule):
    name = "SQL Injection"
    category = "Injection"

    def run(self):
        # Shared baseline cache: (url, param, method) -> response.
        # _test_error_based, _test_boolean_based, and _test_stacked_queries
        # all need the same "benign submission" baseline — fetch it once
        # and reuse to avoid 3 redundant identical requests per param.
        self._baseline_cache: dict = {}

        # Probe targets concurrently — requests are I/O-bound and each
        # (url, param) chain is independent. Order of findings still follows
        # the input order via the scanner's serialized dedupe.
        self.scanner.map_probes(self._check_url, list(self.scanner.pages))
        self.scanner.map_probes(self._check_form, list(self.scanner.forms))

    def _check_url(self, url):
        from urllib.parse import parse_qsl
        # Iterate raw pairs (not dict(...).keys()): duplicate parameters
        # (?id=1&id=2) must not be silently collapsed away.
        params = [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        for param in params:
            hint = getattr(self.scanner, 'param_hints', {}).get((url, "GET", param))
            self._probe_param(url, param, "GET", None, hint)

    def _check_form(self, form):
        # External form action: skip entirely — probing third-party endpoints
        # is out of scope. Compare netloc of action vs scanner root host;
        # empty netloc means same host (relative action).
        action_netloc = urlparse(form.action).netloc
        root_netloc = urlparse(self.scanner.root).netloc
        if action_netloc and action_netloc != root_netloc:
            return

        method = form.method.upper()
        for param in form.inputs:
            hint = getattr(self.scanner, 'param_hints', {}).get(
                (form.action, method, param))
            self._probe_param(form.action, param, form.method, form.inputs, hint)

    def _probe_param(self, url, param, method, base_data, hint):
        """Run the technique chain for one (url, param, method) target.

        hint=None or hint['changes']=True  ->  full chain as before.
        hint exists and hint['changes']=False  ->  reduced chain:
          run error-based as usual; skip union and stacked;
          run time-based in reduced mode (first payload only).
          boolean is also skipped (no response signal = boolean can't confirm).
        """
        if hint is not None and not hint["changes"]:
            # Inert param: reduced chain
            if self._test_error_based(url, param, method, base_data):
                return
            # Skip union, boolean, stacked — no response signal to exploit
            self._test_time_based(url, param, method, base_data, max_payloads=1)
        else:
            # Full chain (no hint, or hint shows changes)
            if self._test_error_based(url, param, method, base_data):
                return
            if self._test_union_based(url, param, method, base_data):
                return
            if self._test_boolean_based(url, param, method, base_data):
                return
            if self._test_time_based(url, param, method, base_data):
                return
            self._test_stacked_queries(url, param, method, base_data)

    # -----------------------------------------------------------------------
    # Shared baseline cache
    # -----------------------------------------------------------------------

    def _baseline(self, url, param, method, base_data=None):
        """Fetch the baseline response for (url, param, method) once and cache.

        Uses the 'sqli_baseline_xploit' sentinel so the server sees a benign
        request the first time, then returns the cached object on subsequent
        calls from other techniques on the same param.  _test_time_based keeps
        its own timed baseline (it needs timing measurement).
        """
        # Lazily created: techniques are also called directly (tests,
        # retest paths) without run() having initialised the cache.
        if getattr(self, "_baseline_cache", None) is None:
            self._baseline_cache = {}
        key = (url, param, method.upper() if method else "GET")
        if key not in self._baseline_cache:
            res = self._send_payload(url, param, method, "sqli_baseline_xploit", base_data)
            self._baseline_cache[key] = res
        return self._baseline_cache[key]

    def _test_error_based(self, url, param, method, base_data=None):
        payloads = [
            "'", "\"", "')", "\")", "'))", "\"))",
            "' OR '1'='1", "\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--",
            "' OR 1=1#", "\" OR 1=1#",
            "\\", "%%", "%' OR '1'='1",
            "')) OR 1=1--",
            "\" OR \"a\"=\"a",
            "') OR ('a'='a",
        ]
        # Use shared baseline (fetched once per param across techniques).
        baseline = self._baseline(url, param, method, base_data)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res:
                continue
            res_text = res.text.lower()
            for error in SQL_ERRORS:
                if error in res_text and error not in baseline_text:
                    self._report(url, param, method, payload,
                                 f"New SQL error message appeared in response: {error}",
                                 base_data, marker=error)
                    return True

    def _send_payload(self, url, param, method, payload, base_data=None):
        if method == "GET":
            # Pass sibling form fields so GET forms (action URL with no query
            # string) actually send the payload instead of dropping it.
            return self.scanner._request("GET", mutate_query(url, param, payload, base_data))
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)

    def _test_union_based(self, url, param, method, base_data=None):
        payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3,4,5--",
            "') UNION SELECT NULL,NULL,NULL--",
        ]
        baseline = self._send_payload(url, param, method, "union_baseline_xploit", base_data)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res:
                continue
            res_lower = res.text.lower()
            matched = next((e for e in SQL_ERRORS if e in res_lower and e not in baseline_text), "")
            if matched:
                self._report(url, param, method, payload,
                             "Union-based SQLi: SQL error appeared in response to UNION payload",
                             base_data, marker=matched)
                return True

    def _test_boolean_based(self, url, param, method, base_data=None):
        true_payloads  = ["' AND '1'='1", "' AND 1=1--", "') AND ('1'='1"]
        false_payloads = ["' AND '1'='2", "' AND 1=2--", "') AND ('1'='2"]

        # Use shared baseline (fetched once per param across techniques).
        baseline = self._baseline(url, param, method, base_data)
        baseline_len = len(baseline.text) if baseline else 0

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_res  = self._send_payload(url, param, method, true_p, base_data)
            false_res = self._send_payload(url, param, method, false_p, base_data)
            if not true_res or not false_res:
                continue
            true_len  = len(true_res.text)
            false_len = len(false_res.text)
            # Empty-body endpoints have a zero baseline — still a valid
            # comparison, so no baseline_len > 0 gate here.
            true_near_baseline = abs(true_len - baseline_len) < 150
            significant_diff   = abs(true_len - false_len) > 200
            if true_near_baseline and significant_diff:
                self._report(url, param, method, true_p,
                             f"Boolean-based blind SQLi: TRUE({true_len}B) vs FALSE({false_len}B) — {abs(true_len - false_len)}B delta",
                             base_data, marker="")
                return True

    def _timed_payload(self, url, param, method, payload, base_data=None):
        """Send a payload, returning (response, elapsed_seconds)."""
        import time
        start = time.monotonic()
        res = self._send_payload(url, param, method, payload, base_data)
        return res, time.monotonic() - start

    def _test_time_based(self, url, param, method, base_data=None, max_payloads=None):
        """Time-based blind SQLi: confirm via reproducible response delay.

        Fires DBMS-specific sleep payloads and requires the delay to reproduce
        on a second firing (differential against a fresh baseline), so a
        one-off slow response can't confirm. Attaches a timing proof, which
        the evidence gate treats as verified and --retest can re-measure.

        When target_profile carries a dbms_hint for a known DBMS family,
        only that family's payloads are fired — wasteful cross-family probes
        (e.g. MySQL SLEEP against an IIS/ASP.NET target) are skipped.

        max_payloads: when set, only the first N payloads of the selected
        family are attempted (used by the reduced-chain path for inert params).
        """
        SLEEP_S = 4
        MARGIN_S = 1.0
        threshold = SLEEP_S - MARGIN_S
        if self.scanner.timeout < SLEEP_S + 2:
            # The sleep wouldn't fit inside the request timeout — any delay
            # measurement would be cut off, so the technique can't confirm.
            return False

        # DBMS-grouped payloads. Keys match the dbms_hint values from
        # _build_target_profile: 'mysql', 'mssql', 'postgres'.
        _mysql_payloads = [
            f"' OR SLEEP({SLEEP_S})--",    # MySQL / MariaDB
            f"' AND SLEEP({SLEEP_S})--",
        ]
        _mssql_payloads = [
            f"'; WAITFOR DELAY '0:0:0{SLEEP_S}'--",  # MSSQL
        ]
        _postgres_payloads = [
            f"' OR pg_sleep({SLEEP_S})--",  # PostgreSQL
        ]

        hint = (getattr(self.scanner, "target_profile", None) or {}).get("dbms_hint", "unknown")
        if hint == "mysql":
            payloads = _mysql_payloads
        elif hint == "mssql":
            payloads = _mssql_payloads
        elif hint == "postgres":
            payloads = _postgres_payloads
        else:
            # Unknown or no hint — fire all families (original behavior).
            payloads = _mysql_payloads + _mssql_payloads + _postgres_payloads

        # Apply the per-call cap (used by reduced-chain path for inert params)
        if max_payloads is not None:
            payloads = payloads[:max_payloads]

        base_res, base_dt = self._timed_payload(
            url, param, method, "sqli_baseline_xploit", base_data)
        if base_res is None:
            # No clean baseline: a delay against nothing proves nothing.
            return False

        for payload in payloads:
            res, dt = self._timed_payload(url, param, method, payload, base_data)
            if res is None:
                continue
            if dt - base_dt < threshold:
                continue
            # Delay observed — confirm it reproduces on a second firing.
            res2, dt2 = self._timed_payload(url, param, method, payload, base_data)
            if res2 is not None and dt2 - base_dt >= threshold:
                self._report(url, param, method, payload,
                             f"Time-based blind SQLi: response delayed "
                             f"{dt:.1f}s / {dt2:.1f}s vs {base_dt:.1f}s baseline "
                             f"(>= {threshold:g}s differential, reproduced twice)",
                             base_data, marker="",
                             kind="timing", delay_s=threshold)
                return True
        return False

    def _test_stacked_queries(self, url, param, method, base_data=None):
        hint = (getattr(self.scanner, "target_profile", None) or {}).get("dbms_hint", "unknown")
        # EXEC sp_MSforeachtable is MSSQL-only; skip it when the target is
        # fingerprinted as a different DBMS. information_schema is generic
        # and always fires.
        payloads = []
        if hint in ("mssql", "unknown"):
            payloads.append("'; EXEC sp_MSforeachtable 'SELECT 1'--")
        payloads.append("1; SELECT COUNT(*) FROM information_schema.tables--")

        # Use shared baseline (fetched once per param across techniques).
        baseline = self._baseline(url, param, method, base_data)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res:
                continue
            indicators = ["multiple statements", "syntax near", "expects parameter"]
            text_lower = res.text.lower()
            matched = next((ind for ind in indicators if ind in text_lower and ind not in baseline_text), "")
            if matched:
                self._report(url, param, method, payload,
                             "Stacked queries SQLi: Error response suggests multiple statement support",
                             base_data, marker=matched)
                return True

    def _report(self, url, param, method, payload, evidence, base_data=None,
                marker="", kind="marker", delay_s=0.0):
        from urllib.parse import urlencode
        ev_lower = evidence.lower()
        if "union" in ev_lower:
            sqli_type, finding_id = "Union-based SQL Injection", "SQLI-003"
        elif "boolean" in ev_lower:
            sqli_type, finding_id = "Boolean-based Blind SQL Injection", "SQLI-004"
        elif "time-based" in ev_lower:
            sqli_type, finding_id = "Time-based Blind SQL Injection", "SQLI-002"
        elif "stacked" in ev_lower:
            sqli_type, finding_id = "Stacked Queries SQL Injection", "SQLI-005"
        else:
            sqli_type, finding_id = "SQL Injection", "SQLI-001"

        finding = Finding(
            id=finding_id,
            name=sqli_type,
            category="SQL Injection",
            severity=HIGH,
            confidence="High",
            url=url,
            parameter=param,
            method=method,
            evidence=evidence,
            trigger=f"payload={payload}",
            impact="If confirmed, SQL injection allows attackers to read, modify, or delete database records — leading to authentication bypass, data theft, or full system compromise.",
            remediation="Use parameterized queries, prepared statements, and input validation. Never concatenate user input into SQL queries.",
            cwe="CWE-89"
        )
        # Replayable proof: the exact request that triggered the finding, so the
        # evidence gate can verify it and --retest can re-fire it.
        if method == "GET":
            proof_url, proof_data = mutate_query(url, param, payload, base_data), ""
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            proof_url, proof_data = url, urlencode(data)
        self.attach_proof(finding, method=method, url=proof_url, marker=marker,
                          data=proof_data, kind=kind, delay_s=delay_s)
        self.add_finding(finding)
