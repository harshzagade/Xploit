from __future__ import annotations
import time
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

class AdvancedInjectionModule(BaseModule):
    name = "Command & Traversal Injection"
    category = "Injection"

    def run(self):
        for url in list(self.scanner.pages):
            self._check_url(url)
        for form in self.scanner.forms:
            self._check_form(form)

    def _check_url(self, url):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            self._test_cmdi(url, param, "GET")
            self._test_traversal(url, param, "GET")

    def _check_form(self, form):
        for param in form.inputs:
            self._test_cmdi(form.action, param, form.method, form.inputs)
            self._test_traversal(form.action, param, form.method, form.inputs)

    def _test_cmdi(self, url, param, method, base_data=None):
        # Time-based CMDI
        payloads = [
            "; sleep 5", "| sleep 5", "& sleep 5", "`sleep 5`", "$(sleep 5)",
            "; ping -c 6 127.0.0.1", "| ping -c 6 127.0.0.1",
            "& ping -n 6 127.0.0.1", # Windows
            "; timeout /t 5", # Windows
        ]
        for payload in payloads:
            start = time.monotonic()
            res = self._send(url, param, method, payload, base_data)
            duration = time.monotonic() - start
            if duration >= 5:
                self._report(url, param, method, payload, "Command Injection", "CMDI-001", "Blind Time-based Command Injection detected.", "CWE-78", "Command Injection")
                return
        
        # Output-based CMDI
        # Using a math expression to distinguish execution from reflection
        payloads = [
            "; echo $((1330+7))", "| echo $((1330+7))", "& echo $((1330+7))",
            "`echo $((1330+7))`", "$(echo $((1330+7)))",
            "; set /a 1330+7", # Windows
        ]
        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res and ("1337" in res.text or "1337" in res.text) and payload not in res.text:
                self._report(url, param, method, payload, "Command Injection", "CMDI-002", "Output-based Command Injection detected via mathematical expression evaluation.", "CWE-78", "Command Injection")
                return

    def _test_traversal(self, url, param, method, base_data=None):
        payloads = [
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//....//etc/passwd",
            "/etc/passwd\x00",
            "../../../../../../etc/passwd%00.jpg",
            "/etc/shadow",
            "/root/.bash_history",
        ]
        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res and any(p in res.text for p in ["root:x:0:0:", "[extensions]", "bin/bash", "[fonts]"]):
                self._report(url, param, method, payload, "Directory Traversal", "TRAV-001", f"Directory Traversal detected using {payload}", "CWE-22", "Directory Traversal")
                return

    def _send(self, url, param, method, payload, base_data=None):
        if method == "GET":
            return self.scanner._request("GET", mutate_query(url, param, payload))
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)

    def _report(self, url, param, method, payload, name, id, evidence, cwe, category):
        self.add_finding(Finding(
            id=id, name=name, category=category, severity=HIGH, confidence="High",
            url=url, parameter=param, method=method, evidence=evidence,
            trigger=f"payload={payload}", impact="Full server compromise possible.",
            remediation="Sanitize inputs and use safe APIs.", cwe=cwe
        ))
