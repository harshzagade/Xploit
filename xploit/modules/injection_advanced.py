from __future__ import annotations
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
        # Output-based CMDI — math expression extremely unlikely to appear in static content
        baseline = self._send(url, param, method, "cmdi_baseline_xploit", base_data)
        baseline_text = baseline.text if baseline else ""

        payloads = [
            "; echo $((1330+7))", "| echo $((1330+7))", "& echo $((1330+7))",
            "`echo $((1330+7))`", "$(echo $((1330+7)))",
            "; set /a 1330+7",
        ]
        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res and "1337" in res.text and "1337" not in baseline_text and payload not in res.text:
                self._report(url, param, method, payload, "Command Injection", "CMDI-001",
                             "Output-based command injection confirmed: arithmetic expression evaluated by shell.",
                             "CWE-78", "Command Injection")
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
                self._report(url, param, method, payload, "Directory Traversal", "TRAV-001",
                             f"Path traversal confirmed: OS file content detected in response.",
                             "CWE-22", "Directory Traversal")
                return

    def _send(self, url, param, method, payload, base_data=None):
        if method == "GET":
            return self.scanner._request("GET", mutate_query(url, param, payload))
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)

    def _report(self, url, param, method, payload, name, id, evidence, cwe, category):
        impacts = {
            "Command Injection": "Command injection allows the attacker to execute arbitrary OS commands on the server, leading to full system compromise, data exfiltration, or lateral movement.",
            "Directory Traversal": "Path traversal allows the attacker to read arbitrary files on the server, including credentials, source code, private keys, and OS configuration files.",
        }
        remediations = {
            "Command Injection": "Never pass user-controlled input to shell commands. Use safe APIs (subprocess with a list, not shell=True). Whitelist allowed values.",
            "Directory Traversal": "Canonicalize file paths and verify they remain within the allowed base directory. Reject any path containing '..' sequences.",
        }
        self.add_finding(Finding(
            id=id, name=name, category=category, severity=HIGH, confidence="High",
            url=url, parameter=param, method=method, evidence=evidence,
            trigger=f"payload={payload}",
            impact=impacts.get(category, "High-severity injection vulnerability confirmed."),
            remediation=remediations.get(category, "Sanitize and validate all user input."),
            cwe=cwe
        ))
