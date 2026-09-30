from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, mutate_query

class MultiVectorInjectionModule(BaseModule):
    """Detects LDAP, XML, NoSQL, and SSTI vulnerabilities"""
    name = "Advanced Injection Vulnerabilities"
    category = "Injection"

    def run(self):
        for url in list(self.scanner.pages):
            self._check_url(url)
        for form in self.scanner.forms:
            self._check_form(form)

    def _check_url(self, url):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            self._test_ldap_injection(url, param, "GET")
            self._test_xml_injection(url, param, "GET")
            self._test_nosql_injection(url, param, "GET")
            self._test_ssti(url, param, "GET")

    def _check_form(self, form):
        for param in form.inputs:
            self._test_ldap_injection(form.action, param, form.method, form.inputs)
            self._test_xml_injection(form.action, param, form.method, form.inputs)
            self._test_nosql_injection(form.action, param, form.method, form.inputs)
            self._test_ssti(form.action, param, form.method, form.inputs)

    def _test_ldap_injection(self, url, param, method, base_data=None):
        """Detect LDAP Injection vulnerabilities"""
        payloads = [
            "*", "*)(&", "*))%00", "*()|&", "admin*", "*)(uid=*"
        ]
        ldap_errors = [
            "javax.naming.directory",
            "LDAPException",
            "com.sun.jndi.ldap",
            "ldap_search",
            "Invalid DN syntax",
            "Protocol error occurred",
        ]

        baseline = self._send(url, param, method, "ldap_baseline_xploit", base_data)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if not res:
                continue
            res_lower = res.text.lower()
            matched = [e for e in ldap_errors if e.lower() in res_lower and e.lower() not in baseline_text]
            if matched:
                finding = Finding(
                    id="LDAP-001",
                    name="LDAP Injection",
                    category="LDAP Injection",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence=f"LDAP error string detected: {matched[0]}",
                    impact="Attacker can bypass authentication or extract sensitive LDAP directory information.",
                    remediation="Use parameterized LDAP queries and escape special characters.",
                    cwe="CWE-90"
                )
                self._attach_proof(finding, url, param, method, payload, base_data, matched[0])
                self.add_finding(finding)
                return

    def _test_xml_injection(self, url, param, method, base_data=None):
        """Detect XML Injection and XXE vulnerabilities"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://example.com">]><foo>&xxe;</foo>',
            '<![CDATA[<script>alert(1)</script>]]>',
        ]

        # Baseline: capture what the page normally says so we don't flag
        # static content like HTML DOCTYPEs or "xml" substrings as XXE evidence.
        baseline = self._send(url, param, method, "xml_baseline_xploit", base_data)
        baseline_text = baseline.text if baseline else ""

        # Only flag these if they appear in the payload response but NOT in baseline.
        # "root:x:" gets the same baseline treatment — a page documenting
        # /etc/passwd must not become an XXE finding.
        xxe_error_indicators = [
            "parser error",
            "XML syntax",
            "xml parsing",
            "xmlParseEntityDecl",
            "SimpleXML",
            "DOMDocument",
        ]

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if not res:
                continue

            # XXE file read success — require the marker to be NEW relative to the
            # baseline: a page about /etc/passwd would otherwise false-positive.
            xxe_marker = "root:x:" if "root:x:" in res.text else ("root:!" if "root:!" in res.text else "")
            if xxe_marker and xxe_marker not in baseline_text:
                finding = Finding(
                    id="XXE-001",
                    name="XML External Entity (XXE) Injection",
                    category="XML Injection",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence="File content disclosure detected in response",
                    impact="Attacker can read local files, perform SSRF attacks, or cause denial of service.",
                    remediation="Disable external entity processing in XML parsers.",
                    cwe="CWE-611"
                )
                self._attach_proof(finding, url, param, method, payload, base_data, xxe_marker)
                self.add_finding(finding)
                return

            # XML error indicators — only count ones NOT already in baseline
            new_errors = [
                ind for ind in xxe_error_indicators
                if ind.lower() in res.text.lower() and ind.lower() not in baseline_text.lower()
            ]
            if new_errors:
                finding = Finding(
                    id="XML-001",
                    name="XML Injection",
                    category="XML Injection",
                    severity=MEDIUM,
                    confidence="Medium",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence=f"XML parsing error detected: {new_errors[0]}",
                    impact="Application may be vulnerable to XML injection attacks.",
                    remediation="Validate and sanitize XML input properly.",
                    cwe="CWE-91"
                )
                self._attach_proof(finding, url, param, method, payload, base_data, new_errors[0])
                self.add_finding(finding)
                return

    def _test_nosql_injection(self, url, param, method, base_data=None):
        """Detect NoSQL Injection vulnerabilities"""
        payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            "' || '1'=='1",
            "';return true;var foo='",
        ]

        # "ReferenceError" removed — generic JS error present on any broken page.
        nosql_errors = [
            "MongoDB",
            "CouchDB",
            "MongoError",
            "Cassandra",
            "redis error",
            "\"ok\":0",
        ]

        baseline = self._send(url, param, method, "nosql_baseline_xploit", base_data)
        baseline_text = baseline.text.lower() if baseline else ""

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if not res:
                continue
            res_lower = res.text.lower()
            matched = [e for e in nosql_errors
                       if e.lower() in res_lower and e.lower() not in baseline_text]
            if matched:
                finding = Finding(
                    id="NOSQL-001",
                    name="NoSQL Injection",
                    category="NoSQL Injection",
                    severity=HIGH,
                    confidence="Medium",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence=f"NoSQL database error detected: {matched[0]}",
                    impact="Attacker can bypass authentication or extract sensitive database records.",
                    remediation="Use parameterized queries and validate input types.",
                    cwe="CWE-943"
                )
                self._attach_proof(finding, url, param, method, payload, base_data, matched[0])
                self.add_finding(finding)
                return

    def _test_ssti(self, url, param, method, base_data=None):
        """Detect Server-Side Template Injection"""
        # Each entry: (probe_payload, probe_expected, confirm_payload, confirm_expected)
        # Two distinct math expressions per engine — both must evaluate correctly to confirm.
        # Expected values are distinctive (1337/1903, never 49): "49" appears in
        # prices, years and counters everywhere, which used to skip 5 of 6 engines
        # because the baseline check fired on static content.
        test_cases = [
            ("{{7*191}}", "1337", "{{11*173}}", "1903"),
            ("${7*191}", "1337", "${11*173}", "1903"),
            ("#{7*191}", "1337", "#{11*173}", "1903"),
            ("<%= 7*191 %>", "1337", "<%= 11*173 %>", "1903"),
            ("{{7*'7'}}", "7777777", "{{6*'6'}}", "666666"),
            ("${{7*191}}", "1337", "${{11*173}}", "1903"),
        ]

        # Baseline: fetch the page with a clearly benign value to record static content.
        baseline = self._send(url, param, method, "ssti_baseline_xploit", base_data)
        baseline_text = baseline.text if baseline else ""

        for payload, expected, confirm_payload, confirm_expected in test_cases:
            # Skip if the expected value already appears in the unmodified response —
            # it's part of static content (e.g. inside a hash, a date, a counter).
            if expected in baseline_text:
                continue

            res = self._send(url, param, method, payload, base_data)
            if not res:
                continue

            # Primary hit: expected value present AND payload not literally reflected.
            if expected not in res.text or payload in res.text:
                continue

            # Confirmation: send a second distinct expression for the same engine.
            # A real template engine must evaluate both; coincidental static matches won't.
            confirm_res = self._send(url, param, method, confirm_payload, base_data)
            if not confirm_res or confirm_expected not in confirm_res.text:
                continue

            finding = Finding(
                id="SSTI-001",
                name="Server-Side Template Injection (SSTI)",
                category="Server-Side Template Injection",
                severity=HIGH,
                confidence="High",
                url=url,
                parameter=param,
                method=method,
                trigger=payload,
                evidence=f"Two expressions evaluated: '{payload}'→{expected}, '{confirm_payload}'→{confirm_expected}",
                impact="Attacker can execute arbitrary code on the server, leading to full system compromise.",
                remediation="Avoid passing user input directly to template engines. Use sandboxed templates.",
                cwe="CWE-94"
            )
            self._attach_proof(finding, url, param, method, payload, base_data, expected)
            self.add_finding(finding)
            return

    def _send(self, url, param, method, payload, base_data=None):
        """Helper to send requests"""
        if method == "GET":
            target_url = mutate_query(url, param, payload, base_data)
            return self.scanner._request("GET", target_url)
        else:  # POST
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)

    def _attach_proof(self, finding, url, param, method, payload, base_data, marker):
        """Attach replayable proof mirroring the exact request that fired.

        GET → the mutated query URL as proof_url, empty proof_data.
        POST → the action URL as proof_url, urlencoded body as proof_data.
        Same pattern as sqli.py / xss.py so --retest can re-fire it.
        """
        from urllib.parse import urlencode
        if method == "GET":
            proof_url, proof_data = mutate_query(url, param, payload, base_data), ""
        else:
            data = dict(base_data) if base_data else {}
            data[param] = payload
            proof_url, proof_data = url, urlencode(data)
        return self.attach_proof(finding, method=method, url=proof_url,
                                 marker=marker, data=proof_data)
