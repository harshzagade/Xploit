from __future__ import annotations
import re
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, mutate_query

class AdvancedInjectionModule(BaseModule):
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
            "Protocol error occurred"
        ]

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res and any(error.lower() in res.text.lower() for error in ldap_errors):
                self.add_finding(Finding(
                    id="LDAP-001",
                    name="LDAP Injection",
                    category="LDAP Injection",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence=f"LDAP error detected in response",
                    impact="Attacker can bypass authentication or extract sensitive LDAP directory information.",
                    remediation="Use parameterized LDAP queries and escape special characters.",
                    cwe="CWE-90"
                ))
                return

    def _test_xml_injection(self, url, param, method, base_data=None):
        """Detect XML Injection and XXE vulnerabilities"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://example.com">]><foo>&xxe;</foo>',
            '<![CDATA[<script>alert(1)</script>]]>',
        ]

        xxe_indicators = [
            "root:x:",  # /etc/passwd content
            "ENTITY",
            "DOCTYPE",
            "xml version",
            "parser error",
            "XML syntax"
        ]

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res:
                # Check for XXE exploitation success
                if "root:x:" in res.text or "root:!" in res.text:
                    self.add_finding(Finding(
                        id="XXE-001",
                        name="XML External Entity (XXE) Injection",
                        category="XML Injection",
                        severity=HIGH,
                        confidence="High",
                        url=url,
                        parameter=param,
                        method=method,
                        trigger=payload[:50],
                        evidence="File content disclosure detected in response",
                        impact="Attacker can read local files, perform SSRF attacks, or cause denial of service.",
                        remediation="Disable external entity processing in XML parsers.",
                        cwe="CWE-611"
                    ))
                    return
                # Check for XML parsing errors
                elif any(indicator in res.text for indicator in xxe_indicators):
                    self.add_finding(Finding(
                        id="XML-001",
                        name="XML Injection",
                        category="XML Injection",
                        severity=MEDIUM,
                        confidence="Medium",
                        url=url,
                        parameter=param,
                        method=method,
                        trigger=payload[:50],
                        evidence="XML parsing error detected",
                        impact="Application may be vulnerable to XML injection attacks.",
                        remediation="Validate and sanitize XML input properly.",
                        cwe="CWE-91"
                    ))
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

        nosql_errors = [
            "MongoDB",
            "CouchDB",
            "\"ok\":0",
            "MongoError",
            "Cassandra",
            "redis error",
            "ReferenceError"
        ]

        for payload in payloads:
            res = self._send(url, param, method, payload, base_data)
            if res and any(error in res.text for error in nosql_errors):
                self.add_finding(Finding(
                    id="NOSQL-001",
                    name="NoSQL Injection",
                    category="NoSQL Injection",
                    severity=HIGH,
                    confidence="Medium",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence="NoSQL database error detected",
                    impact="Attacker can bypass authentication or extract sensitive database records.",
                    remediation="Use parameterized queries and validate input types.",
                    cwe="CWE-943"
                ))
                return

    def _test_ssti(self, url, param, method, base_data=None):
        """Detect Server-Side Template Injection"""
        # Test expressions that evaluate to specific numbers
        test_cases = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${{7*7}}", "49"),
        ]

        for payload, expected in test_cases:
            res = self._send(url, param, method, payload, base_data)
            if res and expected in res.text and payload not in res.text:
                self.add_finding(Finding(
                    id="SSTI-001",
                    name="Server-Side Template Injection (SSTI)",
                    category="Server-Side Template Injection",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    parameter=param,
                    method=method,
                    trigger=payload,
                    evidence=f"Template expression evaluated: {expected} found in response",
                    impact="Attacker can execute arbitrary code on the server, leading to full system compromise.",
                    remediation="Avoid passing user input directly to template engines. Use sandboxed templates.",
                    cwe="CWE-94"
                ))
                return

    def _send(self, url, param, method, payload, base_data=None):
        """Helper to send requests"""
        if method == "GET":
            target_url = mutate_query(url, param, payload)
            return self.scanner._request("GET", target_url)
        else:  # POST
            data = dict(base_data) if base_data else {}
            data[param] = payload
            return self.scanner._request("POST", url, data=data)
