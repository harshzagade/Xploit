from __future__ import annotations
import re
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW

class SensitiveDataModule(BaseModule):
    """Detects sensitive data exposure in responses"""
    name = "Sensitive Data Exposure"
    category = "Sensitive Data"

    # Credit card patterns
    CREDIT_CARD_PATTERNS = [
        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b'),  # Visa
        re.compile(r'\b(?:5[1-5][0-9]{14})\b'),  # MasterCard
        re.compile(r'\b(?:3[47][0-9]{13})\b'),  # American Express
        re.compile(r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b'),  # Discover
    ]

    # SSN patterns
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

    # Private key patterns
    PRIVATE_KEY_PATTERNS = [
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
        re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ]

    # Database connection strings
    DB_CONNECTION_PATTERNS = [
        re.compile(r'(?i)(?:mysql|postgres|mongodb|redis)://[^\s<>"]+'),
        re.compile(r'(?i)Server=.+?;Database=.+?;(?:User Id|UID)=.+?;Password=.+?;'),
        re.compile(r'(?i)jdbc:[a-z]+://[^\s<>"]+'),
    ]

    # AWS/Cloud credentials
    CLOUD_CREDENTIAL_PATTERNS = [
        re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key
        re.compile(r'(?i)aws[_\s-]?secret[_\s-]?access[_\s-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),  # Google API Key
        re.compile(r'sk_live_[0-9a-zA-Z]{24}'),  # Stripe Secret
        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),  # Slack Token
    ]

    # Email addresses (potential PII)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    def run(self):
        for url, response in self.scanner.pages.items():
            self._check_response(url, response)

    def _check_response(self, url, response):
        """Check response for sensitive data"""
        if not response or not hasattr(response, 'text'):
            return

        text = response.text
        content_type = response.headers.get("Content-Type", "").lower()

        # Skip binary content
        if "text" not in content_type and "json" not in content_type and "xml" not in content_type:
            return

        # Check for credit cards
        for pattern in self.CREDIT_CARD_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                # Basic Luhn check to reduce false positives
                for match in matches:
                    if self._luhn_check(match):
                        self.add_finding(Finding(
                            id="SENSDATA-001",
                            name="Credit Card Number Exposure",
                            category="Sensitive Data Exposure",
                            severity=HIGH,
                            confidence="High",
                            url=url,
                            evidence=f"Credit card pattern detected: {match[:6]}******{match[-4:]}",
                            impact="Exposure of credit card numbers violates PCI-DSS and can lead to financial fraud.",
                            remediation="Never expose credit card numbers in responses. Use tokenization.",
                            cwe="CWE-359"
                        ))
                        break  # Report once per page

        # Check for SSN
        ssn_matches = self.SSN_PATTERN.findall(text)
        if ssn_matches:
            self.add_finding(Finding(
                id="SENSDATA-002",
                name="Social Security Number Exposure",
                category="Sensitive Data Exposure",
                severity=HIGH,
                confidence="Medium",
                url=url,
                evidence=f"SSN pattern detected: {ssn_matches[0][:3]}-**-****",
                impact="Exposure of SSNs can lead to identity theft and violates privacy regulations.",
                remediation="Never expose SSNs in responses. Mask sensitive data.",
                cwe="CWE-359"
            ))

        # Check for private keys
        for pattern in self.PRIVATE_KEY_PATTERNS:
            if pattern.search(text):
                self.add_finding(Finding(
                    id="SENSDATA-003",
                    name="Private Key Exposure",
                    category="Sensitive Data Exposure",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    evidence="Private cryptographic key detected in response",
                    impact="Exposed private keys can be used to impersonate the server or decrypt communications.",
                    remediation="Remove private keys from web-accessible locations immediately.",
                    cwe="CWE-321"
                ))
                break

        # Check for database connection strings
        for pattern in self.DB_CONNECTION_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                self.add_finding(Finding(
                    id="SENSDATA-004",
                    name="Database Connection String Exposure",
                    category="Sensitive Data Exposure",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    evidence=f"Database connection string detected: {matches[0][:50]}...",
                    impact="Exposed credentials can lead to unauthorized database access.",
                    remediation="Never expose database connection strings. Use environment variables.",
                    cwe="CWE-798"
                ))
                break

        # Check for cloud credentials
        for pattern in self.CLOUD_CREDENTIAL_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                self.add_finding(Finding(
                    id="SENSDATA-005",
                    name="Cloud API Credentials Exposure",
                    category="Sensitive Data Exposure",
                    severity=HIGH,
                    confidence="High",
                    url=url,
                    evidence=f"Cloud API credential detected",
                    impact="Exposed cloud credentials can lead to unauthorized access to cloud resources and data breaches.",
                    remediation="Rotate exposed credentials immediately. Use secret management services.",
                    cwe="CWE-798"
                ))
                break

        # Check for excessive email addresses (PII)
        email_matches = self.EMAIL_PATTERN.findall(text)
        if len(email_matches) > 10:  # More than 10 emails suggests data dump
            self.add_finding(Finding(
                id="SENSDATA-006",
                name="Excessive Email Address Exposure (PII)",
                category="Sensitive Data Exposure",
                severity=MEDIUM,
                confidence="Medium",
                url=url,
                evidence=f"Found {len(email_matches)} email addresses in response",
                impact="Bulk email exposure may violate privacy regulations (GDPR, CCPA) and enable spam/phishing.",
                remediation="Implement pagination and access controls for user data endpoints.",
                cwe="CWE-359"
            ))

    def _luhn_check(self, card_number):
        """Validate credit card using Luhn algorithm to reduce false positives"""
        try:
            digits = [int(d) for d in card_number.replace('-', '').replace(' ', '')]
            checksum = 0
            odd = True
            for digit in reversed(digits):
                if not odd:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
                odd = not odd
            return checksum % 10 == 0
        except:
            return False
