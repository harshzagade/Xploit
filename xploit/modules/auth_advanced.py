from __future__ import annotations
import re
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM, LOW

class AdvancedAuthModule(BaseModule):
    """Detects advanced authentication and session management issues"""
    name = "Advanced Authentication Issues"
    category = "Authentication"

    def run(self):
        self._check_username_enumeration()
        self._check_weak_password_policy()
        self._check_session_management()
        self._check_default_credentials()

    def _check_username_enumeration(self):
        """Detect username enumeration vulnerabilities"""
        for form in self.scanner.forms:
            # Look for login forms
            if any('password' in inp_type for inp_type in form.input_types.values()):
                # Check if there's a username/email field
                username_fields = [name for name in form.inputs.keys()
                                 if any(x in name.lower() for x in ['user', 'email', 'login', 'name'])]

                if username_fields:
                    # Test with valid-looking and invalid usernames
                    test_cases = [
                        ("admin", "wrongpass"),
                        ("nonexistent_user_12345", "wrongpass")
                    ]

                    responses = []
                    for username, password in test_cases:
                        data = dict(form.inputs)
                        data[username_fields[0]] = username
                        # Find password field
                        pwd_field = [k for k, v in form.input_types.items() if v == 'password']
                        if pwd_field:
                            data[pwd_field[0]] = password

                        res = self.scanner._request(form.method, form.action,
                                                   data=data if form.method == "POST" else None,
                                                   params=data if form.method == "GET" else None)
                        if res:
                            responses.append((username, len(res.text), res.text))

                    # Check for different responses
                    if len(responses) == 2:
                        if abs(responses[0][1] - responses[1][1]) > 50:  # Significant size difference
                            self.add_finding(Finding(
                                id="AUTH-002",
                                name="Username Enumeration via Response Timing/Size",
                                category="Authentication",
                                severity=MEDIUM,
                                confidence="Medium",
                                url=form.action,
                                method=form.method,
                                evidence=f"Different response sizes: {responses[0][1]} vs {responses[1][1]} bytes",
                                impact="Attackers can enumerate valid usernames, enabling targeted password attacks.",
                                remediation="Return identical responses for valid and invalid usernames.",
                                cwe="CWE-204"
                            ))
                        # Check for different error messages
                        elif responses[0][2] != responses[1][2]:
                            error_patterns = [
                                "user not found", "invalid user", "user does not exist",
                                "incorrect password", "wrong password", "invalid credentials"
                            ]
                            resp0_lower = responses[0][2].lower()
                            resp1_lower = responses[1][2].lower()

                            if any(p in resp0_lower or p in resp1_lower for p in error_patterns):
                                if resp0_lower != resp1_lower:
                                    self.add_finding(Finding(
                                        id="AUTH-003",
                                        name="Username Enumeration via Error Messages",
                                        category="Authentication",
                                        severity=MEDIUM,
                                        confidence="High",
                                        url=form.action,
                                        method=form.method,
                                        evidence="Different error messages for valid/invalid usernames",
                                        impact="Attackers can enumerate valid usernames through distinct error messages.",
                                        remediation="Use generic error messages like 'Invalid credentials'.",
                                        cwe="CWE-204"
                                    ))

    def _check_weak_password_policy(self):
        """Check for weak password policy indicators"""
        for form in self.scanner.forms:
            if any('password' in inp_type for inp_type in form.input_types.values()):
                # Try common weak passwords
                weak_passwords = ["password", "123456", "admin", "test"]

                # Look for registration or password change forms
                action_lower = form.action.lower()
                if any(x in action_lower for x in ['register', 'signup', 'create', 'password']):
                    # Test if weak password is accepted (in passive mode, just check form attributes)
                    password_fields = [k for k, v in form.input_types.items() if v == 'password']

                    # Check for password policy indicators in page
                    page_response = self.scanner.pages.get(form.page_url)
                    if page_response:
                        text_lower = page_response.text.lower()
                        has_policy = any(indicator in text_lower for indicator in [
                            'minimum length', 'special character', 'uppercase',
                            'lowercase', 'number required', 'password strength'
                        ])

                        if not has_policy and password_fields:
                            # Check HTML5 pattern attribute
                            has_html_validation = False
                            # This is a heuristic check
                            if 'pattern=' in page_response.text or 'minlength=' in page_response.text:
                                has_html_validation = True

                            if not has_html_validation:
                                self.add_finding(Finding(
                                    id="AUTH-004",
                                    name="Weak Password Policy",
                                    category="Authentication",
                                    severity=MEDIUM,
                                    confidence="Low",
                                    url=form.action,
                                    method=form.method,
                                    evidence="No password complexity requirements detected in form",
                                    impact="Weak passwords make accounts vulnerable to brute-force and dictionary attacks.",
                                    remediation="Enforce minimum 8 characters, mixed case, numbers, and special characters.",
                                    cwe="CWE-521"
                                ))

    def _check_session_management(self):
        """Check for session management issues"""
        for url, response in self.scanner.pages.items():
            if not response:
                continue

            # Check for session tokens in URL
            if any(x in url.lower() for x in ['sessionid', 'session', 'sid', 'token', 'auth']):
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param, values in params.items():
                    if any(x in param.lower() for x in ['session', 'sid', 'token', 'auth']):
                        self.add_finding(Finding(
                            id="AUTH-005",
                            name="Session Token in URL",
                            category="Session Management",
                            severity=MEDIUM,
                            confidence="High",
                            url=url,
                            parameter=param,
                            evidence=f"Session token '{param}' exposed in URL",
                            impact="Session tokens in URLs can be leaked through Referer headers, logs, and browser history.",
                            remediation="Use secure, HTTPOnly cookies for session management.",
                            cwe="CWE-598"
                        ))

            # Check for session fixation indicators
            set_cookie = response.headers.get("Set-Cookie", "")
            if set_cookie:
                # Check if session cookie is set before authentication
                if "session" in set_cookie.lower() or "sid" in set_cookie.lower():
                    # Check if we're on a login page
                    if any(x in url.lower() for x in ['login', 'signin', 'auth']):
                        # Check if the session cookie lacks Secure and HTTPOnly flags
                        if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
                            self.add_finding(Finding(
                                id="AUTH-006",
                                name="Insecure Session Cookie Flags",
                                category="Session Management",
                                severity=MEDIUM,
                                confidence="High",
                                url=url,
                                evidence=f"Session cookie missing Secure or HttpOnly flags",
                                impact="Session cookies without proper flags are vulnerable to interception and XSS attacks.",
                                remediation="Set Secure, HttpOnly, and SameSite flags on session cookies.",
                                cwe="CWE-614"
                            ))

    def _check_default_credentials(self):
        """Check for common default credentials (heuristic)"""
        login_forms = []
        for form in self.scanner.forms:
            if any('password' in inp_type for inp_type in form.input_types.values()):
                login_forms.append(form)

        # Common default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("administrator", "administrator"),
            ("guest", "guest"),
        ]

        for form in login_forms[:1]:  # Only test one form to avoid excessive requests
            username_fields = [name for name in form.inputs.keys()
                             if any(x in name.lower() for x in ['user', 'email', 'login', 'name'])]
            password_fields = [k for k, v in form.input_types.items() if v == 'password']

            if username_fields and password_fields:
                # Just report that default credentials should be tested
                # Actually testing would generate too many requests
                self.add_finding(Finding(
                    id="AUTH-007",
                    name="Potential Default Credentials (Manual Check Required)",
                    category="Authentication",
                    severity=LOW,
                    confidence="Low",
                    url=form.action,
                    method=form.method,
                    evidence="Login form detected - manual testing for default credentials recommended",
                    impact="Default credentials provide easy unauthorized access to attackers.",
                    remediation="Ensure all default credentials are changed and enforce unique passwords.",
                    cwe="CWE-798"
                ))
                break  # Report once
