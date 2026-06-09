from __future__ import annotations
from urllib.parse import parse_qs, urlparse
from .base import BaseModule
from ..scanner import Finding, MEDIUM

class AdvancedAuthModule(BaseModule):
    """Detects authentication and session management issues"""
    name = "Authentication & Session Issues"
    category = "Authentication"

    def run(self):
        self._check_username_enumeration()
        self._check_session_management()

    def _check_username_enumeration(self):
        for form in self.scanner.forms:
            if not any('password' in t for t in form.input_types.values()):
                continue

            username_fields = [
                n for n in form.inputs
                if any(x in n.lower() for x in ['user', 'email', 'login', 'name'])
            ]
            if not username_fields:
                continue

            pwd_fields = [k for k, v in form.input_types.items() if v == 'password']
            if not pwd_fields:
                continue

            ufield = username_fields[0]
            pfield = pwd_fields[0]

            responses = []
            for username in ("admin", "nonexistent_user_xploit_99z"):
                data = dict(form.inputs)
                data[ufield] = username
                data[pfield] = "wrongpass_xploit"
                res = self.scanner._request(
                    form.method, form.action,
                    data=data if form.method == "POST" else None,
                    params=data if form.method == "GET" else None,
                )
                if res:
                    responses.append((username, len(res.text), res.text.lower()))

            if len(responses) != 2:
                continue

            size0, size1 = responses[0][1], responses[1][1]
            text0, text1 = responses[0][2], responses[1][2]

            # Size-based: require a substantial diff (>300 bytes) to avoid noise from
            # dynamic elements like timestamps, session IDs, or minor layout changes.
            if abs(size0 - size1) > 300:
                self.add_finding(Finding(
                    id="AUTH-004",
                    name="Username Enumeration via Response Size",
                    category="Authentication",
                    severity=MEDIUM,
                    confidence="Medium",
                    url=form.action,
                    method=form.method,
                    evidence=f"Response size differs by {abs(size0 - size1)} bytes for valid vs invalid username",
                    impact="Attackers can enumerate valid usernames, enabling targeted brute-force attacks.",
                    remediation="Return identical responses for valid and invalid usernames.",
                    cwe="CWE-204"
                ))
                continue

            # Message-based: only flag if a specific distinguishing error phrase
            # appears for one username but not the other.
            distinct_errors = [
                "user not found", "invalid user", "user does not exist",
                "incorrect password", "wrong password",
            ]
            for phrase in distinct_errors:
                in0 = phrase in text0
                in1 = phrase in text1
                if in0 != in1:
                    self.add_finding(Finding(
                        id="AUTH-003",
                        name="Username Enumeration via Error Messages",
                        category="Authentication",
                        severity=MEDIUM,
                        confidence="High",
                        url=form.action,
                        method=form.method,
                        evidence=f"Error message '{phrase}' present for one username but not the other",
                        impact="Attackers can determine valid usernames through distinct error messages.",
                        remediation="Use a generic message like 'Invalid credentials' for all failures.",
                        cwe="CWE-204"
                    ))
                    break

    def _check_session_management(self):
        for url, response in self.scanner.pages.items():
            if not response:
                continue

            # Session token exposed in URL query string
            parsed = urlparse(url)
            for param in parse_qs(parsed.query):
                if any(x in param.lower() for x in ['sessionid', 'session', 'sid', 'token', 'auth']):
                    self.add_finding(Finding(
                        id="AUTH-005",
                        name="Session Token in URL",
                        category="Session Management",
                        severity=MEDIUM,
                        confidence="High",
                        url=url,
                        parameter=param,
                        evidence=f"Session-like parameter '{param}' exposed in URL",
                        impact="Tokens in URLs leak through Referer headers, browser history, and server logs.",
                        remediation="Use HttpOnly cookies for session tokens, never pass them in URLs.",
                        cwe="CWE-598"
                    ))

            # Insecure session cookie flags — only flag when the URL clearly belongs to
            # a login/auth flow, the response actually sets a session cookie, and both
            # Secure AND HttpOnly are absent (either missing on HTTPS is enough for HIGH,
            # but we report MEDIUM here as a conservative heuristic).
            set_cookie = response.headers.get("Set-Cookie", "")
            if not set_cookie:
                continue
            is_auth_url = any(x in url.lower() for x in ['login', 'signin', 'auth'])
            has_session_cookie = any(x in set_cookie.lower() for x in ['phpsessid', 'session', 'sid', 'jsessionid'])
            if is_auth_url and has_session_cookie:
                missing = []
                if "Secure" not in set_cookie:
                    missing.append("Secure")
                if "HttpOnly" not in set_cookie:
                    missing.append("HttpOnly")
                if missing:
                    self.add_finding(Finding(
                        id="AUTH-006",
                        name="Insecure Session Cookie Flags",
                        category="Session Management",
                        severity=MEDIUM,
                        confidence="High",
                        url=url,
                        evidence=f"Session cookie missing flag(s): {', '.join(missing)}",
                        impact="Session cookies without Secure/HttpOnly are vulnerable to network interception and XSS theft.",
                        remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                        cwe="CWE-614"
                    ))
