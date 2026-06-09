from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, INFO

class BruteForceModule(BaseModule):
    """Comprehensive default credential and weak password testing"""
    name = "Brute Force & Default Credentials"
    category = "Authentication"

    # Known vendor/service default credentials
    DEFAULT_CREDENTIALS = [
        # Web Applications
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("administrator", "password"),

        # System Accounts
        ("root", "root"),
        ("root", "password"),
        ("root", "toor"),
        ("root", ""),

        # Database Defaults
        ("sa", ""),
        ("sa", "sa"),
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("mysql", "mysql"),
        ("oracle", "oracle"),
        ("mongo", "mongo"),

        # Service Accounts
        ("guest", "guest"),
        ("guest", ""),
        ("user", "user"),
        ("user", "password"),
        ("test", "test"),
        ("demo", "demo"),

        # IoT & Routers
        ("admin", ""),
        ("admin", "1234"),
        ("admin", "admin1"),
        ("admin", "default"),
        ("support", "support"),

        # Application Servers
        ("tomcat", "tomcat"),
        ("tomcat", "admin"),
        ("weblogic", "weblogic"),
        ("weblogic", "welcome1"),
        ("jenkins", "jenkins"),

        # CMS Defaults
        ("wordpress", "wordpress"),
        ("joomla", "joomla"),

        # Generic weak passwords
        ("user", "123456"),
        ("admin", "qwerty"),
        ("admin", "letmein"),
    ]

    # Username-based weak passwords: tested against the actual username discovered in the form.
    # e.g. if username field value is "admin", tests admin:admin, admin:password, etc.
    WEAK_PASSWORD_SUFFIXES = [
        "",           # username:username (same as username)
        "123",
        "1234",
        "12345",
        "123456",
        "1234567890",
        "@123",
        "@1234",
        "password",
        "pass",
        "pass123",
        "pass@123",
        "abc123",
        "qwerty",
        "letmein",
        "welcome",
        "welcome1",
        "changeme",
        "secret",
        "test",
        "temp",
        "login",
    ]

    def run(self):
        """Test login forms for default and weak credentials"""
        login_forms = self._identify_login_forms()

        if not login_forms:
            return

        for form in login_forms:
            self._test_form_credentials(form)

    def _identify_login_forms(self):
        """Identify forms that are likely login forms"""
        login_forms = []

        for form in self.scanner.forms:
            has_password = any('password' in inp_type for inp_type in form.input_types.values())
            if not has_password:
                continue

            has_username = any(
                any(x in name.lower() for x in ['user', 'email', 'login', 'name', 'username'])
                for name in form.inputs.keys()
            )

            if has_username:
                action_lower = form.action.lower()
                is_login_action = any(x in action_lower for x in ['login', 'signin', 'auth', 'authenticate'])
                if is_login_action:
                    login_forms.insert(0, form)
                else:
                    login_forms.append(form)

        return login_forms

    def _test_form_credentials(self, form):
        """Test a form with default and weak credentials"""
        username_field = None
        password_field = None

        # Break after first match — avoid overwriting with the last matching field
        for name in form.inputs.keys():
            if any(x in name.lower() for x in ['user', 'email', 'login', 'name', 'username']):
                username_field = name
                break

        for name, inp_type in form.input_types.items():
            if inp_type == 'password':
                password_field = name
                break

        if not username_field or not password_field:
            return

        baseline_res = self.scanner._request(
            form.method,
            form.action,
            data=form.inputs if form.method == "POST" else None,
            params=form.inputs if form.method == "GET" else None,
            allow_redirects=False,
        )

        # --- Phase 1: vendor default credentials ---
        tested_count = 0
        for username, password in self.DEFAULT_CREDENTIALS:
            tested_count += 1
            if self._try_login(form, username_field, password_field, username, password, baseline_res):
                self.add_finding(Finding(
                    id="BRUTE-001",
                    name="Default Credentials Accepted",
                    category="Broken Authentication",
                    severity=HIGH,
                    confidence="High",
                    url=form.action,
                    method=form.method,
                    parameter=f"{username_field}, {password_field}",
                    evidence=f"Successfully authenticated with default credentials: {username}:{password}",
                    impact="Default credentials allow complete unauthorized access. Attackers can take over accounts, access sensitive data, or compromise the entire application.",
                    remediation="Change all default credentials immediately. Disable or remove default accounts. Enforce strong password policies on account creation.",
                    cwe="CWE-798"
                ))
                return

        # --- Phase 2: username-based weak passwords ---
        # Build a short list of username-derived guesses.
        # The username field may contain a pre-filled value from the form HTML (e.g. "admin")
        # or be empty. Either way, enumerate a small set of likely real usernames.
        candidate_usernames = ["admin", "administrator", "user", "test", "guest", "root"]
        existing_val = str(form.inputs.get(username_field, "")).strip()
        if existing_val and existing_val not in candidate_usernames:
            candidate_usernames.insert(0, existing_val)

        for u in candidate_usernames:
            for suffix in self.WEAK_PASSWORD_SUFFIXES:
                password = u + suffix if suffix else u
                tested_count += 1
                if self._try_login(form, username_field, password_field, u, password, baseline_res):
                    self.add_finding(Finding(
                        id="BRUTE-003",
                        name="Weak / Username-Based Credentials Accepted",
                        category="Broken Authentication",
                        severity=HIGH,
                        confidence="High",
                        url=form.action,
                        method=form.method,
                        parameter=f"{username_field}, {password_field}",
                        evidence=f"Successfully authenticated with weak credentials: {u}:{password}",
                        impact="Weak credentials allow account takeover. Attackers exploit predictable patterns (username as password, appended digits) in automated attacks.",
                        remediation="Enforce a strong password policy that rejects passwords matching or derived from the username. Implement rate limiting and account lockout.",
                        cwe="CWE-521"
                    ))
                    return

        # Report that testing was performed — INFO only, not a vulnerability
        self.add_finding(Finding(
            id="BRUTE-002",
            name="Login Form Detected (Credential Testing Performed)",
            category="Authentication",
            severity=INFO,
            confidence="Low",
            url=form.action,
            method=form.method,
            evidence=f"Tested {tested_count} credential pairs (default + username-based weak) — none accepted",
            impact="Login form is present. Common defaults and weak patterns were rejected. Manual testing with a full wordlist is still recommended.",
            remediation="Enforce strong password policies, rate limiting, and account lockout.",
            cwe="CWE-798"
        ))

    def _try_login(self, form, username_field, password_field, username, password, baseline_res):
        """Submit one credential pair and return True if login appears successful."""
        data = dict(form.inputs)
        data[username_field] = username
        data[password_field] = password

        res = self.scanner._request(
            form.method,
            form.action,
            data=data if form.method == "POST" else None,
            params=data if form.method == "GET" else None,
            allow_redirects=False,
        )
        return self._is_successful_login(res, baseline_res)

    def _is_successful_login(self, response, baseline):
        """Determine if a login attempt was successful"""
        if not response:
            return False

        response_text = response.text.lower()
        baseline_text = baseline.text.lower() if baseline else ""
        baseline_len = len(baseline.text) if baseline else 0

        # Failure phrases — checked before redirect so a redirect to /error isn't a false positive
        failure_indicators = [
            "invalid", "incorrect", "failed", "error",
            "wrong", "denied", "unauthorized", "forbidden",
            "bad credentials", "authentication failed",
            "try again", "password is incorrect", "invalid password",
            "invalid username",
        ]
        if any(ind in response_text for ind in failure_indicators):
            return False

        # Redirect to a non-login URL after passing failure check = success
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_location = response.headers.get('Location', '').lower()
            if not any(x in redirect_location for x in ['login', 'signin', 'auth']):
                return True

        # Only count success phrases that were NOT already on the login page baseline.
        success_indicators = [
            "welcome", "dashboard", "logged in",
            "login successful", "authentication successful",
            "sign out", "log out", "my account", "my profile",
            "admin panel", "user panel",
        ]
        new_success = any(
            ind in response_text and ind not in baseline_text
            for ind in success_indicators
        )
        if new_success:
            return True

        # Large response growth (2× baseline) with no failure = likely dashboard loaded.
        if baseline_len > 0 and len(response.text) > baseline_len * 2:
            return True

        return False
