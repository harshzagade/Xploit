from __future__ import annotations
import re
from .base import BaseModule
from ..scanner import Finding, HIGH, INFO

USERNAME_TOKENS = {"user", "username", "email", "login", "userid", "account", "uname"}

def _field_tokens(name: str) -> set:
    return set(re.split(r"[_\-\s]+", name.lower()))

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

            field_names = [n.lower() for n in form.inputs.keys()]
            action_lower = form.action.lower()

            # Registration/signup forms are NOT login forms. Stuffing ~200
            # credential pairs at a signup endpoint creates junk accounts and,
            # combined with welcome-redirects, false HIGH findings.
            if any(h in n for n in field_names for h in ("confirm", "repeat", "verify")):
                continue
            if any(x in action_lower for x in ("register", "signup", "sign-up", "join")):
                continue

            def _tokens(name):
                return _field_tokens(name)

            username_tokens = USERNAME_TOKENS
            personal_name_tokens = {"firstname", "first_name", "lastname", "last_name",
                                    "fullname", "full_name", "name"}

            username_fields = {n for n in field_names if _tokens(n) & username_tokens}
            # A personal-name field alongside (email+password, no login action)
            # is a registration/profile form, not a login form. Note bare
            # "name" no longer counts as a username — substring-matching it was
            # the misclassification trigger.
            personal_name_fields = {
                n for n in field_names
                if n not in username_fields and _tokens(n) & personal_name_tokens
            }
            is_login_action = any(x in action_lower for x in ['login', 'signin', 'auth', 'authenticate'])
            if personal_name_fields and not is_login_action:
                continue

            if username_fields:
                if is_login_action:
                    login_forms.insert(0, form)
                else:
                    login_forms.append(form)

        return login_forms

    def _test_form_credentials(self, form):
        """Test a form with default and weak credentials"""
        username_field = None
        password_field = None

        # Break after first match — avoid overwriting with the last matching field.
        # Token-based (not substring) so fields like "displayname" don't win.
        for name in form.inputs.keys():
            if _field_tokens(name) & USERNAME_TOKENS:
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

        # Failure phrases — checked before redirect so a redirect to /error isn't a false positive.
        # Note: bare "error" is deliberately NOT in this list — it appears in
        # benign pages ("0 errors", error-handling JS) and suppressed real logins.
        failure_indicators = [
            "invalid", "incorrect", "failed",
            "wrong", "denied", "unauthorized", "forbidden",
            "bad credentials", "authentication failed",
            "try again", "password is incorrect", "invalid password",
            "invalid username",
        ]
        if any(ind in response_text for ind in failure_indicators):
            return False

        # Redirect to a non-login URL after passing failure check = success —
        # but ONLY if the redirect target differs from the baseline's. Failed
        # logins often bounce to "/" or "/home" too, which previously produced
        # false HIGH "Default Credentials Accepted" findings.
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_location = (response.headers.get('Location') or '').lower()
            baseline_location = ''
            if baseline is not None and baseline.status_code in [301, 302, 303, 307, 308]:
                baseline_location = (baseline.headers.get('Location') or '').lower()
            if redirect_location and redirect_location == baseline_location:
                return False
            if redirect_location and not any(x in redirect_location for x in ['login', 'signin', 'auth']):
                return True
            return False

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

        return False
