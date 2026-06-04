from __future__ import annotations
from .base import BaseModule
from ..scanner import Finding, HIGH, MEDIUM

class BruteForceModule(BaseModule):
    """Comprehensive default credential and weak password testing"""
    name = "Brute Force & Default Credentials"
    category = "Authentication"

    # Expanded default credentials database
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
        ("admin", "admin123"),
        ("wordpress", "wordpress"),
        ("joomla", "joomla"),

        # Generic weak passwords
        ("user", "123456"),
        ("admin", "qwerty"),
        ("admin", "letmein"),
    ]

    def run(self):
        """Test login forms for default credentials"""
        login_forms = self._identify_login_forms()

        if not login_forms:
            return

        for form in login_forms[:1]:  # Limit to 1 form to avoid excessive requests
            self._test_form_credentials(form)

    def _identify_login_forms(self):
        """Identify forms that are likely login forms"""
        login_forms = []

        for form in self.scanner.forms:
            # Must have password field
            has_password = any('password' in inp_type for inp_type in form.input_types.values())
            if not has_password:
                continue

            # Check for username/email field
            has_username = any(
                any(x in name.lower() for x in ['user', 'email', 'login', 'name', 'username'])
                for name in form.inputs.keys()
            )

            if has_username:
                # Additional indicators this is a login form
                action_lower = form.action.lower()
                is_login_action = any(x in action_lower for x in ['login', 'signin', 'auth', 'authenticate'])

                # Prioritize forms with login-related actions
                if is_login_action:
                    login_forms.insert(0, form)
                else:
                    login_forms.append(form)

        return login_forms

    def _test_form_credentials(self, form):
        """Test a form with default credentials"""
        # Identify username and password fields
        username_field = None
        password_field = None

        for name in form.inputs.keys():
            if any(x in name.lower() for x in ['user', 'email', 'login', 'name', 'username']):
                username_field = name

        for name, inp_type in form.input_types.items():
            if inp_type == 'password':
                password_field = name
                break

        if not username_field or not password_field:
            return

        # Get baseline response for comparison
        baseline_res = self.scanner._request(
            form.method,
            form.action,
            data=form.inputs if form.method == "POST" else None,
            params=form.inputs if form.method == "GET" else None
        )
        baseline_length = len(baseline_res.text) if baseline_res else 0

        # Test default credentials (limit to 15 to avoid excessive requests)
        tested_count = 0
        for username, password in self.DEFAULT_CREDENTIALS[:15]:
            tested_count += 1

            data = dict(form.inputs)
            data[username_field] = username
            data[password_field] = password

            res = self.scanner._request(
                form.method,
                form.action,
                data=data if form.method == "POST" else None,
                params=data if form.method == "GET" else None
            )

            if not res:
                continue

            # Check for successful authentication
            if self._is_successful_login(res, baseline_res):
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
                    remediation="URGENT: Change all default credentials immediately. Disable or remove default accounts. Enforce strong password policies on account creation.",
                    cwe="CWE-798"
                ))
                return  # Stop after finding working credentials

        # Report that testing was performed
        self.add_finding(Finding(
            id="BRUTE-002",
            name="Default Credentials Tested (None Found)",
            category="Authentication",
            severity=MEDIUM,
            confidence="Low",
            url=form.action,
            method=form.method,
            evidence=f"Tested {tested_count} common default credential pairs - none accepted",
            impact="Login form is present. While common defaults were not accepted, manual testing with comprehensive wordlists is recommended.",
            remediation="Continue enforcing strong password policies. Consider implementing account lockout and rate limiting.",
            cwe="CWE-798"
        ))

    def _is_successful_login(self, response, baseline):
        """Determine if a login attempt was successful"""
        if not response:
            return False

        response_text = response.text.lower()
        baseline_text = baseline.text.lower() if baseline else ""

        # Check for redirect (very common success indicator)
        if response.status_code in [301, 302, 303, 307, 308]:
            # Check redirect isn't to login page
            redirect_location = response.headers.get('Location', '').lower()
            if not any(x in redirect_location for x in ['login', 'signin', 'auth']):
                return True

        # Success indicators
        success_indicators = [
            "welcome", "dashboard", "logout", "sign out",
            "profile", "account", "settings",
            "logged in", "login successful", "authentication successful",
            "session", "home", "panel", "admin panel",
            "my account", "user panel"
        ]

        # Failure indicators
        failure_indicators = [
            "invalid", "incorrect", "failed", "error",
            "wrong", "denied", "unauthorized", "forbidden",
            "bad credentials", "authentication failed",
            "try again", "password is incorrect"
        ]

        # Count indicators
        success_count = sum(1 for ind in success_indicators if ind in response_text)
        failure_count = sum(1 for ind in failure_indicators if ind in response_text)

        # If more success indicators than failure
        if success_count > 0 and failure_count == 0:
            return True

        # Check for significant response size change (might indicate successful login)
        if baseline:
            size_diff = abs(len(response.text) - len(baseline.text))
            # If response is significantly larger (loaded dashboard/home page)
            if size_diff > 500:  # More than 500 chars difference
                # Make sure it's not just an error page
                if failure_count == 0:
                    return True

        # Check for new cookies (session cookies often set on successful login)
        if response.headers.get('Set-Cookie'):
            cookie_header = response.headers.get('Set-Cookie', '').lower()
            if any(x in cookie_header for x in ['session', 'auth', 'token', 'jsessionid']):
                # New session cookie + no failure indicators = likely success
                if failure_count == 0 and success_count > 0:
                    return True

        return False
