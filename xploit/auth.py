"""Login-form auto-auth: `--login-url` + credentials.

Submits the login form once, captures the session cookie the server
sets, and leaves it on the scanner's `requests.Session` so the whole
scan runs authenticated. Today auth requires a hand-supplied
`--cookie`; this automates the common form-login case.

Form parsing is stdlib-only (`html.parser`): the scanner's crawl uses
BeautifulSoup, but login needs just one form, and a stdlib parser keeps
this module usable without the bs4 dependency.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

# Input types that never carry credentials and are skipped when picking
# the username field (hidden fields are still submitted as-is).
_NON_CREDENTIAL_TYPES = {"hidden", "submit", "button", "reset", "image",
                         "checkbox", "radio", "file"}
# Name/id hints that mark the username field, checked before falling
# back to the first non-password text input.
_USERNAME_HINTS = ("user", "email", "login", "name", "account")


@dataclass
class LoginForm:
    """One HTML form with a password field, ready to submit."""

    action: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)
    username_field: str = ""
    password_field: str = ""


class _FormParser(HTMLParser):
    """Collects `<form>` elements and their `<input>` fields.

    Only the first form containing a password input is kept — a login
    page's search/newsletter forms never carry one. `<select>` and
    `<textarea>` values are out of scope: login forms use `<input>`.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {
                "action": attrs_d.get("action", ""),
                "method": attrs_d.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append(attrs_d)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_login_form(html_text: str, base_url: str) -> LoginForm | None:
    """Find the login form in `html_text`: the first form with a password
    input. Returns None when no form carries one."""
    parser = _FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        inputs = form["inputs"]
        password = next(
            (i for i in inputs
             if i.get("type", "").lower() == "password" and i.get("name")),
            None)
        if password is None:
            continue
        fields: dict[str, str] = {}
        username = ""
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in _NON_CREDENTIAL_TYPES:
                # Hidden inputs (CSRF tokens, next URLs) ride along
                # with their default values; other non-credential
                # inputs are not submitted.
                if itype == "hidden":
                    fields[name] = inp.get("value", "")
                continue
            fields[name] = inp.get("value", "")
            if itype == "password":
                continue
            if not username:
                ident = (name + " " + inp.get("id", "")).lower()
                if any(h in ident for h in _USERNAME_HINTS):
                    username = name
        if not username:
            # No hint matched: first non-password text field is the
            # username (typical single-text-field login forms).
            username = next(
                (i.get("name", "") for i in inputs
                 if i.get("name") and i.get("type", "text").lower()
                 not in _NON_CREDENTIAL_TYPES
                 and i.get("type", "").lower() != "password"),
                "")
        if not username:
            continue
        return LoginForm(
            action=urljoin(base_url, form["action"] or base_url),
            method=form["method"] if form["method"] in ("get", "post")
            else "post",
            fields=fields,
            username_field=username,
            password_field=password["name"],
        )
    return None


@dataclass
class LoginResult:
    """Outcome of one login attempt."""

    success: bool
    message: str
    cookies: list[str] = field(default_factory=list)
    final_url: str = ""


def perform_login(session, login_url: str, username: str, password: str,
                  timeout: float = 6.0) -> LoginResult:
    """Submit the login form at `login_url` with the given credentials.

    The session cookie the server sets (if any) stays on `session`, so
    the caller scans authenticated. Success means the submit returned
    below 400 AND the login established a session: at least one new
    cookie, or a redirect away from the login page. A submit that sets
    nothing and stays on the login page is a failed login, not a silent
    anonymous scan.
    """
    before = {c.name for c in session.cookies}
    try:
        page = session.request("GET", login_url, timeout=timeout)
    except Exception as exc:  # network error, timeout, bad URL, TLS, ...
        return LoginResult(False, f"could not fetch login page {login_url}: {exc}")
    if page.status_code >= 400:
        return LoginResult(False,
                           f"login page returned HTTP {page.status_code}")
    form = parse_login_form(page.text, login_url)
    if form is None:
        return LoginResult(False,
                           f"no login form (password field) found at {login_url}")
    form.fields[form.username_field] = username
    form.fields[form.password_field] = password
    try:
        if form.method == "get":
            res = session.request("GET", form.action, params=form.fields,
                                  timeout=timeout)
        else:
            res = session.request("POST", form.action, data=form.fields,
                                  timeout=timeout)
    except Exception as exc:
        return LoginResult(False, f"login submit failed: {exc}")
    if res.status_code >= 400:
        return LoginResult(False,
                           f"login submit returned HTTP {res.status_code}")
    new_cookies = sorted({c.name for c in session.cookies} - before)
    moved = res.url.rstrip("/") != login_url.rstrip("/")
    if not new_cookies and not moved:
        return LoginResult(
            False,
            "login submitted but no session was established "
            "(no new cookie, stayed on the login page) — check the "
            "credentials",
            final_url=res.url)
    detail = (f"session cookie(s): {', '.join(new_cookies)}"
              if new_cookies else f"redirected to {res.url}")
    return LoginResult(True, f"logged in as {username} ({detail})",
                       cookies=new_cookies, final_url=res.url)
