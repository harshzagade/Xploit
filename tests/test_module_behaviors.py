"""Behavior contracts for individual modules (round 2)."""
from bs4 import BeautifulSoup

from xploit.modules.brute_force import USERNAME_TOKENS, _field_tokens
from xploit.modules.logic_vulnerabilities import _has_csrf_token
from xploit.modules.sensitive_data import SensitiveDataModule
from xploit.modules.xss import XSSModule
from xploit.scanner import WebScanner


class Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def brute():
    from xploit.modules.brute_force import BruteForceModule
    return BruteForceModule(WebScanner("http://x/", mode="passive"))


# --- _field_tokens ---------------------------------------------------------

def test_field_tokens_splits_on_underscores():
    assert _field_tokens("user_name") == {"user", "name"}


def test_field_tokens_splits_on_hyphens_and_spaces():
    assert _field_tokens("user-name id") == {"user", "name", "id"}


def test_field_tokens_lowercases():
    assert _field_tokens("UserName") == {"username"}


def test_username_tokens_include_email_and_login():
    assert "email" in USERNAME_TOKENS and "login" in USERNAME_TOKENS


# --- _is_successful_login ----------------------------------------------------

def test_login_success_when_redirect_differs_from_baseline():
    m = brute()
    resp = Resp("ok", 302, {"Location": "/dashboard"})
    assert m._is_successful_login(resp, Resp("login page", 200)) is True


def test_login_not_success_when_redirect_matches_baseline():
    m = brute()
    resp = Resp("ok", 302, {"Location": "/"})
    assert m._is_successful_login(resp, Resp("login page", 302, {"Location": "/"})) is False


def test_login_not_success_on_failure_phrase():
    m = brute()
    assert m._is_successful_login(Resp("Invalid password, try again"), Resp("login")) is False


def test_login_not_success_when_redirect_points_at_login():
    m = brute()
    resp = Resp("ok", 302, {"Location": "/login?err=1"})
    assert m._is_successful_login(resp, Resp("login", 200)) is False


def test_login_success_on_new_welcome_text():
    m = brute()
    assert m._is_successful_login(Resp("Welcome back, admin"), Resp("please log in")) is True


def test_login_not_success_on_none_response():
    assert brute()._is_successful_login(None, Resp("login")) is False


# --- XSS contexts ---------------------------------------------------------------

def test_xss_html_comment_is_inert():
    exe, note = XSSModule._executable_context("<!-- ")
    assert exe is False and "comment" in note


def test_xss_textarea_is_inert():
    exe, note = XSSModule._executable_context("<textarea>")
    assert exe is False and "textarea" in note


def test_xss_title_is_inert():
    exe, note = XSSModule._executable_context("<title>")
    assert exe is False and "title" in note


def test_xss_script_block_is_unconfirmed():
    exe, note = XSSModule._executable_context("<script>var x = '")
    assert exe is False and "unconfirmed" in note.lower()


def test_xss_event_handler_attribute_is_executable():
    exe, note = XSSModule._executable_context('<div onmouseover="')
    assert exe is True


def test_xss_element_body_is_executable():
    exe, note = XSSModule._executable_context("<p>")
    assert exe is True


# --- CSRF token words ------------------------------------------------------------

def test_csrf_token_detected_by_name():
    assert _has_csrf_token(["csrf_token"]) is True


def test_csrf_token_detected_by_suffix_form():
    assert _has_csrf_token(["__requestverificationtoken"]) is True


def test_csrf_token_detected_in_camelcase():
    assert _has_csrf_token(["authenticityToken"]) is True


def test_csrf_token_absent_for_plain_fields():
    assert _has_csrf_token(["name", "email", "q"]) is False


# --- Luhn --------------------------------------------------------------------------

def test_luhn_accepts_valid_test_card():
    assert SensitiveDataModule(WebScanner("http://x/", mode="passive"))._luhn_check("4532015112830366") is True


def test_luhn_rejects_altered_card():
    assert SensitiveDataModule(WebScanner("http://x/", mode="passive"))._luhn_check("4532015112830367") is False


# --- _extract_forms -------------------------------------------------------------------

def _forms(html):
    sc = WebScanner("http://x/page", mode="passive")
    soup = BeautifulSoup(html, "html.parser")
    return sc._extract_forms("http://x/page", soup)


def test_extract_forms_defaults_action_to_page_url():
    (form,) = _forms('<form method="post"><input name="q"></form>')
    assert form.action == "http://x/page"
    assert form.method == "POST"


def test_extract_forms_captures_textarea_and_select():
    (form,) = _forms('<form><textarea name="bio"></textarea><select name="c"></select></form>')
    assert "bio" in form.inputs and "c" in form.inputs


def test_extract_forms_skips_nameless_inputs():
    (form,) = _forms('<form><input type="submit" value="go"><input name="q"></form>')
    assert "q" in form.inputs
    assert len(form.inputs) == 1
