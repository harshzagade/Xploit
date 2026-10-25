"""CSRF token check covers every state-changing form method, not just POST."""
from xploit.modules.logic_vulnerabilities import LogicVulnerabilityModule
from xploit.scanner import FormTarget, WebScanner

BASE = "http://x/"


def _module(forms):
    scanner = WebScanner(BASE, depth=0, max_pages=1, timeout=2)
    scanner.forms = forms
    return LogicVulnerabilityModule(scanner), scanner


def _form(method, inputs, action="http://x/submit"):
    return FormTarget(
        page_url=BASE, action=action, method=method,
        inputs=inputs, input_types={n: "text" for n in inputs},
    )


def test_csrf_put_patch_delete_forms_flagged():
    for method in ("PUT", "PATCH", "DELETE"):
        module, scanner = _module([_form(method, {"name": "x", "email": "y"})])
        module._check_csrf()
        assert len(scanner.findings) == 1
        assert scanner.findings[0].id == "CSRF-001"
        assert scanner.findings[0].method == method
        assert method in scanner.findings[0].evidence


def test_csrf_get_form_still_skipped():
    module, scanner = _module([_form("GET", {"name": "x", "email": "y"})])
    module._check_csrf()
    assert scanner.findings == []


def test_csrf_token_present_on_put_no_finding():
    module, scanner = _module(
        [_form("PUT", {"name": "x", "csrf_token": "abc"})])
    module._check_csrf()
    assert scanner.findings == []


def test_csrf_single_search_field_still_skipped_for_put():
    module, scanner = _module([_form("PUT", {"search": "x"})])
    module._check_csrf()
    assert scanner.findings == []
