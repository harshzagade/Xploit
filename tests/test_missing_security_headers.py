"""Missing Referrer-Policy / Permissions-Policy headers (HDR-RP, HDR-PP)."""
from xploit.modules.general import GeneralModule
from xploit.scanner import WebScanner


class Resp:
    def __init__(self, url, headers):
        self.url = url
        self.headers = headers


def _module(pages):
    scanner = WebScanner("http://x/", mode="passive", depth=0, max_pages=16)
    scanner.root = "http://x/"
    scanner.pages = pages
    return GeneralModule(scanner), scanner


def _full_headers():
    # Satisfy every missing-header check so only the new findings vary.
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }


def _by_id(scanner, fid):
    return [f for f in scanner.findings if f.id == fid]


def test_missing_both_flags_hdr_rp_and_hdr_pp():
    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }),
    })
    module._check_headers()
    rp = _by_id(scanner, "HDR-RP")
    pp = _by_id(scanner, "HDR-PP")
    assert len(rp) == 1
    assert len(pp) == 1
    assert rp[0].severity == "INFO"
    assert pp[0].severity == "INFO"
    assert rp[0].name == "Missing Referrer-Policy"
    assert pp[0].name == "Missing Permissions-Policy"
    assert rp[0].category == "Insecure HTTP Headers"
    assert "referrer-policy" in rp[0].evidence
    assert "permissions-policy" in pp[0].evidence
    assert rp[0].cwe == "CWE-200"
    assert pp[0].cwe == "CWE-693"
    assert "Referer" in rp[0].impact
    assert "camera" in pp[0].impact
    assert rp[0].url == "http://x/"


def test_present_both_flags_nothing():
    module, scanner = _module({
        "http://x/": Resp("http://x/", _full_headers()),
    })
    module._check_headers()
    assert _by_id(scanner, "HDR-RP") == []
    assert _by_id(scanner, "HDR-PP") == []


def test_each_header_independent():
    # Only Referrer-Policy present: Permissions-Policy still flags, and
    # vice versa.
    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }),
    })
    module._check_headers()
    assert _by_id(scanner, "HDR-RP") == []
    assert len(_by_id(scanner, "HDR-PP")) == 1

    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "camera=()",
        }),
    })
    module._check_headers()
    assert len(_by_id(scanner, "HDR-RP")) == 1
    assert _by_id(scanner, "HDR-PP") == []


def test_legacy_feature_policy_satisfies_permissions_policy():
    # Feature-Policy is the predecessor of Permissions-Policy: a site
    # still sending it has set a feature policy, so HDR-PP must not fire.
    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Feature-Policy": "camera 'none'",
        }),
    })
    module._check_headers()
    assert _by_id(scanner, "HDR-PP") == []
    # Referrer-Policy is a different header: the legacy header does not
    # excuse it.
    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Feature-Policy": "camera 'none'",
        }),
    })
    module._check_headers()
    assert len(_by_id(scanner, "HDR-RP")) == 1
    assert _by_id(scanner, "HDR-PP") == []


def test_header_names_match_case_insensitively():
    module, scanner = _module({
        "http://x/": Resp("http://x/", {
            "content-security-policy": "default-src 'self'",
            "X-CONTENT-TYPE-OPTIONS": "nosniff",
            "REFERRER-POLICY": "no-referrer",
            "permissions-policy": "camera=()",
        }),
    })
    module._check_headers()
    assert _by_id(scanner, "HDR-RP") == []
    assert _by_id(scanner, "HDR-PP") == []


def test_no_root_page_flags_nothing():
    module, scanner = _module({})
    module._check_headers()
    assert _by_id(scanner, "HDR-RP") == []
    assert _by_id(scanner, "HDR-PP") == []


def test_new_findings_do_not_break_existing_header_checks():
    # A bare root page still gets the established CSP/XCTO findings
    # alongside the two new ones — one finding per missing header.
    module, scanner = _module({
        "http://x/": Resp("http://x/", {}),
    })
    module._check_headers()
    assert len(_by_id(scanner, "HDR-CSP")) == 1
    assert len(_by_id(scanner, "HDR-XCTO")) == 1
    assert len(_by_id(scanner, "HDR-RP")) == 1
    assert len(_by_id(scanner, "HDR-PP")) == 1
