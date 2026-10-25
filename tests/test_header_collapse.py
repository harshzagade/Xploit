"""Version-fingerprint headers collapse to one finding per host, not per URL."""
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


def _root_headers():
    # Satisfy the missing-header checks so only tech-header findings vary.
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
    }


def test_same_banner_on_many_pages_is_one_finding():
    pages = {
        "http://x/": Resp("http://x/", {**_root_headers(), "Server": "Apache/2.4"}),
        "http://x/a": Resp("http://x/a", {"Server": "Apache/2.4"}),
        "http://x/b": Resp("http://x/b", {"Server": "Apache/2.4"}),
    }
    module, scanner = _module(pages)
    module._check_headers()
    tech = [f for f in scanner.findings if f.id == "INFO-SVR"]
    assert len(tech) == 1
    assert tech[0].url == "http://x/"
    assert "seen on 3 pages" in tech[0].evidence
    assert "Apache/2.4" in tech[0].evidence


def test_banner_only_on_subpage_is_still_found():
    pages = {
        "http://x/": Resp("http://x/", _root_headers()),
        "http://x/admin": Resp("http://x/admin", {"X-Powered-By": "PHP/8.1"}),
    }
    module, scanner = _module(pages)
    module._check_headers()
    tech = [f for f in scanner.findings if f.id == "INFO-XPB"]
    assert len(tech) == 1
    assert tech[0].url == "http://x/admin"
    assert "X-Powered-By" in tech[0].evidence or "x-powered-by" in tech[0].evidence


def test_different_values_stay_separate_findings():
    pages = {
        "http://x/": Resp("http://x/", {**_root_headers(), "Server": "Apache/2.4"}),
        "http://x/old": Resp("http://x/old", {"Server": "nginx/1.18"}),
    }
    module, scanner = _module(pages)
    module._check_headers()
    tech = [f for f in scanner.findings if f.id == "INFO-SVR"]
    assert len(tech) == 2
    assert {f.evidence for f in tech} == {"server: Apache/2.4", "server: nginx/1.18"}
