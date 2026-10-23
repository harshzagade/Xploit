"""Canonical finding-dedupe key: same (id, URL, parameter) reported once.

A vulnerability found via both GET (crawled page URL, query string intact)
and POST (bare form action) is one finding, not two. The dedupe key
normalizes the URL (query/fragment/host-case/default-port/trailing-slash
insensitive) so the two reports collapse; the HTTP method is deliberately
excluded from the key.
"""
import unittest

from xploit.modules.base import BaseModule
from xploit.scanner import (
    Finding,
    WebScanner,
    finding_dedupe_key,
    normalize_dedupe_url,
)


def _finding(**over) -> Finding:
    base = dict(
        id="T-001", name="n", category="c", severity="MEDIUM", confidence="High",
        url="http://x/", evidence="e", impact="i", remediation="r",
    )
    base.update(over)
    return Finding(**base)


class _ProbeModule(BaseModule):
    name = "probe"
    category = "probe"

    def run(self):  # pragma: no cover - never called
        raise AssertionError("not used")


def _scanner() -> WebScanner:
    return WebScanner("http://127.0.0.1:9/", timeout=2)


class NormalizeDedupeUrlTest(unittest.TestCase):
    def test_strips_query_and_fragment(self):
        self.assertEqual(
            normalize_dedupe_url("http://x/search?q=a&r=2#frag"),
            "http://x/search",
        )

    def test_folds_host_case_and_default_port(self):
        self.assertEqual(
            normalize_dedupe_url("HTTP://X:80/a/"),
            normalize_dedupe_url("http://x/a"),
        )

    def test_keeps_non_default_port(self):
        self.assertEqual(
            normalize_dedupe_url("http://x:8080/a"),
            "http://x:8080/a",
        )

    def test_https_default_port_stripped(self):
        self.assertEqual(
            normalize_dedupe_url("https://x:443/a"),
            "https://x/a",
        )

    def test_root_variants_collapse(self):
        self.assertEqual(normalize_dedupe_url("http://x"), "http://x")
        self.assertEqual(normalize_dedupe_url("http://x/"), "http://x")

    def test_path_case_preserved(self):
        self.assertNotEqual(
            normalize_dedupe_url("http://x/Admin"),
            normalize_dedupe_url("http://x/admin"),
        )

    def test_garbage_falls_back_to_raw_string(self):
        self.assertEqual(normalize_dedupe_url("not a url"), "not a url")
        self.assertEqual(normalize_dedupe_url(""), "")


class FindingDedupeKeyTest(unittest.TestCase):
    def test_get_and_post_collapse(self):
        get = _finding(id="SQLI-001", url="http://x/search?q=a",
                       parameter="q", method="GET")
        post = _finding(id="SQLI-001", url="http://x/search",
                        parameter="q", method="POST")
        self.assertEqual(finding_dedupe_key(get), finding_dedupe_key(post))

    def test_method_excluded_from_key(self):
        a = _finding(method="GET")
        b = _finding(method="POST")
        self.assertEqual(finding_dedupe_key(a), finding_dedupe_key(b))

    def test_empty_parameter_normalized(self):
        a = _finding(parameter="")
        b = _finding()  # default parameter=""
        self.assertEqual(finding_dedupe_key(a), finding_dedupe_key(b))


class AddFindingDedupeTest(unittest.TestCase):
    def test_get_then_post_reported_once_first_wins(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="SQLI-001", url="http://x/search?q=a",
                                 parameter="q", method="GET"))
        mod.add_finding(_finding(id="SQLI-001", url="http://x/search",
                                 parameter="q", method="POST"))
        self.assertEqual(1, len(scanner.findings))
        self.assertEqual("GET", scanner.findings[0].method)
        # The report keeps the original URL, not the normalized key form.
        self.assertEqual("http://x/search?q=a", scanner.findings[0].url)

    def test_cross_module_get_post_collapse(self):
        scanner = _scanner()
        m1, m2 = _ProbeModule(scanner), _ProbeModule(scanner)
        m1.add_finding(_finding(id="XSS-001", url="http://x/s?x=1",
                                parameter="x", method="GET"))
        m2.add_finding(_finding(id="XSS-001", url="http://x/s",
                                parameter="x", method="POST"))
        self.assertEqual(1, len(scanner.findings))

    def test_different_parameters_both_reported(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="SQLI-001", url="http://x/s?q=1",
                                 parameter="q"))
        mod.add_finding(_finding(id="SQLI-001", url="http://x/s?p=1",
                                 parameter="p"))
        self.assertEqual(2, len(scanner.findings))

    def test_different_paths_both_reported(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="SQLI-001", url="http://x/a?q=1",
                                 parameter="q"))
        mod.add_finding(_finding(id="SQLI-001", url="http://x/b?q=1",
                                 parameter="q"))
        self.assertEqual(2, len(scanner.findings))

    def test_different_ids_both_reported(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="SQLI-001", url="http://x/s",
                                 parameter="q"))
        mod.add_finding(_finding(id="SQLI-003", url="http://x/s",
                                 parameter="q"))
        self.assertEqual(2, len(scanner.findings))

    def test_host_case_and_trailing_slash_collapse(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="T-001", url="HTTP://X:80/a/"))
        mod.add_finding(_finding(id="T-001", url="http://x/a?b=2#z"))
        self.assertEqual(1, len(scanner.findings))

    def test_malformed_url_never_crashes(self):
        scanner = _scanner()
        mod = _ProbeModule(scanner)
        mod.add_finding(_finding(id="T-001", url="not a url"))
        mod.add_finding(_finding(id="T-001", url="not a url"))
        mod.add_finding(_finding(id="T-001", url="http://x/"))
        self.assertEqual(2, len(scanner.findings))

    def test_auth_suppression_lookup_uses_normalized_url(self):
        # auth_advanced suppresses AUTH-006 when general.py already flagged
        # the cookie on the same resource; its lookup must normalize the
        # URL the same way the stored keys were normalized.
        from xploit.scanner import normalize_dedupe_url
        scanner = _scanner()
        _ProbeModule(scanner).add_finding(
            _finding(id="COOK-001", url="http://x/login?x=1",
                     parameter="SessionID"))
        already = {
            (fid, u, (param or "").lower())
            for fid, u, param in scanner._finding_keys
        }
        self.assertIn(
            ("COOK-001", normalize_dedupe_url("http://x/login"),
             "sessionid"),
            already,
        )


if __name__ == "__main__":
    unittest.main()
