"""Tests for nested sitemap recursion in entry-point discovery."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xploit.scanner import WebScanner

BASE = "http://example.com/"


class _FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _scanner_with_sitemaps(docs):
    """Scanner whose _request serves ``docs`` (path -> (status, body))."""
    scanner = WebScanner(BASE, depth=0, timeout=2)

    def fake_request(method, url, **kwargs):
        for path, (status, body) in docs.items():
            if url == BASE.rstrip("/") + path:
                return _FakeResp(status, body)
        return _FakeResp(404, "")

    scanner._request = fake_request
    return scanner


INDEX = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://example.com/sitemaps/pages.xml</loc></sitemap>
  <sitemap><loc>http://example.com/sitemaps/blog.xml</loc></sitemap>
</sitemapindex>
"""

PAGES_XML = """\
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/about</loc></url>
  <url><loc>http://example.com/contact</loc></url>
</urlset>
"""

BLOG_XML = """\
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/blog/first-post</loc></url>
</urlset>
"""


def test_index_recursion_finds_deeper_pages():
    scanner = _scanner_with_sitemaps({
        "/sitemap.xml": (200, INDEX),
        "/sitemaps/pages.xml": (200, PAGES_XML),
        "/sitemaps/blog.xml": (200, BLOG_XML),
    })
    found = scanner._discover_entry_points()
    assert "http://example.com/about" in found
    assert "http://example.com/contact" in found
    assert "http://example.com/blog/first-post" in found
    # Nested sitemap URLs themselves are never entry points.
    assert not any(u.endswith(".xml") for u in found)


def test_self_referencing_index_terminates():
    loop = """\
<sitemapindex>
  <sitemap><loc>http://example.com/sitemap.xml</loc></sitemap>
  <url><loc>http://example.com/home</loc></url>
</sitemapindex>
"""
    # Note: <url> inside an index is non-standard, but the parser must
    # still terminate and return the page instead of looping forever.
    scanner = _scanner_with_sitemaps({"/sitemap.xml": (200, loop)})
    found = scanner._discover_entry_points()
    assert "http://example.com/home" in found


def test_depth_cap_stops_deep_chains():
    docs = {}
    for level in range(6):
        nxt = f"/sitemaps/level{level + 1}.xml"
        docs[f"/sitemaps/level{level}.xml"] = (
            200,
            f"<sitemapindex><sitemap><loc>http://example.com{nxt}</loc>"
            f"</sitemap></sitemapindex>",
        )
    docs["/sitemaps/level6.xml"] = (
        200,
        "<urlset><url><loc>http://example.com/too-deep</loc></url></urlset>",
    )
    docs["/sitemap.xml"] = (
        200,
        "<sitemapindex><sitemap><loc>http://example.com/sitemaps/level0.xml"
        "</loc></sitemap></sitemapindex>",
    )
    scanner = _scanner_with_sitemaps(docs)
    found = scanner._discover_entry_points()
    # /sitemap.xml (depth 0) -> level0 (1) -> level1 (2) -> level2 (3):
    # level3 would be depth 4, past SITEMAP_MAX_DEPTH, so its pages
    # (and everything below) are never fetched.
    assert "http://example.com/too-deep" not in found


def test_off_origin_nested_sitemap_is_not_followed():
    docs = {
        "/sitemap.xml": (
            200,
            "<sitemapindex><sitemap><loc>http://other.example/evil.xml"
            "</loc></sitemap></sitemapindex>",
        ),
    }
    scanner = _scanner_with_sitemaps(docs)
    found = scanner._discover_entry_points()
    assert not any("other.example" in u for u in found)


def test_xml_page_url_inside_urlset_stays_a_page():
    docs = {
        "/sitemap.xml": (
            200,
            "<urlset><url><loc>http://example.com/feed.xml</loc></url>"
            "<url><loc>http://example.com/plain</loc></url></urlset>",
        ),
    }
    scanner = _scanner_with_sitemaps(docs)
    found = scanner._discover_entry_points()
    assert "http://example.com/feed.xml" in found
    assert "http://example.com/plain" in found


def test_unwrapped_loc_list_falls_back_to_suffix_rule():
    docs = {
        "/sitemap.xml": (
            200,
            "<loc>http://example.com/nested.xml</loc>\n"
            "<loc>http://example.com/standalone</loc>\n",
        ),
        "/nested.xml": (
            200,
            "<urlset><url><loc>http://example.com/from-nested</loc></url>"
            "</urlset>",
        ),
    }
    scanner = _scanner_with_sitemaps(docs)
    found = scanner._discover_entry_points()
    assert "http://example.com/from-nested" in found
    assert "http://example.com/standalone" in found
    assert "http://example.com/nested.xml" not in found


def test_gzipped_sitemap_is_skipped():
    docs = {
        "/sitemap.xml": (
            200,
            "<sitemapindex><sitemap><loc>http://example.com/big.xml.gz"
            "</loc></sitemap></sitemapindex>",
        ),
    }
    scanner = _scanner_with_sitemaps(docs)
    assert scanner._discover_entry_points() == [BASE]


def test_broken_or_missing_sitemap_yields_only_root():
    scanner = _scanner_with_sitemaps({"/sitemap.xml": (404, "")})
    assert scanner._discover_entry_points() == [BASE]
    scanner = _scanner_with_sitemaps(
        {"/sitemap.xml": (200, "<urlset><url><loc>")})
    assert scanner._discover_entry_points() == [BASE]


def test_relative_nested_loc_resolves_against_sitemap_url():
    docs = {
        "/sitemap.xml": (
            200,
            "<sitemapindex><sitemap><loc>sitemaps/child.xml</loc>"
            "</sitemap></sitemapindex>",
        ),
        "/sitemaps/child.xml": (
            200,
            "<urlset><url><loc>deep-page</loc></url></urlset>",
        ),
    }
    scanner = _scanner_with_sitemaps(docs)
    found = scanner._discover_entry_points()
    # Relative to the child sitemap's own URL, not the site root.
    assert "http://example.com/sitemaps/deep-page" in found


# --- live fixture: index + child sitemaps served over HTTP -------------

INDEX_LIVE = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>{base}sitemaps/pages.xml</loc></sitemap>
  <sitemap><loc>{base}sitemaps/blog.xml</loc></sitemap>
</sitemapindex>
"""

PAGES_XML_LIVE = """\
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{base}about</loc></url>
  <url><loc>{base}contact</loc></url>
</urlset>
"""

BLOG_XML_LIVE = """\
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{base}blog/first-post</loc></url>
</urlset>
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        docs = {
            "/sitemap.xml": INDEX_LIVE,
            "/sitemaps/pages.xml": PAGES_XML_LIVE,
            "/sitemaps/blog.xml": BLOG_XML_LIVE,
        }
        template = docs.get(self.path)
        if template is None:
            self._send(404, "text/plain", b"not found")
        else:
            body = template.format(base=self.server.base_url).encode()
            self._send(200, "application/xml", body)

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_live_nested_sitemaps_seed_discovery():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}/"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = server.base_url
        scanner = WebScanner(base, depth=0, timeout=5)
        found = scanner._discover_entry_points()
        assert base + "about" in found
        assert base + "blog/first-post" in found
        assert not any(u.endswith(".xml") for u in found)
    finally:
        server.shutdown()
        server.server_close()
