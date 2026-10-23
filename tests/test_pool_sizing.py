"""Per-host connection pool scales with --threads.

urllib3's HTTPAdapter defaults to 10 pooled connections per host; on a
high-thread scan that cap throttles keep-alive reuse and forces needless
TCP+TLS handshakes. WebScanner now sizes pool_connections/pool_maxsize from
its thread count (never below the urllib3 defaults for low counts).
"""
import unittest

from xploit.scanner import WebScanner


def _pool_sizes(scanner: WebScanner) -> tuple:
    adapter = scanner.session.get_adapter("http://")
    pm = adapter.poolmanager
    # connection_pool_kw carries maxsize (per-host pool); pools is the
    # RecentlyUsedContainer of host pools, sized by pool_connections.
    return (
        pm.connection_pool_kw["maxsize"],
        pm.pools._maxsize,  # noqa: SLF001 - urllib3 2.x internal, test only
    )


class PoolSizingTest(unittest.TestCase):
    def test_default_threads_keep_urllib3_defaults(self):
        maxsize, num_pools = _pool_sizes(WebScanner("http://127.0.0.1:9/"))
        self.assertEqual(10, maxsize)
        self.assertEqual(10, num_pools)

    def test_high_thread_count_scales_pool(self):
        maxsize, num_pools = _pool_sizes(
            WebScanner("http://127.0.0.1:9/", threads=25))
        self.assertEqual(25, maxsize)
        self.assertEqual(25, num_pools)

    def test_low_thread_count_never_shrinks_pool(self):
        maxsize, num_pools = _pool_sizes(
            WebScanner("http://127.0.0.1:9/", threads=2))
        self.assertEqual(10, maxsize)
        self.assertEqual(10, num_pools)

    def test_https_adapter_matches(self):
        scanner = WebScanner("http://127.0.0.1:9/", threads=30)
        http_max = scanner.session.get_adapter(
            "http://").poolmanager.connection_pool_kw["maxsize"]
        https_max = scanner.session.get_adapter(
            "https://").poolmanager.connection_pool_kw["maxsize"]
        self.assertEqual(30, http_max)
        self.assertEqual(30, https_max)


if __name__ == "__main__":
    unittest.main()
