import unittest
from webguard.checks.headers import check_headers

class HeaderTests(unittest.TestCase):
    def test_missing_hsts(self):
        codes = {f.code for f in check_headers("https://example.com/", {})}
        self.assertIn("WG-HDR-006", codes)

    def test_hardened(self):
        h = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Strict-Transport-Security": "max-age=31536000",
        }
        codes = {f.code for f in check_headers("https://example.com/", h)}
        self.assertNotIn("WG-HDR-001", codes)
        self.assertNotIn("WG-HDR-006", codes)

if __name__ == "__main__":
    unittest.main()
