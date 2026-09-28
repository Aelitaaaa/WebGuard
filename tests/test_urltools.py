import unittest
from webguard.urltools import normalize_target, safe_join, allowed_host

class UrlTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com/")

    def test_scope(self):
        self.assertTrue(allowed_host("https://example.com/a", {"example.com"}))
        self.assertFalse(allowed_host("https://api.example.com/a", {"example.com"}))

    def test_dangerous_link_blocked(self):
        self.assertIsNone(safe_join("https://example.com/", "/account/logout"))

if __name__ == "__main__":
    unittest.main()
