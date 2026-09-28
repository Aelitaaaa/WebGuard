import unittest
from webguard.checks.content import check_content

class ContentTests(unittest.TestCase):
    def test_http_password_form(self):
        html = '<form action="http://example.com/login"><input type="password"></form>'
        codes = {f.code for f in check_content("http://example.com/login", html)}
        self.assertIn("WG-FORM-001", codes)
        self.assertIn("WG-FORM-002", codes)

    def test_debug_pattern(self):
        html = "<h1>Error</h1><pre>Traceback (most recent call last)</pre>"
        codes = {f.code for f in check_content("https://example.com/", html)}
        self.assertIn("WG-ERR-001", codes)

if __name__ == "__main__":
    unittest.main()
