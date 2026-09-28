import unittest
from webguard.checks.cors import assess_cors

class CorsTests(unittest.TestCase):
    def test_wildcard(self):
        codes = {f.code for f in assess_cors(
            "https://example.com",
            {"Access-Control-Allow-Origin": "*"}
        )}
        self.assertIn("WG-CORS-001", codes)

if __name__ == "__main__":
    unittest.main()
