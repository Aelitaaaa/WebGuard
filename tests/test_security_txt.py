import unittest
from webguard.checks.disclosure import parse_security_txt

class SecurityTxtTests(unittest.TestCase):
    def test_parse(self):
        x = parse_security_txt(
            "Contact: mailto:security@example.com\n"
            "Policy: https://example.com/security\n"
            "Expires: 2030-01-01T00:00:00Z\n"
        )
        self.assertEqual(x["contacts"], ["mailto:security@example.com"])
        self.assertEqual(x["policy"], ["https://example.com/security"])
        self.assertEqual(x["expires"], "2030-01-01T00:00:00Z")

if __name__ == "__main__":
    unittest.main()
