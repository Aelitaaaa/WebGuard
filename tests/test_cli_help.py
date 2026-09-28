import unittest
from webguard.cli import build_parser

class CliHelpTests(unittest.TestCase):
    def test_commands_subcommand(self):
        args = build_parser().parse_args(["commands"])
        self.assertEqual(args.command, "commands")

    def test_help_scan(self):
        args = build_parser().parse_args(["help", "scan"])
        self.assertEqual(args.command, "help")
        self.assertEqual(args.topic, "scan")

if __name__ == "__main__":
    unittest.main()
