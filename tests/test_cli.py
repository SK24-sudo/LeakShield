import sys
import unittest
from unittest.mock import patch

from leakshield import cli


class CliMainTests(unittest.TestCase):
    def test_main_happy_path(self):
        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "sample_project"]
            with patch("leakshield.cli.scan", return_value=[]) as mock_scan:
                result = cli.main()
                self.assertEqual(result, 0)
                mock_scan.assert_called_once()
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
