import sys
import unittest
from unittest.mock import patch

from leakshield import cli
from leakshield.findings import Finding, RawFinding


class CliMainTests(unittest.TestCase):
    def _make_finding(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="src/example.py",
            location=(12, 3),
            candidate_value="<SECRET>",
            detector_id="pattern-secret",
            evidence={
                "pattern": "credential-assignment",
                "credential_name": "<SECRET>",
            },
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"
        return finding

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

    def test_main_with_json_format_calls_json_reporter(self):
        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "sample_project", "--format", "json"]
            with patch("leakshield.cli.scan", return_value=[]) as mock_scan:
                with patch("leakshield.cli.findings_to_json", return_value="json-output") as mock_json:
                    result = cli.main()
                    self.assertEqual(result, 0)
                    mock_scan.assert_called_once()
                    mock_json.assert_called_once_with([])
        finally:
            sys.argv = original_argv

    def test_main_passes_redacted_findings_to_json_reporter(self):
        original_argv = sys.argv[:]
        finding = self._make_finding()
        try:
            sys.argv = ["leakshield", "sample_project", "--format", "json"]
            with patch("leakshield.cli.scan", return_value=[finding]):
                with patch("leakshield.cli.findings_to_json", return_value="json-output") as mock_json:
                    self.assertEqual(cli.main(), 0)

            reported = mock_json.call_args.args[0][0]
            self.assertIsNot(reported, finding)
            self.assertEqual(reported.candidate_value, "[REDACTED]")
            self.assertIsNone(reported.raw_finding)
            self.assertEqual(reported.finding_type, finding.finding_type)
            self.assertEqual(reported.relative_path, finding.relative_path)
            self.assertEqual(reported.location, finding.location)
            self.assertEqual(reported.confidence, finding.confidence)
            self.assertEqual(reported.severity, finding.severity)
            self.assertEqual(reported.risk, finding.risk)
            self.assertEqual(finding.candidate_value, "<SECRET>")
            self.assertIsNotNone(finding.raw_finding)
        finally:
            sys.argv = original_argv

    def test_main_passes_redacted_findings_to_html_reporter(self):
        original_argv = sys.argv[:]
        finding = self._make_finding()
        try:
            sys.argv = ["leakshield", "sample_project", "--format", "html"]
            with patch("leakshield.cli.scan", return_value=[finding]):
                with patch("leakshield.cli.findings_to_html", return_value="html-output") as mock_html:
                    self.assertEqual(cli.main(), 0)

            reported = mock_html.call_args.args[0][0]
            self.assertIsNot(reported, finding)
            self.assertEqual(reported.candidate_value, "[REDACTED]")
            self.assertIsNone(reported.raw_finding)
            self.assertEqual(reported.finding_type, finding.finding_type)
            self.assertEqual(reported.relative_path, finding.relative_path)
            self.assertEqual(reported.location, finding.location)
            self.assertEqual(reported.confidence, finding.confidence)
            self.assertEqual(reported.severity, finding.severity)
            self.assertEqual(reported.risk, finding.risk)
            self.assertEqual(finding.candidate_value, "<SECRET>")
            self.assertIsNotNone(finding.raw_finding)
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
