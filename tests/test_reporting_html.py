import unittest

from leakshield.findings import Finding, RawFinding
from leakshield.reporting import findings_to_html


class HtmlReportingTests(unittest.TestCase):
    def test_findings_to_html_contains_expected_document_structure(self):
        html = findings_to_html([])

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html", html)
        self.assertIn('<meta charset="UTF-8">', html)
        self.assertIn("LeakShield Report", html)
        self.assertIn("Total Findings", html)
        self.assertIn('<div class="stat-value">0</div>', html)

    def test_findings_to_html_renders_finding_metadata(self):
        raw = RawFinding(
            finding_type="secret",
            relative_path="src/example.py",
            location=(12, 3),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "token"},
        )
        finding = Finding(raw)
        finding.severity = "high"

        html = findings_to_html([finding])

        self.assertIn("Findings", html)
        self.assertIn("secret", html)
        self.assertIn("src/example.py", html)
        self.assertIn("12", html)
        self.assertIn("high", html)

    def test_findings_to_html_escapes_user_controlled_file_path(self):
        raw = RawFinding(
            finding_type="secret",
            relative_path="demo<script>.py",
            location=(5, 7),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "token"},
        )
        finding = Finding(raw)
        finding.severity = "medium"

        html = findings_to_html([finding])

        self.assertIn("demo&lt;script&gt;.py", html)
        self.assertNotIn("demo<script>.py", html)

    def test_findings_to_html_renders_redacted_detector_and_evidence(self):
        raw = RawFinding(
            finding_type="secret",
            relative_path="src/example.py",
            location=(12, 3),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "super-secret-key"},
        )
        finding = Finding(raw)
        finding.severity = "high"

        redacted = finding.redacted_copy()
        html = findings_to_html([redacted])

        self.assertIn("Detector", html)
        self.assertIn("Redacted Evidence", html)
        self.assertIn("pattern-secret", html)
        self.assertIn("[REDACTED]", html)
        self.assertNotIn("super-secret-key", html)


if __name__ == "__main__":
    unittest.main()
