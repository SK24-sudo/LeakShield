import json
import unittest

from leakshield.findings import Finding, RawFinding
from leakshield.reporting import findings_to_json


class JsonReportingTests(unittest.TestCase):
    def test_findings_to_json_serializes_redacted_finding_fields(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="src/example.py",
            location=(12, 3),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "credential-assignment", "credential_name": "super-secret-key"},
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"

        redacted = finding.redacted_copy()
        payload = json.loads(findings_to_json([redacted]))

        self.assertEqual(len(payload), 1)
        item = payload[0]
        self.assertEqual(item["detector_id"], "pattern-secret")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["confidence"], "high")
        self.assertEqual(item["relative_path"], "src/example.py")
        self.assertEqual(item["evidence"]["pattern"], "credential-assignment")
        self.assertEqual(item["evidence"]["credential_name"], "[REDACTED]")
        self.assertNotIn("super-secret-key", json.dumps(item))


if __name__ == "__main__":
    unittest.main()
