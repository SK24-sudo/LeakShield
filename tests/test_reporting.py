import json
import unittest

from leakshield.findings import Finding, RawFinding
from leakshield.reporting import findings_to_json, format_findings_cli


def _make_finding(finding_type="credential-assignment", candidate_value="super-secret-key", evidence=None):
    if evidence is None:
        evidence = {"pattern": finding_type, "credential_name": candidate_value}
    raw = RawFinding(
        finding_type=finding_type,
        relative_path="src/example.py",
        location=(12, 3),
        candidate_value=candidate_value,
        detector_id="pattern-secret",
        evidence=evidence,
    )
    finding = Finding(raw)
    finding.confidence = "high"
    finding.severity = "high"
    finding.risk = "high"
    return finding


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


class CliFormatterTests(unittest.TestCase):
    def test_format_findings_cli_returns_string(self):
        result = format_findings_cli([])
        self.assertIsInstance(result, str)

    def test_zero_findings_output_is_understandable(self):
        result = format_findings_cli([])
        self.assertIn("No supported security patterns detected.", result)
        self.assertIn("A clean scan is not a guarantee", result)
        lower = result.lower()
        self.assertNotIn("repository is secure", lower)
        self.assertNotIn("no vulnerabilities", lower)

    def test_format_findings_cli_includes_location(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertIn("src/example.py:12:3", result)

    def test_format_findings_cli_includes_what(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertIn("Hardcoded credential assignment", result)

    def test_format_findings_cli_includes_why(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertIn("credential-like variable is assigned a hardcoded string value", result)

    def test_format_findings_cli_includes_action(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertIn("Move the credential outside source code", result)

    def test_credential_assignment_output(self):
        finding = _make_finding(
            finding_type="credential-assignment",
            candidate_value="my-secret",
            evidence={"pattern": "credential-assignment", "credential_name": "api_key"},
        )
        result = format_findings_cli([finding])
        self.assertIn("Location:", result)
        self.assertIn("What:", result)
        self.assertIn("Why:", result)
        self.assertIn("Action:", result)
        self.assertIn("src/example.py:12:3", result)
        self.assertIn("Hardcoded credential assignment", result)
        self.assertIn("Move the credential outside source code", result)
        self.assertNotIn("my-secret", result)

    def test_provider_token_output(self):
        finding = _make_finding(
            finding_type="provider-token",
            candidate_value="ghp_1234567890abcdefghijklmnop",
            evidence={"pattern": "github-pat", "provider": "github"},
        )
        result = format_findings_cli([finding])
        self.assertIn("Provider-specific access token", result)
        self.assertIn("provider-specific token format", result)
        self.assertIn("Remove the token from the repository", result)
        self.assertNotIn("ghp_1234567890abcdefghijklmnop", result)

    def test_ast_security_finding_output(self):
        finding = _make_finding(
            finding_type="eval",
            candidate_value="eval",
            evidence={"pattern": "eval"},
        )
        result = format_findings_cli([finding])
        self.assertIn("Direct eval() call", result)
        self.assertIn("AST analysis", result)
        self.assertIn("Avoid eval()", result)

    def test_candidate_value_is_absent_from_output(self):
        finding = _make_finding(candidate_value="SUPER_SECRET_VALUE_12345")
        result = format_findings_cli([finding])
        self.assertNotIn("SUPER_SECRET_VALUE_12345", result)

    def test_raw_finding_content_is_absent(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertNotIn("RawFinding", result)
        self.assertNotIn("raw_finding", result)

    def test_multiple_findings_includes_summary(self):
        findings = [
            _make_finding(finding_type="credential-assignment"),
            _make_finding(finding_type="private-key"),
        ]
        result = format_findings_cli(findings)
        self.assertIn("2 potential security findings found.", result)
        self.assertIn("Hardcoded credential assignment", result)
        self.assertIn("PEM private key", result)

    def test_unknown_finding_type_uses_fallback(self):
        finding = _make_finding(
            finding_type="future-unknown-type",
            candidate_value="unknown",
            evidence={"pattern": "unknown"},
        )
        result = format_findings_cli([finding])
        self.assertIn("Security finding detected", result)
        self.assertIn("supported security pattern", result)
        self.assertIn("Review this finding", result)
        self.assertNotIn("unknown", result)

    def test_format_findings_cli_requires_list(self):
        with self.assertRaises(TypeError):
            format_findings_cli(None)


if __name__ == "__main__":
    unittest.main()