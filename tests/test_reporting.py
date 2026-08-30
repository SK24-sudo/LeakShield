import json
import unittest

from leakshield.findings import Finding, RawFinding
from leakshield.reporting import findings_to_html, findings_to_json, format_findings_cli


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
    def test_empty_findings_to_json_returns_empty_array(self):
        result = findings_to_json([])
        self.assertEqual(result, "[]")
        parsed = json.loads(result)
        self.assertEqual(parsed, [])

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
        raw_json = findings_to_json([redacted])
        payload = json.loads(raw_json)

        self.assertEqual(len(payload), 1)
        item = payload[0]
        self.assertEqual(item["finding_type"], "credential-assignment")
        self.assertEqual(item["relative_path"], "src/example.py")
        self.assertEqual(item["location"], [12, 3])
        self.assertEqual(item["candidate_value"], "[REDACTED]")
        self.assertEqual(item["detector_id"], "pattern-secret")
        self.assertEqual(item["evidence"]["pattern"], "credential-assignment")
        self.assertEqual(item["evidence"]["credential_name"], "[REDACTED]")
        self.assertEqual(item["confidence"], "high")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["risk"], "high")
        self.assertNotIn("super-secret-key", raw_json)

    def test_findings_to_json_has_no_terminal_decorations(self):
        finding = _make_finding()
        raw_json = findings_to_json([finding.redacted_copy()])
        self.assertTrue(raw_json.startswith("["))
        self.assertTrue(raw_json.endswith("]"))
        self.assertNotIn("LEAKSHIELD", raw_json)
        self.assertNotIn("Discovering", raw_json)
        self.assertNotIn("✓", raw_json)
        self.assertNotIn("⚠", raw_json)


class HtmlReportingTests(unittest.TestCase):
    def test_findings_to_html_returns_valid_html_string(self):
        result = findings_to_html([])
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("<!DOCTYPE html>"))
        self.assertIn("<html lang=\"en\">", result)
        self.assertIn("</html>", result)

    def test_zero_findings_html_is_accurate_and_does_not_overstate_security(self):
        result = findings_to_html([], target="my/project")
        self.assertIn("No potential security findings found", result)
        self.assertIn("No supported LeakShield findings were detected in the analyzed files.", result)
        self.assertIn("my/project", result)
        lower = result.lower()
        self.assertNotIn("repository is secure", lower)
        self.assertNotIn("no vulnerabilities exist", lower)

    def test_findings_html_displays_summary_metrics_and_breakdowns(self):
        findings = [
            _make_finding(finding_type="credential-assignment"),
            _make_finding(finding_type="eval"),
        ]
        findings[0].severity = "high"
        findings[0].confidence = "high"
        findings[0].risk = "high"
        findings[1].severity = "medium"
        findings[1].confidence = "medium"
        findings[1].risk = "medium"

        result = findings_to_html(findings, target="src/app")
        self.assertIn("Total Findings", result)
        self.assertIn('<div class="stat-value">2</div>', result)
        self.assertIn("Severity Breakdown", result)
        self.assertIn("Confidence Breakdown", result)
        self.assertIn("Risk Breakdown", result)
        self.assertIn("src/app", result)

    def test_findings_html_displays_finding_cards_with_badges_and_actions(self):
        finding = _make_finding(finding_type="credential-assignment")
        finding.severity = "high"
        finding.confidence = "high"
        finding.risk = "high"

        result = findings_to_html([finding.redacted_copy()])
        self.assertIn("Hardcoded credential assignment", result)
        self.assertIn("HIGH SEVERITY", result)
        self.assertIn("High Confidence", result)
        self.assertIn("HIGH RISK", result)
        self.assertIn("src/example.py:12:3", result)
        self.assertIn("Move the credential outside source code", result)

    def test_findings_html_is_self_contained_with_no_external_assets(self):
        finding = _make_finding()
        result = findings_to_html([finding.redacted_copy()])
        self.assertNotIn("http://", result)
        self.assertNotIn("https://", result)
        self.assertNotIn("<script", result)
        self.assertNotIn('<link rel="stylesheet"', result)
        self.assertIn("<style>", result)

    def test_findings_html_escapes_dynamic_content(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="src/<script>alert(1)</script>.py",
            location=(1, 1),
            candidate_value="[REDACTED]",
            detector_id="detector&special",
            evidence={"tag": "<b>bold</b>"},
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"

        result = findings_to_html([finding], target="<evil>target</evil>")
        self.assertNotIn("<script>alert(1)</script>", result)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", result)
        self.assertNotIn("<evil>", result)
        self.assertIn("&lt;evil&gt;target&lt;/evil&gt;", result)
        self.assertIn("detector&amp;special", result)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt;", result)

    def test_findings_html_redacts_secrets_and_does_not_leak_raw_secret(self):
        finding = _make_finding(candidate_value="RAW_SUPER_SECRET_TOKEN_999")
        redacted = finding.redacted_copy()
        result = findings_to_html([redacted])
        self.assertNotIn("RAW_SUPER_SECRET_TOKEN_999", result)
        self.assertIn("[REDACTED]", result)

    def test_findings_to_html_requires_list(self):
        with self.assertRaises(TypeError):
            findings_to_html(None)


class CliFormatterTests(unittest.TestCase):
    def test_format_findings_cli_returns_string(self):
        result = format_findings_cli([])
        self.assertIsInstance(result, str)

    def test_zero_findings_output_is_understandable(self):
        result = format_findings_cli([], target="examples/vulnerable_repo")
        self.assertIn("LEAKSHIELD", result)
        self.assertIn("Target", result)
        self.assertIn("examples/vulnerable_repo", result)
        self.assertIn("No potential security findings found.", result)
        self.assertIn("Scan complete.", result)
        lower = result.lower()
        self.assertNotIn("repository is secure", lower)
        self.assertNotIn("no vulnerabilities", lower)

    def test_cli_output_includes_tool_identity(self):
        result = format_findings_cli([], target="some/path")
        self.assertIn("LEAKSHIELD", result)
        self.assertIn("Local, zero-dependency repository security auditor", result)
        self.assertIn("Prevent accidentally shipping secrets and security-sensitive", result)
        self.assertIn("code patterns.", result)
        self.assertIn("Target", result)
        self.assertIn("some/path", result)

    def test_cli_findings_output_includes_header(self):
        finding = _make_finding()
        result = format_findings_cli([finding], target="test/target")
        self.assertIn("LEAKSHIELD", result)
        self.assertIn("Target", result)
        self.assertIn("test/target", result)
        self.assertIn("Location:", result)
        self.assertIn("What:", result)
        self.assertIn("Why:", result)
        self.assertIn("Action:", result)

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

    def test_single_finding_uses_singular_grammar(self):
        finding = _make_finding(finding_type="credential-assignment")
        result = format_findings_cli([finding])
        self.assertIn("1 potential security finding found.", result)
        self.assertNotIn("1 potential security findings found.", result)

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

    def test_consolidated_finding_shows_multiple_locations_in_cli(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="a.py",
            location=(3, 1),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "credential-assignment", "credential_name": "password"},
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"
        finding.locations = [("a.py", (3, 1)), ("b.py", (10, 1))]

        result = format_findings_cli([finding])
        self.assertIn("Locations:", result)
        self.assertIn("a.py:3:1", result)
        self.assertIn("b.py:10:1", result)

    def test_single_location_finding_uses_location_label(self):
        finding = _make_finding()
        result = format_findings_cli([finding])
        self.assertIn("Location: src/example.py:12:3", result)
        self.assertNotIn("Locations:", result)


class JsonConsolidationTests(unittest.TestCase):
    def test_findings_to_json_includes_locations_when_consolidated(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="a.py",
            location=(3, 1),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "credential-assignment", "credential_name": "password"},
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"
        finding.locations = [("a.py", (3, 1)), ("b.py", (10, 1))]

        raw_json = findings_to_json([finding.redacted_copy()])
        payload = json.loads(raw_json)

        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["location"], [3, 1])
        self.assertEqual(payload[0]["relative_path"], "a.py")
        self.assertIn("locations", payload[0])
        self.assertEqual(len(payload[0]["locations"]), 2)
        self.assertEqual(payload[0]["locations"][0]["relative_path"], "a.py")
        self.assertEqual(payload[0]["locations"][0]["location"], [3, 1])
        self.assertEqual(payload[0]["locations"][1]["relative_path"], "b.py")
        self.assertEqual(payload[0]["locations"][1]["location"], [10, 1])

    def test_findings_to_json_omits_locations_when_not_consolidated(self):
        finding = _make_finding()
        raw_json = findings_to_json([finding.redacted_copy()])
        payload = json.loads(raw_json)

        self.assertEqual(len(payload), 1)
        self.assertNotIn("locations", payload[0])


class HtmlConsolidationTests(unittest.TestCase):
    def test_findings_to_html_shows_multiple_locations(self):
        raw = RawFinding(
            finding_type="credential-assignment",
            relative_path="a.py",
            location=(3, 1),
            candidate_value="super-secret-key",
            detector_id="pattern-secret",
            evidence={"pattern": "credential-assignment", "credential_name": "password"},
        )
        finding = Finding(raw)
        finding.confidence = "high"
        finding.severity = "high"
        finding.risk = "high"
        finding.locations = [("a.py", (3, 1)), ("b.py", (10, 1))]

        result = findings_to_html([finding.redacted_copy()], target="src/app")
        self.assertIn("Locations:", result)
        self.assertIn("a.py:3:1", result)
        self.assertIn("b.py:10:1", result)


if __name__ == "__main__":
    unittest.main()