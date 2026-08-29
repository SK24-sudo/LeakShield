import unittest
from pathlib import Path

from leakshield.config import ScanConfig
from leakshield.discovery import FileInfo
from leakshield.findings import Finding, RawFinding
from leakshield.scanner import collect_raw_findings, deduplicate_findings, normalize_findings, scan


def _make_file_info(extension):
    path = Path(f"synthetic{extension}")
    return FileInfo(
        path=path,
        relative_path=f"synthetic{extension}",
        name=path.name,
        extension=path.suffix,
        size=1,
        classification="python" if extension == ".py" else "text",
    )


class ScannerCollectionTests(unittest.TestCase):
    def test_collects_secret_and_ast_findings_in_fixed_order(self):
        source = 'password = "supersecret123"\nprint(eval("1 + 1"))\n'
        findings = collect_raw_findings(source, _make_file_info(".py"))

        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(findings[0].finding_type, "credential-assignment")
        self.assertEqual(findings[0].detector_id, "pattern-secret")
        self.assertEqual(findings[0].evidence["pattern"], "credential-assignment")
        self.assertEqual(findings[0].evidence["credential_name"], "password")
        self.assertEqual(findings[0].evidence["file_extension"], ".py")
        self.assertEqual(findings[1].finding_type, "eval")
        self.assertEqual(findings[1].detector_id, "ast-security")
        self.assertEqual(findings[1].evidence["pattern"], "eval")
        self.assertEqual(findings[1].evidence["file_extension"], ".py")

    def test_collection_preserves_detector_evidence(self):
        source = 'password = "supersecret123"\nprint(eval("1 + 1"))\n'
        findings = collect_raw_findings(source, _make_file_info(".py"))

        first = findings[0]
        second = findings[1]
        self.assertIn("pattern", first.evidence)
        self.assertIn("credential_name", first.evidence)
        self.assertIn("file_extension", first.evidence)
        self.assertEqual(second.evidence["pattern"], "eval")
        self.assertEqual(second.evidence["file_extension"], ".py")

    def test_original_evidence_dictionary_is_not_mutated(self):
        source = 'password = "supersecret123"\nprint(eval("1 + 1"))\n'
        original = collect_raw_findings(source, _make_file_info(".py"))[0]
        original_evidence = original.evidence.copy()
        enriched = collect_raw_findings(source, _make_file_info(".py"))
        self.assertEqual(original_evidence, original.evidence)
        self.assertEqual(enriched[0].evidence["file_extension"], ".py")

    def test_different_file_extensions_are_preserved_per_finding(self):
        source = 'password = "supersecret123"\nprint(eval("1 + 1"))\n'
        py_findings = collect_raw_findings(source, _make_file_info(".py"))
        txt_findings = collect_raw_findings(source, _make_file_info(".txt"))

        self.assertEqual(py_findings[0].evidence["file_extension"], ".py")
        self.assertEqual(txt_findings[0].evidence["file_extension"], ".txt")
        self.assertEqual(py_findings[1].evidence["file_extension"], ".py")
        self.assertEqual(txt_findings[1].evidence["file_extension"], ".txt")


class ScannerDeterminismTests(unittest.TestCase):
    def test_scan_is_deterministic_across_repeated_runs_on_same_repository(self):
        target = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_repo"

        def snapshot(findings):
            return [
                (
                    finding.finding_type,
                    finding.relative_path,
                    finding.location,
                    finding.candidate_value,
                    finding.detector_id,
                    tuple(sorted(finding.evidence.items())),
                    finding.confidence,
                    finding.severity,
                    finding.risk,
                )
                for finding in findings
            ]

        first = scan(ScanConfig(str(target)))
        second = scan(ScanConfig(str(target)))

        self.assertEqual(snapshot(first), snapshot(second))


class Phase4CDeduplicationTests(unittest.TestCase):
    def _make_raw(self, **overrides):
        data = {
            "finding_type": "credential-assignment",
            "relative_path": "config.py",
            "location": (1, 1),
            "candidate_value": "secret-value",
            "detector_id": "pattern-secret",
            "evidence": {"pattern": "credential-assignment", "credential_name": "password"},
        }
        data.update(overrides)
        return RawFinding(
            finding_type=data["finding_type"],
            relative_path=data["relative_path"],
            location=data["location"],
            candidate_value=data["candidate_value"],
            detector_id=data["detector_id"],
            evidence=data["evidence"],
        )

    def _make_finding(self, **overrides):
        return Finding(self._make_raw(**overrides))

    def test_identical_normalized_findings_are_deduplicated(self):
        first = self._make_finding()
        second = self._make_finding()

        self.assertEqual(deduplicate_findings([first, second]), [first])

    def test_different_evidence_insertion_order_is_still_exact_duplicate(self):
        first = self._make_finding(evidence={"credential_name": "password", "pattern": "credential-assignment"})
        second = self._make_finding(evidence={"pattern": "credential-assignment", "credential_name": "password"})

        self.assertEqual(deduplicate_findings([first, second]), [first])

    def test_different_finding_type_is_not_deduplicated(self):
        first = self._make_finding(finding_type="credential-assignment")
        second = self._make_finding(finding_type="provider-token")

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_different_detector_id_is_not_deduplicated(self):
        first = self._make_finding(detector_id="pattern-secret")
        second = self._make_finding(detector_id="ast-security")

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_different_candidate_value_is_not_deduplicated(self):
        first = self._make_finding(candidate_value="secret-one")
        second = self._make_finding(candidate_value="secret-two")

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_different_confidence_is_not_deduplicated(self):
        first = self._make_finding()
        first.confidence = "low"
        second = self._make_finding()
        second.confidence = "high"

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_different_severity_is_not_deduplicated(self):
        first = self._make_finding()
        first.severity = "medium"
        second = self._make_finding()
        second.severity = "critical"

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_different_risk_is_not_deduplicated(self):
        first = self._make_finding()
        first.risk = "low"
        second = self._make_finding()
        second.risk = "high"

        self.assertEqual(deduplicate_findings([first, second]), [first, second])

    def test_three_identical_findings_keep_only_the_first_object(self):
        first = self._make_finding()
        second = self._make_finding()
        third = self._make_finding()

        result = deduplicate_findings([first, second, third])
        self.assertEqual(result, [first])
        self.assertIs(result[0], first)

    def test_non_duplicate_ordering_is_preserved(self):
        first = self._make_finding(relative_path="a.py", location=(1, 1))
        second = self._make_finding(relative_path="b.py", location=(2, 1))
        duplicate = self._make_finding(relative_path="b.py", location=(2, 1))

        self.assertEqual(deduplicate_findings([first, second, duplicate]), [first, second])

    def test_retained_duplicate_is_the_original_first_object(self):
        first = self._make_finding()
        second = self._make_finding()

        result = deduplicate_findings([first, second])
        self.assertIs(result[0], first)
        self.assertIs(result[0].raw_finding, first.raw_finding)

    def test_raw_finding_provenance_remains_unchanged(self):
        first = self._make_finding()
        second = self._make_finding()

        result = deduplicate_findings([first, second])
        self.assertIs(result[0].raw_finding, first.raw_finding)
        self.assertIs(result[0].raw_finding, first.raw_finding)

    def test_normalize_findings_converts_raw_findings_without_changing_order(self):
        raw = [
            self._make_raw(finding_type="first"),
            self._make_raw(finding_type="second"),
        ]

        normalized = normalize_findings(raw)
        self.assertEqual([item.finding_type for item in normalized], ["first", "second"])
        self.assertTrue(all(isinstance(item, Finding) for item in normalized))
        self.assertIs(normalized[0].raw_finding, raw[0])

    def test_normalize_findings_assigns_metadata(self):
        normalized = normalize_findings([self._make_raw()])[0]

        self.assertIsNotNone(normalized.confidence)
        self.assertIsNotNone(normalized.severity)
        self.assertIsNotNone(normalized.risk)


if __name__ == "__main__":
    unittest.main()
