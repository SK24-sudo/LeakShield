import unittest

from leakshield.findings import Finding, RawFinding


class RawFindingTests(unittest.TestCase):
	def test_valid_construction_preserves_fields(self):
		evidence = {"pattern": "credential-assignment"}
		finding = RawFinding(
			finding_type="hardcoded-secret",
			relative_path="config.py",
			location=(3, 10),
			candidate_value="synthetic-secret",
			detector_id="credential-assignment",
			evidence=evidence,
		)

		self.assertEqual(finding.finding_type, "hardcoded-secret")
		self.assertEqual(finding.relative_path, "config.py")
		self.assertEqual(finding.location, (3, 10))
		self.assertEqual(finding.candidate_value, "synthetic-secret")
		self.assertEqual(finding.detector_id, "credential-assignment")
		self.assertIs(finding.evidence, evidence)

	def test_invalid_location_shape_is_rejected(self):
		with self.assertRaises(TypeError):
			RawFinding(
				"synthetic-type",
				"synthetic.py",
				(1,),
				"synthetic-value",
				"synthetic-detector",
				{},
			)

	def test_invalid_evidence_shape_is_rejected(self):
		with self.assertRaises(TypeError):
			RawFinding(
				"synthetic-type",
				"synthetic.py",
				(1, 1),
				"synthetic-value",
				"synthetic-detector",
				[],
			)


class FindingBoundaryTests(unittest.TestCase):
	def test_normalized_finding_preserves_raw_information(self):
		evidence = {"pattern": "credential-assignment", "credential_name": "password"}
		raw = RawFinding(
			finding_type="hardcoded-secret",
			relative_path="config.py",
			location=(3, 10),
			candidate_value="synthetic-secret",
			detector_id="pattern-secret",
			evidence=evidence,
		)
		normalized = Finding(raw)

		self.assertIs(normalized.raw_finding, raw)
		self.assertEqual(normalized.finding_type, raw.finding_type)
		self.assertEqual(normalized.relative_path, raw.relative_path)
		self.assertEqual(normalized.location, raw.location)
		self.assertEqual(normalized.candidate_value, raw.candidate_value)
		self.assertEqual(normalized.detector_id, raw.detector_id)
		self.assertIs(normalized.evidence, raw.evidence)
		self.assertIsNone(normalized.confidence)
		self.assertIsNone(normalized.severity)
		self.assertIsNone(normalized.risk)

	def test_normalized_finding_rejects_non_raw_finding(self):
		with self.assertRaises(TypeError):
			Finding({"not": "raw"})


class FindingRiskTests(unittest.TestCase):
	def _make_finding(self):
		raw = RawFinding(
			finding_type="hardcoded-secret",
			relative_path="config.py",
			location=(1, 1),
			candidate_value="synthetic-secret",
			detector_id="pattern-secret",
			evidence={"pattern": "credential-assignment"},
		)
		return Finding(raw)

	def test_confidence_requires_pattern_and_uses_strong_structural_signals(self):
		finding = self._make_finding()
		self.assertEqual(finding.assign_confidence(), "low")
		finding.evidence = {"pattern": "credential-assignment", "credential_name": "password"}
		self.assertEqual(finding.assign_confidence(), "medium")

		finding.evidence = {
			"pattern": "credential-assignment",
			"credential_name": "password",
			"entropy_signal": True,
		}
		self.assertEqual(finding.assign_confidence(), "high")

	def test_redacted_copy_preserves_internal_finding_and_redacts_candidate_value(self):
		finding = self._make_finding()
		finding.confidence = "high"
		finding.severity = "high"
		finding.risk = "high"
		finding.evidence = {"pattern": "credential-assignment", "credential_name": "password", "entropy": 4.5}

		redacted = finding.redacted_copy()

		self.assertEqual(finding.candidate_value, "synthetic-secret")
		self.assertEqual(redacted.candidate_value, "[REDACTED]")
		self.assertEqual(redacted.confidence, "high")
		self.assertEqual(redacted.severity, "high")
		self.assertEqual(redacted.risk, "high")
		self.assertIsNone(redacted.raw_finding)
		self.assertEqual(redacted.evidence["pattern"], "credential-assignment")
		self.assertEqual(redacted.evidence["credential_name"], "password")
		self.assertEqual(redacted.evidence["entropy"], 4.5)

	def test_redacted_copy_only_redacts_matching_secret_material_and_is_idempotent(self):
		finding = self._make_finding()
		finding.evidence = {"pattern": "credential-assignment", "credential_name": "synthetic-secret", "entropy": 4.5}

		redacted = finding.redacted_copy()
		redacted_twice = redacted.redacted_copy()

		self.assertEqual(redacted.evidence["credential_name"], "[REDACTED]")
		self.assertEqual(redacted.evidence["pattern"], "credential-assignment")
		self.assertEqual(redacted_twice.candidate_value, "[REDACTED]")
		self.assertEqual(redacted_twice.evidence["credential_name"], "[REDACTED]")

	def test_redacted_copy_keeps_non_secret_findings_unchanged(self):
		finding = self._make_finding()
		finding.finding_type = "eval"
		finding.candidate_value = ""
		finding.evidence = {"pattern": "eval", "file_extension": ".py"}

		redacted = finding.redacted_copy()

		self.assertEqual(redacted.candidate_value, "")
		self.assertEqual(redacted.evidence, {"pattern": "eval", "file_extension": ".py"})
		self.assertIsNone(redacted.raw_finding)

	def test_confidence_high_for_private_key_key_type_exception(self):
		raw = RawFinding(
			finding_type="private-key",
			relative_path="config.py",
			location=(1, 1),
			candidate_value="-----BEGIN PRIVATE KEY-----",
			detector_id="pattern-secret",
			evidence={"pattern": "private-key-pem", "key_type": "PRIVATE KEY"},
		)
		finding = Finding(raw)
		self.assertEqual(finding.assign_confidence(), "high")

	def test_confidence_high_for_jwt_alg_exception(self):
		raw = RawFinding(
			finding_type="jwt",
			relative_path="config.py",
			location=(1, 1),
			candidate_value="header.payload.signature",
			detector_id="pattern-secret",
			evidence={"pattern": "jwt", "alg": "HS256"},
		)
		finding = Finding(raw)
		self.assertEqual(finding.assign_confidence(), "high")

	def test_confidence_medium_for_pattern_with_file_extension_only(self):
		finding = self._make_finding()
		finding.evidence = {"pattern": "credential-assignment", "file_extension": ".py"}
		self.assertEqual(finding.assign_confidence(), "medium")

	def test_severity_uses_category_policy(self):
		secret = self._make_finding()
		secret.finding_type = "credential-assignment"
		self.assertEqual(secret.assign_severity(), "high")

		dangerous = self._make_finding()
		dangerous.finding_type = "eval"
		self.assertEqual(dangerous.assign_severity(), "medium")

		unknown = self._make_finding()
		unknown.finding_type = "custom-find"
		self.assertEqual(unknown.assign_severity(), "medium")

	def test_risk_lookup_matrix(self):
		cases = [
			(("low", "low"), "low"),
			(("low", "medium"), "low"),
			(("low", "high"), "low"),
			(("medium", "low"), "low"),
			(("medium", "medium"), "medium"),
			(("medium", "high"), "medium"),
			(("high", "low"), "medium"),
			(("high", "medium"), "high"),
			(("high", "high"), "high"),
			(("critical", "low"), "high"),
			(("critical", "medium"), "critical"),
			(("critical", "high"), "critical"),
		]
		for (severity, confidence), expected in cases:
			with self.subTest(severity=severity, confidence=confidence):
				finding = self._make_finding()
				finding.severity = severity
				finding.confidence = confidence
				self.assertEqual(finding.calculate_risk(), expected)

	def test_invalid_or_missing_inputs_return_none_risk(self):
		cases = [
			({}, "missing confidence"),
			({"severity": "medium"}, "missing confidence"),
			({"confidence": "medium"}, "missing severity"),
			({"confidence": "unknown", "severity": "high"}, "invalid confidence"),
			({"confidence": "high", "severity": "unknown"}, "invalid severity"),
			({"confidence": "medium", "severity": "bad"}, "invalid severity"),
		]
		for input_values, _ in cases:
			with self.subTest(input_values=input_values):
				finding = self._make_finding()
				for key, value in input_values.items():
					setattr(finding, key, value)
				self.assertIsNone(finding.calculate_risk())


if __name__ == "__main__":
	unittest.main()
