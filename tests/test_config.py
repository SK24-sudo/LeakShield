import unittest

from leakshield.config import ConfigurationError, ScanConfig


class ScanConfigTests(unittest.TestCase):
	def test_default_configuration(self):
		config = ScanConfig("repository")

		self.assertEqual(config.target, "repository")
		self.assertEqual(config.output_format, "cli")
		self.assertEqual(config.severity_threshold, "low")
		self.assertEqual(config.ignore_patterns, ())

	def test_valid_configuration(self):
		config = ScanConfig(
			"requested-target",
			output_format="json",
			severity_threshold="high",
			ignore_patterns=["*.secret", "private/**"],
		)

		self.assertEqual(config.target, "requested-target")
		self.assertEqual(config.output_format, "json")
		self.assertEqual(config.severity_threshold, "high")
		self.assertEqual(config.ignore_patterns, ("*.secret", "private/**"))

	def test_all_valid_output_formats(self):
		for output_format in ("cli", "json", "html"):
			with self.subTest(output_format=output_format):
				self.assertEqual(
					ScanConfig("target", output_format=output_format).output_format,
					output_format,
				)

	def test_all_valid_severity_values(self):
		for severity in ("low", "medium", "high", "critical"):
			with self.subTest(severity=severity):
				self.assertEqual(
					ScanConfig("target", severity_threshold=severity).severity_threshold,
					severity,
				)

	def test_invalid_output_format(self):
		with self.assertRaises(ConfigurationError):
			ScanConfig("target", output_format="yaml")

	def test_invalid_severity(self):
		with self.assertRaises(ConfigurationError):
			ScanConfig("target", severity_threshold="urgent")

	def test_invalid_target(self):
		for target in (None, "", "   ", 42):
			with self.subTest(target=target):
				with self.assertRaises(ConfigurationError):
					ScanConfig(target)

	def test_invalid_ignore_patterns(self):
		invalid_values = (None, "*.secret", [""], ["   "], [42])

		for ignore_patterns in invalid_values:
			with self.subTest(ignore_patterns=ignore_patterns):
				with self.assertRaises(ConfigurationError):
					ScanConfig("target", ignore_patterns=ignore_patterns)

	def test_deterministic_construction(self):
		first = ScanConfig("target", "json", "medium", ["*.secret"])
		second = ScanConfig("target", "json", "medium", ["*.secret"])

		self.assertEqual(first.__dict__, second.__dict__)

	def test_ignore_patterns_are_an_immutable_tuple(self):
		config = ScanConfig("target", ignore_patterns=["*.secret"])

		self.assertIsInstance(config.ignore_patterns, tuple)

	def test_zero_dep_toml_is_unused(self):
		config = ScanConfig(".zero-dep.toml")

		self.assertEqual(config.target, ".zero-dep.toml")


if __name__ == "__main__":
	unittest.main()
