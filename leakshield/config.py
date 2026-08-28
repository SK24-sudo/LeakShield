class ConfigurationError(ValueError):
	"""Raised when configuration values are invalid."""


class ScanConfig:
	"""Validated configuration for one requested scan."""

	_OUTPUT_FORMATS = ("cli", "json", "html")
	_SEVERITY_THRESHOLDS = ("low", "medium", "high", "critical")

	def __init__(
		self,
		target,
		output_format="cli",
		severity_threshold="low",
		ignore_patterns=(),
	):
		if not isinstance(target, str) or not target.strip():
			raise ConfigurationError("target must be a non-empty string")

		if output_format not in self._OUTPUT_FORMATS:
			raise ConfigurationError("unsupported output format")

		if severity_threshold not in self._SEVERITY_THRESHOLDS:
			raise ConfigurationError("unsupported severity threshold")

		if not isinstance(ignore_patterns, (list, tuple, set, frozenset)):
			raise ConfigurationError("ignore_patterns must be a collection")

		patterns = tuple(ignore_patterns)

		if isinstance(ignore_patterns, (set, frozenset)):
			patterns = tuple(sorted(patterns))

		for pattern in patterns:
			if not isinstance(pattern, str) or not pattern.strip():
				raise ConfigurationError(
					"ignore_patterns must contain non-empty strings"
				)

		self.target = target
		self.output_format = output_format
		self.severity_threshold = severity_threshold
		self.ignore_patterns = patterns
