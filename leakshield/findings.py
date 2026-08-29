class RawFinding:
	"""Intermediate finding emitted by a detector."""

	def __init__(
		self,
		finding_type,
		relative_path,
		location,
		candidate_value,
		detector_id,
		evidence,
	):
		if not isinstance(finding_type, str):
			raise TypeError("finding_type must be a string")

		if not isinstance(relative_path, str):
			raise TypeError("relative_path must be a string")

		if (
			not isinstance(location, tuple)
			or len(location) != 2
			or not all(isinstance(value, int) for value in location)
		):
			raise TypeError("location must be a two-integer tuple")

		if not isinstance(candidate_value, str):
			raise TypeError("candidate_value must be a string")

		if not isinstance(detector_id, str):
			raise TypeError("detector_id must be a string")

		if not isinstance(evidence, dict):
			raise TypeError("evidence must be a dictionary")

		self.finding_type = finding_type
		self.relative_path = relative_path
		self.location = location
		self.candidate_value = candidate_value
		self.detector_id = detector_id
		self.evidence = evidence


class Finding:
	"""Normalized post-detection finding boundary for later Phase 4B scoring."""

	_VALID_CONFIDENCE = {"low", "medium", "high"}
	_VALID_SEVERITY = {"low", "medium", "high", "critical"}
	_VALID_RISK = {"low", "medium", "high", "critical"}
	_STRONG_SIGNAL_KEYS = {
		"credential_name",
		"provider",
		"key_type",
		"alg",
		"typ",
		"kid",
		"entropy_signal",
	}
	_WEAK_SIGNAL_KEYS = {"file_extension"}
	_SECRET_FAMILY_FINDINGS = {"private-key", "provider-token", "jwt", "credential-assignment"}
	_DANGEROUS_CODE_FINDINGS = {"eval", "exec", "subprocess", "shell-true", "os-system"}

	def __init__(self, raw_finding):
		if not isinstance(raw_finding, RawFinding):
			raise TypeError("raw_finding must be a RawFinding instance")

		self.raw_finding = raw_finding
		self.finding_type = raw_finding.finding_type
		self.relative_path = raw_finding.relative_path
		self.location = raw_finding.location
		self.candidate_value = raw_finding.candidate_value
		self.detector_id = raw_finding.detector_id
		self.evidence = raw_finding.evidence
		self.confidence = None
		self.severity = None
		self.risk = None

	def _count_corroborating_signals(self):
		if not isinstance(self.evidence, dict):
			return 0, 0

		strong = 0
		weak = 0
		for key in self.evidence:
			if key in self._STRONG_SIGNAL_KEYS:
				strong += 1
			elif key in self._WEAK_SIGNAL_KEYS:
				weak += 1
		return strong, weak

	def assign_confidence(self):
		"""Return confidence based on the approved pattern + evidence rule."""
		if "pattern" not in self.evidence:
			self.confidence = None
			return self.confidence

		strong, weak = self._count_corroborating_signals()
		if self.finding_type == "private-key" and "key_type" in self.evidence:
			self.confidence = "high"
			return self.confidence
		if self.finding_type == "provider-token" and "provider" in self.evidence:
			self.confidence = "high"
			return self.confidence
		if self.finding_type == "jwt" and any(key in self.evidence for key in ("alg", "typ", "kid")):
			self.confidence = "high"
			return self.confidence
		if strong == 0 and weak == 0:
			self.confidence = "low"
			return self.confidence
		if strong >= 2:
			self.confidence = "high"
			return self.confidence
		if strong >= 1 and weak >= 1:
			self.confidence = "high"
			return self.confidence
		if strong >= 1:
			self.confidence = "medium"
			return self.confidence
		if weak >= 1:
			self.confidence = "medium"
			return self.confidence

		self.confidence = "low"
		return self.confidence

	def assign_severity(self):
		"""Return severity based on the approved category-level policy."""
		if self.finding_type in {"private-key", "provider-token", "jwt", "credential-assignment"}:
			self.severity = "high"
			return self.severity
		if self.finding_type in {"eval", "exec", "subprocess", "shell-true", "os-system"}:
			self.severity = "medium"
			return self.severity
		self.severity = "medium"
		return self.severity

	def redacted_copy(self):
		"""Return a redacted external representation without mutating the internal Finding."""
		redacted = self.__class__.__new__(self.__class__)
		redacted.raw_finding = None
		redacted.finding_type = self.finding_type
		redacted.relative_path = self.relative_path
		redacted.location = self.location
		redacted.candidate_value = "[REDACTED]" if self.candidate_value else self.candidate_value
		redacted.detector_id = self.detector_id

		if isinstance(self.evidence, dict):
			redacted.evidence = dict(self.evidence)
			for key, value in redacted.evidence.items():
				if value == self.candidate_value:
					redacted.evidence[key] = "[REDACTED]"
		else:
			redacted.evidence = self.evidence

		redacted.confidence = self.confidence
		redacted.severity = self.severity
		redacted.risk = self.risk
		return redacted

	def calculate_risk(self):
		"""Return the normalized risk for this finding based only on confidence and severity."""
		confidence = getattr(self, "confidence", None)
		severity = getattr(self, "severity", None)

		if confidence not in self._VALID_CONFIDENCE:
			return None
		if severity not in self._VALID_SEVERITY:
			return None

		matrix = {
			("low", "low"): "low",
			("low", "medium"): "low",
			("low", "high"): "low",
			("medium", "low"): "low",
			("medium", "medium"): "medium",
			("medium", "high"): "medium",
			("high", "low"): "medium",
			("high", "medium"): "high",
			("high", "high"): "high",
			("critical", "low"): "high",
			("critical", "medium"): "critical",
			("critical", "high"): "critical",
		}

		self.risk = matrix[(severity, confidence)]
		return self.risk
