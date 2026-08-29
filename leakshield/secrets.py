import base64
import json
import math
import re

from leakshield.findings import RawFinding


_PRIVATE_KEY_PATTERN = re.compile(
	r"-----BEGIN (?:(?P<kind>RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----\r?\n"
	r"(?:[A-Za-z0-9+/]{4,64}(?:={1,2})?\r?\n){1,256}"
	r"-----END (?(kind)(?P=kind) )PRIVATE KEY-----"
)

_CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
	r"(?P<name>password|api_key|secret_key|access_token|client_secret)\b"
	r"\s*=\s*"
	r"(?P<quote>['\"])"
	r"(?P<value>(?:\\.|[^\\'\"])+?)"
	r"(?P=quote)",
	re.IGNORECASE,
)

_MIN_ENTROPY_CANDIDATE_LENGTH = 8
_ENTROPY_THRESHOLD = 3.5

_PROVIDER_TOKEN_PATTERNS = (
	(
		re.compile(
			r"(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])",
		),
		"github-pat",
		"github",
	),
	(
		re.compile(
			r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])",
			re.IGNORECASE,
		),
		"github-fine-grained-pat",
		"github",
	),
	(
		re.compile(
			r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
			re.IGNORECASE,
		),
		"gitlab-pat",
		"gitlab",
	),
	(
		re.compile(
			r"(?<![A-Za-z0-9_-])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9_-])",
			re.IGNORECASE,
		),
		"slack-token",
		"slack",
	),
)


def _is_placeholder_assignment(value):
	"""Return whether a value is an obvious placeholder."""
	normalized = value.strip().lower()
	if not normalized:
		return True

	placeholder_tokens = (
		"example",
		"sample",
		"placeholder",
		"changeme",
		"replace_me",
		"dummy",
		"fake",
		"demo",
		"lorem",
		"your_password",
		"your_api_key",
		"your_secret_key",
		"your_access_token",
		"your_client_secret",
	)

	return normalized in placeholder_tokens or any(
		token in normalized for token in placeholder_tokens
	)


def _shannon_entropy(candidate):
	"""Return Shannon entropy for the supplied character sequence."""
	if not isinstance(candidate, str) or not candidate:
		return 0.0

	counts = {}
	for character in candidate:
		counts[character] = counts.get(character, 0) + 1

	entropy = 0.0
	length = len(candidate)
	for count in counts.values():
		probability = count / length
		entropy -= probability * math.log2(probability)

	return entropy


def _decode_jwt_segment(segment):
	"""Safely decode a single JWT Base64URL segment."""
	if not isinstance(segment, str) or not segment:
		return None

	if any(
		(not ("A" <= character <= "Z")
			and not ("a" <= character <= "z")
			and not ("0" <= character <= "9")
			and character not in "-_"
			and character != "=")
		for character in segment
	):
		return None

	if "=" in segment and not segment.endswith("="):
		return None

	try:
		padded = segment + ("=" * (-len(segment) % 4))
		return base64.b64decode(padded, altchars=b"-_", validate=True)
	except Exception:
		return None


def _detect_jwt_secrets(source_text, file_info):
	"""Return structurally valid JWT candidates from source text."""
	if not isinstance(source_text, str):
		return []

	findings = []
	allowed_chars = set(
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
	)
	index = 0

	while index < len(source_text):
		if source_text[index] not in allowed_chars:
			index += 1
			continue

		start = index
		while index < len(source_text) and source_text[index] in allowed_chars:
			index += 1

		candidate = source_text[start:index]
		if "." not in candidate:
			continue

		parts = candidate.split(".")
		if len(parts) != 3 or any(not part for part in parts):
			continue

		header_part, payload_part, signature_part = parts
		if not header_part or not payload_part or not signature_part:
			continue

		header_bytes = _decode_jwt_segment(header_part)
		payload_bytes = _decode_jwt_segment(payload_part)
		if header_bytes is None or payload_bytes is None:
			continue

		try:
			header_obj = json.loads(header_bytes.decode("utf-8"))
			payload_obj = json.loads(payload_bytes.decode("utf-8"))
		except Exception:
			continue

		if not isinstance(header_obj, dict) or not isinstance(payload_obj, dict):
			continue

		evidence = {"pattern": "jwt"}
		for key in ("alg", "typ", "kid"):
			value = header_obj.get(key)
			if isinstance(value, str):
				evidence[key] = value
		if len(candidate) >= _MIN_ENTROPY_CANDIDATE_LENGTH:
			entropy = _shannon_entropy(candidate)
			if entropy >= _ENTROPY_THRESHOLD:
				evidence["entropy"] = entropy
				evidence["entropy_threshold"] = _ENTROPY_THRESHOLD
				evidence["entropy_signal"] = True

		line = source_text.count("\n", 0, start) + 1
		last_newline = source_text.rfind("\n", 0, start)
		column = start - last_newline

		findings.append(
			RawFinding(
				finding_type="jwt",
				relative_path=file_info.relative_path,
				location=(line, column),
				candidate_value=candidate,
				detector_id="pattern-secret",
				evidence=evidence,
			),
		)

	return findings


def _detect_pattern_secrets(source_text, file_info):
	"""Return pattern findings for source text."""
	findings = []

	for match in _PRIVATE_KEY_PATTERN.finditer(source_text):
		start = match.start()
		line = source_text.count("\n", 0, start) + 1
		last_newline = source_text.rfind("\n", 0, start)
		column = start - last_newline
		kind = match.group("kind")

		evidence = {
			"pattern": "private-key-pem",
			"key_type": (kind + " " if kind else "") + "PRIVATE KEY",
		}
		pem_block = match.group(0)
		pem_body = pem_block
		if "\n" in pem_body:
			lines = pem_body.splitlines()
			if len(lines) >= 2:
				pem_body = "".join(lines[1:-1])
		if len(pem_body) >= _MIN_ENTROPY_CANDIDATE_LENGTH:
			entropy = _shannon_entropy(pem_body)
			if entropy >= _ENTROPY_THRESHOLD:
				evidence["entropy"] = entropy
				evidence["entropy_threshold"] = _ENTROPY_THRESHOLD
				evidence["entropy_signal"] = True

		findings.append(
			RawFinding(
				finding_type="private-key",
				relative_path=file_info.relative_path,
				location=(line, column),
				candidate_value=pem_block,
				detector_id="pattern-secret",
				evidence=evidence,
			),
		)

	return findings


def _detect_credential_assignment_secrets(source_text, file_info):
	"""Return credential-like assignments that are hardcoded string literals."""
	findings = []

	for match in _CREDENTIAL_ASSIGNMENT_PATTERN.finditer(source_text):
		value = match.group("value")
		if not value:
			continue
		if _is_placeholder_assignment(value):
			continue
		if value.startswith("os.getenv(") or value.startswith("os.environ.get("):
			continue

		start = match.start()
		line = source_text.count("\n", 0, start) + 1
		last_newline = source_text.rfind("\n", 0, start)
		column = start - last_newline
		name = match.group("name").lower()
		evidence = {
			"pattern": "credential-assignment",
			"credential_name": name,
		}
		if len(value) >= _MIN_ENTROPY_CANDIDATE_LENGTH:
			entropy = _shannon_entropy(value)
			if entropy >= _ENTROPY_THRESHOLD:
				evidence["entropy"] = entropy
				evidence["entropy_threshold"] = _ENTROPY_THRESHOLD
				evidence["entropy_signal"] = True

		findings.append(
			RawFinding(
				finding_type="credential-assignment",
				relative_path=file_info.relative_path,
				location=(line, column),
				candidate_value=value,
				detector_id="pattern-secret",
				evidence=evidence,
			),
		)

	return findings


def _detect_provider_token_secrets(source_text, file_info):
	"""Return high-confidence structured provider tokens with distinctive prefixes."""
	findings = []

	for pattern, token_pattern, provider in _PROVIDER_TOKEN_PATTERNS:
		for match in pattern.finditer(source_text):
			value = match.group(0)
			if not value or _is_placeholder_assignment(value):
				continue

			start = match.start()
			line = source_text.count("\n", 0, start) + 1
			last_newline = source_text.rfind("\n", 0, start)
			column = start - last_newline
			evidence = {
				"pattern": token_pattern,
				"provider": provider,
			}
			if len(value) >= _MIN_ENTROPY_CANDIDATE_LENGTH:
				entropy = _shannon_entropy(value)
				if entropy >= _ENTROPY_THRESHOLD:
					evidence["entropy"] = entropy
					evidence["entropy_threshold"] = _ENTROPY_THRESHOLD
					evidence["entropy_signal"] = True

			findings.append(
				RawFinding(
					finding_type="provider-token",
					relative_path=file_info.relative_path,
					location=(line, column),
					candidate_value=value,
					detector_id="pattern-secret",
					evidence=evidence,
				),
			)

	return findings


def detect_secrets(source_text, file_info):
	"""Run secret detectors in the fixed detector sequence."""
	findings = []

	try:
		findings.extend(_detect_pattern_secrets(source_text, file_info))
	except Exception:
		pass

	try:
		findings.extend(_detect_credential_assignment_secrets(source_text, file_info))
	except Exception:
		pass

	try:
		findings.extend(_detect_provider_token_secrets(source_text, file_info))
	except Exception:
		pass

	try:
		findings.extend(_detect_jwt_secrets(source_text, file_info))
	except Exception:
		pass

	return findings
