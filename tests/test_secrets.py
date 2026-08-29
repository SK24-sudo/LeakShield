import base64
import json
import unittest
from pathlib import Path

from leakshield.discovery import FileInfo
from leakshield.secrets import (
	_ENTROPY_THRESHOLD,
	_MIN_ENTROPY_CANDIDATE_LENGTH,
	_decode_jwt_segment,
	_detect_jwt_secrets,
	_detect_pattern_secrets,
	_shannon_entropy,
	detect_secrets,
)


def _file_info():
	path = Path("synthetic.py")
	return FileInfo(
		path=path,
		relative_path="synthetic.py",
		name=path.name,
		extension=path.suffix,
		size=1,
		classification="python",
	)


class JWTSegmentDecodingTests(unittest.TestCase):
	def test_decode_valid_base64url_with_padding(self):
		segment = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode("ascii")
		self.assertEqual(_decode_jwt_segment(segment), b'{"alg":"HS256"}')

	def test_decode_valid_base64url_without_padding(self):
		segment = 'eyJhbGciOiJIUzI1NiJ9'
		self.assertEqual(_decode_jwt_segment(segment), b'{"alg":"HS256"}')

	def test_decode_base64url_with_dash_and_underscore(self):
		payload = b'\xff\xff\xff\xff'
		segment = base64.urlsafe_b64encode(payload).decode("ascii")
		self.assertEqual(_decode_jwt_segment(segment), payload)

	def test_decode_rejects_invalid_base64url_characters(self):
		self.assertIsNone(_decode_jwt_segment('abc!def'))

	def test_decode_rejects_malformed_input(self):
		self.assertIsNone(_decode_jwt_segment(None))
		self.assertIsNone(_decode_jwt_segment('===='))

	def test_decode_rejects_empty_input(self):
		self.assertIsNone(_decode_jwt_segment(''))

	def test_decode_rejects_modulo_4_equals_1(self):
		self.assertIsNone(_decode_jwt_segment('Y'))

	def test_decode_accepts_modulo_4_equals_2(self):
		self.assertEqual(_decode_jwt_segment('YWI'), b'ab')

	def test_decode_accepts_modulo_4_equals_3(self):
		self.assertEqual(_decode_jwt_segment('YWJjZA'), b'abcd')

	def test_decode_rejects_padding_in_middle(self):
		self.assertIsNone(_decode_jwt_segment('ab=c'))

	def test_decode_rejects_padding_with_additional_characters(self):
		self.assertIsNone(_decode_jwt_segment('abc=def'))

	def test_decode_rejects_padding_only_input(self):
		self.assertIsNone(_decode_jwt_segment('==='))


class JWTStructuralDetectorTests(unittest.TestCase):
	def _make_jwt(self, header_obj, payload_obj, signature='signature'):
		header = base64.urlsafe_b64encode(json.dumps(header_obj, separators=(',', ':')).encode('utf-8')).rstrip(b'=')
		payload = base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')).rstrip(b'=')
		return header.decode('ascii') + '.' + payload.decode('ascii') + '.' + signature

	def test_valid_structural_jwt_candidate_is_detected(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "jwt")
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].candidate_value, candidate)
		self.assertEqual(result[0].evidence["pattern"], "jwt")

	def test_valid_jwt_has_expected_location(self):
		candidate = "prefix " + self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].location, (1, 8))

	def test_valid_jwt_does_not_expose_raw_token_in_evidence(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertNotIn(candidate, str(result[0].evidence))

	def test_ordinary_dotted_string_is_rejected(self):
		self.assertEqual(_detect_jwt_secrets("foo.bar.baz", _file_info()), [])

	def test_two_component_value_is_rejected(self):
		self.assertEqual(_detect_jwt_secrets("header.payload", _file_info()), [])

	def test_four_component_value_is_rejected(self):
		self.assertEqual(_detect_jwt_secrets("a.b.c.d", _file_info()), [])

	def test_invalid_base64url_header_is_rejected(self):
		header = "!!!"
		payload = base64.urlsafe_b64encode(b'{"sub":"user"}').rstrip(b'=')
		candidate = header + "." + payload.decode("ascii") + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_invalid_base64url_payload_is_rejected(self):
		header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b'=')
		payload = "!!!"
		candidate = header.decode("ascii") + "." + payload + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_valid_base64url_but_invalid_json_header_is_rejected(self):
		header = base64.urlsafe_b64encode(b'not-json').rstrip(b'=')
		payload = base64.urlsafe_b64encode(b'{"sub":"user"}').rstrip(b'=')
		candidate = header.decode("ascii") + "." + payload.decode("ascii") + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_valid_base64url_but_invalid_json_payload_is_rejected(self):
		header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b'=')
		payload = base64.urlsafe_b64encode(b'not-json').rstrip(b'=')
		candidate = header.decode("ascii") + "." + payload.decode("ascii") + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_header_json_array_instead_of_object_is_rejected(self):
		header = base64.urlsafe_b64encode(b'["not","an","object"]').rstrip(b'=')
		payload = base64.urlsafe_b64encode(b'{"sub":"user"}').rstrip(b'=')
		candidate = header.decode("ascii") + "." + payload.decode("ascii") + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_payload_json_array_instead_of_object_is_rejected(self):
		header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b'=')
		payload = base64.urlsafe_b64encode(b'["not","an","object"]').rstrip(b'=')
		candidate = header.decode("ascii") + "." + payload.decode("ascii") + ".signature"
		self.assertEqual(_detect_jwt_secrets(candidate, _file_info()), [])

	def test_multiple_valid_jwts_produce_multiple_findings(self):
		first = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		second = self._make_jwt({"typ": "JWT"}, {"sub": "admin"})
		source = first + " " + second
		result = _detect_jwt_secrets(source, _file_info())
		self.assertEqual(len(result), 2)
		self.assertEqual([item.candidate_value for item in result], [first, second])

	def test_detect_secrets_returns_jwt_findings_in_pipeline(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = detect_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "jwt")
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].candidate_value, candidate)
		self.assertEqual(result[0].evidence["pattern"], "jwt")

	def test_jwt_header_alg_is_added_to_evidence(self):
		candidate = self._make_jwt({"alg": "HS256"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertEqual(result[0].evidence["alg"], "HS256")

	def test_jwt_header_typ_is_added_to_evidence(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertEqual(result[0].evidence["typ"], "JWT")

	def test_jwt_header_kid_is_added_to_evidence(self):
		candidate = self._make_jwt({"kid": "abc123"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertEqual(result[0].evidence["kid"], "abc123")

	def test_jwt_header_all_optional_fields_are_added_to_evidence(self):
		candidate = self._make_jwt({"alg": "HS256", "typ": "JWT", "kid": "abc123"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertEqual(result[0].evidence["alg"], "HS256")
		self.assertEqual(result[0].evidence["typ"], "JWT")
		self.assertEqual(result[0].evidence["kid"], "abc123")

	def test_jwt_header_missing_optional_fields_keeps_only_pattern_evidence(self):
		candidate = self._make_jwt({"cty": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertNotIn("alg", result[0].evidence)
		self.assertNotIn("typ", result[0].evidence)
		self.assertNotIn("kid", result[0].evidence)
		self.assertIn("entropy", result[0].evidence)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_jwt_header_unexpected_json_types_are_ignored(self):
		candidate = self._make_jwt({"alg": 123, "typ": {"value": "JWT"}, "kid": ["abc"]}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertNotIn("alg", result[0].evidence)
		self.assertNotIn("typ", result[0].evidence)
		self.assertNotIn("kid", result[0].evidence)
		self.assertIn("entropy", result[0].evidence)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_jwt_below_length_threshold_has_no_entropy_evidence(self):
		candidate = "aaa.bbb"
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(result, [])

	def test_jwt_meeting_min_length_but_below_entropy_threshold_has_no_entropy_evidence(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertGreater(result[0].evidence["entropy"], _ENTROPY_THRESHOLD)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_jwt_meeting_entropy_threshold_adds_entropy_evidence(self):
		candidate = self._make_jwt({"typ": "JWT"}, {"sub": "user12345"})
		result = _detect_jwt_secrets(candidate, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["pattern"], "jwt")
		self.assertGreater(result[0].evidence["entropy"], _ENTROPY_THRESHOLD)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])


class ShannonEntropyTests(unittest.TestCase):
	def test_min_entropy_candidate_length_is_eight(self):
		self.assertEqual(_MIN_ENTROPY_CANDIDATE_LENGTH, 8)

	def test_entropy_threshold_is_three_point_five(self):
		self.assertEqual(_ENTROPY_THRESHOLD, 3.5)

	def test_entropy_empty_string_is_zero(self):
		self.assertEqual(_shannon_entropy(""), 0.0)

	def test_entropy_repeated_character_is_zero(self):
		self.assertEqual(_shannon_entropy("aaaa"), 0.0)

	def test_entropy_two_equally_frequent_characters_is_one(self):
		self.assertAlmostEqual(_shannon_entropy("abab"), 1.0)

	def test_entropy_known_non_uniform_distribution(self):
		value = "aabbbc"
		self.assertAlmostEqual(_shannon_entropy(value), 1.4591479170272448)

	def test_entropy_more_diverse_string_is_greater_than_repeated_string(self):
		self.assertGreater(_shannon_entropy("abcdabcd"), _shannon_entropy("aaaaaa"))

	def test_entropy_handles_unicode_characters(self):
		value = "πλΩ🙂π"
		result = _shannon_entropy(value)
		self.assertIsInstance(result, float)
		self.assertGreater(result, 0.0)

	def test_credential_assignment_below_min_length_has_no_entropy_evidence(self):
		source = 'api_key = "abc123"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "credential-assignment")
		self.assertNotIn("entropy", result[0].evidence)
		self.assertNotIn("entropy_threshold", result[0].evidence)
		self.assertNotIn("entropy_signal", result[0].evidence)

	def test_credential_assignment_high_entropy_adds_entropy_evidence(self):
		source = 'api_key = "x7Q2!mL9#kP4$"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "credential-assignment")
		self.assertGreater(result[0].evidence["entropy"], _ENTROPY_THRESHOLD)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_credential_assignment_low_entropy_keeps_phase_3b_finding_without_entropy_signal(self):
		source = 'password = "aaaaaaaa"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "credential-assignment")
		self.assertNotIn("entropy", result[0].evidence)
		self.assertNotIn("entropy_threshold", result[0].evidence)
		self.assertNotIn("entropy_signal", result[0].evidence)


class SecretDetectorInterfaceTests(unittest.TestCase):
	def test_detect_secrets_accepts_source_text_and_file_info(self):
		result = detect_secrets("value = 1\n", _file_info())

		self.assertIsInstance(result, list)

	def test_pattern_detector_returns_no_findings_without_supported_patterns(self):
		result = _detect_pattern_secrets("value = 1\n", _file_info())

		self.assertEqual(result, [])

	def test_rsa_private_key_pem_is_detected(self):
		source = "prefix\n-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END RSA PRIVATE KEY-----\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].finding_type, "private-key")
		self.assertEqual(result[0].relative_path, "synthetic.py")
		self.assertEqual(result[0].location, (2, 1))
		self.assertEqual(result[0].candidate_value, "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END RSA PRIVATE KEY-----")
		self.assertEqual(
			result[0].evidence,
			{"pattern": "private-key-pem", "key_type": "RSA PRIVATE KEY"},
		)

	def test_pem_private_key_entropy_evidence_is_added_for_high_entropy_body(self):
		source = "-----BEGIN RSA PRIVATE KEY-----\nQWxhZGRpbjpvcGVuIHNlc2FtZQ==\n-----END RSA PRIVATE KEY-----\n"
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertIn("entropy", result[0].evidence)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_pem_private_key_entropy_uses_body_only_not_pem_wrappers(self):
		source = "-----BEGIN RSA PRIVATE KEY-----\nQWERTYUIOPASDFGHJKLZXCVBNM\n-----END RSA PRIVATE KEY-----\n"
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertIn("entropy", result[0].evidence)
		self.assertNotEqual(result[0].evidence["entropy"], _shannon_entropy(result[0].candidate_value))

	def test_pem_private_key_entropy_does_not_create_a_second_finding(self):
		source = "-----BEGIN RSA PRIVATE KEY-----\nQWxhZGRpbjpvcGVuIHNlc2FtZQ==\n-----END RSA PRIVATE KEY-----\n"
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "private-key")

	def test_ec_private_key_pem_is_detected(self):
		source = "-----BEGIN EC PRIVATE KEY-----\nU1lOVEhFVElD\n-----END EC PRIVATE KEY-----\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["key_type"], "EC PRIVATE KEY")

	def test_all_supported_private_key_labels_are_detected(self):
		for label in (
			"PRIVATE KEY",
			"RSA PRIVATE KEY",
			"EC PRIVATE KEY",
			"DSA PRIVATE KEY",
			"OPENSSH PRIVATE KEY",
		):
			with self.subTest(label=label):
				source = (
					"-----BEGIN " + label + "-----\n"
					"U1lOVEhFVElD\n"
					"-----END " + label + "-----\n"
				)

				result = detect_secrets(source, _file_info())

				self.assertEqual(len(result), 1)
				self.assertEqual(result[0].evidence["key_type"], label)

	def test_multiple_private_keys_are_ordered_by_source_position(self):
		source = (
			"-----BEGIN PRIVATE KEY-----\nRklSU1Q=\n-----END PRIVATE KEY-----\n"
			"gap\n"
			"-----BEGIN OPENSSH PRIVATE KEY-----\nU0VDT05E\n-----END OPENSSH PRIVATE KEY-----\n"
		)

		result = detect_secrets(source, _file_info())

		self.assertEqual([finding.location for finding in result], [(1, 1), (5, 1)])

	def test_location_is_correct_after_same_line_text(self):
		source = "prefix -----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(result[0].location, (1, 8))

	def test_malformed_body_and_mismatched_labels_are_rejected(self):
		source = (
			"-----BEGIN RSA PRIVATE KEY-----\nnot-base64!\n"
			"-----END RSA PRIVATE KEY-----\n"
			"-----BEGIN EC PRIVATE KEY-----\nU1lOVEhFVElD\n"
			"-----END DSA PRIVATE KEY-----\n"
		)

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_non_private_pem_and_incomplete_blocks_are_not_detected(self):
		source = (
			"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
			"-----BEGIN RSA PRIVATE KEY-----\nINCOMPLETE\n"
		)

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_api_key_assignment_is_detected(self):
		source = 'api_key = "abc123"\n'

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "credential-assignment")
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].location, (1, 1))
		self.assertEqual(
			result[0].evidence,
			{"pattern": "credential-assignment", "credential_name": "api_key"},
		)

	def test_password_assignment_is_detected(self):
		source = "password = 's3cret!'\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["credential_name"], "password")
		self.assertEqual(result[0].location, (1, 1))

	def test_os_getenv_assignment_is_not_detected(self):
		source = 'api_key = os.getenv("API_KEY")\n'

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_placeholder_assignment_is_not_detected(self):
		source = 'password = "example"\n'

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_assignment_detection_uses_source_location_and_evidence(self):
		source = "prefix\nclient_secret = \"real-value\"\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].location, (2, 1))
		self.assertEqual(
			result[0].evidence,
			{"pattern": "credential-assignment", "credential_name": "client_secret"},
		)

	def test_github_pat_token_is_detected(self):
		source = "token = \"ghp_1234567890abcdefghijklmnop\"\n"

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "provider-token")
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].location, (1, 10))
		self.assertEqual(result[0].evidence["pattern"], "github-pat")
		self.assertEqual(result[0].evidence["provider"], "github")
		self.assertNotIn("1234567890abcdefghijklmnop", str(result[0].evidence))

	def test_github_pat_rejects_malformed_value(self):
		source = 'token = "ghp_short"\n'

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_gitlab_pat_is_detected(self):
		source = 'token = "glpat-1234567890abcdefghijklmnop"\n'

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["provider"], "gitlab")
		self.assertEqual(result[0].location, (1, 10))

	def test_slack_token_is_detected(self):
		source = 'token = "xoxb-1234567890-abcdefghijklmnop"\n'

		result = detect_secrets(source, _file_info())

		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["provider"], "slack")
		self.assertEqual(result[0].location, (1, 10))

	def test_provider_pattern_rejects_ordinary_string(self):
		source = 'note = "this is a normal sentence with common words"\n'

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_provider_pattern_rejects_placeholder_token(self):
		source = 'token = "ghp_exampleplaceholder"\n'

		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_provider_token_high_entropy_adds_entropy_evidence(self):
		source = 'token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "provider-token")
		self.assertGreater(result[0].evidence["entropy"], _ENTROPY_THRESHOLD)
		self.assertEqual(result[0].evidence["entropy_threshold"], _ENTROPY_THRESHOLD)
		self.assertTrue(result[0].evidence["entropy_signal"])

	def test_provider_token_low_entropy_keeps_existing_finding_without_entropy_signal(self):
		source = 'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].finding_type, "provider-token")
		self.assertNotIn("entropy", result[0].evidence)
		self.assertNotIn("entropy_threshold", result[0].evidence)
		self.assertNotIn("entropy_signal", result[0].evidence)

	def test_all_supported_credential_names_are_detected(self):
		for name in (
			"password",
			"api_key",
			"secret_key",
			"access_token",
			"client_secret",
		):
			with self.subTest(name=name):
				source = f'{name} = "synthetic-value"\n'
				result = detect_secrets(source, _file_info())
				self.assertEqual(len(result), 1)
				self.assertEqual(result[0].evidence["credential_name"], name)
				self.assertEqual(result[0].location, (1, 1))

	def test_assignment_rejects_empty_value(self):
		source = 'password = ""\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_assignment_rejects_placeholder_case_insensitive(self):
		source = 'SECRET_KEY = "CHANGEme"\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_os_environ_get_assignment_is_not_detected(self):
		source = 'access_token = os.environ.get("ACCESS_TOKEN")\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_unrelated_variable_names_are_not_detected(self):
		source = 'nickname = "long-value-that-should-not-match"\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_ordinary_long_string_is_not_detected(self):
		source = 'note = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_github_fine_grained_pat_is_detected(self):
		source = 'token = "github_pat_1234567890abcdefghijklmno"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].evidence["provider"], "github")
		self.assertEqual(result[0].location, (1, 10))

	def test_provider_pattern_rejects_near_miss_prefix(self):
		source = 'token = "gHp_1234567890abcdefghijklmnop"\n'
		self.assertEqual(detect_secrets(source, _file_info()), [])

	def test_provider_redirects_are_deterministic_and_repeatable(self):
		source = (
			'password = "s3cret"\n'
			'api_key = "abc123"\n'
			'ghp_1234567890abcdefghijklmnop\n'
		)
		first = detect_secrets(source, _file_info())
		second = detect_secrets(source, _file_info())
		self.assertEqual(
			[(finding.finding_type, finding.location, finding.detector_id, finding.evidence)
			 for finding in first],
			[(finding.finding_type, finding.location, finding.detector_id, finding.evidence)
			 for finding in second],
		)
		self.assertEqual(
			[finding.location for finding in first],
			[(1, 1), (2, 1), (3, 1)],
		)

	def test_finding_contract_contains_no_raw_value(self):
		source = 'client_secret = "real-value"\n'
		result = detect_secrets(source, _file_info())
		self.assertEqual(len(result), 1)
		self.assertEqual(result[0].relative_path, "synthetic.py")
		self.assertEqual(result[0].finding_type, "credential-assignment")
		self.assertEqual(result[0].detector_id, "pattern-secret")
		self.assertEqual(result[0].location, (1, 1))
		self.assertEqual(
			result[0].evidence,
			{"pattern": "credential-assignment", "credential_name": "client_secret"},
		)
		self.assertNotIn("real-value", str(result[0].evidence))


if __name__ == "__main__":
	unittest.main()
