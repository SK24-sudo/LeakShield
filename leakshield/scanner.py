from leakshield.ast_security import (
    _detect_credential_assignments,
    _detect_eval_calls,
    _detect_exec_calls,
    _detect_os_system,
    _detect_shell_true,
    _detect_subprocess_popen,
)
from leakshield.findings import Finding
from leakshield.secrets import detect_secrets


def _freeze_for_identity(value):
    """Create a hashable value snapshot for equality comparisons of normalized findings."""
    if isinstance(value, dict):
        return tuple(sorted((key, _freeze_for_identity(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_for_identity(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted(_freeze_for_identity(item) for item in value))
    return value


def _finding_identity(finding):
    return (
        finding.finding_type,
        finding.relative_path,
        finding.location,
        finding.candidate_value,
        finding.detector_id,
        _freeze_for_identity(finding.evidence),
        finding.confidence,
        finding.severity,
        finding.risk,
    )


def normalize_findings(raw_findings):
    """Convert a deterministic list of RawFinding values into normalized Finding objects."""
    if raw_findings is None:
        return []
    return [Finding(raw_finding) for raw_finding in raw_findings]


def deduplicate_findings(findings):
    """Drop later exact duplicate normalized findings while preserving the first object unchanged."""
    if findings is None:
        return []

    deduped = []
    seen = set()
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding instance")

        identity = _finding_identity(finding)
        if identity in seen:
            continue

        seen.add(identity)
        deduped.append(finding)

    return deduped


def collect_findings(source_text, file_info):
    """Collect and deduplicate the normalized findings for one file."""
    raw_findings = collect_raw_findings(source_text, file_info)
    return deduplicate_findings(normalize_findings(raw_findings))


def _enrich_with_extension(findings, file_info):
    """Attach existing file extension context to detector evidence without changing detector semantics."""
    if file_info is None:
        return findings

    extension = getattr(file_info, "extension", None)
    if not isinstance(extension, str):
        return findings

    enriched = []
    for finding in findings:
        evidence = dict(finding.evidence)
        evidence["file_extension"] = extension
        enriched.append(
            type(finding)(
                finding_type=finding.finding_type,
                relative_path=finding.relative_path,
                location=finding.location,
                candidate_value=finding.candidate_value,
                detector_id=finding.detector_id,
                evidence=evidence,
            )
        )
    return enriched


def collect_raw_findings(source_text, file_info):
    """Collect the existing detector-produced RawFinding results for one file.

    Deterministic order:
    1. secret findings from detect_secrets()
    2. AST findings in the fixed rule order below

    This step is collection only and must not change any detector evidence.
    """
    findings = []
    findings.extend(detect_secrets(source_text, file_info))

    for detector in (
        _detect_eval_calls,
        _detect_exec_calls,
        _detect_subprocess_popen,
        _detect_shell_true,
        _detect_os_system,
        _detect_credential_assignments,
    ):
        findings.extend(detector(source_text, file_info))

    return _enrich_with_extension(findings, file_info)
