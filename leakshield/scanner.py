from leakshield.ast_security import (
    _detect_credential_assignments,
    _detect_eval_calls,
    _detect_exec_calls,
    _detect_os_system,
    _detect_shell_true,
    _detect_subprocess_popen,
)
from leakshield.config import ScanConfig
from leakshield.discovery import discover, filter_files
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

    normalized = []
    for raw_finding in raw_findings:
        finding = Finding(raw_finding)
        finding.assign_confidence()
        finding.assign_severity()
        finding.calculate_risk()
        normalized.append(finding)

    return normalized


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


def _consolidation_identity(finding):
    """Return an identity suitable for grouping equivalent findings across locations."""
    return (
        finding.finding_type,
        finding.candidate_value,
        finding.detector_id,
        _freeze_for_identity(finding.evidence),
        finding.confidence,
        finding.severity,
        finding.risk,
    )


def consolidate_findings(findings):
    """Group equivalent findings across locations while preserving distinct findings."""
    if findings is None:
        return []

    groups = {}
    for finding in findings:
        identity = _consolidation_identity(finding)
        if identity not in groups:
            groups[identity] = []
        groups[identity].append(finding)

    consolidated = []
    for group in groups.values():
        if len(group) == 1:
            consolidated.append(group[0])
        else:
            representative = group[0]
            representative.locations = [
                (f.relative_path, f.location) for f in group
            ]
            consolidated.append(representative)

    return consolidated


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


def scan(config: ScanConfig, progress_callback=None) -> list[Finding]:
    """Scan the configured target and return the aggregated findings list."""
    if progress_callback is not None:
        progress_callback("discovering")
    files = filter_files(discover(config.target), config.ignore_patterns)
    if progress_callback is not None:
        progress_callback("analyzing")
    findings = []
    for file_info in files:
        with open(file_info.path, "r", encoding="utf-8", errors="replace") as handle:
            findings.extend(collect_findings(handle.read(), file_info))
    if progress_callback is not None:
        progress_callback("preparing")
    return consolidate_findings(deduplicate_findings(findings))
