import json


def findings_to_json(findings: list) -> str:
    """Return a JSON string for the provided Finding objects."""
    payload = []
    for finding in findings:
        payload.append(
            {
                "finding_type": finding.finding_type,
                "relative_path": finding.relative_path,
                "location": list(finding.location),
                "candidate_value": finding.candidate_value,
                "detector_id": finding.detector_id,
                "evidence": finding.evidence,
                "confidence": finding.confidence,
                "severity": finding.severity,
                "risk": finding.risk,
            }
        )
    return json.dumps(payload, indent=2)
