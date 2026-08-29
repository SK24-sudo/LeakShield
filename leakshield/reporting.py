import json
from html import escape


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


def findings_to_html(findings: list) -> str:
    """Return a minimal HTML report document for the provided Finding objects."""
    total_findings = len(findings)
    sections = []
    for finding in findings:
        sections.append(
            "        <article>\n"
            "            <p>Type: {}</p>\n"
            "            <p>File: {}</p>\n"
            "            <p>Line: {}</p>\n"
            "            <p>Severity: {}</p>\n"
            "            <p>Detector: {}</p>\n"
            "            <p>Redacted Evidence: {}</p>\n"
            "        </article>\n".format(
                escape(finding.finding_type),
                escape(finding.relative_path),
                escape(str(finding.location[0])),
                escape(finding.severity),
                escape(finding.detector_id),
                escape(str(finding.evidence)),
            )
        )

    findings_html = "".join(sections)
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <title>LeakShield Report</title>\n"
        "</head>\n"
        "<body>\n"
        "    <h1>LeakShield Report</h1>\n"
        "    <section>\n"
        "        <h2>Summary</h2>\n"
        f"        <p>Total Findings: {total_findings}</p>\n"
        "    </section>\n"
        "    <section>\n"
        "        <h2>Findings</h2>\n"
        f"{findings_html}"
        "    </section>\n"
        "</body>\n"
        "</html>\n"
    )
