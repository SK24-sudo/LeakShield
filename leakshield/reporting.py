import json
from html import escape


_TYPE_DESCRIPTIONS = {
    "credential-assignment": "Hardcoded credential assignment",
    "private-key": "PEM private key",
    "provider-token": "Provider-specific access token",
    "jwt": "JWT-like token",
    "eval": "Direct eval() call",
    "exec": "Direct exec() call",
    "subprocess": "subprocess.Popen() call",
    "shell-true": "subprocess.Popen() with shell=True",
    "os-system": "os.system() call",
}

_ACTION_MESSAGES = {
    "credential-assignment": "Move the credential outside source code and rotate it if it may already have been exposed.",
    "private-key": "Remove the private key from the repository and rotate it if it may have been exposed.",
    "provider-token": "Remove the token from the repository and revoke or rotate it if it may have been exposed.",
    "jwt": "Avoid hardcoding JWTs in source code; rotate the signing key if the token may have been exposed.",
    "eval": "Avoid eval() with untrusted input; consider safer alternatives.",
    "exec": "Avoid exec() with untrusted input; consider safer alternatives.",
    "subprocess": "Validate and sanitize arguments passed to subprocess.Popen.",
    "shell-true": "Avoid shell=True when possible and sanitize any untrusted input.",
    "os-system": "Avoid os.system() when possible; prefer subprocess.run with shell=False.",
}

_WHY_MESSAGES = {
    "credential-assignment": "A credential-like variable is assigned a hardcoded string value.",
    "private-key": "A PEM private-key pattern was detected in the source.",
    "provider-token": "The value matches a supported provider-specific token format.",
    "jwt": "A JWT-like structure with decodable header and payload was detected.",
    "eval": "A direct eval() call was detected by AST analysis.",
    "exec": "A direct exec() call was detected by AST analysis.",
    "subprocess": "A direct subprocess.Popen() call was detected by AST analysis.",
    "shell-true": "A subprocess call uses shell=True.",
    "os-system": "A direct os.system() call was detected by AST analysis.",
}


def _describe_finding(finding):
    finding_type = getattr(finding, "finding_type", None)
    if not isinstance(finding_type, str):
        finding_type = None
    what = _TYPE_DESCRIPTIONS.get(finding_type, "Security finding detected")
    why = _WHY_MESSAGES.get(
        finding_type,
        "LeakShield detected a supported security pattern.",
    )
    action = _ACTION_MESSAGES.get(
        finding_type,
        "Review this finding and determine whether the detected pattern is necessary and safe.",
    )
    return what, why, action


def _format_location(finding):
    relative_path = getattr(finding, "relative_path", "")
    location = getattr(finding, "location", None)
    line = ""
    column = ""
    if isinstance(location, (list, tuple)) and len(location) >= 2:
        line = str(location[0])
        column = str(location[1])
    return f"{relative_path}:{line}:{column}"


def format_findings_cli(findings: list) -> str:
    """Return a human-readable CLI report for the provided redacted Finding objects."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    total = len(findings)
    lines = []
    if total == 0:
        lines.append("No supported credential or secret patterns detected.")
        lines.append("")
        lines.append("LeakShield did not find any supported patterns in the files it analyzed.")
        lines.append("A clean scan is not a guarantee that the repository contains no secrets.")
        return "\n".join(lines)

    lines.append(f"{total} potential security findings found.")
    lines.append("")

    for finding in findings:
        lines.append(f"Location: {_format_location(finding)}")
        what, why, action = _describe_finding(finding)
        lines.append(f"What: {what}")
        lines.append(f"Why: {why}")
        lines.append(f"Action: {action}")
        lines.append("")

    return "\n".join(lines)


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