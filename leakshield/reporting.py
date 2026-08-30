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


_HEADER_DIVIDER = "=" * 60
_SECTION_DIVIDER = "-" * 60


def format_header() -> str:
    """Return the visual header banner for LeakShield."""
    lines = [
        _HEADER_DIVIDER,
        "LEAKSHIELD".center(60).rstrip(),
        _HEADER_DIVIDER,
        "",
        "Local, zero-dependency repository security auditor".center(60).rstrip(),
        "",
        "Prevent accidentally shipping secrets and security-sensitive".center(60).rstrip(),
        "code patterns.".center(60).rstrip(),
    ]
    return "\n".join(lines)


def format_target_cli(target: str) -> str:
    """Return the formatted Target section."""
    lines = [
        _SECTION_DIVIDER,
        "Target",
        _SECTION_DIVIDER,
        "",
        str(target),
    ]
    return "\n".join(lines)


def format_scan_cli() -> str:
    """Return the formatted Scan header section."""
    lines = [
        _SECTION_DIVIDER,
        "Scan",
        _SECTION_DIVIDER,
    ]
    return "\n".join(lines)


def format_result_cli(findings: list) -> str:
    """Return the formatted Result section for scan findings."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    lines = [
        _SECTION_DIVIDER,
        "Result",
        _SECTION_DIVIDER,
        "",
    ]

    total = len(findings)
    if total == 0:
        lines.append("✓ No potential security findings found.")
        lines.append("")
        lines.append("Scan complete.")
        return "\n".join(lines)

    finding_word = "finding" if total == 1 else "findings"
    lines.append(f"⚠ {total} potential security {finding_word} found.")
    lines.append("")
    lines.append("Review the findings below and address them before committing")
    lines.append("security-sensitive code.")
    lines.append("")

    for finding in findings:
        lines.append(_SECTION_DIVIDER)
        lines.append("")
        lines.append(f"Location: {_format_location(finding)}")
        what, why, action = _describe_finding(finding)
        lines.append(f"What: {what}")
        lines.append("")
        lines.append("Why:")
        lines.append(why)
        lines.append("")
        lines.append("Action:")
        lines.append(action)
        lines.append("")

    lines.append(_SECTION_DIVIDER)
    lines.append("")
    lines.append("Scan complete.")
    return "\n".join(lines)


def format_error_cli(explanation: str, action: str = "Provide a valid repository path and run LeakShield again.") -> str:
    """Return the formatted Result section for an uncompleted scan."""
    lines = [
        _SECTION_DIVIDER,
        "Result",
        _SECTION_DIVIDER,
        "",
        "✗ Scan could not be completed.",
        "",
        explanation,
        "",
        "Action:",
        action,
    ]
    return "\n".join(lines)


def format_pre_commit_result_cli(findings: list) -> str:
    """Return the formatted Result section for pre-commit staged scan."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    lines = [
        _SECTION_DIVIDER,
        "Result",
        _SECTION_DIVIDER,
        "",
    ]

    total = len(findings)
    if total == 0:
        lines.append("✓ No potential security findings found in staged changes.")
        lines.append("")
        lines.append("Commit allowed.")
        return "\n".join(lines)

    finding_word = "finding" if total == 1 else "findings"
    lines.append(f"⚠ {total} potential security {finding_word} found in staged changes.")
    lines.append("")
    lines.append("Commit blocked.")
    lines.append("")

    for finding in findings:
        lines.append(_SECTION_DIVIDER)
        lines.append("")
        lines.append(f"Location: {_format_location(finding)}")
        what, why, action = _describe_finding(finding)
        lines.append(f"What: {what}")
        lines.append("")
        lines.append("Why:")
        lines.append(why)
        lines.append("")
        lines.append("Action:")
        lines.append(action)
        lines.append("")

    lines.append(_SECTION_DIVIDER)
    lines.append("")
    if total == 1:
        lines.append("Fix the finding and stage the updated file before committing.")
    else:
        lines.append("Fix the findings and stage the updated files before committing.")
    return "\n".join(lines)


def format_pre_commit_error_cli(explanation: str, action: str = "Review the error above and retry.") -> str:
    """Return the formatted Result section for an uncompleted pre-commit check."""
    lines = [
        _SECTION_DIVIDER,
        "Result",
        _SECTION_DIVIDER,
        "",
        "✗ LeakShield pre-commit check could not complete.",
        "",
        "Commit blocked.",
        "",
        explanation,
        "",
        "Action:",
        action,
    ]
    return "\n".join(lines)


def format_findings_cli(findings: list, target: str = "") -> str:
    """Return a human-readable CLI report for the provided redacted Finding objects."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    sections = [format_header()]

    if target:
        sections.append("")
        sections.append(format_target_cli(target))

    sections.append("")
    sections.append(format_result_cli(findings))

    return "\n".join(sections)


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


def findings_to_html(findings: list, target: str = "") -> str:
    """Return a self-contained HTML security review report for the provided Finding objects."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    total_findings = len(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        sev = getattr(f, "severity", None)
        if sev in severity_counts:
            severity_counts[sev] += 1
        conf = getattr(f, "confidence", None)
        if conf in confidence_counts:
            confidence_counts[conf] += 1
        risk = getattr(f, "risk", None)
        if risk in risk_counts:
            risk_counts[risk] += 1

    target_html = ""
    if target:
        target_html = f'<p class="target-meta"><strong>Target:</strong> <code>{escape(target)}</code></p>'

    if total_findings == 0:
        findings_content = """        <div class="zero-state">
            <div class="zero-icon">✓</div>
            <h3>No potential security findings found</h3>
            <p>No supported LeakShield findings were detected in the analyzed files.</p>
        </div>"""
    else:
        finding_cards = []
        for finding in findings:
            what, why, action = _describe_finding(finding)
            location_str = _format_location(finding)
            finding_type_val = getattr(finding, "finding_type", "unknown")
            sev_val = getattr(finding, "severity", "medium") or "medium"
            conf_val = getattr(finding, "confidence", "medium") or "medium"
            risk_val = getattr(finding, "risk", "medium") or "medium"
            detector_id_val = getattr(finding, "detector_id", "detector")

            evidence_items = []
            if isinstance(finding.evidence, dict) and finding.evidence:
                for k, v in sorted(finding.evidence.items()):
                    evidence_items.append(f'<span class="evidence-tag"><code>{escape(str(k))}={escape(str(v))}</code></span>')
            evidence_html = " ".join(evidence_items) if evidence_items else '<span class="evidence-tag"><code>none</code></span>'

            card = f"""        <article class="finding-card">
            <header class="card-header">
                <div class="card-title-group">
                    <h3 class="card-title">{escape(what)}</h3>
                    <span class="finding-type-code">{escape(finding_type_val)}</span>
                </div>
                <div class="badges">
                    <span class="badge badge-sev-{escape(sev_val)}">{escape(sev_val.upper())} SEVERITY</span>
                    <span class="badge badge-conf">{escape(conf_val.capitalize())} Confidence</span>
                    <span class="badge badge-risk-{escape(risk_val)}">{escape(risk_val.upper())} RISK</span>
                </div>
            </header>
            <div class="card-body">
                <div class="detail-row">
                    <span class="detail-label">Location:</span>
                    <span class="detail-value"><code>{escape(location_str)}</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Detector:</span>
                    <span class="detail-value"><code>{escape(detector_id_val)}</code></span>
                </div>
                <div class="detail-section">
                    <h4>Why it matters:</h4>
                    <p>{escape(why)}</p>
                </div>
                <div class="detail-section action-section">
                    <h4>Recommended action:</h4>
                    <p>{escape(action)}</p>
                </div>
                <div class="detail-section evidence-section">
                    <h4>Redacted Evidence:</h4>
                    <div class="evidence-list">{evidence_html}</div>
                </div>
            </div>
        </article>"""
            finding_cards.append(card)
        findings_content = "\n".join(finding_cards)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeakShield Security Report</title>
    <style>
        :root {{
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --brand-primary: #1e293b;
            --color-critical: #dc2626;
            --color-high: #ea580c;
            --color-medium: #d97706;
            --color-low: #2563eb;
            --color-success: #16a34a;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        .report-header {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .report-header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--brand-primary);
            margin-bottom: 0.25rem;
        }}
        .subtitle {{
            color: var(--text-muted);
            font-size: 0.95rem;
            margin-bottom: 0.75rem;
        }}
        .target-meta {{
            font-size: 0.9rem;
            color: var(--text-main);
            padding-top: 0.5rem;
            border-top: 1px solid var(--border-color);
        }}
        .target-meta code {{
            background: #f1f5f9;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        .summary-section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .summary-section h2, .findings-section h2 {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--brand-primary);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 0.75rem;
        }}
        .stat-card {{
            background: #f8fafc;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .stat-label {{
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}
        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--brand-primary);
        }}
        .stat-breakdown {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }}
        .findings-section {{
            margin-bottom: 2rem;
        }}
        .zero-state {{
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            border-radius: 8px;
            padding: 2.5rem 2rem;
            text-align: center;
            color: #065f46;
        }}
        .zero-icon {{
            font-size: 2.5rem;
            line-height: 1;
            margin-bottom: 0.5rem;
            color: var(--color-success);
        }}
        .zero-state h3 {{
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }}
        .zero-state p {{
            font-size: 0.95rem;
            color: #047857;
        }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card-header {{
            background: #f8fafc;
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}
        .card-title-group {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        .card-title {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-main);
        }}
        .finding-type-code {{
            font-size: 0.75rem;
            background: #e2e8f0;
            color: #475569;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
        }}
        .badges {{
            display: flex;
            gap: 0.4rem;
            flex-wrap: wrap;
        }}
        .badge {{
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        .badge-sev-critical {{ background: #fee2e2; color: #991b1b; }}
        .badge-sev-high {{ background: #ffedd5; color: #9a3412; }}
        .badge-sev-medium {{ background: #fef3c7; color: #92400e; }}
        .badge-sev-low {{ background: #dbeafe; color: #1e40af; }}
        .badge-conf {{ background: #f1f5f9; color: #475569; }}
        .badge-risk-critical {{ background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }}
        .badge-risk-high {{ background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }}
        .badge-risk-medium {{ background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }}
        .badge-risk-low {{ background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }}
        .card-body {{
            padding: 1.25rem;
        }}
        .detail-row {{
            display: flex;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }}
        .detail-label {{
            font-weight: 600;
            width: 90px;
            flex-shrink: 0;
            color: var(--text-muted);
        }}
        .detail-value code {{
            background: #f1f5f9;
            padding: 0.1rem 0.35rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        .detail-section {{
            margin-top: 0.75rem;
            padding-top: 0.75rem;
            border-top: 1px solid #f1f5f9;
            font-size: 0.9rem;
        }}
        .detail-section h4 {{
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}
        .action-section p {{
            color: #1e293b;
            font-weight: 500;
        }}
        .evidence-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.35rem;
            margin-top: 0.25rem;
        }}
        .evidence-tag code {{
            background: #f1f5f9;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: #334155;
        }}
        .report-footer {{
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            padding: 1rem 0;
        }}
        @media print {{
            body {{ padding: 0; background: #fff; }}
            .report-header, .summary-section, .finding-card {{ box-shadow: none; border-color: #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <h1>LeakShield Report</h1>
            <p class="subtitle">Local, zero-dependency repository security auditor</p>
            {target_html}
        </header>

        <section class="summary-section">
            <h2>Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Findings</div>
                    <div class="stat-value">{total_findings}</div>
                    <div class="stat-breakdown">Potential security findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Severity Breakdown</div>
                    <div class="stat-breakdown">
                        High: {severity_counts['high']} &bull; Medium: {severity_counts['medium']} &bull; Low: {severity_counts['low']}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Confidence Breakdown</div>
                    <div class="stat-breakdown">
                        High: {confidence_counts['high']} &bull; Medium: {confidence_counts['medium']} &bull; Low: {confidence_counts['low']}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Risk Breakdown</div>
                    <div class="stat-breakdown">
                        High: {risk_counts['high']} &bull; Medium: {risk_counts['medium']} &bull; Low: {risk_counts['low']}
                    </div>
                </div>
            </div>
        </section>

        <section class="findings-section">
            <h2>Findings</h2>
{findings_content}
        </section>

        <footer class="report-footer">
            <p>Generated by LeakShield — Local Zero-Dependency Security Auditor</p>
        </footer>
    </div>
</body>
</html>
"""