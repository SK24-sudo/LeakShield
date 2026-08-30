import argparse

from leakshield.config import ScanConfig
from leakshield.reporting import findings_to_html, findings_to_json, format_findings_cli
from leakshield.scanner import scan


def main() -> int:
    parser = argparse.ArgumentParser(prog="leakshield")
    parser.add_argument("target")
    parser.add_argument(
        "--format",
        choices=("cli", "json", "html"),
        default="cli",
    )
    args = parser.parse_args()
    config = ScanConfig(args.target, output_format=args.format)
    findings = scan(config)
    reported_findings = [finding.redacted_copy() for finding in findings]
    if config.output_format == "json":
        print(findings_to_json(reported_findings))
    elif config.output_format == "html":
        print(findings_to_html(reported_findings))
    else:
        print(format_findings_cli(reported_findings))
    return 0
