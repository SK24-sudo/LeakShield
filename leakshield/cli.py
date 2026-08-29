import argparse

from leakshield.config import ScanConfig
from leakshield.reporting import findings_to_html, findings_to_json
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
    if config.output_format == "json":
        print(findings_to_json(findings))
    elif config.output_format == "html":
        print(findings_to_html(findings))
    else:
        print(f"Findings: {len(findings)}")
    return 0
