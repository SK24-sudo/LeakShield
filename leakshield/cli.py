import argparse

from leakshield.config import ScanConfig
from leakshield.reporting import findings_to_json
from leakshield.scanner import scan


def main() -> int:
    parser = argparse.ArgumentParser(prog="leakshield")
    parser.add_argument("target")
    args = parser.parse_args()
    config = ScanConfig(args.target)
    findings = scan(config)
    if config.output_format == "json":
        print(findings_to_json(findings))
    else:
        print(f"Findings: {len(findings)}")
    return 0
