import argparse
import sys
from pathlib import Path

from leakshield.config import ConfigurationError, ScanConfig
from leakshield.discovery import DiscoveryError
from leakshield.reporting import (
    findings_to_html,
    findings_to_json,
    format_error_cli,
    format_header,
    format_result_cli,
    format_scan_cli,
    format_target_cli,
)
from leakshield.scanner import scan


def resolve_target_display(target: str) -> str:
    """Return a resolved path representation for display."""
    try:
        p = Path(target)
        if p.exists():
            return str(p.resolve())
        return str(p.absolute())
    except Exception:
        return target


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(prog="leakshield")
    parser.add_argument("target")
    parser.add_argument(
        "--format",
        choices=("cli", "json", "html"),
        default="cli",
    )
    args = parser.parse_args()

    try:
        config = ScanConfig(args.target, output_format=args.format)
    except ConfigurationError as exc:
        if args.format == "cli":
            print(format_header())
            print()
            print(format_error_cli(
                f"Configuration error:\n{exc}",
                action="Check your command-line arguments and run LeakShield again.",
            ))
        else:
            print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    if config.output_format == "json":
        try:
            findings = scan(config)
        except Exception as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return 1
        reported_findings = [finding.redacted_copy() for finding in findings]
        print(findings_to_json(reported_findings))
        return 0

    if config.output_format == "html":
        try:
            findings = scan(config)
        except Exception as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return 1
        reported_findings = [finding.redacted_copy() for finding in findings]
        print(findings_to_html(reported_findings))
        return 0

    # CLI presentation format
    print(format_header())
    print()
    resolved_target = resolve_target_display(config.target)
    print(format_target_cli(resolved_target))
    print()
    print(format_scan_cli())
    print()

    def on_progress(phase: str):
        if phase == "discovering":
            print("[1/3] Discovering repository files...")
        elif phase == "analyzing":
            print("[2/3] Analyzing supported security patterns...")
        elif phase == "preparing":
            print("[3/3] Preparing findings...")

    try:
        findings = scan(config, progress_callback=on_progress)
    except DiscoveryError as exc:
        print()
        target_path = Path(config.target)
        if not target_path.exists():
            explanation = f"Target does not exist:\n{resolved_target}"
        elif target_path.is_symlink():
            explanation = f"Symlink targets are not supported:\n{resolved_target}"
        elif not target_path.is_dir() and not target_path.is_file():
            explanation = f"Target is not a supported filesystem target:\n{resolved_target}"
        else:
            explanation = f"Unable to process target:\n{resolved_target}\n\nDetails: {exc}"

        print(format_error_cli(
            explanation,
            action="Provide a valid repository path and run LeakShield again.",
        ))
        return 1
    except Exception as exc:
        print()
        print(format_error_cli(
            f"Scan encountered an error:\n{exc}",
            action="Check target path and permissions, then run LeakShield again.",
        ))
        return 1

    reported_findings = [finding.redacted_copy() for finding in findings]
    print()
    print(format_result_cli(reported_findings))
    return 0
