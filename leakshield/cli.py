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
    format_pre_commit_error_cli,
    format_pre_commit_result_cli,
    format_result_cli,
    format_scan_cli,
    format_target_cli,
)
from leakshield.scanner import scan

EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def resolve_target_display(target: str) -> str:
    """Return a resolved path representation for display."""
    try:
        p = Path(target)
        if p.exists():
            return str(p.resolve())
        return str(p.absolute())
    except Exception:
        return target


def handle_install_hook(target: str) -> int:
    """Handle the install-hook command."""
    from leakshield.git_protection import install_hook

    success, message = install_hook(target)
    if success:
        print(message)
        print()
        print("LeakShield will now automatically inspect staged changes before every commit.")
        print("To bypass in an emergency, use: git commit --no-verify")
        return 0
    else:
        print(message, file=sys.stderr)
        return 1


def handle_uninstall_hook(target: str) -> int:
    """Handle the uninstall-hook command."""
    from leakshield.git_protection import uninstall_hook

    success, message = uninstall_hook(target)
    if success:
        print(message)
        return 0
    else:
        print(message, file=sys.stderr)
        return 1


def handle_pre_commit(target: str, output_format: str = "cli") -> int:
    """Handle the pre-commit scan of staged changes."""
    from leakshield.git_protection import (
        GitProtectionError,
        get_git_root,
        is_git_repository,
        scan_staged,
    )

    target_path = Path(target).resolve()
    if not is_git_repository(target_path):
        if output_format == "cli":
            print(format_header())
            print()
            print(
                format_pre_commit_error_cli(
                    f"Target is not a Git repository:\n{target_path}",
                    action="Run this command inside a valid Git repository.",
                )
            )
        else:
            print(f"Target is not a Git repository: {target_path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        repo_root = get_git_root(target_path)
    except GitProtectionError as exc:
        if output_format == "cli":
            print(format_header())
            print()
            print(
                format_pre_commit_error_cli(
                    f"Could not determine Git repository root:\n{exc}",
                    action="Check Git repository status and permissions.",
                )
            )
        else:
            print(f"Could not determine Git repository root: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if output_format == "cli":
        print(format_header())
        print()
        print(format_target_cli(f"Staged changes ({repo_root})"))
        print()
        print(format_scan_cli())
        print()
        print("[1/2] Inspecting staged Git changes...")

    try:
        if output_format == "cli":
            print("[2/2] Analyzing supported security patterns...")
        findings = scan_staged(repo_root)
    except GitProtectionError as exc:
        if output_format == "cli":
            print()
            print(
                format_pre_commit_error_cli(
                    f"Failed to scan staged changes:\n{exc}",
                    action="Check Git repository status and staged files.",
                )
            )
        else:
            print(f"Failed to scan staged changes: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        if output_format == "cli":
            print()
            print(
                format_pre_commit_error_cli(
                    f"Unexpected error while scanning staged changes:\n{exc}",
                    action="Review the error above and retry.",
                )
            )
        else:
            print(f"Unexpected error while scanning staged changes: {exc}", file=sys.stderr)
        return EXIT_ERROR

    reported_findings = [f.redacted_copy() for f in findings]

    if output_format == "json":
        print(findings_to_json(reported_findings))
        return 1 if reported_findings else 0
    elif output_format == "html":
        print(findings_to_html(reported_findings, target=f"Staged changes ({repo_root})"))
        return 1 if reported_findings else 0

    print()
    print(format_pre_commit_result_cli(reported_findings))
    return 1 if reported_findings else 0


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

    # Check for Git protection subcommands
    if len(sys.argv) > 1 and sys.argv[1] in ("install-hook", "uninstall-hook", "pre-commit"):
        subcommand = sys.argv[1]
        target = "."
        output_format = "cli"

        # Parse optional target and --format arguments for subcommands
        idx = 2
        while idx < len(sys.argv):
            arg = sys.argv[idx]
            if arg == "--format" and idx + 1 < len(sys.argv):
                output_format = sys.argv[idx + 1]
                idx += 2
            elif not arg.startswith("-"):
                target = arg
                idx += 1
            else:
                idx += 1

        if subcommand == "install-hook":
            return handle_install_hook(target)
        elif subcommand == "uninstall-hook":
            return handle_uninstall_hook(target)
        elif subcommand == "pre-commit":
            return handle_pre_commit(target, output_format=output_format)

    parser = argparse.ArgumentParser(
        prog="leakshield",
        description="Local, zero-dependency repository security auditor.",
    )
    parser.add_argument(
        "target",
        help="path to repository or directory to scan",
    )
    parser.add_argument(
        "--format",
        choices=("cli", "json", "html"),
        default="cli",
        help="output format (cli: developer action, json: machine automation, html: security review report)",
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
        return EXIT_ERROR

    if config.output_format == "json":
        try:
            findings = scan(config)
        except Exception as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        reported_findings = [finding.redacted_copy() for finding in findings]
        print(findings_to_json(reported_findings))
        return EXIT_SUCCESS if not reported_findings else EXIT_FINDINGS

    if config.output_format == "html":
        try:
            findings = scan(config)
        except Exception as exc:
            print(f"Scan error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        reported_findings = [finding.redacted_copy() for finding in findings]
        resolved_target = resolve_target_display(config.target)
        print(findings_to_html(reported_findings, target=resolved_target))
        return EXIT_SUCCESS if not reported_findings else EXIT_FINDINGS

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
        return EXIT_ERROR
    except Exception as exc:
        print()
        print(format_error_cli(
            f"Scan encountered an error:\n{exc}",
            action="Check target path and permissions, then run LeakShield again.",
        ))
        return EXIT_ERROR

    reported_findings = [finding.redacted_copy() for finding in findings]
    print()
    print(format_result_cli(reported_findings))
    return EXIT_SUCCESS if not reported_findings else EXIT_FINDINGS
