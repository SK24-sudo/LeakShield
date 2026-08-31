import subprocess
from pathlib import Path

from leakshield.discovery import FileInfo, _classify_file, is_ignored
from leakshield.findings import Finding
from leakshield.scanner import collect_findings, deduplicate_findings

LEAKSHIELD_HOOK_MARKER = "# LeakShield managed pre-commit hook"


class GitProtectionError(Exception):
    """Raised when a Git protection or inspection operation fails."""


def _run_git_command(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run a Git command and return the completed process."""
    try:
        return subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        raise GitProtectionError(f"Git CLI could not be executed: {exc}") from exc


def is_git_repository(target: str | Path = ".") -> bool:
    """Return True if target is inside a valid Git repository work tree."""
    target_path = Path(target).resolve()
    if not target_path.exists():
        return False
    # If target is a file, use its parent directory
    cwd = target_path if target_path.is_dir() else target_path.parent
    try:
        proc = _run_git_command(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
        return proc.returncode == 0 and proc.stdout.decode("utf-8", errors="replace").strip() == "true"
    except GitProtectionError:
        return False


def get_git_root(target: str | Path = ".") -> Path:
    """Return the absolute root Path of the Git repository for target."""
    target_path = Path(target).resolve()
    cwd = target_path if target_path.is_dir() else target_path.parent
    proc = _run_git_command(["rev-parse", "--show-toplevel"], cwd=cwd)
    if proc.returncode != 0:
        raise GitProtectionError(f"Target is not inside a Git repository work tree: {target_path}")
    raw_root = proc.stdout.decode("utf-8", errors="replace").strip()
    return Path(raw_root).resolve()


def get_git_hooks_dir(repo_root: Path) -> Path:
    """Return the hooks directory path for the given repository root."""
    proc = _run_git_command(["rev-parse", "--git-path", "hooks"], cwd=repo_root)
    if proc.returncode == 0:
        hooks_rel = proc.stdout.decode("utf-8", errors="replace").strip()
        hooks_path = Path(hooks_rel)
        if hooks_path.is_absolute():
            return hooks_path.resolve()
        return (repo_root / hooks_path).resolve()
    return (repo_root / ".git" / "hooks").resolve()


def get_staged_files(repo_root: Path) -> list[str]:
    """Return list of staged file paths relative to the repository root.

    Uses --diff-filter=ACMR to include Added, Copied, Modified, and Renamed files,
    while excluding Deleted files.
    """
    proc = _run_git_command(["diff", "--cached", "--name-only", "--diff-filter=ACMR"], cwd=repo_root)
    if proc.returncode != 0:
        raise GitProtectionError("Failed to list staged Git files.")
    output = proc.stdout.decode("utf-8", errors="replace")
    files = [line.strip() for line in output.splitlines() if line.strip()]
    return sorted(files)


def get_staged_content(repo_root: Path, relative_path: str) -> str | None:
    """Extract staged content in-memory for a relative file path.

    Returns the decoded string content, or None if the file is binary or cannot be decoded.
    """
    normalized_path = relative_path.replace("\\", "/")
    proc = _run_git_command(["show", f":{normalized_path}"], cwd=repo_root)
    if proc.returncode != 0:
        return None

    raw_bytes = proc.stdout
    # Gracefully skip binary files (presence of null byte)
    if b"\x00" in raw_bytes:
        return None

    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None


def scan_staged(repo_root: Path, ignore_patterns=()) -> list[Finding]:
    """Scan all staged files in repo_root and return aggregated normalized/deduplicated findings."""
    staged_rel_paths = get_staged_files(repo_root)
    findings = []

    for rel_path in staged_rel_paths:
        posix_rel_path = rel_path.replace("\\", "/")
        path_obj = Path(posix_rel_path)
        classification = _classify_file(path_obj)

        file_info = FileInfo(
            path=repo_root / path_obj,
            relative_path=posix_rel_path,
            name=path_obj.name,
            extension=path_obj.suffix.lower(),
            size=0,
            classification=classification,
        )

        if is_ignored(file_info, ignore_patterns):
            continue

        content = get_staged_content(repo_root, posix_rel_path)
        if content is None:
            continue

        file_info.size = len(content.encode("utf-8", errors="replace"))
        findings.extend(collect_findings(content, file_info))

    return deduplicate_findings(findings)


def is_leakshield_hook(hook_path: Path) -> bool:
    """Return True if hook_path exists and contains the LeakShield management marker."""
    if not hook_path.exists() or not hook_path.is_file():
        return False
    try:
        text = hook_path.read_text(encoding="utf-8", errors="replace")
        return LEAKSHIELD_HOOK_MARKER in text
    except Exception:
        return False


def generate_hook_script(leakshield_source_dir: str) -> str:
    """Generate the POSIX pre-commit hook script content."""
    # Convert source dir to forward slashes for cross-platform POSIX sh compatibility
    posix_source_dir = Path(leakshield_source_dir).as_posix()
    return f"""#!/bin/sh
{LEAKSHIELD_HOOK_MARKER}
# Automatically audits staged changes for secrets and security-sensitive patterns.

# Ensure LeakShield is available on PYTHONPATH when running from source tree
if [ -z "$PYTHONPATH" ]; then
    export PYTHONPATH="{posix_source_dir}"
else
    export PYTHONPATH="{posix_source_dir}:$PYTHONPATH"
fi

if command -v python >/dev/null 2>&1; then
    PYTHON_EXEC="python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXEC="python3"
elif command -v py >/dev/null 2>&1; then
    PYTHON_EXEC="py -3"
else
    echo "LeakShield pre-commit check could not complete." >&2
    echo "Python executable not found in PATH." >&2
    exit 1
fi

exec $PYTHON_EXEC -m leakshield pre-commit
"""


def install_hook(target_repo: str | Path = ".") -> tuple[bool, str]:
    """Install the LeakShield pre-commit hook in target_repo.

    Returns (True, success_message) on success, or (False, error_message) on failure.
    Never overwrites an existing hook unless it was created by LeakShield.
    """
    target_path = Path(target_repo).resolve()
    if not is_git_repository(target_path):
        return False, f"Target is not a Git repository:\n{target_path}"

    try:
        repo_root = get_git_root(target_path)
    except GitProtectionError as exc:
        return False, str(exc)

    hooks_dir = get_git_hooks_dir(repo_root)
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"Could not create hooks directory {hooks_dir}:\n{exc}"

    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        if not is_leakshield_hook(hook_file):
            return (
                False,
                f"An existing pre-commit hook is already present and is not managed by LeakShield:\n"
                f"{hook_file}\n\n"
                "Action:\n"
                "Review or backup your existing hook, or chain LeakShield manually.\n"
                "LeakShield will never silently overwrite existing developer tooling.",
            )

    leakshield_source_dir = Path(__file__).resolve().parent.parent.as_posix()
    hook_content = generate_hook_script(leakshield_source_dir)

    try:
        hook_file.write_text(hook_content, encoding="utf-8", newline="\n")
        # Ensure executable permissions on POSIX systems
        try:
            current_mode = hook_file.stat().st_mode
            hook_file.chmod(current_mode | 0o755)
        except OSError:
            pass
        return True, f"LeakShield pre-commit hook installed successfully in:\n{repo_root}"
    except OSError as exc:
        return False, f"Failed to write pre-commit hook file:\n{exc}"


def uninstall_hook(target_repo: str | Path = ".") -> tuple[bool, str]:
    """Uninstall the LeakShield pre-commit hook from target_repo.

    Returns (True, success_message) on success, or (False, error_message) on failure.
    Refuses to remove an unrelated hook.
    """
    target_path = Path(target_repo).resolve()
    if not is_git_repository(target_path):
        return False, f"Target is not a Git repository:\n{target_path}"

    try:
        repo_root = get_git_root(target_path)
    except GitProtectionError as exc:
        return False, str(exc)

    hooks_dir = get_git_hooks_dir(repo_root)
    hook_file = hooks_dir / "pre-commit"

    if not hook_file.exists():
        return False, f"No pre-commit hook found in:\n{repo_root}"

    if not is_leakshield_hook(hook_file):
        return (
            False,
            f"The existing pre-commit hook was not installed or managed by LeakShield:\n"
            f"{hook_file}\n\n"
            "Action:\n"
            "Manual removal required if you wish to remove this hook.\n"
            "LeakShield will never delete unrelated developer tooling.",
        )

    try:
        hook_file.unlink()
        return True, f"LeakShield pre-commit hook uninstalled successfully from:\n{repo_root}"
    except OSError as exc:
        return False, f"Failed to remove pre-commit hook file:\n{exc}"

