import fnmatch
from pathlib import Path


class FileInfo:
    """Discovery-level information about one filesystem file."""

    def __init__(
        self,
        path,
        relative_path,
        name,
        extension,
        size,
        classification,
    ):
        self.path = path
        self.relative_path = relative_path
        self.name = name
        self.extension = extension
        self.size = size
        self.classification = classification

    def __repr__(self):
        return (
            "FileInfo("
            f"path={self.path!r}, "
            f"relative_path={self.relative_path!r}, "
            f"name={self.name!r}, "
            f"extension={self.extension!r}, "
            f"size={self.size!r}, "
            f"classification={self.classification!r}"
            ")"
        )


class DiscoveryError(Exception):
    """Raised when the discovery target cannot be processed."""


_TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".css",
    ".csv",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".md",
    ".py",
    ".rst",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

_PYTHON_EXTENSIONS = {".py"}


def _classify_file(path):
    """Perform only basic discovery-level classification."""
    extension = path.suffix.lower()

    if extension in _PYTHON_EXTENSIONS:
        return "python"

    if extension in _TEXT_EXTENSIONS:
        return "text"

    return "unknown"


def _relative_path(root, path):
    """Return a deterministic POSIX-style repository-relative path."""
    return path.relative_to(root).as_posix()


def _make_file_info(root, path):
    """Create FileInfo from filesystem metadata."""
    try:
        size = path.stat().st_size
    except OSError:
        return None

    relative = _relative_path(root, path)

    return FileInfo(
        path=path,
        relative_path=relative,
        name=path.name,
        extension=path.suffix.lower(),
        size=size,
        classification=_classify_file(path),
    )


def discover(target):
    """
    Discover regular files under a target directory or a single target file.

    Directory symlinks and symlinked files are not followed.
    Filesystem traversal errors are skipped conservatively.
    """
    original_target = Path(target)

    try:
        if original_target.is_symlink():
            raise DiscoveryError("Symlink targets are not supported.")

        target = original_target.resolve(strict=True)
    except DiscoveryError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DiscoveryError("Unable to resolve discovery target.") from exc

    if target.is_symlink():
        raise DiscoveryError("Symlink targets are not supported.")

    if target.is_file():
        root = target.parent

        file_info = _make_file_info(root, target)

        if file_info is None:
            raise DiscoveryError("Unable to read target file metadata.")

        return [file_info]

    if not target.is_dir():
        raise DiscoveryError("Target is not a supported filesystem target.")

    root = target
    discovered = []
    pending = [root]

    while pending:
        current = pending.pop()

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda entry: entry.name.casefold(),
            )
        except OSError:
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    pending.append(entry)
                    continue

                if not entry.is_file():
                    continue

                file_info = _make_file_info(root, entry)

                if file_info is not None:
                    discovered.append(file_info)

            except OSError:
                continue
            except RuntimeError:
                continue

    discovered.sort(key=lambda item: item.relative_path)

    return discovered


DEFAULT_IGNORE_PATTERNS = (
    ".git/",
    ".git/**",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".venv/",
    "venv/",
    "env/",
    "node_modules/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".idea/",
    ".vscode/",
)


def _normalize_ignore_path(path):
    """Return a repository-relative path in POSIX form."""
    normalized = str(path).replace("\\", "/")

    if normalized.startswith("./"):
        normalized = normalized[2:]

    return normalized


def is_ignored(file_info, custom_patterns=()):
    """Return whether a discovered file matches an ignore pattern."""
    relative_path = _normalize_ignore_path(file_info.relative_path)
    match_paths = [relative_path]
    path_parts = relative_path.split("/")

    for index in range(1, len(path_parts)):
        match_paths.append("/".join(path_parts[:index]) + "/")

    match_paths.extend(path_part + "/" for path_part in path_parts[:-1])

    for pattern in DEFAULT_IGNORE_PATTERNS + tuple(custom_patterns):
        for match_path in match_paths:
            if fnmatch.fnmatchcase(match_path, pattern):
                return True

    return False


def filter_files(files, custom_patterns=()):
    """Return files that do not match the configured ignore patterns."""
    return [
        file_info
        for file_info in files
        if not is_ignored(file_info, custom_patterns)
    ]