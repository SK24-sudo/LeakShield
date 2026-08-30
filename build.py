#!/usr/bin/env python3
"""Deterministic build script for LeakShield."""

import hashlib
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
PACKAGE_DIR = REPO_ROOT / "leakshield"
DIST_DIR = REPO_ROOT / "dist"
ARTIFACT_NAME = "LeakShield.pyz"
ARTIFACT_PATH = DIST_DIR / ARTIFACT_NAME

ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def collect_source_files(root: Path):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in (".git", "__pycache__", ".pytest_cache", "node_modules")
        )
        for filename in sorted(filenames):
            if filename.endswith((".pyc", ".pyo")):
                continue
            files.append(Path(dirpath) / filename)
    return sorted(files)


def build():
    if not PACKAGE_DIR.is_dir():
        print(f"ERROR: package directory not found: {PACKAGE_DIR}", file=sys.stderr)
        sys.exit(1)

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    if ARTIFACT_PATH.exists():
        ARTIFACT_PATH.unlink()

    tmpdir = tempfile.mkdtemp(prefix="leakshield_build_")
    try:
        staging = Path(tmpdir) / "app"
        staging.mkdir(parents=True, exist_ok=True)

        root_main = staging / "__main__.py"
        root_main.write_text(
            "from leakshield.cli import main\n\n"
            "if __name__ == \"__main__\":\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )

        for src in collect_source_files(PACKAGE_DIR):
            rel = src.relative_to(PACKAGE_DIR)
            dst = staging / "leakshield" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

        zip_path = Path(tmpdir) / ARTIFACT_NAME
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
            for arcname in sorted(
                p.relative_to(staging).as_posix()
                for p in staging.rglob("*")
                if p.is_file()
            ):
                file_path = staging / arcname
                info = zipfile.ZipInfo(filename=arcname, date_time=ZIP_DATE_TIME)
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (0o644 & 0xFFFF) << 16
                with file_path.open("rb") as f:
                    zf.writestr(info, f.read())

        shutil.move(str(zip_path), str(ARTIFACT_PATH))

        digest = compute_sha256(ARTIFACT_PATH)
        print(f"Built: {ARTIFACT_PATH}")
        print(f"SHA-256: {digest}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    build()
